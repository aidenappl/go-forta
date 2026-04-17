package forta

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"log"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// Client is the configured Forta client. All methods are safe for concurrent use.
type Client struct {
	cfg        Config
	httpClient *http.Client
	grants     *grantCache // nil when EnforceGrants is false
}

// newClient validates cfg and returns a ready-to-use Client.
func newClient(cfg Config) (*Client, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	// Strip trailing slashes so all URL construction is consistent.
	cfg.APIDomain = strings.TrimRight(cfg.APIDomain, "/")
	cfg.LoginDomain = strings.TrimRight(cfg.LoginDomain, "/")
	c := &Client{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}
	if cfg.EnforceGrants {
		c.grants = newGrantCache(2 * time.Minute)
		log.Printf("go-forta: grant enforcement enabled (client_id=%s, api=%s)", cfg.ClientID, cfg.APIDomain)
	}
	return c, nil
}

// url builds a full URL against the configured Forta API domain.
func (c *Client) url(path string) string {
	return c.cfg.APIDomain + path
}

// Ping calls GET /healthcheck and returns an error if the Forta API is not
// reachable or does not return 2xx. It uses context.Background(); use
// PingContext to supply a custom context.
func (c *Client) Ping() error {
	return c.PingContext(context.Background())
}

// PingContext is like Ping but accepts a context for cancellation and timeouts.
func (c *Client) PingContext(ctx context.Context) error {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url("/healthcheck"), nil)
	if err != nil {
		return fmt.Errorf("go-forta: ping: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("go-forta: ping: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()
	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return fmt.Errorf("go-forta: ping: unexpected status %d", resp.StatusCode)
	}
	return nil
}

// exchangeCode calls POST /auth/exchange to swap an authorization code for a
// full token pair and user profile. The Forta API validates the client
// credentials as part of this request.
func (c *Client) exchangeCode(ctx context.Context, code string) (*AuthResponse, error) {
	body, err := json.Marshal(exchangeCodeRequest{
		ClientID:     c.cfg.ClientID,
		ClientSecret: c.cfg.ClientSecret,
		Code:         code,
	})
	if err != nil {
		return nil, fmt.Errorf("go-forta: exchange: marshal: %w", err)
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url("/auth/exchange"), bytes.NewReader(body))
	if err != nil {
		return nil, fmt.Errorf("go-forta: exchange: request: %w", err)
	}
	req.Header.Set("Content-Type", "application/json")

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("go-forta: exchange: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("go-forta: exchange: forta returned status %d", resp.StatusCode)
	}

	var envelope fortaEnvelope[AuthResponse]
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("go-forta: exchange: decode: %w", err)
	}
	if !envelope.Success {
		return nil, fmt.Errorf("go-forta: exchange: %s", envelope.Message)
	}

	return &envelope.Data, nil
}

// getUserInfo calls GET /auth/self with the given Bearer token and returns
// the full authenticated user profile.
func (c *Client) getUserInfo(ctx context.Context, accessToken string) (*User, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url("/auth/self"), nil)
	if err != nil {
		return nil, fmt.Errorf("go-forta: auth/self: request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("go-forta: auth/self: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("go-forta: auth/self: invalid or expired token")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("go-forta: auth/self: forta returned status %d", resp.StatusCode)
	}

	var envelope fortaEnvelope[User]
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("go-forta: auth/self: decode: %w", err)
	}

	return &envelope.Data, nil
}

// refreshTokens calls POST /auth/refresh with the given refresh token and
// returns a fresh token pair and the user profile.
func (c *Client) refreshTokens(ctx context.Context, refreshToken string) (*AuthResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url("/auth/refresh"), nil)
	if err != nil {
		return nil, fmt.Errorf("go-forta: refresh: request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+refreshToken)
	req.Header.Set("X-Forta-Client-ID", c.cfg.ClientID)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("go-forta: refresh: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("go-forta: refresh: invalid or expired refresh token")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("go-forta: refresh: forta returned status %d", resp.StatusCode)
	}

	var envelope fortaEnvelope[AuthResponse]
	if err := json.NewDecoder(resp.Body).Decode(&envelope); err != nil {
		return nil, fmt.Errorf("go-forta: refresh: decode: %w", err)
	}
	if !envelope.Success {
		return nil, fmt.Errorf("go-forta: refresh: %s", envelope.Message)
	}

	return &envelope.Data, nil
}

// checkGrant calls GET /internal/grants/check?client_id=<ClientID> to verify
// the user holds an active grant for this platform. Returns true if the grant
// is active, false if revoked/missing. On transient errors the method returns
// false (fail-closed) along with the error.
func (c *Client) checkGrant(ctx context.Context, accessToken string) (bool, error) {
	endpoint := c.url("/internal/grants/check") + "?client_id=" + url.QueryEscape(c.cfg.ClientID)
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, endpoint, nil)
	if err != nil {
		return false, fmt.Errorf("go-forta: grant check: request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return false, fmt.Errorf("go-forta: grant check: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode == http.StatusForbidden {
		log.Printf("go-forta: grant denied for client_id=%s", c.cfg.ClientID)
		return false, nil
	}
	if resp.StatusCode == http.StatusOK {
		return true, nil
	}

	return false, fmt.Errorf("go-forta: grant check: unexpected status %d", resp.StatusCode)
}
