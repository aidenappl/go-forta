package forta

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"strconv"
	"strings"
	"time"
)

// Client is the configured Forta client. All methods are safe for concurrent use.
type Client struct {
	cfg        Config
	httpClient *http.Client
}

// newClient validates cfg and returns a ready-to-use Client.
func newClient(cfg Config) (*Client, error) {
	if err := cfg.validate(); err != nil {
		return nil, err
	}
	// Strip trailing slash so all URL construction is consistent.
	cfg.Domain = strings.TrimRight(cfg.Domain, "/")
	return &Client{
		cfg: cfg,
		httpClient: &http.Client{
			Timeout: 10 * time.Second,
		},
	}, nil
}

// url builds a full URL against the configured Forta domain.
func (c *Client) url(path string) string {
	return c.cfg.Domain + path
}

// Ping calls GET /healthcheck and returns an error if the Forta API is not
// reachable or does not return 2xx.
func (c *Client) Ping() error {
	req, err := http.NewRequest(http.MethodGet, c.url("/healthcheck"), nil)
	if err != nil {
		return fmt.Errorf("go-forta: ping: %w", err)
	}
	resp, err := c.httpClient.Do(req)
	if err != nil {
		return fmt.Errorf("go-forta: ping: %w", err)
	}
	defer resp.Body.Close()
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
	defer resp.Body.Close()

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

// getUserInfo calls GET /oauth/userinfo with the given Bearer token and returns
// the user's OIDC profile. The returned User contains the fields available from
// the standard userinfo response; database-only fields (e.g. Status) are empty.
func (c *Client) getUserInfo(ctx context.Context, accessToken string) (*User, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, c.url("/oauth/userinfo"), nil)
	if err != nil {
		return nil, fmt.Errorf("go-forta: userinfo: request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+accessToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("go-forta: userinfo: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode == http.StatusUnauthorized {
		return nil, fmt.Errorf("go-forta: userinfo: invalid or expired token")
	}
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("go-forta: userinfo: forta returned status %d", resp.StatusCode)
	}

	var info OAuthUserInfoResponse
	if err := json.NewDecoder(resp.Body).Decode(&info); err != nil {
		return nil, fmt.Errorf("go-forta: userinfo: decode: %w", err)
	}

	id, err := strconv.ParseInt(info.Sub, 10, 64)
	if err != nil {
		return nil, fmt.Errorf("go-forta: userinfo: invalid sub %q: %w", info.Sub, err)
	}

	user := &User{
		ID:              id,
		Email:           info.Email,
		EmailVerified:   info.EmailVerified,
		Name:            info.Name,
		ProfileImageURL: info.Picture,
	}
	if info.PreferredUsername != nil {
		user.Metadata = &UserMetadata{Username: info.PreferredUsername}
	}
	return user, nil
}

// refreshTokens calls POST /auth/refresh with the given refresh token and
// returns a fresh token pair and the user profile.
func (c *Client) refreshTokens(ctx context.Context, refreshToken string) (*AuthResponse, error) {
	req, err := http.NewRequestWithContext(ctx, http.MethodPost, c.url("/auth/refresh"), nil)
	if err != nil {
		return nil, fmt.Errorf("go-forta: refresh: request: %w", err)
	}
	req.Header.Set("Authorization", "Bearer "+refreshToken)

	resp, err := c.httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("go-forta: refresh: %w", err)
	}
	defer resp.Body.Close()

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
