package sso

import (
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/url"
	"strings"
	"time"
)

// introspectTimeout bounds one introspection call. The checkpoint runs on a
// user-facing request, so a slow IdP must degrade to "could not check" quickly
// rather than holding the request open.
const introspectTimeout = 5 * time.Second

// IntrospectResponse is the subset of RFC 7662 §2.2 this package reads.
type IntrospectResponse struct {
	// Active is the only field that matters for a revocation decision, and RFC 7662
	// §2.2 makes it the only REQUIRED one.
	Active bool `json:"active"`

	Scope    string `json:"scope,omitempty"`
	ClientID string `json:"client_id,omitempty"`
	Username string `json:"username,omitempty"`
	Sub      string `json:"sub,omitempty"`
	Exp      int64  `json:"exp,omitempty"`
}

// Introspect asks the provider whether a token is still active (RFC 7662).
//
// ⚠️ DISTINGUISH THE TWO FAILURE MODES, because the whole checkpoint design rests
// on it:
//
//	(active: false, nil)  — a DEFINITIVE NEGATIVE. The IdP says this grant is
//	                        gone. Act on it.
//	(nil, err)            — NO ANSWER. Network failure, timeout, 5xx, malformed
//	                        response. This says nothing about the grant.
//
// Collapsing them — treating an error as "not active" — turns every IdP blip into
// a platform-wide logout. Collapsing them the other way — treating an error as
// "active" — makes revocation unenforceable whenever an attacker can disrupt the
// connection. Checkpoint handles them separately and bounds the second.
func Introspect(ctx context.Context, p *Provider, token, hint string) (*IntrospectResponse, error) {
	if p.IntrospectURL == "" {
		return nil, fmt.Errorf("sso: provider %q has no introspect_url", p.Slug)
	}
	if p.ClientID == "" || p.ClientSecret == "" {
		// RFC 7662 §2.1 requires the caller to authenticate. A public client cannot
		// introspect, and a request without credentials would be refused anyway.
		return nil, fmt.Errorf("sso: provider %q has no client credentials, so it cannot introspect", p.Slug)
	}
	if token == "" {
		return nil, fmt.Errorf("sso: introspect requires a token")
	}

	form := url.Values{}
	form.Set("token", token)
	if hint != "" {
		form.Set("token_type_hint", hint)
	}

	ctx, cancel := context.WithTimeout(ctx, introspectTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodPost, p.IntrospectURL, strings.NewReader(form.Encode()))
	if err != nil {
		return nil, fmt.Errorf("sso: introspect request: %w", err)
	}
	req.Header.Set("Content-Type", "application/x-www-form-urlencoded")
	req.Header.Set("Accept", "application/json")
	// HTTP Basic per RFC 6749 §2.3.1 — the form of client authentication every
	// introspection endpoint supports.
	req.SetBasicAuth(p.ClientID, p.ClientSecret)

	resp, err := httpClient.Do(req)
	if err != nil {
		return nil, fmt.Errorf("sso: introspect: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	body, err := readLimited(resp.Body, maxResponseBytes)
	if err != nil {
		return nil, fmt.Errorf("sso: introspect read: %w", err)
	}

	if resp.StatusCode != http.StatusOK {
		// ⚠️ A NON-200 IS AN ERROR, NEVER active:false. A 401 means OUR client
		// credentials are wrong; a 500 means the IdP is broken. Reading either as "the
		// user's grant was revoked" would log out every user on the platform in
		// response to our own misconfiguration — which is precisely the shape of
		// outage this distinction exists to prevent.
		return nil, fmt.Errorf("sso: introspect status %d: %s", resp.StatusCode, truncate(string(body), 256))
	}

	var out IntrospectResponse
	if err := json.Unmarshal(body, &out); err != nil {
		return nil, fmt.Errorf("sso: introspect decode: %w", err)
	}
	return &out, nil
}
