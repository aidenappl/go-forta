package sso

import (
	"context"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"sync"
	"time"

	"github.com/coreos/go-oidc/v3/oidc"
	"golang.org/x/oauth2"
)

// discoveryTimeout bounds an OIDC discovery fetch. Discovery happens on the
// first login through a provider and is then cached, so this is a startup-shaped
// cost, not a per-request one — but it sits on a user-facing path, so it must not
// hang.
const discoveryTimeout = 10 * time.Second

// userInfoTimeout bounds the optional UserInfo call.
const userInfoTimeout = 5 * time.Second

var (
	discoveryMu    sync.Mutex
	discoveryCache = map[string]*oidc.Provider{}
)

// discover performs OIDC discovery once per issuer and caches the result.
//
// The cache is keyed on the issuer URL and never invalidated. That is correct for
// what it holds: endpoint URLs and the JWKS URI, which are part of the issuer's
// stable identity rather than rotating material. The KEYS behind that JWKS URI are
// fetched and re-fetched by go-oidc's own remote key set, which handles rotation —
// so caching this does not pin a retired signing key.
func discover(ctx context.Context, issuer string) (*oidc.Provider, error) {
	discoveryMu.Lock()
	defer discoveryMu.Unlock()

	if p, ok := discoveryCache[issuer]; ok {
		return p, nil
	}

	ctx, cancel := context.WithTimeout(ctx, discoveryTimeout)
	defer cancel()

	p, err := oidc.NewProvider(ctx, issuer)
	if err != nil {
		return nil, fmt.Errorf("sso: oidc discovery for %q: %w", issuer, err)
	}
	discoveryCache[issuer] = p
	return p, nil
}

// oidcAdapter drives a compliant OpenID Connect provider.
type oidcAdapter struct {
	provider *Provider
	oidcProv *oidc.Provider
	verifier *oidc.IDTokenVerifier
	oauth    *oauth2.Config
}

func newOIDCAdapter(ctx context.Context, p *Provider) (Adapter, error) {
	op, err := discover(ctx, p.IssuerURL)
	if err != nil {
		return nil, err
	}

	// The verifier checks the signature against the provider's JWKS, plus `iss`,
	// `aud` (== our client_id) and `exp`.
	//
	// ⚠️ IT DOES NOT CHECK THE NONCE. go-oidc documents this and leaves it to the
	// caller; Exchange below does it. "We use a well-known library" is not a
	// substitute for reading which checks the library actually performs — one of
	// the implementations this package replaced relied on exactly that assumption
	// and verified no nonce at all.
	verifier := op.Verifier(&oidc.Config{ClientID: p.ClientID})

	return &oidcAdapter{
		provider: p,
		oidcProv: op,
		verifier: verifier,
		oauth: &oauth2.Config{
			ClientID:     p.ClientID,
			ClientSecret: p.ClientSecret,
			Endpoint:     op.Endpoint(),
			RedirectURL:  p.RedirectURL,
			Scopes:       p.scopeList(),
		},
	}, nil
}

// LogoutVerifier exposes the id_token verifier for back-channel logout.
//
// It satisfies logoutVerifierSource, the narrow interface BackchannelLogout
// type-asserts for. Only KindOIDC implements it — an OAuth2 provider has no
// signed tokens and no JWKS, so there is nothing to verify a logout token
// against, and back-channel logout is genuinely unavailable there rather than
// merely unimplemented.
func (a *oidcAdapter) LogoutVerifier() *oidc.IDTokenVerifier { return a.verifier }

func (a *oidcAdapter) AuthCodeURL(state, nonce, verifier string) (string, error) {
	if state == "" || nonce == "" || verifier == "" {
		// All three come from GenerateState. An empty one means the caller
		// hand-assembled the flow and dropped a defence; refuse rather than build a
		// URL that authenticates without it.
		return "", fmt.Errorf("sso: AuthCodeURL requires state, nonce and verifier")
	}
	return a.oauth.AuthCodeURL(state,
		oidc.Nonce(nonce),
		oauth2.S256ChallengeOption(verifier),
	), nil
}

func (a *oidcAdapter) Exchange(ctx context.Context, code, verifier, nonce string) (*Identity, *TokenSet, error) {
	if verifier == "" || nonce == "" {
		return nil, nil, fmt.Errorf("sso: Exchange requires the verifier and nonce from the state record")
	}

	// oauth2.VerifierOption sends code_verifier. Without it the S256 challenge we
	// sent at authorize time is unanswered and the exchange fails at any server
	// that enforces PKCE — and silently succeeds at one that does not, which is the
	// failure mode worth fearing.
	oauthToken, err := a.oauth.Exchange(ctx, code, oauth2.VerifierOption(verifier))
	if err != nil {
		return nil, nil, fmt.Errorf("sso: oidc code exchange: %w", err)
	}

	rawID, _ := oauthToken.Extra("id_token").(string)
	if rawID == "" {
		return nil, nil, fmt.Errorf("sso: oidc token response carried no id_token")
	}

	idToken, err := a.verifier.Verify(ctx, rawID)
	if err != nil {
		return nil, nil, fmt.Errorf("sso: oidc id_token verification failed: %w", err)
	}

	// ── The nonce check go-oidc does not do ──────────────────────────────────
	//
	// This binds the id_token to the authorization request we started. Without it,
	// an id_token obtained in ANY session for this client is accepted in THIS
	// session — the id_token injection attack. The comparison is on the value from
	// the server-side state record, never on anything in the request.
	if idToken.Nonce != nonce {
		return nil, nil, fmt.Errorf("sso: oidc id_token nonce mismatch")
	}

	var claims map[string]any
	if err := idToken.Claims(&claims); err != nil {
		return nil, nil, fmt.Errorf("sso: oidc claim decode: %w", err)
	}

	// Subject comes from the VERIFIED id_token, and the configured claim override
	// is read from that same verified claim set — never from an unverified source.
	subject := claimString(claims, a.provider.SubjectClaim, "sub")
	if subject == "" {
		subject = idToken.Subject
	}
	if subject == "" {
		return nil, nil, fmt.Errorf("sso: oidc identity has no subject")
	}

	if a.provider.FetchUserInfo {
		uiClaims, err := a.fetchUserInfo(ctx, oauthToken, subject)
		if err != nil {
			return nil, nil, err
		}
		// Merge UserInfo UNDER the id_token: a claim present in both keeps the
		// id_token's value, because that one is signed.
		for k, v := range uiClaims {
			if _, exists := claims[k]; !exists {
				claims[k] = v
			}
		}
	}

	email := claimString(claims, a.provider.EmailClaim, "email")
	emailVerified := a.provider.TrustEmailVerified ||
		claimBool(claims, a.provider.EmailVerifiedClaim, "email_verified")

	raw, err := json.Marshal(claims)
	if err != nil {
		// Claims came out of a JSON document, so this cannot normally fail; not
		// swallowed, because a silently-empty RawClaims would be a confusing thing
		// for an application to debug.
		return nil, nil, fmt.Errorf("sso: re-encode claims: %w", err)
	}

	id := &Identity{
		Provider:      a.provider.Slug,
		Subject:       subject,
		Email:         email,
		EmailVerified: emailVerified,
		Name:          claimPtr(claims, "name"),
		Picture:       claimPtr(claims, "picture"),
		RawClaims:     raw,
	}
	tokens := &TokenSet{
		AccessToken:  oauthToken.AccessToken,
		RefreshToken: oauthToken.RefreshToken,
		IDToken:      rawID,
	}
	return id, tokens, nil
}

// fetchUserInfo calls the UserInfo endpoint and returns its claims.
//
// ─────────────────────────────────────────────────────────────────────────────
// OIDC Core §5.3.2: THE `sub` MUST MATCH, OR THE RESPONSE MUST NOT BE USED.
//
// The specification is unusually blunt about this, and the reason is worth
// stating: the UserInfo response is fetched with a BEARER TOKEN and is not signed.
// If its `sub` were merged without comparison, then any way of getting a
// different user's access token — a mix-up between providers, a confused-deputy
// endpoint, a caching proxy — becomes a way to log in as that user, because the
// email and name merged in would be theirs.
//
// So a mismatch is a hard failure of the whole login, not a skipped merge. There
// is no configuration to relax it.
// ─────────────────────────────────────────────────────────────────────────────
func (a *oidcAdapter) fetchUserInfo(ctx context.Context, tok *oauth2.Token, idTokenSubject string) (map[string]any, error) {
	ctx, cancel := context.WithTimeout(ctx, userInfoTimeout)
	defer cancel()

	ui, err := a.oidcProv.UserInfo(ctx, oauth2.StaticTokenSource(tok))
	if err != nil {
		return nil, fmt.Errorf("sso: oidc userinfo: %w", err)
	}

	if ui.Subject != idTokenSubject {
		return nil, fmt.Errorf("sso: oidc userinfo sub %q does not match id_token sub %q (OIDC Core §5.3.2 — response discarded)",
			ui.Subject, idTokenSubject)
	}

	var claims map[string]any
	if err := ui.Claims(&claims); err != nil {
		return nil, fmt.Errorf("sso: oidc userinfo claim decode: %w", err)
	}
	return claims, nil
}

// readLimited reads at most n bytes.
//
// Every response body this package parses goes through it. An IdP is a trusted
// party right up until it is a compromised or misconfigured one, and an unbounded
// io.ReadAll on a remote response is a memory-exhaustion primitive handed to
// whoever controls that endpoint.
func readLimited(r io.Reader, n int64) ([]byte, error) {
	return io.ReadAll(io.LimitReader(r, n))
}

// maxResponseBytes bounds an IdP response. Generous for a token or UserInfo
// document — a large id_token with many claims is a few kilobytes.
const maxResponseBytes = 1 << 20 // 1 MiB

// claimString reads a string claim by the configured name, falling back to the
// standard name.
//
// Values are stringified via fmt.Sprint so a numeric `sub` — which some providers
// emit despite the specification requiring a string — is read rather than
// silently dropped. "<nil>" is filtered because that is what fmt.Sprint produces
// for a JSON null, and a literal "<nil>" subject would be a shared identity for
// every user whose claim was null.
func claimString(claims map[string]any, field, fallback string) string {
	for _, f := range []string{field, fallback} {
		if f == "" {
			continue
		}
		v, ok := claims[f]
		if !ok || v == nil {
			continue
		}
		if s := fmt.Sprint(v); s != "" && s != "<nil>" {
			return s
		}
	}
	return ""
}

// claimBool reads a boolean claim, accepting the string forms some providers send.
func claimBool(claims map[string]any, field, fallback string) bool {
	for _, f := range []string{field, fallback} {
		if f == "" {
			continue
		}
		switch v := claims[f].(type) {
		case bool:
			return v
		case string:
			return v == "true"
		}
	}
	return false
}

func claimPtr(claims map[string]any, field string) *string {
	if v, ok := claims[field]; ok && v != nil {
		if s := fmt.Sprint(v); s != "" && s != "<nil>" {
			return &s
		}
	}
	return nil
}

// httpClient is the client used for the hand-rolled OAuth2 calls. A timeout is
// set explicitly: http.DefaultClient has none, so a hung IdP would hold a request
// goroutine indefinitely.
var httpClient = &http.Client{Timeout: 15 * time.Second}
