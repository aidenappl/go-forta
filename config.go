package forta

import (
	"errors"
	"fmt"
	"strings"
	"time"
)

// Config holds all the settings needed to use Forta as an authentication
// provider. Pass it to Setup once at application startup.
type Config struct {
	// APIDomain is the base URL of the Forta API server used for token exchange,
	// token validation, and user info lookups.
	// Required. Example: "https://auth.appleby.cloud"
	//
	// This must be the real Forta API host, because the JWKS endpoint is
	// derived from it ({APIDomain}/oauth/jwks) and must agree with the
	// "jwks_uri" advertised by the issuer's OIDC discovery document.
	APIDomain string

	// LoginDomain is the base URL of the Forta login UI used to build the
	// OAuth2 authorization redirect in LoginHandler.
	// Required. Example: "https://forta.appleby.cloud"
	LoginDomain string

	// ClientID is the OAuth2 client ID registered with Forta for this platform.
	// Required.
	ClientID string

	// ClientSecret is the OAuth2 client secret for this platform.
	// Required.
	ClientSecret string

	// CallbackURL is the full URL Forta will redirect to after a successful
	// login via the OAuth2 authorization code flow.
	// Required for external (non-first-party) services.
	// Example: "https://openbucket.appleby.cloud/forta/callback"
	CallbackURL string

	// PostLoginRedirect is where to redirect the browser after the
	// CallbackHandler completes successfully. Defaults to "/".
	PostLoginRedirect string

	// PostLogoutRedirect is where to redirect the browser after
	// LogoutHandler completes. Defaults to "/".
	PostLogoutRedirect string

	// AppDomain is the base URL of the application using Forta
	// (e.g. "https://myapp.appleby.cloud"). When set it is used as the origin
	// for all redirect URIs constructed by the library, preventing open-redirect
	// attacks that could otherwise be triggered via manipulated request Host
	// headers. Highly recommended in production.
	AppDomain string

	// CookieDomain sets the Domain attribute on auth cookies. Use
	// ".appleby.cloud" for shared first-party cookies so they are readable
	// across all subdomains. Leave empty for site-specific cookies.
	CookieDomain string

	// CookieInsecure disables the Secure flag on auth cookies when true.
	// Only set this for local HTTP development. Production deployments
	// should leave this false (cookies require HTTPS).
	CookieInsecure bool

	// JWTSigningKey is the HMAC-SHA512 key the Forta server uses to sign its
	// access tokens. When set, token validation is done entirely in-process
	// with no network round-trip. When empty, each Protected request will
	// call the /oauth/userinfo endpoint to validate the token and the full User
	// object is automatically available in the context.
	JWTSigningKey string

	// JWKSURL overrides where the issuer's public JSON Web Key Set is fetched
	// from. Optional — when empty it defaults to {APIDomain}/oauth/jwks, which
	// is correct for every real deployment. Mainly useful in tests.
	//
	// The key set is only ever fetched lazily, on the first RS256 token the
	// process actually sees. A service that only receives HS512 tokens never
	// makes a JWKS request.
	JWKSURL string

	// JWKSMinRefreshInterval is the minimum time between two JWKS fetches
	// triggered by a token carrying an unknown key id. Optional — defaults to
	// DefaultJWKSMinRefreshInterval (5 minutes).
	//
	// Lowering this shortens the window before a rotated signing key is picked
	// up, at the cost of letting an attacker drive more JWKS traffic with
	// forged "kid" values. Do not set it to zero-ish values in production.
	JWKSMinRefreshInterval time.Duration

	// JWKSMaxAge is how long a cached key set is served before it is re-fetched.
	// Optional — defaults to DefaultJWKSMaxAge (1 hour). A Cache-Control
	// max-age on the JWKS response takes precedence when present, clamped to
	// [5 minutes, 24 hours]; forta-api serves "public, max-age=3600".
	//
	// This bounds **revocation** latency for a compromised signing key, which
	// is a different problem from rotation: rotation is discovered by the
	// unknown-kid re-fetch, but a key that is already cached is only ever
	// re-checked because of this max age. It is independent of
	// JWKSMinRefreshInterval and does not affect that rate limit.
	JWKSMaxAge time.Duration

	// AcceptedIssuers overrides the set of "iss" claim values accepted during
	// local token validation. Optional — when empty, both the legacy
	// "forta:auth-service" and the OIDC discovery issuer
	// "https://auth.appleby.cloud" are accepted (see DefaultAcceptedIssuers).
	//
	// The URL form is the target; the legacy string is transitional and will be
	// dropped once no live token carries it. Set this only if you need to pin a
	// single issuer — the list is honoured exactly, with no defaults merged in.
	AcceptedIssuers []string

	// EnableJWKS opts in to local JWT validation with no shared HMAC secret at
	// all — i.e. RS256-only. Optional, default false.
	//
	// It is not needed to accept RS256 tokens: whenever JWTSigningKey is set,
	// local validation already accepts both HS512 (shared key) and RS256
	// (JWKS). Set this only once the shared secret has been removed from the
	// deployment, after forta-api has flipped to RS256.
	EnableJWKS bool

	// FetchUserOnProtect controls whether the Protected middleware fetches the
	// full user profile from /oauth/userinfo on every authenticated request.
	// Only relevant when JWTSigningKey is set (local validation). When false,
	// only the Forta user ID is available in the context via GetFortaIDFromContext.
	// When true, the full User is also available via GetUserFromContext.
	FetchUserOnProtect bool

	// DisableAutoRefresh prevents the Protected middleware from transparently
	// refreshing an expired access token using the refresh token cookie.
	// Auto-refresh is enabled by default.
	DisableAutoRefresh bool

	// EnforceGrants enables grant checking on every authenticated request.
	// When true, the Protected middleware verifies the user holds an active
	// grant for this platform (identified by ClientID) via a cached call to
	// the Forta API. Revoked grants take effect once the cache entry expires.
	// Default: false (existing behavior).
	EnforceGrants bool

	// GrantCacheTTL controls how long grant check results are cached in memory.
	// Only relevant when EnforceGrants is true. Default: 30 seconds.
	GrantCacheTTL time.Duration

	// APITokenCacheTTL controls how long a resolved opaque API token (frt_…) is
	// reused before being re-validated against Forta. This also bounds
	// revocation latency: a token revoked in Forta keeps working for at most
	// this long. Default: 60 seconds.
	APITokenCacheTTL time.Duration
}

// String returns a human-readable representation of the config with secrets
// redacted so it is safe to include in logs.
func (c Config) String() string {
	return fmt.Sprintf("Config{APIDomain:%s, ClientID:%s, LoginDomain:%s}", c.APIDomain, c.ClientID, c.LoginDomain)
}

func (c Config) validate() error {
	if c.APIDomain == "" {
		return errors.New("go-forta: Config.APIDomain is required")
	}
	if c.LoginDomain == "" {
		return errors.New("go-forta: Config.LoginDomain is required")
	}
	if c.ClientID == "" {
		return errors.New("go-forta: Config.ClientID is required")
	}
	if c.ClientSecret == "" {
		return errors.New("go-forta: Config.ClientSecret is required")
	}
	return nil
}

// jwksURL returns the JWKS endpoint to use, defaulting to the issuer's
// well-known path on the configured API domain.
func (c Config) jwksURL() string {
	if c.JWKSURL != "" {
		return c.JWKSURL
	}
	return strings.TrimRight(c.APIDomain, "/") + jwksPath
}

// acceptedIssuers returns the configured "iss" allowlist, falling back to the
// package defaults when unset. The configured list is used exactly as given.
func (c Config) acceptedIssuers() []string {
	if len(c.AcceptedIssuers) > 0 {
		return c.AcceptedIssuers
	}
	return defaultAcceptedIssuers
}

// postLoginRedirect returns the configured redirect URL with a safe default.
func (c Config) postLoginRedirect() string {
	if c.PostLoginRedirect != "" {
		return c.PostLoginRedirect
	}
	return "/"
}

// postLogoutRedirect returns the configured logout redirect URL with a safe default.
func (c Config) postLogoutRedirect() string {
	if c.PostLogoutRedirect != "" {
		return c.PostLogoutRedirect
	}
	return "/"
}
