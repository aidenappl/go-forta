package forta

import "errors"

// Config holds all the settings needed to use Forta as an authentication
// provider. Pass it to Setup once at application startup.
type Config struct {
	// Domain is the base URL of the Forta authentication server.
	// Required. Example: "https://forta.appleby.cloud"
	Domain string

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
}

func (c Config) validate() error {
	if c.Domain == "" {
		return errors.New("go-forta: Config.Domain is required")
	}
	if c.ClientID == "" {
		return errors.New("go-forta: Config.ClientID is required")
	}
	if c.ClientSecret == "" {
		return errors.New("go-forta: Config.ClientSecret is required")
	}
	return nil
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
