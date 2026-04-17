// Package forta provides a Go client library for integrating Forta as an
// authentication provider into any service.
//
// # Quick Start
//
// Call Setup once at application startup with your platform credentials:
//
//	err := forta.Setup(forta.Config{
//	    Domain:       "https://forta.appleby.cloud",
//	    ClientID:     "my-client-id",
//	    ClientSecret: "my-secret",
//	    CallbackURL:  "https://myapp.example.com/forta/callback",
//	})
//	if err != nil { log.Fatal(err) }
//
//	if err := forta.Ping(); err != nil { log.Fatal("forta unreachable:", err) }
//
// Register the built-in handlers and protect your routes:
//
//	mux.HandleFunc("/forta/login",    forta.LoginHandler)
//	mux.HandleFunc("/forta/callback", forta.CallbackHandler)
//	mux.HandleFunc("/forta/logout",   forta.LogoutHandler)
//
//	mux.HandleFunc("/api/resource", forta.Protected(handleResource))
//
// Inside a protected handler retrieve the authenticated identity:
//
//	func handleResource(w http.ResponseWriter, r *http.Request) {
//	    fortaID, _ := forta.GetFortaIDFromContext(r.Context())
//	    user, _    := forta.GetUserFromContext(r.Context()) // populated when FetchUserOnProtect: true
//	}
//
// # OAuth2 / Appleby-cloud first-party services
//
// Services hosted on *.appleby.cloud may share the Forta session cookie
// (set with CookieDomain: ".appleby.cloud") and therefore do not need
// the full code-exchange callback flow. The Protected middleware will
// automatically accept and validate the shared cookie.
package forta

import (
	"context"
	"errors"
	"net/http"
	"sync"
)

// ErrNotConfigured is returned by package-level functions when Setup has not
// been called yet.
var ErrNotConfigured = errors.New("go-forta: Setup has not been called")

var (
	defaultClientMu sync.RWMutex
	defaultClient   *Client
)

// Setup initialises the global Forta client with the provided configuration.
// It must be called once before any other function in this package.
func Setup(cfg Config) error {
	c, err := newClient(cfg)
	if err != nil {
		return err
	}
	defaultClientMu.Lock()
	defaultClient = c
	defaultClientMu.Unlock()
	return nil
}

// getDefaultClient returns the global client safely under a read lock.
func getDefaultClient() *Client {
	defaultClientMu.RLock()
	defer defaultClientMu.RUnlock()
	return defaultClient
}

// Ping tests connectivity to the configured Forta API by calling its
// /healthcheck endpoint. Returns an error if the service is unreachable or
// returns a non-2xx response.
func Ping() error {
	c := getDefaultClient()
	if c == nil {
		return ErrNotConfigured
	}
	return c.Ping()
}

// PingContext is like Ping but accepts a context for cancellation and timeouts.
func PingContext(ctx context.Context) error {
	c := getDefaultClient()
	if c == nil {
		return ErrNotConfigured
	}
	return c.PingContext(ctx)
}

// Protected wraps the given http.HandlerFunc, requiring a valid Forta access
// token provided either as an Authorization: Bearer <token> header or via the
// forta-access-token cookie. On success the Forta user ID is injected into the
// request context; call GetFortaIDFromContext to retrieve it.
//
// If AutoRefresh is enabled (default) and the access token is expired but a
// valid refresh token cookie is present, the tokens are refreshed transparently
// and new cookies are written to the response.
func Protected(next http.HandlerFunc) http.HandlerFunc {
	c := getDefaultClient()
	if c == nil {
		return func(w http.ResponseWriter, r *http.Request) {
			writeJSONError(w, http.StatusInternalServerError, "forta: not configured")
		}
	}
	return c.Protected(next)
}

// LoginHandler redirects the browser to the Forta OAuth2 authorization
// endpoint. A CSRF state token is stored in an HttpOnly cookie and validated
// on return via CallbackHandler.
func LoginHandler(w http.ResponseWriter, r *http.Request) {
	c := getDefaultClient()
	if c == nil {
		writeJSONError(w, http.StatusInternalServerError, "forta: not configured")
		return
	}
	c.LoginHandler(w, r)
}

// CallbackHandler handles the OAuth2 redirect callback from Forta.
// It validates the CSRF state, exchanges the authorization code for a token
// pair, stores the tokens as HttpOnly cookies, and redirects to
// Config.PostLoginRedirect (default "/").
func CallbackHandler(w http.ResponseWriter, r *http.Request) {
	c := getDefaultClient()
	if c == nil {
		writeJSONError(w, http.StatusInternalServerError, "forta: not configured")
		return
	}
	c.CallbackHandler(w, r)
}

// LogoutHandler clears all Forta auth cookies and redirects to
// Config.PostLogoutRedirect (default "/").
func LogoutHandler(w http.ResponseWriter, r *http.Request) {
	c := getDefaultClient()
	if c == nil {
		writeJSONError(w, http.StatusInternalServerError, "forta: not configured")
		return
	}
	c.LogoutHandler(w, r)
}

// GetFortaIDFromContext returns the authenticated user's Forta ID injected by
// the Protected middleware. The second return value is false if the value is
// not present (i.e. the handler was not wrapped with Protected).
func GetFortaIDFromContext(ctx context.Context) (int64, bool) {
	return getFortaIDFromContext(ctx)
}

// GetUserFromContext returns the full Forta User profile injected by the
// Protected middleware. The profile is only present when:
//   - Config.FetchUserOnProtect is true, OR
//   - Config.JWTSigningKey is empty (remote validation via /auth/self)
func GetUserFromContext(ctx context.Context) (*User, bool) {
	return getUserFromContext(ctx)
}

// FetchCurrentUser retrieves the full Forta user profile for the access token
// present in r. It calls the /auth/self endpoint and is safe to call from
// any handler (not just Protected ones).
func FetchCurrentUser(r *http.Request) (*User, error) {
	c := getDefaultClient()
	if c == nil {
		return nil, ErrNotConfigured
	}
	token := extractToken(r)
	if token == "" {
		return nil, errors.New("go-forta: no access token found in request")
	}
	return c.getUserInfo(r.Context(), token)
}
