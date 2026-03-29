package forta

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/url"
	"strings"
)

// LoginHandler redirects the browser to the Forta OAuth2 authorization
// endpoint. A cryptographically random state value is stored in a short-lived
// HttpOnly cookie to guard against CSRF during the callback.
//
// Register this handler at your login route, e.g.:
//
//	mux.HandleFunc("/forta/login", forta.LoginHandler)
func (c *Client) LoginHandler(w http.ResponseWriter, r *http.Request) {
	// First-party appleby.cloud services share the Forta session cookie and do
	// not need the full OAuth2 code-exchange flow. Redirect directly to the
	// Forta login page with a redirect_uri pointing back to this application.
	if c.cfg.CookieDomain == ".appleby.cloud" {
		redirectBack := c.cfg.postLoginRedirect()
		if !strings.HasPrefix(redirectBack, "http") {
			scheme := "https"
			if r.TLS == nil && r.Header.Get("X-Forwarded-Proto") != "https" {
				scheme = "http"
			}
			redirectBack = scheme + "://" + r.Host + redirectBack
		}
		loginURL := c.cfg.LoginDomain + "/?redirect_uri=" + url.QueryEscape(redirectBack)
		http.Redirect(w, r, loginURL, http.StatusFound)
		return
	}

	state, err := generateState()
	if err != nil {
		writeJSONError(w, http.StatusInternalServerError, "failed to generate state token")
		return
	}

	c.setStateCookie(w, state)

	loginURL := fmt.Sprintf(
		"%s/oauth/authorize?response_type=code&client_id=%s&redirect_uri=%s&state=%s&scope=openid",
		c.cfg.LoginDomain,
		url.QueryEscape(c.cfg.ClientID),
		url.QueryEscape(c.cfg.CallbackURL),
		url.QueryEscape(state),
	)

	http.Redirect(w, r, loginURL, http.StatusFound)
}

// CallbackHandler handles the OAuth2 redirect from Forta at your callback URL
// (e.g. /forta/callback). It:
//
//  1. Validates the CSRF state cookie against the state query parameter.
//  2. Exchanges the authorization code for a token pair via POST /auth/exchange.
//  3. Sets HttpOnly forta-access-token and forta-refresh-token cookies.
//  4. Redirects to Config.PostLoginRedirect (default "/").
//
// Register this handler at the URL you specified in Config.CallbackURL, e.g.:
//
//	mux.HandleFunc("/forta/callback", forta.CallbackHandler)
func (c *Client) CallbackHandler(w http.ResponseWriter, r *http.Request) {
	// Check for an error from the authorization server.
	if errParam := r.URL.Query().Get("error"); errParam != "" {
		errDesc := r.URL.Query().Get("error_description")
		writeJSONError(w, http.StatusBadRequest, fmt.Sprintf("authorization error: %s: %s", errParam, errDesc))
		return
	}

	code := r.URL.Query().Get("code")
	state := r.URL.Query().Get("state")

	if code == "" {
		writeJSONError(w, http.StatusBadRequest, "missing code parameter")
		return
	}

	// Validate CSRF state.
	stateCookie, err := r.Cookie(cookieOAuthState)
	if err != nil || stateCookie.Value == "" {
		writeJSONError(w, http.StatusBadRequest, "missing state cookie — possible CSRF or expired session")
		return
	}
	if stateCookie.Value != state {
		writeJSONError(w, http.StatusBadRequest, "state mismatch — possible CSRF attack")
		return
	}
	c.clearStateCookie(w)

	// Exchange code for token pair.
	authResp, err := c.exchangeCode(r.Context(), code)
	if err != nil {
		writeJSONError(w, http.StatusUnauthorized, "failed to exchange authorization code")
		return
	}

	c.setAuthCookies(w, authResp.Authorization)
	http.Redirect(w, r, c.cfg.postLoginRedirect(), http.StatusFound)
}

// LogoutHandler clears all Forta auth cookies from the client and redirects
// to Config.PostLogoutRedirect (default "/").
//
// Register this handler at your logout route, e.g.:
//
//	mux.HandleFunc("/forta/logout", forta.LogoutHandler)
func (c *Client) LogoutHandler(w http.ResponseWriter, r *http.Request) {
	c.clearAuthCookies(w)
	http.Redirect(w, r, c.cfg.postLogoutRedirect(), http.StatusFound)
}

// generateState returns a 32-byte cryptographically random hex string for use
// as an OAuth2 CSRF state parameter.
func generateState() (string, error) {
	b := make([]byte, 32)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return hex.EncodeToString(b), nil
}
