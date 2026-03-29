package forta

import (
	"net/http"
	"time"
)

const (
	cookieAccessToken  = "forta-access-token"
	cookieRefreshToken = "forta-refresh-token"
	cookieOAuthState   = "forta-oauth-state"
)

// setAuthCookies writes the access and refresh token cookies to w using the
// configured domain and security settings.
func (c *Client) setAuthCookies(w http.ResponseWriter, tokens TokenPair) {
	secure := !c.cfg.CookieInsecure

	http.SetCookie(w, &http.Cookie{
		Name:     cookieAccessToken,
		Value:    tokens.AccessToken,
		Domain:   c.cfg.CookieDomain,
		Path:     "/",
		Expires:  tokens.ExpiresAt,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     cookieRefreshToken,
		Value:    tokens.RefreshToken,
		Domain:   c.cfg.CookieDomain,
		Path:     "/",
		MaxAge:   7 * 24 * 60 * 60, // 7 days
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// clearAuthCookies immediately expires both auth cookies.
func (c *Client) clearAuthCookies(w http.ResponseWriter) {
	secure := !c.cfg.CookieInsecure

	http.SetCookie(w, &http.Cookie{
		Name:     cookieAccessToken,
		Value:    "",
		Domain:   c.cfg.CookieDomain,
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})

	http.SetCookie(w, &http.Cookie{
		Name:     cookieRefreshToken,
		Value:    "",
		Domain:   c.cfg.CookieDomain,
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// setStateCookie writes a short-lived CSRF state cookie.
func (c *Client) setStateCookie(w http.ResponseWriter, state string) {
	secure := !c.cfg.CookieInsecure
	http.SetCookie(w, &http.Cookie{
		Name:     cookieOAuthState,
		Value:    state,
		Path:     "/",
		Expires:  time.Now().Add(10 * time.Minute),
		HttpOnly: true,
		Secure:   secure,
		SameSite: http.SameSiteLaxMode,
	})
}

// clearStateCookie immediately expires the CSRF state cookie.
func (c *Client) clearStateCookie(w http.ResponseWriter) {
	http.SetCookie(w, &http.Cookie{
		Name:     cookieOAuthState,
		Value:    "",
		Path:     "/",
		MaxAge:   -1,
		HttpOnly: true,
		Secure:   !c.cfg.CookieInsecure,
		SameSite: http.SameSiteLaxMode,
	})
}
