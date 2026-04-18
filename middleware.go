package forta

import (
	"log"
	"net/http"
	"strings"
)

// Protected wraps next, requiring a valid Forta access token. The token is
// read from (in order of preference):
//
//  1. Authorization: Bearer <token> header (valid 3-part JWT only)
//  2. forta-access-token cookie
//
// Validation strategy:
//   - If Config.JWTSigningKey is set: tokens are validated locally via HMAC-SHA512.
//   - Otherwise: tokens are validated remotely by calling /auth/self on the
//     Forta API. The full User profile is then available via GetUserFromContext.
//
// If Config.FetchUserOnProtect is true and local validation is used, the
// middleware additionally calls /auth/self so that the full User profile
// is placed in the context.
//
// Auto-refresh: if the access token is expired (and DisableAutoRefresh is false)
// the middleware attempts to refresh using the forta-refresh-token cookie. On
// success, new cookies are written to the response and the request proceeds.
func (c *Client) Protected(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		tokenStr := extractToken(r)

		if tokenStr == "" {
			writeJSONError(w, http.StatusUnauthorized, "missing or invalid authorization")
			return
		}

		var userID int64
		var user *User

		if c.cfg.JWTSigningKey != "" {
			// ── Local JWT validation ─────────────────────────────────────────
			id, err := validateAccessTokenLocal(tokenStr, c.cfg.JWTSigningKey)
			if err != nil {
				if !isTokenExpiredError(err) || c.cfg.DisableAutoRefresh {
					writeJSONError(w, http.StatusUnauthorized, "invalid or expired access token")
					return
				}

				// Access token is expired — try to refresh transparently.
				refreshedID, newToken, refreshErr := c.tryRefresh(w, r)
				if refreshedID == 0 {
					writeJSONError(w, http.StatusUnauthorized, "session expired, please log in again")
					if refreshErr != nil {
						log.Printf("go-forta: auto-refresh failed: %v", refreshErr)
					}
					return
				}
				// Update tokenStr so FetchUserOnProtect below uses the new token.
				tokenStr = newToken
				id = refreshedID
				// Invalidate cached grant so it is re-checked with the fresh token.
				if c.grants != nil {
					c.grants.invalidate(refreshedID)
				}
			}
			userID = id

			if c.cfg.FetchUserOnProtect {
				u, fetchErr := c.getUserInfo(r.Context(), tokenStr)
				if fetchErr != nil {
					log.Printf("go-forta: FetchUserOnProtect: getUserInfo: %v", fetchErr)
					// Non-fatal: the user ID is valid, continue without full profile.
				} else {
					user = u
				}
			}
		} else {
			// ── Remote validation via /auth/self ─────────────────────────────
			u, err := c.getUserInfo(r.Context(), tokenStr)
			if err != nil {
				if c.cfg.DisableAutoRefresh {
					writeJSONError(w, http.StatusUnauthorized, "invalid or expired access token")
					return
				}
				// Try to refresh using the refresh token cookie.
				refreshedID, newToken, refreshErr := c.tryRefresh(w, r)
				if refreshedID == 0 {
					writeJSONError(w, http.StatusUnauthorized, "session expired, please log in again")
					if refreshErr != nil {
						log.Printf("go-forta: auto-refresh failed: %v", refreshErr)
					}
					return
				}
				userID = refreshedID
				// Invalidate cached grant so it is re-checked with the fresh token.
				if c.grants != nil {
					c.grants.invalidate(refreshedID)
				}
				// Fetch the updated profile with the new token.
				if newToken != "" {
					if nu, uiErr := c.getUserInfo(r.Context(), newToken); uiErr == nil {
						user = nu
						userID = nu.ID
					}
				}
			} else {
				userID = u.ID
				user = u
			}
		}

		// ── Grant enforcement (opt-in) ──────────────────────────────────
		if c.cfg.EnforceGrants && c.grants != nil {
			granted, found := c.grants.get(userID)
			if !found {
				var grantErr error
				granted, grantErr = c.checkGrant(r.Context(), tokenStr)
				if grantErr != nil {
					log.Printf("go-forta: grant check failed: %v (denying request)", grantErr)
					writeGrantDenied(w)
					return
				}
				c.grants.set(userID, granted)
			}
			if !granted {
				writeGrantDenied(w)
				return
			}
		}

		ctx := contextWithFortaID(r.Context(), userID)
		if user != nil {
			ctx = contextWithUser(ctx, user)
		}
		next.ServeHTTP(w, r.WithContext(ctx))
	}
}

// tryRefresh reads the forta-refresh-token cookie, calls /auth/refresh, and on
// success sets the new auth cookies. Returns the refreshed user ID, the new
// access token string, and any error. A zero ID means refresh failed.
func (c *Client) tryRefresh(w http.ResponseWriter, r *http.Request) (int64, string, error) {
	refreshCookie, err := r.Cookie(cookieRefreshToken)
	if err != nil || refreshCookie.Value == "" {
		return 0, "", nil
	}

	authResp, err := c.refreshTokens(r.Context(), refreshCookie.Value)
	if err != nil {
		return 0, "", err
	}

	c.setAuthCookies(w, authResp.Authorization)
	return authResp.User.ID, authResp.Authorization.AccessToken, nil
}

// extractToken returns the Bearer token from the Authorization header, falling
// back to the forta-access-token cookie. Returns "" if neither is present.
func extractToken(r *http.Request) string {
	if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
		candidate := strings.TrimPrefix(authHeader, "Bearer ")
		// A valid JWT has exactly 2 dots. Guard against "Bearer undefined" etc.
		if strings.Count(candidate, ".") == 2 {
			return candidate
		}
	}
	if cookie, err := r.Cookie(cookieAccessToken); err == nil && cookie.Value != "" {
		return cookie.Value
	}
	return ""
}
