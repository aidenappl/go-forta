package forta

import (
	"context"
	"errors"
	"net/http"
	"strings"
)

// Protected wraps next, requiring a valid Forta credential. The token is
// read from (in order of preference):
//
//  1. Authorization: Bearer <token> header (a 3-part JWT, or an frt_ API token)
//  2. forta-access-token cookie
//
// Validation strategy:
//   - Opaque API tokens (frt_…) are always validated remotely via /auth/self,
//     since they carry no claims. Results are cached for APITokenCacheTTL,
//     which also bounds how long a revoked token keeps working.
//   - If Config.JWTSigningKey is set (or Config.EnableJWKS is true): JWTs are
//     validated locally. Verification dispatches on the JWS header algorithm —
//     HS512 uses the shared Config.JWTSigningKey, RS256 uses the issuer's
//     public key looked up by "kid" from {APIDomain}/oauth/jwks. Any other
//     algorithm, including "none", is rejected.
//   - Otherwise: JWTs are validated remotely by calling /auth/self on the
//     Forta API. The full User profile is then available via GetUserFromContext.
//
// If Config.FetchUserOnProtect is true and local validation is used, the
// middleware additionally calls /auth/self so that the full User profile
// is placed in the context.
//
// Auto-refresh: if the access token is expired or absent entirely (and
// DisableAutoRefresh is false) the middleware attempts to refresh using the
// forta-refresh-token cookie. On success, new cookies are written to the
// response and the request proceeds.
// API tokens are never refreshed — they are long-lived by design.
func (c *Client) Protected(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// Stash correlation ids (host response header, then inbound request
		// headers) on the context when it does not already carry them, so every
		// outbound call below is joinable to this request in forta-api's logs.
		r = withInboundCorrelation(w, r)

		tokenStr := extractToken(r)

		if tokenStr == "" {
			// No credential at all. This is the common case for a browser
			// session rather than an error: setAuthCookies gives the access
			// cookie a hard Expires equal to the token's own lifetime, so the
			// browser drops it from the jar the moment the token expires —
			// while the refresh cookie lives on for seven days. Falling
			// straight through to 401 here strands a session that is still
			// perfectly refreshable, and the caller only recovers by reloading
			// the page. Spend the refresh cookie before giving up.
			refreshedID, newToken, refreshErr := c.tryRefreshOnMissingToken(w, r)
			if refreshedID == 0 || newToken == "" {
				reason := ReasonMissingCredential
				if refreshErr != nil {
					c.logf("go-forta: auto-refresh failed: %v", refreshErr)
					reason = refreshFailureReason(refreshErr)
				}
				c.fail(w, r, http.StatusUnauthorized, "missing or invalid authorization", reason, refreshErr)
				return
			}
			// Continue with the fresh token; it is re-validated below on
			// whichever branch this client is configured for.
			tokenStr = newToken
			if c.grants != nil {
				c.grants.invalidate(refreshedID)
			}
		}

		var userID int64
		var user *User

		if IsAPIToken(tokenStr) {
			// ── Opaque API token: always resolved remotely ───────────────────
			u, err := c.resolveAPIToken(r.Context(), tokenStr)
			if err != nil {
				reason := ReasonAPITokenInvalid
				if isUpstreamUnavailable(err) {
					reason = ReasonUpstreamUnavailable
				}
				c.logf("go-forta: api token rejected (%s): %v%s", reason, err, c.requestSuffix(r))
				c.fail(w, r, http.StatusUnauthorized, "invalid or expired api token", reason, err)
				return
			}
			userID = u.ID
			user = u
		} else if c.cfg.JWTSigningKey != "" || c.cfg.EnableJWKS {
			// ── Local JWT validation ─────────────────────────────────────────
			id, err := c.validateAccessToken(r.Context(), tokenStr)
			if err != nil {
				expired := isTokenExpiredError(err)
				if !expired || c.cfg.DisableAutoRefresh {
					reason := ReasonTokenExpired
					if !expired {
						reason = ReasonTokenInvalid
						if isUpstreamUnavailable(err) {
							// The JWKS could not be fetched, so the token was
							// never actually judged.
							reason = ReasonUpstreamUnavailable
						}
						c.logf("go-forta: access token rejected (%s): %v%s", reason, err, c.requestSuffix(r))
					}
					c.fail(w, r, http.StatusUnauthorized, "invalid or expired access token", reason, err)
					return
				}

				// Access token is expired — try to refresh transparently.
				refreshedID, newToken, refreshErr := c.tryRefresh(w, r)
				if refreshedID == 0 {
					reason, failErr := ReasonTokenExpired, error(errNoRefreshCookie)
					if refreshErr != nil {
						reason, failErr = refreshFailureReason(refreshErr), refreshErr
					}
					c.reportFailure(r, reason, http.StatusUnauthorized, failErr)
					writeJSONError(w, http.StatusUnauthorized, "session expired, please log in again")
					if refreshErr != nil {
						c.logf("go-forta: auto-refresh failed: %v", refreshErr)
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
					c.logf("go-forta: FetchUserOnProtect: getUserInfo: %v", fetchErr)
					// Non-fatal: the user ID is valid, continue without full profile.
				} else {
					user = u
				}
			}
		} else {
			// ── Remote validation via /auth/self ─────────────────────────────
			u, err := c.getUserInfo(r.Context(), tokenStr)
			if err != nil {
				// A transport failure or 5xx here means Forta never judged the
				// token. The response and the refresh attempt below are
				// deliberately unchanged from previous releases; only the
				// REPORTED reason distinguishes the outage.
				upstreamDown := isUpstreamUnavailable(err)
				if upstreamDown {
					// Logged only for the outage case: a plain 401 here is the
					// normal expiry path and is followed by a refresh.
					c.logf("go-forta: auth/self unavailable, treating as expired: %v%s", err, c.requestSuffix(r))
				}
				if c.cfg.DisableAutoRefresh {
					reason := ReasonTokenInvalid
					if upstreamDown {
						reason = ReasonUpstreamUnavailable
					}
					c.fail(w, r, http.StatusUnauthorized, "invalid or expired access token", reason, err)
					return
				}
				// Try to refresh using the refresh token cookie.
				refreshedID, newToken, refreshErr := c.tryRefresh(w, r)
				if refreshedID == 0 {
					reason, failErr := ReasonTokenExpired, err
					switch {
					case upstreamDown:
						reason = ReasonUpstreamUnavailable
						if refreshErr != nil {
							failErr = errors.Join(err, refreshErr)
						}
					case refreshErr != nil:
						reason, failErr = refreshFailureReason(refreshErr), refreshErr
					}
					c.reportFailure(r, reason, http.StatusUnauthorized, failErr)
					writeJSONError(w, http.StatusUnauthorized, "session expired, please log in again")
					if refreshErr != nil {
						c.logf("go-forta: auto-refresh failed: %v", refreshErr)
					}
					return
				}
				userID = refreshedID
				tokenStr = newToken
				// Invalidate cached grant so it is re-checked with the fresh token.
				if c.grants != nil {
					c.grants.invalidate(refreshedID)
				}
				// Fetch the updated profile with the new token.
				if newToken != "" {
					if nu, uiErr := c.getUserInfo(r.Context(), newToken); uiErr == nil {
						user = nu
						userID = nu.ID
					} else {
						c.logf("go-forta: auth/self after refresh failed, continuing without profile: %v%s", uiErr, c.requestSuffix(r))
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
					c.logf("go-forta: grant check failed: %v (denying request)", grantErr)
					c.failGrant(w, r, ReasonGrantCheckFailed, grantErr)
					return
				}
				c.grants.set(userID, granted)
			}
			if !granted {
				c.failGrant(w, r, ReasonGrantDenied, nil)
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

// refreshFailureReason classifies an error from tryRefresh: an unreachable or
// failing Forta is ReasonUpstreamUnavailable, anything else (a rejected refresh
// token, a malformed response) is ReasonRefreshFailed.
func refreshFailureReason(err error) string {
	if isUpstreamUnavailable(err) {
		return ReasonUpstreamUnavailable
	}
	return ReasonRefreshFailed
}

// tryRefreshOnMissingToken is tryRefresh guarded by DisableAutoRefresh, for the
// path where no credential was presented at all. It is kept separate from
// tryRefresh because the expired-token callers check DisableAutoRefresh
// themselves before deciding which error string to write.
func (c *Client) tryRefreshOnMissingToken(w http.ResponseWriter, r *http.Request) (int64, string, error) {
	if c.cfg.DisableAutoRefresh {
		return 0, "", nil
	}
	return c.tryRefresh(w, r)
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

// resolveAPIToken exchanges an opaque API token for its owning user via
// /auth/self, memoizing the result so a token used on every request does not
// produce a round-trip each time. A token that fails to resolve is evicted so
// revocation takes effect at the end of the cache TTL rather than never.
func (c *Client) resolveAPIToken(ctx context.Context, token string) (*User, error) {
	if c.apiTokens != nil {
		if user, ok := c.apiTokens.get(token); ok {
			return user, nil
		}
	}

	user, err := c.getUserInfo(ctx, token)
	if err != nil {
		if c.apiTokens != nil {
			c.apiTokens.invalidate(token)
		}
		return nil, err
	}

	if c.apiTokens != nil {
		c.apiTokens.set(token, user)
	}
	return user, nil
}

// extractToken returns the Bearer token from the Authorization header, falling
// back to the forta-access-token cookie. Returns "" if neither is present.
func extractToken(r *http.Request) string {
	if authHeader := r.Header.Get("Authorization"); strings.HasPrefix(authHeader, "Bearer ") {
		candidate := strings.TrimPrefix(authHeader, "Bearer ")
		// Opaque API tokens are passed through as-is; they are not JWTs.
		if IsAPIToken(candidate) {
			return candidate
		}
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
