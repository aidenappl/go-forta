package forta

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// LegacyIssuer is the "iss" claim Forta access tokens carried BEFORE the
	// issuer migration. It is no longer accepted by default.
	//
	// ⚠️ IT IS NO LONGER IN defaultAcceptedIssuers. A token carrying it is
	// REJECTED unless a caller opts back in explicitly via
	// Config.AcceptedIssuers. The constant is retained — not deleted — for two
	// reasons: a service that has not yet redeployed can name it to buy time, and
	// deleting an exported identifier is a breaking API change for a value that
	// costs one line to keep.
	//
	// It is not a URL, so it could never be the issuer identifier in an OIDC
	// discovery document, and OIDC Core §3.1.3.7 requires an id_token's "iss" to
	// equal the discovery issuer exactly. That is why it had to go.
	LegacyIssuer = "forta:auth-service"

	// Issuer is the **target** "iss" value — the issuer identifier published in
	// forta-api's OIDC discovery document. Every new integration should assume
	// this is what tokens will carry.
	Issuer = "https://auth.appleby.cloud"

	// There was a `jwtIssuer = LegacyIssuer` alias here, kept so nothing in this
	// package had to be renamed during the migration. Its last reader was the
	// test helper that minted claims with the legacy issuer; once that helper
	// moved to Issuer, the alias became dead and golangci-lint's `unused` check
	// failed the build. Do not reintroduce it — LegacyIssuer is the name, and an
	// alias for a retired value is two names for something that should be used
	// deliberately or not at all.

	jwtAccessTokenType = "access"
)

// defaultAcceptedIssuers is the "iss" allowlist used when Config.AcceptedIssuers
// is empty.
//
// ─────────────────────────────────────────────────────────────────────────────
// THE MIGRATION IS COMPLETE. This is now Issuer ALONE.
//
// The dual-acceptance window ran from v1.4.0 (which shipped both values so the
// fleet needed exactly ONE redeploy) to this release. forta-api has minted the
// new issuer on every token since 2026-07-28, and access tokens live ten
// minutes, so nothing carrying the old value can have been minted recently.
//
// ⚠️ WHAT THIS DOES COST, stated plainly rather than glossed: a REFRESH token
// minted before the cut-over lives seven days, so one may still be presented
// until 2026-08-04. Presenting it now fails, and the user logs in again. That is
// the whole cost — a forced re-login for a session that has been idle since
// before the cut-over, not a service outage. An ACTIVE session re-mints both
// tokens on every refresh, so anyone who has used the platform since the
// cut-over rolled onto the new issuer automatically and is unaffected.
//
// A service that cannot absorb that can set Config.AcceptedIssuers to
// []string{LegacyIssuer, Issuer} explicitly. Nothing in this repo does.
// ─────────────────────────────────────────────────────────────────────────────
var defaultAcceptedIssuers = []string{Issuer}

// DefaultAcceptedIssuers returns a copy of the "iss" values accepted when
// Config.AcceptedIssuers is not set: the OIDC discovery issuer
// "https://auth.appleby.cloud", and — since the issuer migration completed —
// nothing else. LegacyIssuer must now be named explicitly to be accepted.
func DefaultAcceptedIssuers() []string {
	out := make([]string, len(defaultAcceptedIssuers))
	copy(out, defaultAcceptedIssuers)
	return out
}

// allowedSigningAlgs is the algorithm allowlist passed to every JWT parse in
// this package.
//
// This is a security boundary. It is what makes it impossible for a token to
// select its own verification path: the parser rejects any token whose "alg"
// header is not in this list *before* the keyfunc runs, which kills both the
// "alg: none" attack and any future downgrade to a weaker algorithm. The
// keyfunc then adds the second half of the defence by switching on the
// *verified* method type, so an RSA public key can never be handed to an HMAC
// verifier (the classic RS256→HMAC key-confusion forgery, which here would be
// an HS512 token signed with the issuer's public RSA key as the secret).
//
// The HMAC entry is HS512 and only HS512, because that is what forta-api
// actually signs with (forta/jwt.forta.go: jwt.SigningMethodHS512). Do not
// widen this list — not to HS256, not to "just in case" values. Accepting an
// algorithm the issuer never emits only creates attack surface.
var allowedSigningAlgs = []string{"RS256", "HS512"}

// hmacOnlySigningAlgs is the allowlist used by the legacy HS512-only path.
var hmacOnlySigningAlgs = []string{"HS512"}

// FortaClaims is the JWT claims payload used by all Forta access tokens.
// It mirrors the FortaClaims struct in forta-api so that tokens can be
// validated locally when JWTSigningKey is configured.
//
// PlatformID is set when the token was issued via an OAuth2 platform exchange
// (HandleOAuthToken / HandleExchangeCode). It binds the token to a specific
// platform so revocation can be enforced on refresh without trusting a
// caller-supplied header. Tokens minted by direct Forta login (Google/Apple/
// local) leave PlatformID nil.
type FortaClaims struct {
	Type       string `json:"typ"`
	PlatformID *int64 `json:"platform_id,omitempty"`

	// ClientID is the RFC 9068 §2.2 `client_id` claim: the OAuth client the
	// access token was issued to. It is set on ACCESS tokens issued through a
	// grant, alongside an `aud` of the same value and an `at+jwt` JOSE header.
	//
	// ⚠️ EMPTY IS NORMAL AND IS NOT A DOWNGRADE. Forta's first-party session
	// tokens are minted by a login endpoint rather than by a grant, so there is
	// no client to name; refresh tokens never carry it either. A resource server
	// that starts REQUIRING this claim will reject Forta's own session tokens.
	//
	// ⚠️ The `typ` field above is the Forta CLAIM meaning "access"/"refresh",
	// which long predates RFC 9068 and is unrelated to the profile's `at+jwt`
	// JOSE HEADER. Separate namespaces; neither shadows the other.
	ClientID string `json:"client_id,omitempty"`

	jwt.RegisteredClaims
}

// validateAccessTokenLocal validates tokenStr using the shared HMAC-SHA512
// signing key. Returns the Forta user ID on success.
//
// This is the original HS512-only path and its behaviour is unchanged. Use
// Client.validateAccessToken for the algorithm-dispatching version that also
// understands RS256 tokens signed with the issuer's JWKS keys.
func validateAccessTokenLocal(tokenStr, signingKey string) (int64, error) {
	return parseAccessToken(tokenStr, hmacOnlySigningAlgs, defaultAcceptedIssuers, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("go-forta: unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(signingKey), nil
	})
}

// validateAccessToken validates tokenStr, dispatching on the JWS header
// algorithm:
//
//   - HS512 → verified with Config.JWTSigningKey, exactly as before.
//   - RS256 → verified with the issuer's public key looked up by the token's
//     "kid" from the JWKS published at {APIDomain}/oauth/jwks. The key set is
//     fetched lazily on the first RS256 token, cached in memory, and re-fetched
//     (rate-limited) when an unknown kid is seen.
//
// Anything else — including "alg: none" — is rejected by the allowlist before
// any key material is selected.
func (c *Client) validateAccessToken(ctx context.Context, tokenStr string) (int64, error) {
	return parseAccessToken(tokenStr, allowedSigningAlgs, c.cfg.acceptedIssuers(), func(t *jwt.Token) (interface{}, error) {
		switch t.Method.(type) {
		case *jwt.SigningMethodHMAC:
			if c.cfg.JWTSigningKey == "" {
				return nil, errors.New("go-forta: HS512 token received but Config.JWTSigningKey is not set")
			}
			return []byte(c.cfg.JWTSigningKey), nil
		case *jwt.SigningMethodRSA:
			jwks := c.jwks
			if jwks == nil {
				return nil, errors.New("go-forta: RS256 token received but no JWKS source is configured")
			}
			kid, _ := t.Header["kid"].(string)
			return jwks.keyFor(ctx, kid)
		default:
			return nil, fmt.Errorf("go-forta: unexpected signing method: %v", t.Header["alg"])
		}
	})
}

// parseAccessToken parses and validates a Forta access token with an explicit
// algorithm allowlist and an explicit "iss" allowlist, then applies the
// remaining Forta-specific claim checks.
func parseAccessToken(tokenStr string, validMethods, acceptedIssuers []string, keyFunc jwt.Keyfunc) (int64, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &FortaClaims{}, keyFunc, jwt.WithValidMethods(validMethods))
	if err != nil {
		return 0, err
	}

	claims, ok := token.Claims.(*FortaClaims)
	if !ok || !token.Valid {
		return 0, errors.New("go-forta: invalid token")
	}
	if !issuerAccepted(claims.Issuer, acceptedIssuers) {
		return 0, fmt.Errorf("go-forta: invalid token issuer %q", claims.Issuer)
	}
	if claims.Type != jwtAccessTokenType {
		return 0, fmt.Errorf("go-forta: expected token type %q, got %q", jwtAccessTokenType, claims.Type)
	}

	return strconv.ParseInt(claims.Subject, 10, 64)
}

// issuerAccepted reports whether iss is in the allowlist. The comparison is
// exact — OIDC Core §3.1.3.7 requires the issuer to match exactly, so there is
// no normalisation of scheme, case, or trailing slash here.
func issuerAccepted(iss string, accepted []string) bool {
	if iss == "" {
		return false
	}
	for _, want := range accepted {
		if iss == want {
			return true
		}
	}
	return false
}

// isTokenExpiredError returns true when err indicates the JWT has expired (as
// opposed to being malformed or having the wrong signing key).
func isTokenExpiredError(err error) bool {
	return errors.Is(err, jwt.ErrTokenExpired)
}
