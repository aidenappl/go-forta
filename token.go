package forta

import (
	"context"
	"errors"
	"fmt"
	"strconv"

	"github.com/golang-jwt/jwt/v5"
)

const (
	// LegacyIssuer is the "iss" claim Forta access tokens carry today.
	//
	// It is **transitional**. It is not a URL, so it can never be the issuer
	// identifier in an OIDC discovery document, and OIDC Core §3.1.3.7 requires
	// an id_token's "iss" to equal the discovery issuer exactly. Tokens will
	// move to Issuer; this value exists so the fleet keeps working until they
	// do, and it will be removed once no live token carries it.
	LegacyIssuer = "forta:auth-service"

	// Issuer is the **target** "iss" value — the issuer identifier published in
	// forta-api's OIDC discovery document. Every new integration should assume
	// this is what tokens will carry.
	Issuer = "https://auth.appleby.cloud"

	// jwtIssuer is the historical unexported name for LegacyIssuer, kept so
	// nothing in this package (or its tests) has to be renamed.
	jwtIssuer = LegacyIssuer

	jwtAccessTokenType = "access"
)

// defaultAcceptedIssuers is the "iss" allowlist used when Config.AcceptedIssuers
// is empty.
//
// Both values are accepted so the issuer migration needs exactly ONE fleet
// redeploy: ship an SDK that takes both, roll it everywhere, then change what
// forta-api emits. This mirrors the HS512→RS256 choreography, and doing them in
// the same release means the fleet redeploys once rather than twice.
var defaultAcceptedIssuers = []string{LegacyIssuer, Issuer}

// DefaultAcceptedIssuers returns a copy of the "iss" values accepted when
// Config.AcceptedIssuers is not set: the legacy "forta:auth-service" and the
// OIDC discovery issuer "https://auth.appleby.cloud".
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
