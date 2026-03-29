package forta

import (
	"errors"
	"fmt"
	"strconv"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const (
	jwtIssuer          = "forta:auth-service"
	jwtAccessTokenType = "access"
)

// FortaClaims is the JWT claims payload used by all Forta access tokens.
// It mirrors the FortaClaims struct in forta-api so that tokens can be
// validated locally when JWTSigningKey is configured.
type FortaClaims struct {
	Type string `json:"typ"`
	jwt.RegisteredClaims
}

// validateAccessTokenLocal validates tokenStr using the shared HMAC-SHA512
// signing key. Returns the Forta user ID on success.
func validateAccessTokenLocal(tokenStr, signingKey string) (int64, error) {
	token, err := jwt.ParseWithClaims(tokenStr, &FortaClaims{}, func(t *jwt.Token) (interface{}, error) {
		if _, ok := t.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("go-forta: unexpected signing method: %v", t.Header["alg"])
		}
		return []byte(signingKey), nil
	})
	if err != nil {
		return 0, err
	}

	claims, ok := token.Claims.(*FortaClaims)
	if !ok || !token.Valid {
		return 0, errors.New("go-forta: invalid token")
	}
	if claims.Issuer != jwtIssuer {
		return 0, errors.New("go-forta: invalid token issuer")
	}
	if claims.Type != jwtAccessTokenType {
		return 0, fmt.Errorf("go-forta: expected token type %q, got %q", jwtAccessTokenType, claims.Type)
	}

	return strconv.ParseInt(claims.Subject, 10, 64)
}

// isTokenExpiredError returns true when err indicates the JWT has expired (as
// opposed to being malformed or having the wrong signing key).
func isTokenExpiredError(err error) bool {
	return errors.Is(err, jwt.ErrTokenExpired)
}

// tokenExpiresAt parses tokenStr without validation and returns the expiry time.
// Used to determine whether a token is worth trying to refresh.
func tokenExpiresAt(tokenStr string) (time.Time, error) {
	parser := jwt.NewParser(jwt.WithoutClaimsValidation())
	token, _, err := parser.ParseUnverified(tokenStr, &FortaClaims{})
	if err != nil {
		return time.Time{}, err
	}
	claims, ok := token.Claims.(*FortaClaims)
	if !ok || claims.ExpiresAt == nil {
		return time.Time{}, errors.New("go-forta: missing exp claim")
	}
	return claims.ExpiresAt.Time, nil
}
