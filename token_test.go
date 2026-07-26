package forta

import (
	"context"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"encoding/base64"
	"encoding/json"
	"encoding/pem"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strconv"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

const testHMACKey = "test-hmac-signing-key-do-not-use-in-production"

// ── helpers ─────────────────────────────────────────────────────────────────

// newTestClaims builds a well-formed Forta access-token claim set.
func newTestClaims(sub string) FortaClaims {
	return FortaClaims{
		Type: jwtAccessTokenType,
		RegisteredClaims: jwt.RegisteredClaims{
			Issuer:    jwtIssuer,
			Subject:   sub,
			IssuedAt:  jwt.NewNumericDate(time.Now().Add(-time.Minute)),
			ExpiresAt: jwt.NewNumericDate(time.Now().Add(time.Hour)),
		},
	}
}

// signHS512 mints an HS512 token with an arbitrary secret.
func signHS512(t *testing.T, claims FortaClaims, secret []byte) string {
	t.Helper()
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS512, claims).SignedString(secret)
	if err != nil {
		t.Fatalf("sign HS512: %v", err)
	}
	return s
}

// signRS256 mints an RS256 token carrying the given kid header.
func signRS256(t *testing.T, claims FortaClaims, key *rsa.PrivateKey, kid string) string {
	t.Helper()
	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, claims)
	tok.Header["kid"] = kid
	s, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign RS256: %v", err)
	}
	return s
}

func newRSAKey(t *testing.T) *rsa.PrivateKey {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, 2048)
	if err != nil {
		t.Fatalf("generate RSA key: %v", err)
	}
	return k
}

// jwksJSON renders the given public keys as a JWKS document.
func jwksJSON(t *testing.T, keys map[string]*rsa.PublicKey) []byte {
	t.Helper()
	set := jwkSet{}
	for kid, pub := range keys {
		set.Keys = append(set.Keys, jwk{
			Kty: "RSA",
			Use: "sig",
			Alg: "RS256",
			Kid: kid,
			N:   base64.RawURLEncoding.EncodeToString(pub.N.Bytes()),
			E:   base64.RawURLEncoding.EncodeToString(big.NewInt(int64(pub.E)).Bytes()),
		})
	}
	b, err := json.Marshal(set)
	if err != nil {
		t.Fatalf("marshal jwks: %v", err)
	}
	return b
}

// testClient builds a Client with the required config fields filled in.
func testClient(t *testing.T, mutate func(*Config)) *Client {
	t.Helper()
	cfg := Config{
		APIDomain:    "https://api.forta.test",
		LoginDomain:  "https://forta.test",
		ClientID:     "test-client",
		ClientSecret: "test-secret",
	}
	if mutate != nil {
		mutate(&cfg)
	}
	c, err := newClient(cfg)
	if err != nil {
		t.Fatalf("newClient: %v", err)
	}
	return c
}

// ── security: algorithm confusion ───────────────────────────────────────────

// TestAlgConfusion_RSAPublicKeyAsHMACSecret is the single most important test
// in this package. An attacker who knows the issuer's *public* RSA key (it is
// published, by definition) mints an HS512 token using that public key as the
// HMAC secret. A naive verifier that hands the keyfunc's RSA key to an HMAC
// verifier accepts it as genuine. It must be rejected in every configuration.
func TestAlgConfusion_RSAPublicKeyAsHMACSecret(t *testing.T) {
	key := newRSAKey(t)
	pub := &key.PublicKey

	der, err := x509.MarshalPKIXPublicKey(pub)
	if err != nil {
		t.Fatalf("marshal public key: %v", err)
	}
	pemBytes := pem.EncodeToMemory(&pem.Block{Type: "PUBLIC KEY", Bytes: der})

	var jwksHits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&jwksHits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON(t, map[string]*rsa.PublicKey{"key-1": pub}))
	}))
	defer srv.Close()

	// Every representation of the public key an attacker might try as the
	// HMAC secret.
	secrets := map[string][]byte{
		"pem":            pemBytes,
		"pem_trimmed":    []byte(strings.TrimSpace(string(pemBytes))),
		"der":            der,
		"modulus_bytes":  pub.N.Bytes(),
		"modulus_base64": []byte(base64.RawURLEncoding.EncodeToString(pub.N.Bytes())),
	}

	configs := map[string]func(*Config){
		"hs256_and_jwks": func(c *Config) {
			c.JWTSigningKey = testHMACKey
			c.JWKSURL = srv.URL
		},
		"jwks_only": func(c *Config) {
			c.EnableJWKS = true
			c.JWKSURL = srv.URL
		},
	}

	for cfgName, mutate := range configs {
		for secretName, secret := range secrets {
			t.Run(cfgName+"/"+secretName, func(t *testing.T) {
				c := testClient(t, mutate)
				// Prime the JWKS cache so the RSA key is definitely loaded —
				// this is the state in which the attack would succeed.
				if _, err := c.jwks.keyFor(context.Background(), "key-1"); err != nil {
					t.Fatalf("prime jwks: %v", err)
				}

				forged := signHS512(t, newTestClaims("1"), secret)
				if id, err := c.validateAccessToken(context.Background(), forged); err == nil {
					t.Fatalf("forged HS512 token signed with the RSA public key was ACCEPTED (user id %d) — algorithm confusion", id)
				}
			})
		}
	}
}

// TestAlgNone_Rejected verifies unsigned tokens are never accepted.
func TestAlgNone_Rejected(t *testing.T) {
	tok := jwt.NewWithClaims(jwt.SigningMethodNone, newTestClaims("1"))
	unsigned, err := tok.SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatalf("sign none: %v", err)
	}

	cases := map[string]func(*Config){
		"hs256_configured": func(c *Config) { c.JWTSigningKey = testHMACKey },
		"jwks_only":        func(c *Config) { c.EnableJWKS = true; c.JWKSURL = "http://127.0.0.1:1/jwks" },
	}

	for name, mutate := range cases {
		t.Run(name, func(t *testing.T) {
			c := testClient(t, mutate)
			if _, err := c.validateAccessToken(context.Background(), unsigned); err == nil {
				t.Fatal("alg:none token was ACCEPTED")
			}
		})
	}

	t.Run("legacy_hs256_path", func(t *testing.T) {
		if _, err := validateAccessTokenLocal(unsigned, testHMACKey); err == nil {
			t.Fatal("alg:none token was ACCEPTED by validateAccessTokenLocal")
		}
	})
}

// ── JWKS behaviour ──────────────────────────────────────────────────────────

// TestUnknownKID_TriggersRefetch_ThenSucceeds models an OIDC key rotation: the
// SDK has key-1 cached, forta-api starts signing with key-2, and the SDK must
// discover key-2 by re-fetching the key set on the unknown kid.
func TestUnknownKID_TriggersRefetch_ThenSucceeds(t *testing.T) {
	key1, key2 := newRSAKey(t), newRSAKey(t)

	var (
		hits    int32
		rotated atomic.Bool
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		keys := map[string]*rsa.PublicKey{"key-1": &key1.PublicKey}
		if rotated.Load() {
			keys["key-2"] = &key2.PublicKey
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON(t, keys))
	}))
	defer srv.Close()

	c := testClient(t, func(cfg *Config) {
		cfg.JWTSigningKey = testHMACKey
		cfg.JWKSURL = srv.URL
		// Tiny interval so the rotation is discovered within the test.
		cfg.JWKSMinRefreshInterval = time.Nanosecond
	})

	t.Run("no fetch before the first RS256 token", func(t *testing.T) {
		if got := atomic.LoadInt32(&hits); got != 0 {
			t.Fatalf("JWKS fetched %d times before any RS256 token", got)
		}
	})

	t.Run("first RS256 token fetches the key set", func(t *testing.T) {
		id, err := c.validateAccessToken(context.Background(), signRS256(t, newTestClaims("42"), key1, "key-1"))
		if err != nil {
			t.Fatalf("validate key-1 token: %v", err)
		}
		if id != 42 {
			t.Fatalf("user id = %d, want 42", id)
		}
		if got := atomic.LoadInt32(&hits); got != 1 {
			t.Fatalf("JWKS fetches = %d, want 1", got)
		}
	})

	t.Run("cached key needs no further fetch", func(t *testing.T) {
		if _, err := c.validateAccessToken(context.Background(), signRS256(t, newTestClaims("42"), key1, "key-1")); err != nil {
			t.Fatalf("validate cached key-1 token: %v", err)
		}
		if got := atomic.LoadInt32(&hits); got != 1 {
			t.Fatalf("JWKS fetches = %d, want 1 (cache miss on a known kid)", got)
		}
	})

	t.Run("unknown kid before rotation is rejected", func(t *testing.T) {
		if _, err := c.validateAccessToken(context.Background(), signRS256(t, newTestClaims("42"), key2, "key-2")); err == nil {
			t.Fatal("token with an unpublished kid was ACCEPTED")
		}
	})

	t.Run("unknown kid after rotation refetches and succeeds", func(t *testing.T) {
		rotated.Store(true)
		before := atomic.LoadInt32(&hits)

		id, err := c.validateAccessToken(context.Background(), signRS256(t, newTestClaims("7"), key2, "key-2"))
		if err != nil {
			t.Fatalf("validate rotated key-2 token: %v", err)
		}
		if id != 7 {
			t.Fatalf("user id = %d, want 7", id)
		}
		if got := atomic.LoadInt32(&hits); got <= before {
			t.Fatalf("JWKS fetches = %d, want > %d (no refetch on unknown kid)", got, before)
		}
	})
}

// TestUnknownKID_RefetchIsRateLimited proves an attacker cannot use random kid
// values to turn this SDK into a DoS amplifier against the JWKS endpoint.
func TestUnknownKID_RefetchIsRateLimited(t *testing.T) {
	key := newRSAKey(t)

	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON(t, map[string]*rsa.PublicKey{"key-1": &key.PublicKey}))
	}))
	defer srv.Close()

	c := testClient(t, func(cfg *Config) {
		cfg.JWTSigningKey = testHMACKey
		cfg.JWKSURL = srv.URL
		// Leave JWKSMinRefreshInterval unset: the default must be safe.
	})

	const attempts = 25
	for i := 0; i < attempts; i++ {
		kid := "attacker-kid-" + strconv.Itoa(i)
		if _, err := c.validateAccessToken(context.Background(), signRS256(t, newTestClaims("1"), key, kid)); err == nil {
			t.Fatalf("token with unknown kid %q was ACCEPTED", kid)
		}
	}

	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("JWKS fetches = %d after %d unknown kids, want 1 (refetch is not rate-limited)", got, attempts)
	}

	t.Run("legitimate cached key still verifies", func(t *testing.T) {
		id, err := c.validateAccessToken(context.Background(), signRS256(t, newTestClaims("9"), key, "key-1"))
		if err != nil {
			t.Fatalf("validate key-1 token: %v", err)
		}
		if id != 9 {
			t.Fatalf("user id = %d, want 9", id)
		}
	})
}

// TestHS512_StillVerifies_NoJWKSRequest is the backward-compatibility guard:
// an existing consumer that upgrades and changes nothing must behave exactly
// as before, and in particular must never gain a network dependency on the
// JWKS endpoint. The test server fails the test if it is contacted at all.
func TestHS512_StillVerifies_NoJWKSRequest(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		t.Errorf("JWKS endpoint was contacted (%s %s) while validating an HS512 token", r.Method, r.URL.Path)
		w.WriteHeader(http.StatusInternalServerError)
	}))
	defer srv.Close()

	c := testClient(t, func(cfg *Config) {
		cfg.JWTSigningKey = testHMACKey
		cfg.JWKSURL = srv.URL
	})

	secret := []byte(testHMACKey)

	tests := []struct {
		name    string
		token   string
		wantID  int64
		wantErr bool
	}{
		{
			name:   "valid HS512 token",
			token:  signHS512(t, newTestClaims("123"), secret),
			wantID: 123,
		},
		{
			name:    "wrong signing key",
			token:   signHS512(t, newTestClaims("123"), []byte("not-the-key")),
			wantErr: true,
		},
		{
			name: "wrong issuer",
			token: signHS512(t, func() FortaClaims {
				cl := newTestClaims("123")
				cl.Issuer = "someone-else"
				return cl
			}(), secret),
			wantErr: true,
		},
		{
			name: "wrong token type",
			token: signHS512(t, func() FortaClaims {
				cl := newTestClaims("123")
				cl.Type = "refresh"
				return cl
			}(), secret),
			wantErr: true,
		},
		{
			name: "expired token",
			token: signHS512(t, func() FortaClaims {
				cl := newTestClaims("123")
				cl.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour))
				return cl
			}(), secret),
			wantErr: true,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			id, err := c.validateAccessToken(context.Background(), tt.token)
			if tt.wantErr {
				if err == nil {
					t.Fatalf("expected an error, got user id %d", id)
				}
				return
			}
			if err != nil {
				t.Fatalf("unexpected error: %v", err)
			}
			if id != tt.wantID {
				t.Fatalf("user id = %d, want %d", id, tt.wantID)
			}
		})
	}

	t.Run("legacy validateAccessTokenLocal is unchanged", func(t *testing.T) {
		id, err := validateAccessTokenLocal(signHS512(t, newTestClaims("123"), secret), testHMACKey)
		if err != nil {
			t.Fatalf("unexpected error: %v", err)
		}
		if id != 123 {
			t.Fatalf("user id = %d, want 123", id)
		}
	})

	t.Run("expired token is reported as expired for auto-refresh", func(t *testing.T) {
		cl := newTestClaims("123")
		cl.ExpiresAt = jwt.NewNumericDate(time.Now().Add(-time.Hour))
		_, err := c.validateAccessToken(context.Background(), signHS512(t, cl, secret))
		if !isTokenExpiredError(err) {
			t.Fatalf("isTokenExpiredError(%v) = false, want true — auto-refresh would break", err)
		}
	})
}

// TestRS256_MissingKID_Rejected covers a token that omits the kid header.
func TestRS256_MissingKID_Rejected(t *testing.T) {
	key := newRSAKey(t)

	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		_, _ = w.Write(jwksJSON(t, map[string]*rsa.PublicKey{"key-1": &key.PublicKey}))
	}))
	defer srv.Close()

	c := testClient(t, func(cfg *Config) {
		cfg.JWTSigningKey = testHMACKey
		cfg.JWKSURL = srv.URL
	})

	tok := jwt.NewWithClaims(jwt.SigningMethodRS256, newTestClaims("1"))
	signed, err := tok.SignedString(key)
	if err != nil {
		t.Fatalf("sign: %v", err)
	}

	if _, err := c.validateAccessToken(context.Background(), signed); err == nil {
		t.Fatal("RS256 token without a kid was ACCEPTED")
	}
	if got := atomic.LoadInt32(&hits); got != 0 {
		t.Fatalf("JWKS fetches = %d, want 0 (a kid-less token must not trigger a fetch)", got)
	}
}

// TestHS512_RejectedWhenNoSigningKeyConfigured covers the RS256-only end state:
// once the shared secret is gone, HS512 tokens must not verify at all.
func TestHS512_RejectedWhenNoSigningKeyConfigured(t *testing.T) {
	c := testClient(t, func(cfg *Config) {
		cfg.EnableJWKS = true
		cfg.JWKSURL = "http://127.0.0.1:1/jwks"
	})
	if _, err := c.validateAccessToken(context.Background(), signHS512(t, newTestClaims("1"), []byte(""))); err == nil {
		t.Fatal("HS512 token was ACCEPTED with no JWTSigningKey configured")
	}
}

// TestHMACAlgorithmIsHS512 is the regression test for the one mistake that
// would take the whole platform down: forta-api signs its access tokens with
// HS512 (see forta/jwt.forta.go — jwt.SigningMethodHS512). If the allowlist
// were narrowed to HS256, every genuine Forta token in production would be
// rejected and nothing would authenticate anywhere.
//
// It also pins the other direction: a weaker HMAC variant must not be accepted
// even when it is signed with the correct shared secret.
func TestHMACAlgorithmIsHS512(t *testing.T) {
	c := testClient(t, func(cfg *Config) { cfg.JWTSigningKey = testHMACKey })
	secret := []byte(testHMACKey)

	tests := []struct {
		name   string
		method jwt.SigningMethod
		wantOK bool
	}{
		{"HS512 — what forta-api actually issues", jwt.SigningMethodHS512, true},
		{"HS256 — not issued, must be rejected", jwt.SigningMethodHS256, false},
		{"HS384 — not issued, must be rejected", jwt.SigningMethodHS384, false},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			signed, err := jwt.NewWithClaims(tt.method, newTestClaims("55")).SignedString(secret)
			if err != nil {
				t.Fatalf("sign %s: %v", tt.method.Alg(), err)
			}

			id, err := c.validateAccessToken(context.Background(), signed)
			if !tt.wantOK {
				if err == nil {
					t.Fatalf("%s token was ACCEPTED (user id %d)", tt.method.Alg(), id)
				}
				return
			}
			if err != nil {
				t.Fatalf("genuine %s token was REJECTED: %v — this would be a platform-wide auth outage", tt.method.Alg(), err)
			}
			if id != 55 {
				t.Fatalf("user id = %d, want 55", id)
			}

			// The legacy helper must agree.
			legacyID, legacyErr := validateAccessTokenLocal(signed, testHMACKey)
			if legacyErr != nil || legacyID != 55 {
				t.Fatalf("validateAccessTokenLocal(%s) = %d, %v; want 55, nil", tt.method.Alg(), legacyID, legacyErr)
			}
		})
	}
}

// ── JWKS cache max age (revocation) ─────────────────────────────────────────

// testClock is a manually advanced clock, safe for concurrent reads.
type testClock struct{ nanos atomic.Int64 }

func newTestClock() *testClock {
	c := &testClock{}
	c.nanos.Store(time.Date(2026, 1, 1, 0, 0, 0, 0, time.UTC).UnixNano())
	return c
}

func (c *testClock) Now() time.Time          { return time.Unix(0, c.nanos.Load()).UTC() }
func (c *testClock) Advance(d time.Duration) { c.nanos.Add(int64(d)) }

// TestJWKSMaxAge_WithdrawnKeyStopsVerifying is the regression test for the
// defect this max age exists to fix.
//
// Before it, jwks.go only re-fetched on an *unknown* kid. A kid already in the
// cache was never revalidated — no TTL, no Cache-Control handling — so when the
// issuer withdrew a compromised signing key the SDK kept accepting tokens signed
// with it, making no further network request, for the life of the process.
// Emergency revocation had no propagation mechanism at all.
//
// Time is injected rather than slept, so this runs instantly.
func TestJWKSMaxAge_WithdrawnKeyStopsVerifying(t *testing.T) {
	withdrawals := map[string]func(live *rsa.PublicKey, replacement *rsa.PublicKey) map[string]*rsa.PublicKey{
		// The empirically demonstrated case: /oauth/jwks returns {"keys":[]}.
		"published set becomes empty": func(_, _ *rsa.PublicKey) map[string]*rsa.PublicKey {
			return map[string]*rsa.PublicKey{}
		},
		// The ordinary emergency case: the key is replaced, not just removed.
		"key replaced by a different one": func(_, replacement *rsa.PublicKey) map[string]*rsa.PublicKey {
			return map[string]*rsa.PublicKey{"key-2": replacement}
		},
	}

	for name, withdraw := range withdrawals {
		t.Run(name, func(t *testing.T) {
			live, replacement := newRSAKey(t), newRSAKey(t)

			var (
				hits      int32
				withdrawn atomic.Bool
			)
			srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
				atomic.AddInt32(&hits, 1)
				keys := map[string]*rsa.PublicKey{"key-1": &live.PublicKey}
				if withdrawn.Load() {
					keys = withdraw(&live.PublicKey, &replacement.PublicKey)
				}
				w.Header().Set("Content-Type", "application/json")
				_, _ = w.Write(jwksJSON(t, keys))
			}))
			defer srv.Close()

			clock := newTestClock()
			c := testClient(t, func(cfg *Config) {
				cfg.JWTSigningKey = testHMACKey
				cfg.JWKSURL = srv.URL
				cfg.JWKSMaxAge = time.Hour
			})
			c.jwks.now = clock.Now

			token := func() string { return signRS256(t, newTestClaims("42"), live, "key-1") }

			t.Run("key verifies while published", func(t *testing.T) {
				if _, err := c.validateAccessToken(context.Background(), token()); err != nil {
					t.Fatalf("validate: %v", err)
				}
				if got := atomic.LoadInt32(&hits); got != 1 {
					t.Fatalf("JWKS fetches = %d, want 1", got)
				}
			})

			withdrawn.Store(true)

			t.Run("still verifies inside the max age", func(t *testing.T) {
				clock.Advance(59 * time.Minute)
				if _, err := c.validateAccessToken(context.Background(), token()); err != nil {
					t.Fatalf("validate: %v", err)
				}
				if got := atomic.LoadInt32(&hits); got != 1 {
					t.Fatalf("JWKS fetches = %d, want 1 (refetched before the max age elapsed)", got)
				}
			})

			t.Run("stops verifying once the max age passes", func(t *testing.T) {
				clock.Advance(2 * time.Minute) // now 61m old, past the 1h max age
				if _, err := c.validateAccessToken(context.Background(), token()); err == nil {
					t.Fatal("token signed by a WITHDRAWN key was ACCEPTED after the max age — revocation does not propagate")
				}
				if got := atomic.LoadInt32(&hits); got != 2 {
					t.Fatalf("JWKS fetches = %d, want 2 (the aged-out set was not re-fetched)", got)
				}
			})
		})
	}
}

// TestJWKSMaxAge_HonoursCacheControl checks that the max-age advertised by the
// JWKS response wins over the configured default, and is clamped.
func TestJWKSMaxAge_HonoursCacheControl(t *testing.T) {
	t.Run("parsing and clamping", func(t *testing.T) {
		tests := []struct {
			name   string
			header string
			want   time.Duration
		}{
			{"absent", "", 0},
			{"forta-api's real header", "public, max-age=3600", time.Hour},
			{"clamped up from too small", "max-age=1", 5 * time.Minute},
			{"clamped down from too large", "public, max-age=999999999", 24 * time.Hour},
			{"no-store floors at the minimum", "no-store", 5 * time.Minute},
			{"unparseable max-age is ignored", "max-age=soon", 0},
			{"irrelevant directives ignored", "public, must-revalidate", 0},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				if got := cacheControlMaxAge(tt.header); got != tt.want {
					t.Fatalf("cacheControlMaxAge(%q) = %v, want %v", tt.header, got, tt.want)
				}
			})
		}
	})

	t.Run("response header overrides the configured max age", func(t *testing.T) {
		key := newRSAKey(t)
		var hits int32
		srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
			atomic.AddInt32(&hits, 1)
			// Much shorter than the configured 24h max age.
			w.Header().Set("Cache-Control", "public, max-age=600")
			w.Header().Set("Content-Type", "application/json")
			_, _ = w.Write(jwksJSON(t, map[string]*rsa.PublicKey{"key-1": &key.PublicKey}))
		}))
		defer srv.Close()

		clock := newTestClock()
		c := testClient(t, func(cfg *Config) {
			cfg.JWTSigningKey = testHMACKey
			cfg.JWKSURL = srv.URL
			cfg.JWKSMaxAge = 24 * time.Hour
		})
		c.jwks.now = clock.Now

		tok := signRS256(t, newTestClaims("1"), key, "key-1")
		if _, err := c.validateAccessToken(context.Background(), tok); err != nil {
			t.Fatalf("validate: %v", err)
		}

		clock.Advance(11 * time.Minute) // past max-age=600s, far inside 24h
		if _, err := c.validateAccessToken(context.Background(), tok); err != nil {
			t.Fatalf("validate: %v", err)
		}
		if got := atomic.LoadInt32(&hits); got != 2 {
			t.Fatalf("JWKS fetches = %d, want 2 (Cache-Control max-age was ignored)", got)
		}
	})
}

// TestJWKSMaxAge_RefreshFailureKeepsServingCachedKeys pins the failure posture:
// an unreachable JWKS endpoint must not become a platform-wide outage, but a
// failed attempt must not extend the entry's age either.
func TestJWKSMaxAge_RefreshFailureKeepsServingCachedKeys(t *testing.T) {
	key := newRSAKey(t)

	var (
		hits   int32
		broken atomic.Bool
	)
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		if broken.Load() {
			w.WriteHeader(http.StatusInternalServerError)
			return
		}
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON(t, map[string]*rsa.PublicKey{"key-1": &key.PublicKey}))
	}))
	defer srv.Close()

	clock := newTestClock()
	c := testClient(t, func(cfg *Config) {
		cfg.JWTSigningKey = testHMACKey
		cfg.JWKSURL = srv.URL
		cfg.JWKSMaxAge = time.Hour
		cfg.JWKSMinRefreshInterval = 5 * time.Minute
	})
	c.jwks.now = clock.Now

	tok := signRS256(t, newTestClaims("42"), key, "key-1")

	if _, err := c.validateAccessToken(context.Background(), tok); err != nil {
		t.Fatalf("prime cache: %v", err)
	}
	broken.Store(true)

	t.Run("failed refresh serves the cached key rather than failing closed", func(t *testing.T) {
		clock.Advance(61 * time.Minute)
		if _, err := c.validateAccessToken(context.Background(), tok); err != nil {
			t.Fatalf("cached key was NOT served while the JWKS endpoint was down: %v", err)
		}
		if got := atomic.LoadInt32(&hits); got != 2 {
			t.Fatalf("JWKS fetches = %d, want 2", got)
		}
	})

	t.Run("failed refresh does not extend the age — it retries", func(t *testing.T) {
		clock.Advance(6 * time.Minute) // past the failure backoff
		if _, err := c.validateAccessToken(context.Background(), tok); err != nil {
			t.Fatalf("validate: %v", err)
		}
		if got := atomic.LoadInt32(&hits); got != 3 {
			t.Fatalf("JWKS fetches = %d, want 3 (a failed attempt reset the entry's age)", got)
		}
	})

	t.Run("recovery re-establishes a fresh entry", func(t *testing.T) {
		broken.Store(false)
		clock.Advance(6 * time.Minute)
		if _, err := c.validateAccessToken(context.Background(), tok); err != nil {
			t.Fatalf("validate: %v", err)
		}
		before := atomic.LoadInt32(&hits)

		clock.Advance(10 * time.Minute) // well inside the fresh 1h max age
		if _, err := c.validateAccessToken(context.Background(), tok); err != nil {
			t.Fatalf("validate: %v", err)
		}
		if got := atomic.LoadInt32(&hits); got != before {
			t.Fatalf("JWKS fetches = %d, want %d (entry was not marked fresh after recovery)", got, before)
		}
	})
}

// TestJWKSMaxAge_IndependentOfUnknownKIDRateLimit is the load-bearing test for
// the separation of the two refresh triggers. minRefresh is set absurdly high so
// that anything driven by the unknown-kid rate limit is frozen:
//
//   - the age-based refresh must still happen (it is not gated by the limit), and
//   - the age-based refresh must not reset the limit's clock, so an attacker
//     flooding unknown kids still cannot drive a second fetch.
func TestJWKSMaxAge_IndependentOfUnknownKIDRateLimit(t *testing.T) {
	key := newRSAKey(t)

	var hits int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		atomic.AddInt32(&hits, 1)
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write(jwksJSON(t, map[string]*rsa.PublicKey{"key-1": &key.PublicKey}))
	}))
	defer srv.Close()

	clock := newTestClock()
	c := testClient(t, func(cfg *Config) {
		cfg.JWTSigningKey = testHMACKey
		cfg.JWKSURL = srv.URL
		cfg.JWKSMaxAge = time.Hour
		cfg.JWKSMinRefreshInterval = 24 * time.Hour // effectively frozen
	})
	c.jwks.now = clock.Now

	good := signRS256(t, newTestClaims("42"), key, "key-1")

	if _, err := c.validateAccessToken(context.Background(), good); err != nil {
		t.Fatalf("prime cache: %v", err)
	}
	if got := atomic.LoadInt32(&hits); got != 1 {
		t.Fatalf("JWKS fetches = %d, want 1", got)
	}

	t.Run("age refresh happens even though the rate limit has not elapsed", func(t *testing.T) {
		clock.Advance(2 * time.Hour) // > JWKSMaxAge, << JWKSMinRefreshInterval
		if _, err := c.validateAccessToken(context.Background(), good); err != nil {
			t.Fatalf("validate: %v", err)
		}
		if got := atomic.LoadInt32(&hits); got != 2 {
			t.Fatalf("JWKS fetches = %d, want 2 (age-based refresh was suppressed by the unknown-kid rate limit)", got)
		}
	})

	t.Run("the age refresh did not reset or weaken the rate limit", func(t *testing.T) {
		before := atomic.LoadInt32(&hits)
		for i := 0; i < 25; i++ {
			forged := signRS256(t, newTestClaims("1"), key, "attacker-kid-"+strconv.Itoa(i))
			if _, err := c.validateAccessToken(context.Background(), forged); err == nil {
				t.Fatal("token with an unknown kid was ACCEPTED")
			}
		}
		if got := atomic.LoadInt32(&hits); got != before {
			t.Fatalf("JWKS fetches = %d, want %d — 25 unknown kids drove %d extra fetches; the DoS amplification limit is not intact", got, before, got-before)
		}
	})
}

// ── Issuer acceptance ───────────────────────────────────────────────────────

// TestAcceptedIssuers covers the dual-issuer window. Tokens carry
// "forta:auth-service" today; the OIDC discovery document forta-api publishes
// advertises "https://auth.appleby.cloud", and OIDC Core §3.1.3.7 requires an
// id_token's iss to equal the discovery issuer exactly. Accepting both here
// means the fleet redeploys once, not twice.
func TestAcceptedIssuers(t *testing.T) {
	secret := []byte(testHMACKey)

	tokenWithIssuer := func(iss string) string {
		cl := newTestClaims("77")
		cl.Issuer = iss
		return signHS512(t, cl, secret)
	}

	t.Run("defaults accept both issuers", func(t *testing.T) {
		c := testClient(t, func(cfg *Config) { cfg.JWTSigningKey = testHMACKey })

		tests := []struct {
			name   string
			issuer string
			wantOK bool
		}{
			{"legacy issuer, what tokens carry today", LegacyIssuer, true},
			{"discovery issuer, the migration target", Issuer, true},
			{"unrelated issuer", "https://evil.example.com", false},
			{"empty issuer", "", false},
			{"issuer with a trailing slash is not the same string", Issuer + "/", false},
			{"lookalike host", "https://auth.appleby.cloud.evil.com", false},
		}
		for _, tt := range tests {
			t.Run(tt.name, func(t *testing.T) {
				id, err := c.validateAccessToken(context.Background(), tokenWithIssuer(tt.issuer))
				if !tt.wantOK {
					if err == nil {
						t.Fatalf("token with issuer %q was ACCEPTED (user id %d)", tt.issuer, id)
					}
					return
				}
				if err != nil {
					t.Fatalf("token with issuer %q was REJECTED: %v", tt.issuer, err)
				}
				if id != 77 {
					t.Fatalf("user id = %d, want 77", id)
				}
			})
		}
	})

	t.Run("legacy validateAccessTokenLocal accepts both too", func(t *testing.T) {
		for _, iss := range []string{LegacyIssuer, Issuer} {
			if _, err := validateAccessTokenLocal(tokenWithIssuer(iss), testHMACKey); err != nil {
				t.Fatalf("issuer %q rejected by validateAccessTokenLocal: %v", iss, err)
			}
		}
		if _, err := validateAccessTokenLocal(tokenWithIssuer("nope"), testHMACKey); err == nil {
			t.Fatal("unrelated issuer was ACCEPTED by validateAccessTokenLocal")
		}
	})

	t.Run("AcceptedIssuers is honoured exactly, with no defaults merged in", func(t *testing.T) {
		c := testClient(t, func(cfg *Config) {
			cfg.JWTSigningKey = testHMACKey
			cfg.AcceptedIssuers = []string{"https://tenant.example.com"}
		})

		if _, err := c.validateAccessToken(context.Background(), tokenWithIssuer("https://tenant.example.com")); err != nil {
			t.Fatalf("configured issuer was REJECTED: %v", err)
		}
		for _, iss := range []string{LegacyIssuer, Issuer} {
			if _, err := c.validateAccessToken(context.Background(), tokenWithIssuer(iss)); err == nil {
				t.Fatalf("default issuer %q was accepted despite an explicit AcceptedIssuers list", iss)
			}
		}
	})

	t.Run("DefaultAcceptedIssuers returns a copy callers cannot corrupt", func(t *testing.T) {
		got := DefaultAcceptedIssuers()
		if len(got) != 2 || got[0] != LegacyIssuer || got[1] != Issuer {
			t.Fatalf("DefaultAcceptedIssuers() = %v", got)
		}
		got[0] = "https://attacker.example.com"
		if DefaultAcceptedIssuers()[0] != LegacyIssuer {
			t.Fatal("mutating the returned slice corrupted the package defaults")
		}

		c := testClient(t, func(cfg *Config) { cfg.JWTSigningKey = testHMACKey })
		if _, err := c.validateAccessToken(context.Background(), tokenWithIssuer("https://attacker.example.com")); err == nil {
			t.Fatal("mutating the returned slice widened the accepted issuer set")
		}
	})
}

// TestConfigJWKSURL checks the default endpoint derivation.
func TestConfigJWKSURL(t *testing.T) {
	tests := []struct {
		name string
		cfg  Config
		want string
	}{
		{"default", Config{APIDomain: "https://api.forta.test"}, "https://api.forta.test/oauth/jwks"},
		{"trailing slash", Config{APIDomain: "https://api.forta.test/"}, "https://api.forta.test/oauth/jwks"},
		{"override", Config{APIDomain: "https://api.forta.test", JWKSURL: "https://elsewhere/keys"}, "https://elsewhere/keys"},
	}
	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			if got := tt.cfg.jwksURL(); got != tt.want {
				t.Fatalf("jwksURL() = %q, want %q", got, tt.want)
			}
		})
	}
}
