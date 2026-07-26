package forta

import (
	"context"
	"crypto/rsa"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"math/big"
	"net/http"
	"strconv"
	"strings"
	"sync"
	"time"
)

const (
	// jwksPath is the path on the Forta API where the public JSON Web Key Set
	// is published. Only used when Config.JWKSURL is empty.
	jwksPath = "/oauth/jwks"

	// DefaultJWKSMinRefreshInterval is the minimum amount of time that must
	// elapse between two JWKS fetches triggered by an unknown key id.
	//
	// This is a security control, not a performance tuning knob: without it an
	// attacker can send a stream of tokens carrying random "kid" values and
	// turn every relying party into a traffic amplifier against the Forta
	// JWKS endpoint. Key rotation is discovered at most this long after the
	// new key is published, which is the accepted trade-off in OIDC Core
	// §10.1.1 key-rotation handling.
	DefaultJWKSMinRefreshInterval = 5 * time.Minute

	// DefaultJWKSMaxAge is how long a cached key set is served before it is
	// re-fetched, when the JWKS response carries no usable Cache-Control
	// max-age and Config.JWKSMaxAge is unset.
	//
	// This is what makes **revocation** possible, as opposed to rotation. A
	// cached key that the issuer has withdrawn is only discovered by asking
	// again; before this existed, a kid that was already cached was never
	// revalidated and a compromised signing key kept verifying tokens for the
	// life of the process. Key removal now propagates within this window.
	DefaultJWKSMaxAge = time.Hour

	// jwksMinCacheControlMaxAge and jwksMaxCacheControlMaxAge clamp the
	// Cache-Control max-age advertised by the JWKS endpoint. The issuer is
	// trusted, but a header is still remote input: a tiny value would let the
	// endpoint drive unbounded traffic at itself, and a huge one would push
	// revocation latency out past anything operationally useful.
	jwksMinCacheControlMaxAge = 5 * time.Minute
	jwksMaxCacheControlMaxAge = 24 * time.Hour

	// jwksFetchTimeout bounds a single JWKS HTTP request.
	jwksFetchTimeout = 5 * time.Second

	// jwksMaxBodyBytes bounds how much of a JWKS response body is read, so a
	// hostile or misbehaving endpoint cannot exhaust memory.
	jwksMaxBodyBytes = 1 << 20 // 1 MiB
)

// ErrUnknownKeyID is returned when a token references a key id that is not in
// the cached key set and the key set cannot be re-fetched yet because the
// refresh rate limit has not elapsed.
var ErrUnknownKeyID = errors.New("go-forta: unknown JWKS key id")

// jwkSet is the wire format of the JWKS document served by forta-api.
type jwkSet struct {
	Keys []jwk `json:"keys"`
}

// jwk is a single JSON Web Key. Only RSA public keys are supported; any other
// key type in the document is ignored rather than treated as an error, so the
// server can publish additional key types without breaking older SDKs.
type jwk struct {
	Kty string `json:"kty"`
	Use string `json:"use"`
	Alg string `json:"alg"`
	Kid string `json:"kid"`
	N   string `json:"n"`
	E   string `json:"e"`
}

// jwksCache fetches and caches the Forta JWKS in memory, keyed by key id.
//
// Fetching is entirely lazy: the cache performs no network I/O until the first
// RS256 token is actually presented. A consumer configured only for HS512
// therefore never contacts the JWKS endpoint.
//
// Two *independent* triggers cause a re-fetch. They must stay independent:
//
//  1. **Unknown kid** — a token references a key id that is not cached. This is
//     how rotation is discovered, and it is rate-limited by minRefresh because
//     the trigger is attacker-controlled (see DefaultJWKSMinRefreshInterval).
//  2. **Age** — the cached key set is older than its max age. This is how
//     *revocation* is discovered, and it is deliberately NOT subject to the
//     unknown-kid rate limit: the trigger is the clock, not the attacker, so it
//     cannot be used to amplify traffic. An age-based refresh never touches
//     lastAttempt, so it can neither reset nor weaken the rate limit.
type jwksCache struct {
	url        string
	httpClient *http.Client
	minRefresh time.Duration
	maxAge     time.Duration

	// now is the clock, injectable so tests can advance time without sleeping.
	now func() time.Time

	mu   sync.RWMutex
	keys map[string]*rsa.PublicKey
	// fetchedAt is when the current key set was retrieved; zero means "never
	// fetched". entryMaxAge is the max age that applies to it, taken from the
	// response's Cache-Control when present and from maxAge otherwise.
	fetchedAt   time.Time
	entryMaxAge time.Duration

	// fetchMu serialises refreshes so a burst of requests for the same unknown
	// kid produces a single fetch. lastAttempt and lastFailure are guarded by
	// fetchMu. lastAttempt tracks ONLY unknown-kid-triggered attempts;
	// lastFailure tracks ONLY failed age-based refreshes. They are separate on
	// purpose — neither mechanism may reset the other's clock.
	fetchMu     sync.Mutex
	lastAttempt time.Time
	lastFailure time.Time
}

// newJWKSCache builds a cache for the given JWKS URL. It performs no I/O.
func newJWKSCache(url string, minRefresh, maxAge time.Duration) *jwksCache {
	if minRefresh <= 0 {
		minRefresh = DefaultJWKSMinRefreshInterval
	}
	if maxAge <= 0 {
		maxAge = DefaultJWKSMaxAge
	}
	return &jwksCache{
		url:        url,
		httpClient: &http.Client{Timeout: jwksFetchTimeout},
		minRefresh: minRefresh,
		maxAge:     maxAge,
		now:        time.Now,
		keys:       make(map[string]*rsa.PublicKey),
	}
}

// lookup returns the cached key for kid, or nil.
func (j *jwksCache) lookup(kid string) *rsa.PublicKey {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return j.keys[kid]
}

// snapshot reports the cached key for kid (may be nil), whether the cache has
// ever been populated, and whether the cached key set has exceeded its max age.
func (j *jwksCache) snapshot(kid string) (key *rsa.PublicKey, loaded, stale bool) {
	j.mu.RLock()
	defer j.mu.RUnlock()

	key = j.keys[kid]
	if j.fetchedAt.IsZero() {
		return key, false, false
	}
	maxAge := j.entryMaxAge
	if maxAge <= 0 {
		maxAge = j.maxAge
	}
	return key, true, j.now().Sub(j.fetchedAt) >= maxAge
}

// keyFor returns the RSA public key for kid.
//
// It re-fetches the key set when the cached copy has aged out (revocation), or
// when the kid is unknown and the rate limit permits it (rotation). See the
// jwksCache doc comment: those two triggers are independent by design.
func (j *jwksCache) keyFor(ctx context.Context, kid string) (*rsa.PublicKey, error) {
	if kid == "" {
		return nil, errors.New("go-forta: token is missing the 'kid' header required for RS256 verification")
	}

	if key, _, stale := j.snapshot(kid); key != nil && !stale {
		return key, nil
	}

	j.fetchMu.Lock()
	defer j.fetchMu.Unlock()

	// Another goroutine may have refreshed while we waited for the lock.
	key, loaded, stale := j.snapshot(kid)
	if key != nil && !stale {
		return key, nil
	}

	// ── Trigger 1: the cached set has aged out. ─────────────────────────────
	// Not rate-limited by lastAttempt, and it never writes lastAttempt.
	if loaded && stale {
		// Back off only from a *failed* refresh, so a JWKS endpoint that is
		// down does not make every request pay a fetch timeout. This is its
		// own clock; it is neither read nor written by the unknown-kid limit.
		if !j.lastFailure.IsZero() && j.now().Sub(j.lastFailure) < j.minRefresh {
			if key != nil {
				return key, nil
			}
			return nil, fmt.Errorf("%w %q (jwks refresh failing)", ErrUnknownKeyID, kid)
		}

		if err := j.refresh(ctx); err != nil {
			j.lastFailure = j.now()
			// An unreachable JWKS endpoint must not become a platform-wide
			// outage, so keep serving what we have. fetchedAt is deliberately
			// left untouched by a failed attempt, so the entry stays stale and
			// a later request retries rather than getting a free extension.
			if key != nil {
				return key, nil
			}
			return nil, err
		}
		j.lastFailure = time.Time{}

		if k := j.lookup(kid); k != nil {
			return k, nil
		}
		// The refresh succeeded and kid is not in the new set — the issuer has
		// withdrawn this key. This is the revocation path.
		return nil, fmt.Errorf("%w %q", ErrUnknownKeyID, kid)
	}

	// ── Trigger 2: unknown kid. Rate-limited — this is the DoS control. ─────
	if !j.lastAttempt.IsZero() && j.now().Sub(j.lastAttempt) < j.minRefresh {
		return nil, fmt.Errorf("%w %q (refresh rate-limited)", ErrUnknownKeyID, kid)
	}
	j.lastAttempt = j.now()

	if err := j.refresh(ctx); err != nil {
		return nil, err
	}
	if k := j.lookup(kid); k != nil {
		return k, nil
	}
	return nil, fmt.Errorf("%w %q", ErrUnknownKeyID, kid)
}

// refresh fetches the key set and, on success, replaces the cache and resets
// its age. On any error the cache is left completely untouched — including
// fetchedAt, so a failed attempt never extends the life of a stale entry.
//
// A 200 response carrying a well-formed but *empty* key set is honoured when a
// key set is already cached: publishing an empty JWKS is how the issuer
// performs an emergency revocation, and ignoring it would defeat the whole
// point of the max age. When nothing is cached yet it is still an error, so a
// misconfigured endpoint fails loudly at first use instead of silently
// reporting every kid as unknown.
func (j *jwksCache) refresh(ctx context.Context) error {
	keys, maxAge, err := j.fetch(ctx)
	if err != nil {
		return err
	}
	if len(keys) == 0 && !j.hasKeys() {
		return errors.New("go-forta: jwks: key set contains no usable RSA signing keys")
	}
	if maxAge <= 0 {
		maxAge = j.maxAge
	}

	j.mu.Lock()
	j.keys = keys
	j.fetchedAt = j.now()
	j.entryMaxAge = maxAge
	j.mu.Unlock()
	return nil
}

// hasKeys reports whether any key is currently cached.
func (j *jwksCache) hasKeys() bool {
	j.mu.RLock()
	defer j.mu.RUnlock()
	return len(j.keys) > 0
}

// fetch downloads and parses the key set. It never mutates the cache itself.
// The returned duration is the clamped Cache-Control max-age of the response,
// or zero when the response advertises none.
func (j *jwksCache) fetch(ctx context.Context) (map[string]*rsa.PublicKey, time.Duration, error) {
	if ctx == nil {
		ctx = context.Background()
	}
	ctx, cancel := context.WithTimeout(ctx, jwksFetchTimeout)
	defer cancel()

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, j.url, nil)
	if err != nil {
		return nil, 0, fmt.Errorf("go-forta: jwks: request: %w", err)
	}
	req.Header.Set("Accept", "application/json")

	resp, err := j.httpClient.Do(req)
	if err != nil {
		return nil, 0, fmt.Errorf("go-forta: jwks: %w", err)
	}
	defer func() { _ = resp.Body.Close() }()

	if resp.StatusCode != http.StatusOK {
		return nil, 0, fmt.Errorf("go-forta: jwks: unexpected status %d", resp.StatusCode)
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, jwksMaxBodyBytes))
	if err != nil {
		return nil, 0, fmt.Errorf("go-forta: jwks: read: %w", err)
	}

	var set jwkSet
	if err := json.Unmarshal(body, &set); err != nil {
		return nil, 0, fmt.Errorf("go-forta: jwks: decode: %w", err)
	}

	keys := make(map[string]*rsa.PublicKey, len(set.Keys))
	for _, k := range set.Keys {
		if k.Kty != "RSA" || k.Kid == "" {
			continue
		}
		if k.Use != "" && k.Use != "sig" {
			continue
		}
		pub, err := k.rsaPublicKey()
		if err != nil {
			// Skip malformed entries rather than discarding the whole set —
			// one bad key must not lock out every other key.
			continue
		}
		keys[k.Kid] = pub
	}

	return keys, cacheControlMaxAge(resp.Header.Get("Cache-Control")), nil
}

// cacheControlMaxAge extracts the max-age directive from a Cache-Control
// header and clamps it to [jwksMinCacheControlMaxAge, jwksMaxCacheControlMaxAge].
// It returns zero when there is no usable directive, meaning "use the
// configured JWKSMaxAge". forta-api serves "public, max-age=3600".
//
// no-store / no-cache are honoured as "the shortest age we are willing to use"
// rather than "never cache", because a JWKS cache that genuinely does not cache
// would fetch the key set on every single token.
func cacheControlMaxAge(header string) time.Duration {
	if header == "" {
		return 0
	}
	for _, part := range strings.Split(header, ",") {
		directive := strings.ToLower(strings.TrimSpace(part))
		switch {
		case directive == "no-store" || directive == "no-cache":
			return jwksMinCacheControlMaxAge
		case strings.HasPrefix(directive, "max-age="):
			secs, err := strconv.Atoi(strings.TrimSpace(strings.TrimPrefix(directive, "max-age=")))
			if err != nil {
				continue
			}
			d := time.Duration(secs) * time.Second
			if d < jwksMinCacheControlMaxAge {
				return jwksMinCacheControlMaxAge
			}
			if d > jwksMaxCacheControlMaxAge {
				return jwksMaxCacheControlMaxAge
			}
			return d
		}
	}
	return 0
}

// rsaPublicKey converts the base64url-encoded modulus/exponent into a key.
func (k jwk) rsaPublicKey() (*rsa.PublicKey, error) {
	nBytes, err := base64.RawURLEncoding.DecodeString(k.N)
	if err != nil {
		return nil, fmt.Errorf("go-forta: jwks: bad modulus: %w", err)
	}
	eBytes, err := base64.RawURLEncoding.DecodeString(k.E)
	if err != nil {
		return nil, fmt.Errorf("go-forta: jwks: bad exponent: %w", err)
	}
	if len(nBytes) == 0 || len(eBytes) == 0 || len(eBytes) > 8 {
		return nil, errors.New("go-forta: jwks: malformed RSA key parameters")
	}

	e := new(big.Int).SetBytes(eBytes)
	if !e.IsInt64() || e.Int64() < 3 {
		return nil, errors.New("go-forta: jwks: invalid RSA exponent")
	}

	return &rsa.PublicKey{
		N: new(big.Int).SetBytes(nBytes),
		E: int(e.Int64()),
	}, nil
}
