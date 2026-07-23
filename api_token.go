package forta

import (
	"strings"
	"sync"
	"time"
)

// APITokenPrefix marks a credential as an opaque Forta API token rather than a
// JWT. Opaque tokens cannot be verified locally — they carry no claims — so
// they are always resolved against the Forta API.
const APITokenPrefix = "frt_"

// DefaultAPITokenCacheTTL bounds how long a resolved API token is reused before
// it is re-validated against Forta. It also bounds revocation latency: a token
// revoked in Forta keeps working here for at most this long.
const DefaultAPITokenCacheTTL = 60 * time.Second

// IsAPIToken reports whether a bearer credential is an opaque Forta API token.
func IsAPIToken(token string) bool {
	return strings.HasPrefix(token, APITokenPrefix)
}

type apiTokenCacheEntry struct {
	user       *User
	resolvedAt time.Time
}

// apiTokenCache memoizes API-token-to-user resolutions so that a token used on
// every request does not produce a round-trip to Forta each time. Keyed by the
// plaintext token, which never leaves the process.
type apiTokenCache struct {
	entries sync.Map
	ttl     time.Duration
}

func newAPITokenCache(ttl time.Duration) *apiTokenCache {
	return &apiTokenCache{ttl: ttl}
}

func (ac *apiTokenCache) get(token string) (*User, bool) {
	val, ok := ac.entries.Load(token)
	if !ok {
		return nil, false
	}
	entry, ok := val.(apiTokenCacheEntry)
	if !ok {
		ac.entries.Delete(token)
		return nil, false
	}
	if time.Since(entry.resolvedAt) > ac.ttl {
		ac.entries.Delete(token)
		return nil, false
	}
	return entry.user, true
}

func (ac *apiTokenCache) set(token string, user *User) {
	ac.entries.Store(token, apiTokenCacheEntry{
		user:       user,
		resolvedAt: time.Now(),
	})
}

func (ac *apiTokenCache) invalidate(token string) {
	ac.entries.Delete(token)
}
