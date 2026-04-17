package forta

import (
	"sync"
	"time"
)

type grantCacheEntry struct {
	granted   bool
	checkedAt time.Time
}

// grantCache is a simple in-memory cache for grant check results.
// Keyed by userID since each Client instance represents a single platform.
type grantCache struct {
	entries sync.Map
	ttl     time.Duration
}

func newGrantCache(ttl time.Duration) *grantCache {
	return &grantCache{ttl: ttl}
}

// get returns the cached grant status for the given user. The second return
// value is false if the entry is missing or expired.
func (gc *grantCache) get(userID int64) (granted bool, found bool) {
	val, ok := gc.entries.Load(userID)
	if !ok {
		return false, false
	}
	entry := val.(grantCacheEntry)
	if time.Since(entry.checkedAt) > gc.ttl {
		gc.entries.Delete(userID)
		return false, false
	}
	return entry.granted, true
}

// set stores a grant check result for the given user.
func (gc *grantCache) set(userID int64, granted bool) {
	gc.entries.Store(userID, grantCacheEntry{
		granted:   granted,
		checkedAt: time.Now(),
	})
}
