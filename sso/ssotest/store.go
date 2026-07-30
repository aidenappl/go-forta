package ssotest

import (
	"context"
	"sync"
	"time"

	sso "github.com/aidenappl/go-forta/sso"
)

// MemoryStateStore is an in-memory StateStore for tests.
//
// ⚠️ ITS ConsumeState IS GENUINELY ATOMIC, and that is deliberate rather than
// incidental. A test fixture whose consume had the SELECT-then-DELETE race would
// make the single-use test pass for the wrong reason — the race would simply not
// be exercised under a single-goroutine test — and would model the bug the real
// implementations must avoid. Holding the mutex across the read and the delete is
// this store's equivalent of a row lock.
type MemoryStateStore struct {
	mu      sync.Mutex
	records map[string]memoryRecord
}

type memoryRecord struct {
	data      []byte
	expiresAt time.Time
}

// NewMemoryStateStore returns an empty store.
func NewMemoryStateStore() *MemoryStateStore {
	return &MemoryStateStore{records: map[string]memoryRecord{}}
}

func (s *MemoryStateStore) SaveState(_ context.Context, state string, data []byte, expiresAt time.Time) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.records[state] = memoryRecord{data: data, expiresAt: expiresAt}
	return nil
}

func (s *MemoryStateStore) ConsumeState(_ context.Context, state string) ([]byte, error) {
	s.mu.Lock()
	defer s.mu.Unlock()

	rec, ok := s.records[state]
	if !ok {
		return nil, sso.ErrNoState
	}
	// Deleted whether or not it turns out to be valid: a record that has been
	// presented once must never be presentable again, expired or not.
	delete(s.records, state)

	if time.Now().After(rec.expiresAt) {
		return nil, sso.ErrNoState
	}
	return rec.data, nil
}

// Count reports how many records remain, so a test can assert consumption.
func (s *MemoryStateStore) Count() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.records)
}

// MemorySessionStore is an in-memory SessionStore for tests. It optionally
// records local-token revocations so a test can assert the hook fired.
type MemorySessionStore struct {
	mu       sync.Mutex
	sessions map[int64]*sso.Session

	// Revoked records the user ids RevokeLocalTokens was called for.
	Revoked []int64

	// SupportRevoke controls whether this store advertises LocalTokenRevoker. It is
	// a field rather than two types so a test can cover both the "application
	// implements the hook" and "application does not" paths with one fixture.
	SupportRevoke bool
}

// NewMemorySessionStore returns an empty store.
func NewMemorySessionStore() *MemorySessionStore {
	return &MemorySessionStore{sessions: map[int64]*sso.Session{}}
}

func (s *MemorySessionStore) SaveSession(_ context.Context, userID int64, sess sso.Session) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	copied := sess
	s.sessions[userID] = &copied
	return nil
}

func (s *MemorySessionStore) LoadSession(_ context.Context, userID int64) (*sso.Session, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	sess, ok := s.sessions[userID]
	if !ok {
		// (nil, nil) — "not an SSO session". See SessionStore.LoadSession.
		return nil, nil
	}
	copied := *sess
	return &copied, nil
}

func (s *MemorySessionStore) TouchSession(_ context.Context, userID int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	if sess, ok := s.sessions[userID]; ok {
		sess.LastCheckedAt = time.Now()
	}
	return nil
}

func (s *MemorySessionStore) DeleteSession(_ context.Context, userID int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	delete(s.sessions, userID)
	return nil
}

// RevokeLocalTokens records the call. Only meaningful when SupportRevoke is set;
// see AsRevoker.
func (s *MemorySessionStore) RevokeLocalTokens(_ context.Context, userID int64) error {
	s.mu.Lock()
	defer s.mu.Unlock()
	s.Revoked = append(s.Revoked, userID)
	return nil
}

// RevokedCount reports how many revocations were recorded.
func (s *MemorySessionStore) RevokedCount() int {
	s.mu.Lock()
	defer s.mu.Unlock()
	return len(s.Revoked)
}

// plainSessionStore wraps a MemorySessionStore WITHOUT the RevokeLocalTokens
// method, so a test can exercise the "application does not implement the optional
// hook" path. Go interface satisfaction is structural, so hiding the method
// requires a distinct type.
type plainSessionStore struct{ inner *MemorySessionStore }

func (p plainSessionStore) SaveSession(ctx context.Context, userID int64, s sso.Session) error {
	return p.inner.SaveSession(ctx, userID, s)
}
func (p plainSessionStore) LoadSession(ctx context.Context, userID int64) (*sso.Session, error) {
	return p.inner.LoadSession(ctx, userID)
}
func (p plainSessionStore) TouchSession(ctx context.Context, userID int64) error {
	return p.inner.TouchSession(ctx, userID)
}
func (p plainSessionStore) DeleteSession(ctx context.Context, userID int64) error {
	return p.inner.DeleteSession(ctx, userID)
}

// WithoutRevoker returns a SessionStore view of s that does NOT satisfy
// LocalTokenRevoker.
func WithoutRevoker(s *MemorySessionStore) sso.SessionStore {
	return plainSessionStore{inner: s}
}
