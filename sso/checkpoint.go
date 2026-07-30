package sso

import (
	"context"
	"errors"
	"fmt"
	"log"
	"time"
)

// CheckpointInterval is how long a successful check is trusted before the
// upstream grant is re-introspected.
//
// Five minutes: short enough that a revocation takes effect in minutes rather
// than at the end of a session, long enough to keep the IdP off the per-request
// hot path. It is a deliberate trade — an IdP call on every request would make
// this service's availability strictly worse than the IdP's.
const CheckpointInterval = 5 * time.Minute

// CheckpointGrace bounds how long a session may be trusted when introspection
// cannot get an answer at all.
//
// ─────────────────────────────────────────────────────────────────────────────
// THIS CONSTANT IS THE WHOLE ARGUMENT. Fail-open and fail-closed are both wrong.
//
// FAIL-CLOSED (deny when the IdP is unreachable) makes this service strictly less
// available than the IdP, and worse, makes IdP availability a lever: anyone who
// can disrupt that connection logs out every user.
//
// FAIL-OPEN FOREVER (always trust the last known good) makes revocation
// unenforceable in exactly the circumstance where it matters. An attacker who has
// compromised an account and can degrade the introspection path keeps their
// session indefinitely, and nothing in the logs looks wrong.
//
// So: fail open, BUT ON A CLOCK. An unreachable IdP is survivable for thirty
// minutes; after that the session is denied. That converts "revocation may never
// take effect" into "revocation takes effect within thirty minutes even under
// attack", which is a bound rather than a hope.
//
// ⚠️ THIS APPLIES ONLY TO "NO ANSWER". A DEFINITIVE active:false is acted on
// immediately, with no grace whatsoever — see Checkpoint.
// ─────────────────────────────────────────────────────────────────────────────
const CheckpointGrace = 30 * time.Minute

// CheckpointResult is what a checkpoint concluded.
type CheckpointResult int

const (
	// CheckpointOK — the session may proceed. Either it is not SSO-backed, or the
	// grant was confirmed live, or it is inside the grace window after a failure.
	CheckpointOK CheckpointResult = iota

	// CheckpointRevoked — the IdP definitively reported the grant gone, or the
	// grace window expired. END THE SESSION. The correct HTTP response is 401.
	CheckpointRevoked

	// CheckpointUnavailable — no answer, and the grace window has expired.
	//
	// ⚠️ THE CORRECT HTTP RESPONSE IS 503, NOT 401, and the difference is
	// operational rather than pedantic. A 401 tells a client its credentials are
	// bad, so it discards them and re-authenticates — against the very identity
	// provider that is down. Ten thousand clients doing that is a thundering herd
	// arriving exactly when the IdP can least absorb it, and the users are logged
	// out for a problem that was never theirs. A 503 with Retry-After tells the
	// client to wait, and the session survives to be revalidated.
	CheckpointUnavailable
)

func (r CheckpointResult) String() string {
	switch r {
	case CheckpointOK:
		return "ok"
	case CheckpointRevoked:
		return "revoked"
	case CheckpointUnavailable:
		return "unavailable"
	default:
		return fmt.Sprintf("CheckpointResult(%d)", int(r))
	}
}

// Checkpointer periodically re-checks that the upstream IdP grant behind a local
// session is still live.
//
// Providers is a lookup rather than a map so an application can resolve a slug
// however it likes — a database read, a config map, a literal — and so a provider
// whose client secret rotates is re-resolved rather than cached here forever.
type Checkpointer struct {
	Sessions  SessionStore
	Providers func(ctx context.Context, slug string) (*Provider, error)

	// Interval and Grace default to CheckpointInterval and CheckpointGrace when
	// zero.
	Interval time.Duration
	Grace    time.Duration

	// Logf defaults to log.Printf. Set it to route these lines into a structured
	// logger.
	//
	// ⚠️ Every message this type emits names a user id and a provider slug, and
	// NEVER a token, a claim value, or an introspection response body. A checkpoint
	// log is written on every session and is exactly the kind of high-volume log
	// that ends up somewhere less protected than the database.
	Logf func(format string, args ...any)
}

func (c *Checkpointer) interval() time.Duration {
	if c.Interval > 0 {
		return c.Interval
	}
	return CheckpointInterval
}

func (c *Checkpointer) grace() time.Duration {
	if c.Grace > 0 {
		return c.Grace
	}
	return CheckpointGrace
}

func (c *Checkpointer) logf(format string, args ...any) {
	if c.Logf != nil {
		c.Logf(format, args...)
		return
	}
	log.Printf(format, args...)
}

// Check decides whether a user's session may proceed.
//
// The order of the branches is the design, and each early return is load-bearing:
//
//  1. NO SESSION ROW → OK. A native password login has nothing upstream to check.
//     ⚠️ Getting this wrong logs out every non-SSO user on the platform, which is
//     why SessionStore.LoadSession documents (nil, nil) as the required answer.
//  2. CHECKED RECENTLY → OK, without touching the network.
//  3. PROVIDER GONE or NOT INTROSPECTABLE → OK, and reset the clock. A provider
//     with no introspection endpoint cannot be checked at all; pretending
//     otherwise would deny every session using it.
//  4. active:false → REVOKED, immediately, no grace.
//  5. NO ANSWER → OK while inside the grace window, UNAVAILABLE once outside it.
func (c *Checkpointer) Check(ctx context.Context, userID int64) CheckpointResult {
	if c.Sessions == nil {
		// Nothing configured to check against. OK rather than deny: a missing
		// configuration must not be a platform-wide outage.
		return CheckpointOK
	}

	sess, err := c.Sessions.LoadSession(ctx, userID)
	if err != nil {
		// The session store is this application's own database. If it is unreachable,
		// the request was going to fail anyway; passing here keeps the checkpoint from
		// being the thing that reports it, and bounded by the fact that nothing else
		// will work either.
		c.logf("sso: checkpoint: load session for user %d failed, passing: %v", userID, err)
		return CheckpointOK
	}
	if sess == nil {
		return CheckpointOK
	}

	if time.Since(sess.LastCheckedAt) < c.interval() {
		return CheckpointOK
	}

	if c.Providers == nil {
		c.logf("sso: checkpoint: no provider lookup configured, passing user %d", userID)
		return CheckpointOK
	}
	provider, err := c.Providers(ctx, sess.Provider)
	if err != nil || provider == nil {
		c.logf("sso: checkpoint: load provider %q for user %d failed, passing: %v", sess.Provider, userID, err)
		return c.graceOrUnavailable(ctx, userID, sess)
	}

	if provider.IntrospectURL == "" {
		// Nothing to ask. Reset the clock so this does not retry on every request for
		// a provider that will never be introspectable.
		//
		// ⚠️ This is a real gap, not a solved case: for such a provider, a revocation
		// at the IdP is invisible until the local session ends on its own. It is a
		// reason to configure introspect_url, not a reason to deny the session.
		c.touch(ctx, userID)
		return CheckpointOK
	}

	// Prefer the refresh token: it is the long-lived half, so it remains
	// introspectable after the access token has expired on its own — and an expired
	// access token would introspect as active:false, which would be read as a
	// revocation and end the session on a schedule.
	token, hint := sess.Tokens.RefreshToken, "refresh_token"
	if token == "" {
		token, hint = sess.Tokens.AccessToken, "access_token"
	}
	if token == "" {
		c.logf("sso: checkpoint: session for user %d has no token to introspect, passing", userID)
		c.touch(ctx, userID)
		return CheckpointOK
	}

	resp, err := Introspect(ctx, provider, token, hint)
	if err != nil {
		// NO ANSWER. Not a revocation.
		c.logf("sso: checkpoint: introspect for user %d via %q failed: %v", userID, sess.Provider, err)
		return c.graceOrUnavailable(ctx, userID, sess)
	}

	if !resp.Active {
		// ── DEFINITIVE. No grace, no retry, no benefit of the doubt. ──────────
		//
		// The IdP was reachable, authenticated us, and said this grant is gone. That
		// is the one unambiguous signal in the whole mechanism, and the entire point
		// of running a checkpoint is to act on it the moment it arrives.
		c.logf("sso: checkpoint: upstream grant for user %d via %q is inactive — ending session", userID, sess.Provider)

		if err := c.Sessions.DeleteSession(ctx, userID); err != nil {
			c.logf("sso: checkpoint: failed to delete revoked session for user %d: %v", userID, err)
		}

		// Deleting the session row is not necessarily enough. If the application also
		// issued its own long-lived token, that token outlives the row and the user
		// keeps their access — a checkpoint that detects revocation and does not stop
		// it. LocalTokenRevoker is the hook that closes it.
		if revoker, ok := c.Sessions.(LocalTokenRevoker); ok {
			if err := revoker.RevokeLocalTokens(ctx, userID); err != nil {
				c.logf("sso: checkpoint: failed to revoke local tokens for user %d: %v", userID, err)
			}
		}
		return CheckpointRevoked
	}

	c.touch(ctx, userID)
	return CheckpointOK
}

// graceOrUnavailable applies the bounded fail-open rule.
//
// The clock runs from LastCheckedAt — the last time an answer was actually
// obtained — NOT from now. Measuring from now would restart the window on every
// failed attempt, so a permanently unreachable IdP would grant permanent access,
// which is the unbounded fail-open this exists to prevent.
func (c *Checkpointer) graceOrUnavailable(ctx context.Context, userID int64, sess *Session) CheckpointResult {
	if sess.LastCheckedAt.IsZero() {
		// Never successfully checked. There is no last-known-good to extend, so there
		// is nothing to fail open ONTO — the session has never been confirmed against
		// the IdP at all.
		c.logf("sso: checkpoint: user %d has never been checked and the IdP is unreachable — unavailable", userID)
		return CheckpointUnavailable
	}

	if since := time.Since(sess.LastCheckedAt); since < c.grace() {
		return CheckpointOK
	}

	c.logf("sso: checkpoint: user %d unverified for longer than the %s grace window — unavailable", userID, c.grace())
	return CheckpointUnavailable
}

func (c *Checkpointer) touch(ctx context.Context, userID int64) {
	if err := c.Sessions.TouchSession(ctx, userID); err != nil {
		// Not fatal: the check itself succeeded. The only cost is that the next request
		// re-checks, which is wasted work rather than a wrong answer.
		c.logf("sso: checkpoint: failed to touch session for user %d: %v", userID, err)
	}
}

// ErrCheckpointUnavailable is what an HTTP layer should map to 503.
//
// Provided so a middleware can `errors.Is` rather than switching on the result
// enum in every adopting service — and so the 503-not-401 rule is expressed once,
// in a place a caller is likely to read.
var ErrCheckpointUnavailable = errors.New("sso: cannot verify the upstream grant; retry shortly")
