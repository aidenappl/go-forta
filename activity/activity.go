// Package activity reports what a user did inside a platform to Forta's
// activity trail (POST /internal/activity), so "everything this person did"
// spans every appleby.cloud platform, not just their Forta sign-ins.
//
// It is deliberately fire-and-forget: Report never blocks, never returns an
// error and never fails the caller's request. Events queue in memory and one
// background worker delivers them; when the queue is full, new events are
// dropped and counted (Stats). The platform's own audit table stays the record
// of truth — this is a mirror into the user's cross-platform history.
//
// Stdlib only (plus the module's internal correlate for the User-Agent), so
// importing it costs a platform nothing beyond this package.
package activity

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"regexp"
	"strings"
	"sync"
	"sync/atomic"
	"time"

	"github.com/aidenappl/go-forta/internal/correlate"
)

// Outcomes accepted by Forta.
const (
	Success = "success"
	Failure = "failure"
	Denied  = "denied"
)

// Limits enforced by Forta; Report trims to them so a long value does not get
// the whole event refused.
const (
	maxActionLen   = 48
	maxDetails     = 10
	maxDetailKey   = 32
	maxDetailVal   = 200
	defaultQueue   = 1000
	defaultTimeout = 5 * time.Second
)

var actionRE = regexp.MustCompile(`[^a-z0-9._-]+`)

// Config identifies the platform to Forta. ClientID and ClientSecret are the
// platform's own OAuth client credentials — the same ones its SSO uses.
type Config struct {
	// APIURL is Forta's API base, e.g. https://auth.appleby.cloud.
	APIURL       string
	ClientID     string
	ClientSecret string
	// QueueSize bounds the in-memory queue (default 1000).
	QueueSize int
	// HTTPClient overrides the client (default: 5s timeout).
	HTTPClient *http.Client
	// OnError, when set, is called (from the worker goroutine) for each event
	// Forta refused or that could not be delivered. Never pass it the event
	// body: callers usually just count or log the error.
	OnError func(action string, err error)
}

type event struct {
	Subject string            `json:"sub"`
	Action  string            `json:"action"`
	Outcome string            `json:"outcome"`
	Details map[string]string `json:"details,omitempty"`
}

// Reporter delivers events. The zero value and a nil *Reporter are valid and
// discard everything, so a platform without Forta credentials configured can
// call Report unconditionally.
type Reporter struct {
	cfg       Config
	endpoint  string
	client    *http.Client
	queue     chan event
	done      chan struct{}
	closeOnce sync.Once

	sent, dropped, failed atomic.Int64
}

// New starts a Reporter. With an empty APIURL, ClientID or ClientSecret it
// returns a nil *Reporter, which accepts and discards events.
func New(cfg Config) *Reporter {
	if cfg.APIURL == "" || cfg.ClientID == "" || cfg.ClientSecret == "" {
		return nil
	}
	if cfg.QueueSize <= 0 {
		cfg.QueueSize = defaultQueue
	}
	client := cfg.HTTPClient
	if client == nil {
		client = &http.Client{Timeout: defaultTimeout}
	}
	r := &Reporter{
		cfg:      cfg,
		endpoint: strings.TrimRight(cfg.APIURL, "/") + "/internal/activity",
		client:   client,
		queue:    make(chan event, cfg.QueueSize),
		done:     make(chan struct{}),
	}
	go r.run()
	return r
}

// Report queues one event about the user whose Forta subject (the `sub` the
// platform received at sign-in) is sub. action is a short token such as
// "secret.reveal"; Forta stores it as "platform.<action>". details are small
// identifiers — never a secret, token, password or URL query.
func (r *Reporter) Report(sub, action, outcome string, details map[string]string) {
	if r == nil || sub == "" || action == "" {
		return
	}
	switch outcome {
	case Success, Failure, Denied:
	default:
		outcome = Success
	}
	ev := event{Subject: sub, Action: normaliseAction(action), Outcome: outcome, Details: trimDetails(details)}
	if ev.Action == "" {
		return
	}
	select {
	case r.queue <- ev:
	default:
		r.dropped.Add(1)
	}
}

// Stats reports delivery counters since start.
func (r *Reporter) Stats() (sent, dropped, failed int64) {
	if r == nil {
		return 0, 0, 0
	}
	return r.sent.Load(), r.dropped.Load(), r.failed.Load()
}

// Close stops accepting events and waits (until ctx is done) for the queue to
// drain. Call it on shutdown.
func (r *Reporter) Close(ctx context.Context) {
	if r == nil {
		return
	}
	r.closeOnce.Do(func() { close(r.queue) })
	select {
	case <-r.done:
	case <-ctx.Done():
	}
}

func (r *Reporter) run() {
	defer close(r.done)
	for ev := range r.queue {
		r.deliver(ev)
	}
}

// deliver posts one event, retrying once on a network error or 5xx. A 4xx is
// Forta refusing the event (unknown subject, no grant) and is not retried.
func (r *Reporter) deliver(ev event) {
	body, err := json.Marshal(ev)
	if err != nil {
		r.fail(ev.Action, err)
		return
	}
	var last error
	for attempt := 0; attempt < 2; attempt++ {
		if attempt > 0 {
			time.Sleep(time.Second)
		}
		status, err := r.post(body)
		switch {
		case err != nil:
			last = err
			continue
		case status >= 500:
			last = fmt.Errorf("forta answered %d", status)
			continue
		case status >= 400:
			r.fail(ev.Action, fmt.Errorf("forta refused the event: %d", status))
			return
		default:
			r.sent.Add(1)
			return
		}
	}
	r.fail(ev.Action, errors.Join(errors.New("activity not delivered"), last))
}

func (r *Reporter) post(body []byte) (int, error) {
	req, err := http.NewRequest(http.MethodPost, r.endpoint, bytes.NewReader(body))
	if err != nil {
		return 0, err
	}
	req.Header.Set("Content-Type", "application/json")
	req.Header.Set("User-Agent", correlate.UserAgent)
	req.SetBasicAuth(r.cfg.ClientID, r.cfg.ClientSecret)
	res, err := r.client.Do(req)
	if err != nil {
		return 0, err
	}
	_ = res.Body.Close()
	return res.StatusCode, nil
}

func (r *Reporter) fail(action string, err error) {
	r.failed.Add(1)
	if r.cfg.OnError != nil {
		r.cfg.OnError(action, err)
	}
}

// normaliseAction lowercases, replaces anything outside [a-z0-9._-] with "_"
// and trims to Forta's limit: "Deploy Stack" → "deploy_stack".
func normaliseAction(a string) string {
	a = actionRE.ReplaceAllString(strings.ToLower(strings.TrimSpace(a)), "_")
	if len(a) > maxActionLen {
		a = a[:maxActionLen]
	}
	return strings.Trim(a, "_")
}

func trimDetails(in map[string]string) map[string]string {
	if len(in) == 0 {
		return nil
	}
	out := make(map[string]string, min(len(in), maxDetails))
	for k, v := range in {
		if len(out) == maxDetails {
			break
		}
		if len(k) > maxDetailKey {
			k = k[:maxDetailKey]
		}
		if len(v) > maxDetailVal {
			v = v[:maxDetailVal]
		}
		out[k] = v
	}
	return out
}
