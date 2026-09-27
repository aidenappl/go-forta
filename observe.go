package forta

import (
	"context"
	"errors"
	"fmt"
	"log"
	"net/http"
	"net/url"

	"github.com/aidenappl/go-forta/internal/correlate"
)

// Version is this SDK's release version. It is sent to Forta as the
// User-Agent "go-forta/<Version>" on every outbound call.
const Version = correlate.Version

// WithCorrelation returns ctx carrying a request id and a trace id that go-forta
// forwards on every outbound call made with that context (X-Request-ID,
// X-Trace-ID and a W3C traceparent). Ids that are not a UUID or 8-64 hex
// characters — the shape monitor-core accepts — are dropped, never forwarded.
//
// Hosts that keep their ids under their own context key can set
// Config.Correlation instead; this is for hosts that would rather push ids in.
func WithCorrelation(ctx context.Context, requestID, traceID string) context.Context {
	return correlate.With(ctx, requestID, traceID)
}

// Reason values reported in AuthFailure.Reason. They are stable strings, safe to
// use as a metric label or an event name suffix.
const (
	// ReasonMissingCredential — no bearer token or access cookie, and no usable
	// refresh cookie.
	ReasonMissingCredential = "missing_credential"
	// ReasonTokenInvalid — a JWT failed validation for a reason other than
	// expiry (bad signature, wrong issuer, unknown kid, malformed), or /auth/self
	// rejected it with auto-refresh disabled.
	ReasonTokenInvalid = "token_invalid"
	// ReasonTokenExpired — the access token expired and no refresh was possible
	// (auto-refresh disabled, or no refresh cookie).
	ReasonTokenExpired = "token_expired"
	// ReasonRefreshFailed — a refresh was attempted and Forta rejected it.
	ReasonRefreshFailed = "refresh_failed"
	// ReasonAPITokenInvalid — an frt_ API token did not resolve.
	ReasonAPITokenInvalid = "api_token_invalid"
	// ReasonUpstreamUnavailable — Forta could not be reached or answered 5xx/429,
	// so the credential was never actually judged. The HTTP response is still
	// the same 401 it has always been; this reason exists so a host can tell an
	// outage from a bad credential.
	ReasonUpstreamUnavailable = "upstream_unavailable"
	// ReasonGrantDenied — Forta said the user holds no active grant for this
	// platform.
	ReasonGrantDenied = "grant_denied"
	// ReasonGrantCheckFailed — the grant check itself failed (transport error or
	// unexpected status). The request is denied (fail-closed) with the same 403
	// as a real denial.
	ReasonGrantCheckFailed = "grant_check_failed"
	// ReasonExchangeFailed — the authorization code could not be exchanged in
	// CallbackHandler.
	ReasonExchangeFailed = "exchange_failed"
	// ReasonCallbackInvalid — CallbackHandler/LoginHandler rejected the request
	// itself: an error from the authorization server, a missing code or state,
	// a missing or mismatched state cookie, or an unexpected Host.
	ReasonCallbackInvalid = "callback_invalid"
	// ReasonInternalError — the SDK could not complete the flow for a local
	// reason (e.g. generating the OAuth state failed).
	ReasonInternalError = "internal_error"
)

// AuthFailure describes why go-forta rejected a request. It is passed to
// Config.OnAuthFailure immediately before the error response is written.
type AuthFailure struct {
	// Reason is one of the Reason* constants.
	Reason string
	// Status is the HTTP status about to be written (401, 403, 400 or 500).
	Status int
	// Err is the underlying error, when there is one. It never contains a
	// token value.
	Err error
	// UpstreamRequestID is the X-Request-ID forta-api echoed on the failing
	// call, when the failure came from a Forta response. Search forta-api's
	// logs for it.
	UpstreamRequestID string
}

// UpstreamError is returned (wrapped) when forta-api answers with an
// unexpected status. Use errors.As on AuthFailure.Err to read it.
type UpstreamError struct {
	// Op names the call: "auth/self", "auth/refresh", "exchange", "grant check",
	// "ping", "jwks".
	Op string
	// Status is the HTTP status forta-api returned.
	Status int
	// RequestID is the X-Request-ID forta-api echoed on the response, if any.
	RequestID string

	msg string
}

func (e *UpstreamError) Error() string {
	if e.msg != "" {
		return e.msg
	}
	return fmt.Sprintf("go-forta: %s: forta returned status %d", e.Op, e.Status)
}

// newUpstreamError builds an UpstreamError from resp. msg, when non-empty, is
// the exact error text — kept identical to what each call returned before the
// type existed, so existing log lines do not change.
func newUpstreamError(op string, resp *http.Response, msg string) *UpstreamError {
	return &UpstreamError{
		Op:        op,
		Status:    resp.StatusCode,
		RequestID: resp.Header.Get(correlate.HeaderRequestID),
		msg:       msg,
	}
}

// isUpstreamUnavailable reports whether err means Forta did not give an answer
// about the credential at all: a transport failure (every error from
// http.Client.Do is a *url.Error) or a 5xx/429 response.
func isUpstreamUnavailable(err error) bool {
	if err == nil {
		return false
	}
	var ue *UpstreamError
	if errors.As(err, &ue) {
		return ue.Status >= 500 || ue.Status == http.StatusTooManyRequests
	}
	var urlErr *url.Error
	return errors.As(err, &urlErr)
}

// upstreamRequestID extracts the echoed forta-api request id from err.
func upstreamRequestID(err error) string {
	var ue *UpstreamError
	if errors.As(err, &ue) {
		return ue.RequestID
	}
	return ""
}

// do sends req with the correlation ids for its context applied. Ids come from
// Config.Correlation first, then from ids carried on the context (see
// WithCorrelation, and the inbound fallback in Protected).
func (c *Client) do(req *http.Request) (*http.Response, error) {
	c.applyCorrelation(req)
	return c.httpClient.Do(req)
}

func (c *Client) applyCorrelation(req *http.Request) {
	rid, tid := c.correlationIDs(req.Context())
	correlate.Apply(req, rid, tid)
}

func (c *Client) correlationIDs(ctx context.Context) (string, string) {
	var rid, tid string
	if c.cfg.Correlation != nil {
		rid, tid = c.cfg.Correlation(ctx)
	}
	crid, ctid := correlate.From(ctx)
	if !correlate.Valid(rid) {
		rid = crid
	}
	if !correlate.Valid(tid) {
		tid = ctid
	}
	return rid, tid
}

// withInboundCorrelation stashes correlation ids on r's context when it does not
// already carry them: first from the response headers a host request-id
// middleware set before calling us, then from the inbound request headers.
func withInboundCorrelation(w http.ResponseWriter, r *http.Request) *http.Request {
	var respHeader http.Header
	if w != nil {
		respHeader = w.Header()
	}
	ctx := correlate.FromInbound(r.Context(), respHeader, r)
	if ctx == r.Context() {
		return r
	}
	return r.WithContext(ctx)
}

// logf writes one log line through Config.Logf, defaulting to log.Printf.
func (c *Client) logf(format string, args ...any) {
	if c.cfg.Logf != nil {
		c.cfg.Logf(format, args...)
		return
	}
	log.Printf(format, args...)
}

// requestSuffix renders " request_id=… trace_id=…" for a log line, or "".
func (c *Client) requestSuffix(r *http.Request) string {
	rid, tid := c.correlationIDs(r.Context())
	s := ""
	if rid != "" {
		s += " request_id=" + rid
	}
	if tid != "" {
		s += " trace_id=" + tid
	}
	return s
}

// reportFailure calls Config.OnAuthFailure, if set. It must be called
// immediately before the error response is written, so the host sees the
// failure while it can still add headers or record the request.
func (c *Client) reportFailure(r *http.Request, reason string, status int, err error) {
	if c.cfg.OnAuthFailure == nil {
		return
	}
	c.cfg.OnAuthFailure(r, AuthFailure{
		Reason:            reason,
		Status:            status,
		Err:               err,
		UpstreamRequestID: upstreamRequestID(err),
	})
}

// fail reports an authentication failure and writes the JSON error response.
func (c *Client) fail(w http.ResponseWriter, r *http.Request, status int, message, reason string, err error) {
	c.reportFailure(r, reason, status, err)
	writeJSONError(w, status, message)
}

// failGrant reports a grant failure and writes the standard 403 4003 response.
func (c *Client) failGrant(w http.ResponseWriter, r *http.Request, reason string, err error) {
	c.reportFailure(r, reason, http.StatusForbidden, err)
	writeGrantDenied(w)
}

// errNoRefreshCookie is the AuthFailure.Err when a refresh was wanted but the
// request carried no refresh cookie.
var errNoRefreshCookie = errors.New("go-forta: no refresh cookie presented")
