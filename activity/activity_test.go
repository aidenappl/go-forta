package activity

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNilReporterIsSafe(t *testing.T) {
	r := New(Config{}) // unconfigured → nil *Reporter
	r.Report("sub", "x", Success, nil)
	r.Close(context.Background())
	if s, d, f := r.Stats(); s+d+f != 0 {
		t.Fatal("nil reporter counted something")
	}
}

func TestDeliversWithBasicAuthAndNormalises(t *testing.T) {
	var mu sync.Mutex
	var got []event
	var user, pass string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		if req.URL.Path != "/internal/activity" {
			t.Errorf("path = %s", req.URL.Path)
		}
		user, pass, _ = req.BasicAuth()
		var e event
		_ = json.NewDecoder(req.Body).Decode(&e)
		mu.Lock()
		got = append(got, e)
		mu.Unlock()
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()

	r := New(Config{APIURL: srv.URL + "/", ClientID: "cid", ClientSecret: "csec"})
	r.Report("u-1", "Deploy Stack!", "weird", map[string]string{"stack_id": "22", strings.Repeat("k", 40): strings.Repeat("v", 300)})
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	r.Close(ctx)

	if user != "cid" || pass != "csec" {
		t.Errorf("basic auth = %q/%q", user, pass)
	}
	if len(got) != 1 || got[0].Action != "deploy_stack" || got[0].Outcome != Success || got[0].Subject != "u-1" {
		t.Fatalf("got %+v", got)
	}
	for k, v := range got[0].Details {
		if len(k) > maxDetailKey || len(v) > maxDetailVal {
			t.Errorf("detail not trimmed: %d/%d", len(k), len(v))
		}
	}
	if s, _, _ := r.Stats(); s != 1 {
		t.Errorf("sent = %d", s)
	}
}

func TestEndpointOverridesAPIURL(t *testing.T) {
	var path string
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, req *http.Request) {
		path = req.URL.Path
		w.WriteHeader(http.StatusCreated)
	}))
	defer srv.Close()
	r := New(Config{APIURL: "http://unused.invalid", Endpoint: srv.URL + "/sink", ClientID: "a", ClientSecret: "b"})
	r.Report("u", "x", Success, nil)
	r.Close(context.Background())
	if path != "/sink" {
		t.Fatalf("path = %q", path)
	}
}

func TestRefusalIsNotRetriedAndReported(t *testing.T) {
	calls := 0
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		calls++
		w.WriteHeader(http.StatusForbidden)
	}))
	defer srv.Close()
	var errs []string
	r := New(Config{APIURL: srv.URL, ClientID: "a", ClientSecret: "b", OnError: func(a string, _ error) { errs = append(errs, a) }})
	r.Report("u", "secret.reveal", Success, nil)
	r.Close(context.Background())
	if calls != 1 || len(errs) != 1 {
		t.Fatalf("calls=%d errs=%v", calls, errs)
	}
}

func TestFullQueueDropsInsteadOfBlocking(t *testing.T) {
	block := make(chan struct{})
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) { <-block }))
	defer srv.Close()
	defer close(block)
	r := New(Config{APIURL: srv.URL, ClientID: "a", ClientSecret: "b", QueueSize: 2})
	done := make(chan struct{})
	go func() {
		for i := 0; i < 50; i++ {
			r.Report("u", "x", Success, nil)
		}
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(time.Second):
		t.Fatal("Report blocked on a full queue")
	}
	if _, d, _ := r.Stats(); d == 0 {
		t.Error("expected drops")
	}
}
