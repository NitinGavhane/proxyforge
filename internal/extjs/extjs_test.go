package extjs

import (
	"context"
	"path/filepath"
	"testing"
	"time"

	"github.com/NitinGavhane/proxyforge/internal/flows"
	"github.com/NitinGavhane/proxyforge/internal/store"
)

func newExtEngine(t *testing.T) (*store.Store, *Manager) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "ext.pf.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	mgr, err := NewManager(st, nil)
	if err != nil {
		t.Fatal(err)
	}
	return st, mgr
}

func TestScriptErrorsRecordedNotFatal(t *testing.T) {
	st, mgr := newExtEngine(t)
	// throwing hook: recorded, applied-skip, no panic
	if _, err := mgr.Add(context.Background(), "thrower", `
		function onRequest(flow) { throw new Error("boom"); }
	`, true); err != nil {
		t.Fatal(err)
	}
	// syntax error rejected at save
	if _, err := mgr.Add(context.Background(), "broken", "function (", true); err == nil {
		t.Fatal("syntax error accepted")
	}
	// non-function hook rejected
	if _, err := mgr.Add(context.Background(), "notfn", `var onRequest = 42;`, true); err == nil {
		t.Fatal("non-function hook accepted")
	}

	f := &flows.Flow{Request: &flows.Request{Method: "GET", Host: "h", Port: 80, Path: "/"}}
	mgr.RunRequest(f) // must not panic

	exts, _ := st.ListExtensions(context.Background())
	if len(exts) != 1 {
		t.Fatalf("stored scripts = %d (only valid ones persist)", len(exts))
	}
	if exts[0].Runs != 1 || exts[0].Errors != 1 || exts[0].LastError == "" {
		t.Fatalf("stats not recorded: %+v", exts[0])
	}
}

func TestScriptTimeoutInterrupted(t *testing.T) {
	st, mgr := newExtEngine(t)
	if _, err := mgr.Add(context.Background(), "looper", `
		function onRequest(flow) { while (true) {} }
	`, true); err != nil {
		t.Fatal(err)
	}
	f := &flows.Flow{
		Request: &flows.Request{Method: "GET", Host: "h", Port: 80, Path: "/"},
	}
	started := time.Now()
	mgr.RunRequest(f)
	if elapsed := time.Since(started); elapsed > 5*time.Second {
		t.Fatalf("runaway script not interrupted in time: %v", elapsed)
	}
	exts, _ := st.ListExtensions(context.Background())
	if exts[0].LastError != "timeout after "+RunTimeout.String() {
		t.Fatalf("last error = %q", exts[0].LastError)
	}
	_ = st
}

func TestTruncatedBodyProtected(t *testing.T) {
	_, mgr := newExtEngine(t)
	if _, err := mgr.Add(context.Background(), "body", `
		function onRequest(flow) { flow.request.body = "replaced"; }
	`, true); err != nil {
		t.Fatal(err)
	}
	f := &flows.Flow{
		Request: &flows.Request{Method: "POST", Host: "h", Port: 80, Path: "/",
			Body: []byte("original"), BodyTrunc: true},
	}
	mgr.RunRequest(f)
	if string(f.Request.Body) != "original" {
		t.Fatalf("truncated body was edited: %q", f.Request.Body)
	}
}

func TestNoAmbientIO(t *testing.T) {
	// goja exposes pure ECMAScript: require/process/fetch are undefined, and
	// a script that probes for them runs without error
	_, mgr := newExtEngine(t)
	if _, err := mgr.Add(context.Background(), "io-check", `
		function onRequest(flow) {
			if (typeof require !== "undefined") throw new Error("require exists");
			if (typeof process !== "undefined") throw new Error("process exists");
			if (typeof fetch !== "undefined") throw new Error("fetch exists");
			if (typeof XMLHttpRequest !== "undefined") throw new Error("XHR exists");
		}
	`, true); err != nil {
		t.Fatal(err)
	}
	f := &flows.Flow{Request: &flows.Request{Method: "GET", Host: "h", Port: 80, Path: "/"}}
	mgr.RunRequest(f)
	exts, _ := mgr.List(context.Background())
	if exts[0].Errors != 0 {
		t.Fatalf("ambient IO unexpectedly available: %q", exts[0].LastError)
	}
}

func TestDisabledScriptInert(t *testing.T) {
	st, mgr := newExtEngine(t)
	id, err := mgr.Add(context.Background(), "off", `
		function onRequest(flow) { flow.request.path = "/rewritten"; }
	`, false)
	if err != nil {
		t.Fatal(err)
	}
	f := &flows.Flow{Request: &flows.Request{Method: "GET", Host: "h", Port: 80, Path: "/orig"}}
	mgr.RunRequest(f)
	if f.Request.Path != "/orig" {
		t.Fatal("disabled script ran")
	}
	// enable → applies
	if err := mgr.Update(context.Background(), id, nil, nil, boolPtr(true)); err != nil {
		t.Fatal(err)
	}
	mgr.RunRequest(f)
	if f.Request.Path != "/rewritten" {
		t.Fatalf("enabled script did not run: %q", f.Request.Path)
	}
	// code update resets stats
	if err := mgr.Update(context.Background(), id, nil, strPtr(`function onRequest(f){}`), nil); err != nil {
		t.Fatal(err)
	}
	exts, _ := st.ListExtensions(context.Background())
	if exts[0].Runs != 0 {
		t.Fatalf("stats not reset on code change: %+v", exts[0])
	}
}

func TestResponseHookAndContentLength(t *testing.T) {
	_, mgr := newExtEngine(t)
	if _, err := mgr.Add(context.Background(), "resp", `
		function onResponse(flow) {
			flow.response.body = "much longer replacement body";
		}
	`, true); err != nil {
		t.Fatal(err)
	}
	f := &flows.Flow{
		Request: &flows.Request{Method: "GET", Host: "h", Port: 80, Path: "/"},
		Response: &flows.Response{
			Status:  200,
			Headers: flows.Headers{{Key: "Content-Length", Value: "3"}},
			Body:    []byte("abc"),
		},
	}
	mgr.RunResponse(f)
	if string(f.Response.Body) != "much longer replacement body" {
		t.Fatalf("body: %q", f.Response.Body)
	}
	if v, _ := f.Response.Headers.Get("Content-Length"); v != "28" { // len("much longer replacement body")
		t.Fatalf("content-length = %q", v)
	}
}

func boolPtr(b bool) *bool    { return &b }
func strPtr(s string) *string { return &s }
