package proxy

import (
	"bytes"
	"context"
	"io"
	"log/slog"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/NitinGavhane/proxyforge/internal/flows"
	"github.com/NitinGavhane/proxyforge/internal/pipeline"
	"github.com/NitinGavhane/proxyforge/internal/store"
)

// newEngine spins up the engine as an httptest server (the "proxy") plus a
// pipeline backed by a temp store, and returns a client configured to use it.
func newEngine(t *testing.T) (*httptest.Server, *store.Store, *http.Client) {
	t.Helper()
	st, err := store.Open(t.TempDir() + "/e.pf.sqlite")
	if err != nil {
		t.Fatalf("store: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	bus := flows.NewBus()
	pipe := pipeline.New(st, bus, slog.Default())
	eng := &Engine{Pipeline: pipe}
	proxySrv := httptest.NewServer(eng)
	t.Cleanup(proxySrv.Close)
	proxyURL, _ := url.Parse(proxySrv.URL)
	client := &http.Client{
		Transport: &http.Transport{
			Proxy: http.ProxyURL(proxyURL),
		},
		Timeout: 10 * time.Second,
	}
	return proxySrv, st, client
}

func singleFlow(t *testing.T, st *store.Store) *flows.Flow {
	t.Helper()
	rows, err := st.ListFlows(context.Background(), store.Filter{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 1 {
		t.Fatalf("flows = %d, want 1", len(rows))
	}
	f, err := st.GetFlow(context.Background(), rows[0].ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	return f
}

func TestProxiedGETCaptured(t *testing.T) {
	_, st, client := newEngine(t)
	var seenHeaders http.Header
	var seenPath string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		seenHeaders = r.Header.Clone()
		seenPath = r.URL.RequestURI()
		w.Header().Set("X-Upstream", "yes")
		w.WriteHeader(200)
		_, _ = w.Write([]byte("hello from upstream"))
	}))
	t.Cleanup(up.Close)

	resp, err := client.Get(up.URL + "/thing?x=1")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if string(body) != "hello from upstream" {
		t.Fatalf("client body = %q", body)
	}
	if resp.Header.Get("X-Upstream") != "yes" {
		t.Fatalf("client missing upstream header")
	}

	f := singleFlow(t, st)
	if f.Request.Method != "GET" || f.Request.Path != "/thing?x=1" {
		t.Errorf("request: %+v", f.Request)
	}
	if !strings.Contains(f.Request.URL(), up.URL[len("http://"):]) && f.Request.Host == "" {
		t.Errorf("host capture failed: %+v", f.Request)
	}
	if seenPath != "/thing?x=1" {
		t.Errorf("upstream saw path %q", seenPath)
	}
	if ua, _ := f.Request.Headers.Get("User-Agent"); ua == "" && seenHeaders.Get("User-Agent") == "" {
		t.Errorf("user agent lost")
	}
	if f.Response == nil || f.Response.Status != 200 {
		t.Fatalf("response: %+v", f.Response)
	}
	if string(f.Response.Body) != "hello from upstream" {
		t.Errorf("captured body = %q", f.Response.Body)
	}
	if f.Err != "" {
		t.Errorf("flow error: %q", f.Err)
	}
	if f.Origin != flows.OriginProxy {
		t.Errorf("origin = %q", f.Origin)
	}
	if f.DurationMS < 0 {
		t.Errorf("negative duration")
	}
}

func TestProxiedPOSTBodyCaptured(t *testing.T) {
	_, st, client := newEngine(t)
	var upBody []byte
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upBody, _ = io.ReadAll(r.Body)
		w.WriteHeader(201)
	}))
	t.Cleanup(up.Close)

	payload := `{"username":"admin","password":"hunter2"}`
	resp, err := client.Post(up.URL+"/api/login", "application/json", strings.NewReader(payload))
	if err != nil {
		t.Fatalf("post: %v", err)
	}
	resp.Body.Close()

	f := singleFlow(t, st)
	if string(f.Request.Body) != payload {
		t.Errorf("captured req body = %q", f.Request.Body)
	}
	if string(upBody) != payload {
		t.Errorf("upstream saw body = %q", upBody)
	}
	if f.Response.Status != 201 {
		t.Errorf("status = %d", f.Response.Status)
	}
}

func TestHopByHopStrippedUpstream(t *testing.T) {
	_, st, client := newEngine(t)
	var gotConn, gotProxyConn, gotCustom string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		gotConn = r.Header.Get("Connection")
		gotProxyConn = r.Header.Get("Proxy-Connection")
		gotCustom = r.Header.Get("X-Custom")
	}))
	t.Cleanup(up.Close)

	req, _ := http.NewRequest("GET", up.URL+"/", nil)
	req.Header.Set("Proxy-Connection", "keep-alive")
	req.Header.Set("Connection", "close")
	req.Header.Set("X-Custom", "kept")
	resp, err := client.Do(req)
	if err != nil {
		t.Fatalf("do: %v", err)
	}
	resp.Body.Close()

	if gotProxyConn != "" || gotConn != "" {
		t.Errorf("hop-by-hop forwarded: proxy-conn=%q conn=%q", gotProxyConn, gotConn)
	}
	if gotCustom != "kept" {
		t.Errorf("end-to-end header dropped: %q", gotCustom)
	}
	f := singleFlow(t, st)
	// captured flow records what the CLIENT sent (fidelity), stripped only in transit
	if _, ok := f.Request.Headers.Get("Proxy-Connection"); !ok {
		t.Errorf("capture should record Proxy-Connection even though it is not forwarded")
	}
}

func TestUpstreamErrorFlowRecorded(t *testing.T) {
	_, st, client := newEngine(t)
	// dead upstream: reserved port with no listener
	resp, err := client.Get("http://127.0.0.1:1/nope")
	if err == nil {
		resp.Body.Close()
	}
	// the client surfaces the proxy's 502 as an error or a 502 response
	f := singleFlow(t, st)
	if f.Err == "" {
		t.Fatalf("expected recorded error, got %+v", f)
	}
	if !strings.Contains(f.Err, "upstream") {
		t.Errorf("unexpected err text: %q", f.Err)
	}
	if f.Response != nil {
		t.Errorf("no response expected on error flow: %+v", f.Response)
	}
}

func TestStatusCodesAndMethods(t *testing.T) {
	_, st, client := newEngine(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.Method {
		case "DELETE":
			w.WriteHeader(204)
		case "PUT":
			w.WriteHeader(403)
			_, _ = w.Write([]byte("denied"))
		default:
			w.WriteHeader(500)
		}
	}))
	t.Cleanup(up.Close)

	for _, m := range []string{"DELETE", "PUT"} {
		req, _ := http.NewRequest(m, up.URL+"/x", nil)
		resp, err := client.Do(req)
		if err != nil {
			t.Fatalf("%s: %v", m, err)
		}
		io.Copy(io.Discard, resp.Body)
		resp.Body.Close()
	}
	rows, err := st.ListFlows(context.Background(), store.Filter{})
	if err != nil {
		t.Fatalf("list: %v", err)
	}
	if len(rows) != 2 {
		t.Fatalf("rows = %d", len(rows))
	}
	// newest first → PUT (403) then DELETE (204)
	if rows[0].Status != 403 || rows[1].Status != 204 {
		t.Errorf("statuses = %d,%d", rows[0].Status, rows[1].Status)
	}
}

func TestBigResponseBodyTruncated(t *testing.T) {
	_, st, client := newEngine(t)
	big := bytes.Repeat([]byte("z"), flows.MaxBodyBytes+1024)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write(big) // no explicit Content-Length → chunked
	}))
	t.Cleanup(up.Close)

	resp, err := client.Get(up.URL + "/big")
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	got, _ := io.ReadAll(resp.Body)
	resp.Body.Close()

	f := singleFlow(t, st)
	if !f.Truncated || !f.Response.BodyTrunc {
		t.Fatalf("truncation flags not set: flow=%v resp=%v", f.Truncated, f.Response.BodyTrunc)
	}
	if len(f.Response.Body) != flows.MaxBodyBytes {
		t.Errorf("captured len = %d", len(f.Response.Body))
	}
	if len(got) != flows.MaxBodyBytes {
		t.Errorf("client received %d bytes (expected truncated delivery)", len(got))
	}
}

func TestConnectRefusedClearly(t *testing.T) {
	_, _, client := newEngine(t)
	// https target → client sends CONNECT; engine must refuse with 502, not hang
	_, err := client.Get("https://example.invalid/")
	if err == nil {
		t.Fatal("expected error on CONNECT refusal")
	}
}

func TestConcurrentRequestsAllCaptured(t *testing.T) {
	_, st, client := newEngine(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		time.Sleep(5 * time.Millisecond)
		_, _ = w.Write([]byte("ok"))
	}))
	t.Cleanup(up.Close)

	const n = 40
	var wg sync.WaitGroup
	for i := 0; i < n; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			resp, err := client.Get(up.URL + "/c")
			if err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}()
	}
	wg.Wait()
	deadline := time.Now().Add(2 * time.Second)
	for {
		cnt, _ := st.CountFlows(context.Background())
		if cnt == n || time.Now().After(deadline) {
			if cnt != n {
				t.Fatalf("captured %d/%d flows", cnt, n)
			}
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
}
