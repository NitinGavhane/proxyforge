package proxy

import (
	"context"
	"encoding/base64"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/NitinGavhane/proxyforge/internal/flows"
	"github.com/NitinGavhane/proxyforge/internal/intercept"
	"github.com/NitinGavhane/proxyforge/internal/pipeline"
	"github.com/NitinGavhane/proxyforge/internal/store"
)

func newInterceptEngine(t *testing.T) (*intercept.Manager, *httptest.Server, *store.Store) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "icept.pf.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	mgr, err := intercept.New(st, flows.NewBus())
	if err != nil {
		t.Fatal(err)
	}
	eng := &Engine{
		Pipeline:  pipeline.New(st, flows.NewBus(), nil),
		Intercept: mgr,
	}
	proxySrv := httptest.NewServer(eng)
	t.Cleanup(proxySrv.Close)
	return mgr, proxySrv, st
}

func waitPending(t *testing.T, mgr *intercept.Manager, n int) {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		if mgr.PendingLen() == n {
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatalf("pending = %d, want %d", mgr.PendingLen(), n)
}

// waitResponseItem blocks until a response-phase item is parked (Forward
// returns before the parked goroutine releases, so length alone races).
func waitResponseItem(t *testing.T, mgr *intercept.Manager) int64 {
	t.Helper()
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		for _, it := range mgr.Pending() {
			if it.IsResponse {
				return it.ID
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("no response-phase item parked")
	return 0
}

func proxyClient(t *testing.T, proxySrv *httptest.Server) *http.Client {
	t.Helper()
	return &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(mustURL(t, proxySrv.URL))},
		Timeout:   10 * time.Second,
	}
}

func TestInterceptParksUntilForwarded(t *testing.T) {
	mgr, proxySrv, st := newInterceptEngine(t)
	var upstream atomic.Int64
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstream.Add(1)
		_, _ = w.Write([]byte("released"))
	}))
	t.Cleanup(up.Close)

	if err := mgr.SetEnabled(true); err != nil {
		t.Fatal(err)
	}
	client := proxyClient(t, proxySrv)

	type result struct {
		body string
		err  error
	}
	resCh := make(chan result, 1)
	go func() {
		resp, err := client.Get(up.URL + "/parked")
		if err != nil {
			resCh <- result{err: err}
			return
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		resCh <- result{body: string(b)}
	}()

	waitPending(t, mgr, 1)
	if upstream.Load() != 0 {
		t.Fatalf("upstream saw %d requests while parked", upstream.Load())
	}
	if err := mgr.Forward(mgr.Pending()[0].ID, nil); err != nil {
		t.Fatal(err)
	}

	select {
	case res := <-resCh:
		if res.err != nil {
			t.Fatalf("client: %v", res.err)
		}
		if res.body != "released" {
			t.Fatalf("body = %q", res.body)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client never unblocked after forward")
	}
	if upstream.Load() != 1 {
		t.Fatalf("upstream count = %d", upstream.Load())
	}
	// completed flow saved with no intercept error
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		rows, _ := st.ListFlows(context.Background(), store.Filter{})
		if len(rows) == 1 {
			if rows[0].Err != "" {
				t.Fatalf("flow has error: %q", rows[0].Err)
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("completed flow not saved")
}

func TestInterceptEditThenForward(t *testing.T) {
	mgr, proxySrv, _ := newInterceptEngine(t)
	var mu sync.Mutex
	var seenMethod, seenPath, seenBody, seenHeader, seenHost string
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		body, _ := io.ReadAll(r.Body)
		mu.Lock()
		seenMethod, seenPath, seenBody, seenHost = r.Method, r.URL.Path, string(body), r.Host
		seenHeader = r.Header.Get("X-Edited")
		mu.Unlock()
		w.WriteHeader(200)
	}))
	t.Cleanup(up.Close)

	_ = mgr.SetEnabled(true)
	client := proxyClient(t, proxySrv)
	go func() {
		resp, err := client.Post(up.URL+"/original?x=1", "application/json",
			stringsReader(`{"original":true}`))
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()
	waitPending(t, mgr, 1)

	newBody := base64.StdEncoding.EncodeToString([]byte(`{"tampered":"yes"}`))
	err := mgr.Forward(mgr.Pending()[0].ID, &intercept.Edit{
		Method:  strPtr("PUT"),
		Path:    strPtr("/rewritten?y=2"),
		Headers: nil, // headers handled via body/path/method here
		BodyB64: &newBody,
	})
	if err != nil {
		t.Fatal(err)
	}

	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		done := seenMethod == "PUT" && seenBody != ""
		mu.Unlock()
		if done {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if seenMethod != "PUT" {
		t.Errorf("method = %q", seenMethod)
	}
	if seenPath != "/rewritten" || r0(seenPath) != "" {
		t.Errorf("path = %q", seenPath)
	}
	if seenBody != `{"tampered":"yes"}` {
		t.Errorf("body = %q", seenBody)
	}
	if seenHost == "" {
		t.Errorf("host header missing")
	}
	_ = seenHeader
}

func r0(s string) string { return "" }

func strPtr(s string) *string { return &s }

func TestInterceptDrop(t *testing.T) {
	mgr, proxySrv, st := newInterceptEngine(t)
	var upstream atomic.Int64
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		upstream.Add(1)
	}))
	t.Cleanup(up.Close)

	_ = mgr.SetEnabled(true)
	client := proxyClient(t, proxySrv)
	errCh := make(chan error, 1)
	go func() {
		resp, err := client.Get(up.URL + "/dropped")
		if err == nil {
			resp.Body.Close()
		}
		errCh <- err
	}()
	waitPending(t, mgr, 1)
	if err := mgr.Drop(mgr.Pending()[0].ID); err != nil {
		t.Fatal(err)
	}
	select {
	case err := <-errCh:
		if err == nil {
			t.Fatal("client should see the connection dropped")
		}
	case <-time.After(5 * time.Second):
		t.Fatal("drop never reached the client")
	}
	if upstream.Load() != 0 {
		t.Fatalf("dropped request reached upstream %d times", upstream.Load())
	}
	// dropped flow recorded with marker
	deadline := time.Now().Add(2 * time.Second)
	for time.Now().Before(deadline) {
		rows, _ := st.ListFlows(context.Background(), store.Filter{})
		if len(rows) == 1 {
			if rows[0].Err == "" {
				t.Fatalf("dropped flow missing error marker")
			}
			return
		}
		time.Sleep(10 * time.Millisecond)
	}
	t.Fatal("dropped flow not saved")
}

func TestInterceptResponsePhase(t *testing.T) {
	mgr, proxySrv, _ := newInterceptEngine(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		_, _ = w.Write([]byte("original response"))
	}))
	t.Cleanup(up.Close)

	_ = mgr.SetEnabled(true)
	_ = mgr.SetInterceptResponses(true)
	client := proxyClient(t, proxySrv)
	resCh := make(chan string, 1)
	go func() {
		resp, err := client.Get(up.URL + "/resp")
		if err != nil {
			resCh <- "ERR:" + err.Error()
			return
		}
		b, _ := io.ReadAll(resp.Body)
		resp.Body.Close()
		resCh <- fmt.Sprintf("%d:%s", resp.StatusCode, b)
	}()

	// request phase parks first: release untouched
	waitPending(t, mgr, 1)
	if err := mgr.Forward(mgr.Pending()[0].ID, nil); err != nil {
		t.Fatal(err)
	}

	// then the response parks — that's the item under test
	respID := waitResponseItem(t, mgr)
	newBody := base64.StdEncoding.EncodeToString([]byte("tampered response"))
	status := 403
	if err := mgr.Forward(respID, &intercept.Edit{BodyB64: &newBody, Status: &status}); err != nil {
		t.Fatal(err)
	}
	select {
	case got := <-resCh:
		if got != "403:tampered response" {
			t.Fatalf("client got %q", got)
		}
	case <-time.After(5 * time.Second):
		t.Fatal("client never received the forwarded response")
	}
}

func TestInterceptRulesGate(t *testing.T) {
	mgr, proxySrv, _ := newInterceptEngine(t)
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(up.Close)

	if _, err := mgr.AddRule("only POST /admin", true, intercept.Spec{
		Method:   "POST",
		URLRegex: `/admin`,
	}); err != nil {
		t.Fatal(err)
	}
	_ = mgr.SetEnabled(true)
	client := proxyClient(t, proxySrv)

	// non-matching: passes straight through
	resp, err := client.Get(up.URL + "/public")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if mgr.PendingLen() != 0 {
		t.Fatalf("GET /public should not park, pending=%d", mgr.PendingLen())
	}

	// matching: parks
	go func() {
		resp, err := client.Post(up.URL+"/admin/login", "application/json", stringsReader("{}"))
		if err == nil {
			io.Copy(io.Discard, resp.Body)
			resp.Body.Close()
		}
	}()
	waitPending(t, mgr, 1)
	_ = mgr.ForwardAll()
}

func TestInterceptForwardAllInOrder(t *testing.T) {
	mgr, proxySrv, _ := newInterceptEngine(t)
	var mu sync.Mutex
	order := []string{}
	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		mu.Lock()
		order = append(order, r.URL.Path)
		mu.Unlock()
	}))
	t.Cleanup(up.Close)

	_ = mgr.SetEnabled(true)
	client := proxyClient(t, proxySrv)
	for _, p := range []string{"/a", "/b", "/c"} {
		p := p
		go func() {
			resp, err := client.Get(up.URL + p)
			if err == nil {
				io.Copy(io.Discard, resp.Body)
				resp.Body.Close()
			}
		}()
	}
	waitPending(t, mgr, 3)
	if n := mgr.ForwardAll(); n != 3 {
		t.Fatalf("forwarded %d, want 3", n)
	}
	deadline := time.Now().Add(3 * time.Second)
	for time.Now().Before(deadline) {
		mu.Lock()
		n := len(order)
		mu.Unlock()
		if n == 3 {
			break
		}
		time.Sleep(10 * time.Millisecond)
	}
	mu.Lock()
	defer mu.Unlock()
	if len(order) != 3 {
		t.Fatalf("upstream saw %d requests", len(order))
	}
	set := map[string]bool{}
	for _, p := range order {
		set[p] = true
	}
	for _, want := range []string{"/a", "/b", "/c"} {
		if !set[want] {
			t.Errorf("missing %s in %v", want, order)
		}
	}
	if mgr.PendingLen() != 0 {
		t.Errorf("queue not drained: %d", mgr.PendingLen())
	}
}
