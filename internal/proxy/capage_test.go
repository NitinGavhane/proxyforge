package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/NitinGavhane/proxyforge/internal/ca"
	"github.com/NitinGavhane/proxyforge/internal/flows"
	"github.com/NitinGavhane/proxyforge/internal/intercept"
	"github.com/NitinGavhane/proxyforge/internal/pipeline"
	"github.com/NitinGavhane/proxyforge/internal/scope"
	"github.com/NitinGavhane/proxyforge/internal/store"
)

func newIceptForTest(st *store.Store, bus *flows.Bus) (*intercept.Manager, error) {
	return intercept.New(st, bus)
}

func newScopeForTest(st *store.Store, bus *flows.Bus) (*scope.Manager, error) {
	return scope.New(st, bus)
}

var _ = ca.Load

func newCAPageEngine(t *testing.T) (*httptest.Server, *store.Store, *caRootPEM) {
	t.Helper()
	st, err := store.Open(filepath.Join(t.TempDir(), "cap.pf.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	authority := newAuthority(t)
	eng := &Engine{
		Pipeline: pipeline.New(st, flows.NewBus(), nil),
		CA:       authority,
	}
	proxySrv := httptest.NewServer(eng)
	t.Cleanup(proxySrv.Close)
	return proxySrv, st, &caRootPEM{pem: string(authority.RootPEM())}
}

type caRootPEM struct{ pem string }

func TestProxyLocalServesCAPage(t *testing.T) {
	proxySrv, st, root := newCAPageEngine(t)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(mustURL(t, proxySrv.URL))},
	}

	// the page
	resp, err := client.Get("http://proxy.local/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	page := string(body)
	if !strings.Contains(page, "ProxyForge") || !strings.Contains(page, "proxyforge-root-ca.pem") {
		t.Fatalf("CA page malformed: %.200s", page)
	}
	if strings.Contains(page, "Bearer ") {
		t.Fatal("CA page must never leak the API token")
	}

	// browser-specific highlight via UA
	req, _ := http.NewRequest("GET", "http://proxy.local/", nil)
	req.Header.Set("User-Agent", "Mozilla/5.0 Firefox/128.0")
	resp2, err := client.Do(req)
	if err != nil {
		t.Fatal(err)
	}
	body2, _ := io.ReadAll(resp2.Body)
	resp2.Body.Close()
	if !strings.Contains(string(body2), "Firefox ← your browser") {
		t.Error("UA-based highlight missing")
	}

	// the cert
	resp3, err := client.Get("http://proxy.local/ca.pem")
	if err != nil {
		t.Fatal(err)
	}
	pem, _ := io.ReadAll(resp3.Body)
	resp3.Body.Close()
	if string(pem) != root.pem {
		t.Fatalf("/ca.pem does not serve the root: %.80s", pem)
	}
	if resp3.Header.Get("Content-Type") != "application/x-pem-file" {
		t.Errorf("content-type = %q", resp3.Header.Get("Content-Type"))
	}

	// health
	resp4, err := client.Get("http://proxy.local/health")
	if err != nil {
		t.Fatal(err)
	}
	hb, _ := io.ReadAll(resp4.Body)
	resp4.Body.Close()
	if !strings.Contains(string(hb), `"ok":true`) {
		t.Errorf("health = %s", hb)
	}

	// virtual-host traffic is never logged
	if n, _ := st.CountFlows(context.Background()); n != 0 {
		t.Fatalf("proxy.local traffic was logged: %d rows", n)
	}
}

func TestProxyLocalUnknownPath404(t *testing.T) {
	proxySrv, _, _ := newCAPageEngine(t)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(mustURL(t, proxySrv.URL))},
	}
	resp, err := client.Get("http://proxy.local/nope")
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	if resp.StatusCode != http.StatusNotFound {
		t.Fatalf("status = %d", resp.StatusCode)
	}
}

func TestProxyLocalWithoutCA(t *testing.T) {
	st, _ := store.Open(filepath.Join(t.TempDir(), "cap2.pf.sqlite"))
	t.Cleanup(func() { st.Close() })
	eng := &Engine{Pipeline: pipeline.New(st, flows.NewBus(), nil)} // no CA
	proxySrv := httptest.NewServer(eng)
	t.Cleanup(proxySrv.Close)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(mustURL(t, proxySrv.URL))},
	}
	resp, err := client.Get("http://proxy.local/")
	if err != nil {
		t.Fatal(err)
	}
	body, _ := io.ReadAll(resp.Body)
	resp.Body.Close()
	if !strings.Contains(string(body), "no CA loaded") {
		t.Error("missing no-CA warning")
	}
	resp2, _ := client.Get("http://proxy.local/ca.pem")
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusServiceUnavailable {
		t.Errorf("ca.pem without CA = %d", resp2.StatusCode)
	}
}

func TestProxyLocalNotInterceptedOrScoped(t *testing.T) {
	// proxy.local must be served even with intercept on + tight scope
	st, _ := store.Open(filepath.Join(t.TempDir(), "cap3.pf.sqlite"))
	t.Cleanup(func() { st.Close() })
	bus := flows.NewBus()
	authority := newAuthority(t)
	icept, err := newIceptForTest(st, bus)
	if err != nil {
		t.Fatal(err)
	}
	sc, err := newScopeForTest(st, bus)
	if err != nil {
		t.Fatal(err)
	}
	if err := icept.SetEnabled(true); err != nil {
		t.Fatal(err)
	}
	if _, err := sc.Add("include", `^https://only-this\.example`, true); err != nil {
		t.Fatal(err)
	}
	eng := &Engine{
		Pipeline:  pipeline.New(st, bus, nil),
		CA:        authority,
		Intercept: icept,
		Scope:     sc,
	}
	proxySrv := httptest.NewServer(eng)
	t.Cleanup(proxySrv.Close)
	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(mustURL(t, proxySrv.URL))},
	}
	resp, err := client.Get("http://proxy.local/health")
	if err != nil {
		t.Fatalf("proxy.local blocked by scope/intercept: %v", err)
	}
	resp.Body.Close()
	if icept.PendingLen() != 0 {
		t.Error("proxy.local must never park in the intercept queue")
	}
}
