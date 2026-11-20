package tools

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"net/url"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/NitinGavhane/proxyforge/internal/flows"
	"github.com/NitinGavhane/proxyforge/internal/store"
)

// session-aware origin: /login sets a session cookie; /data requires it.
func newSessionOrigin(t *testing.T) *httptest.Server {
	t.Helper()
	sessions := map[string]bool{}
	return httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		cookie := r.Header.Get("Cookie")
		hasSession := strings.Contains(cookie, "sid=")
		switch r.URL.Path {
		case "/login":
			token := fmt.Sprintf("tok-%d", time.Now().UnixNano())
			sessions[token] = true
			w.Header().Set("Set-Cookie",
				"sid="+token+"; Path=/; HttpOnly; SameSite=Strict")
			w.Write([]byte(`{"ok":true}`))
		case "/data":
			if !hasSession {
				w.WriteHeader(401)
				w.Write([]byte(`{"err":"unauthorized"}`))
				return
			}
			w.Write([]byte(`{"secret":"session-data"}`))
		default:
			w.Write([]byte("ok"))
		}
	}))
}

func TestCookieJarCapturedFromProxyTraffic(t *testing.T) {
	eng, st := newEngine(t)
	up := newSessionOrigin(t)
	t.Cleanup(up.Close)

	// login through the proxy → Set-Cookie captured into the jar
	client := &http.Client{
		Transport: proxyOf(t, eng),
	}
	resp, err := client.Post(up.URL+"/login", "application/json", strings.NewReader("{}"))
	if err != nil {
		t.Fatal(err)
	}
	resp.Body.Close()
	time.Sleep(150 * time.Millisecond)

	host, port := hostPort(t, up.URL)
	cs, err := st.JarCookies(context.Background(), host, port)
	if err != nil || len(cs) != 1 {
		t.Fatalf("jar: %v %+v", err, cs)
	}
	if cs[0].Name != "sid" || !strings.HasPrefix(cs[0].Value, "tok-") ||
		!cs[0].HTTPOnly || cs[0].SameSite != "strict" {
		t.Fatalf("cookie: %+v", cs[0])
	}
}

func TestRepeaterUsesJar(t *testing.T) {
	eng, st := newEngine(t)
	up := newSessionOrigin(t)
	t.Cleanup(up.Close)
	host, port := hostPort(t, up.URL)

	// seed the jar via the proxy login
	client := &http.Client{Transport: proxyOf(t, eng)}
	resp, _ := client.Post(up.URL+"/login", "application/json", strings.NewReader("{}"))
	resp.Body.Close()
	time.Sleep(150 * time.Millisecond)

	rep := NewRepeater(st, eng)
	tab, _ := rep.NewTab(context.Background(), "jar", "")
	raw := fmt.Sprintf("GET /data HTTP/1.1\nHost: %s:%d\n", host, port)

	// without the jar → 401
	res, err := rep.SendOpts(context.Background(), tab, raw, false, 1, SendOptions{})
	if err != nil {
		t.Fatal(err)
	}
	if res.Final.Response.Status != 401 {
		t.Fatalf("no-jar status = %d", res.Final.Response.Status)
	}

	// with the jar → 200 + secret
	res, err = rep.SendOpts(context.Background(), tab, raw, false, 1, SendOptions{UseJar: true})
	if err != nil {
		t.Fatal(err)
	}
	if res.Final.Response.Status != 200 || !strings.Contains(string(res.Final.Response.Body), "session-data") {
		t.Fatalf("jar status = %d body = %s", res.Final.Response.Status, res.Final.Response.Body)
	}
}

func TestMacroRefreshOn401(t *testing.T) {
	eng, st := newEngine(t)
	up := newSessionOrigin(t)
	t.Cleanup(up.Close)
	host, port := hostPort(t, up.URL)

	// capture a login flow through the proxy (macro source)
	client := &http.Client{Transport: proxyOf(t, eng)}
	resp, _ := client.Post(up.URL+"/login", "application/json", strings.NewReader("{}"))
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()
	time.Sleep(150 * time.Millisecond)
	rows, _ := st.ListFlows(context.Background(), store.Filter{})
	var loginFlow int64
	for _, r := range rows {
		if r.Path == "/login" {
			loginFlow = r.ID
		}
	}
	if loginFlow == 0 {
		t.Fatal("login flow not captured")
	}
	// stale the jar deliberately (bogus cookie value) so the macro must fix it
	// — simulate by sending with jar off first would 401; instead prove the
	// refresh path: clear the jar.
	if err := clearJar(t, st, host, port); err != nil {
		t.Fatal(err)
	}

	rep := NewRepeater(st, eng)
	tab, _ := rep.NewTab(context.Background(), "macro", "")
	raw := fmt.Sprintf("GET /data HTTP/1.1\nHost: %s:%d\n", host, port)

	res, err := rep.SendOpts(context.Background(), tab, raw, false, 1, SendOptions{
		UseJar:      true,
		MacroFlowID: loginFlow,
	})
	if err != nil {
		t.Fatal(err)
	}
	if res.Final.Response.Status != 200 || !strings.Contains(string(res.Final.Response.Body), "session-data") {
		t.Fatalf("macro refresh failed: status=%d body=%s",
			res.Final.Response.Status, res.Final.Response.Body)
	}
	// hops: 401 attempt, macro login, retried request
	if len(res.Hops) != 3 {
		t.Fatalf("hops = %d (want 3: 401 → login → retry)", len(res.Hops))
	}
}

func proxyOf(t *testing.T, eng interface {
	ServeHTTP(http.ResponseWriter, *http.Request)
}) *http.Transport {
	t.Helper()
	srv := httptest.NewServer(eng)
	t.Cleanup(srv.Close)
	u := mustParseURL(srv.URL)
	return &http.Transport{Proxy: http.ProxyURL(u)}
}

func mustParseURL(raw string) *url.URL {
	u, err := url.Parse(raw)
	if err != nil {
		panic(err)
	}
	return u
}

func hostPort(t *testing.T, raw string) (string, int) {
	t.Helper()
	u := mustParseURL(raw)
	port, _ := strconv.Atoi(u.Port())
	return u.Hostname(), port
}

func clearJar(t *testing.T, st *store.Store, host string, port int) error {
	t.Helper()
	// no direct API; delete via a deletion Set-Cookie through a captured flow
	f := &flows.Flow{
		Started: time.Now(), Origin: flows.OriginProxy,
		Request:  &flows.Request{Method: "GET", Scheme: "http", Host: host, Port: port, Path: "/clear"},
		Response: &flows.Response{Status: 200, Headers: flows.Headers{{Key: "Set-Cookie", Value: "sid=; Path=/; Max-Age=0"}}},
	}
	return st.CaptureCookies(context.Background(), f)
}
