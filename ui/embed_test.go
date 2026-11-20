package ui

import (
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
)

func TestHandlerServesAppOrPlaceholder(t *testing.T) {
	h := Handler()
	srv := httptest.NewServer(h)
	defer srv.Close()

	resp, err := http.Get(srv.URL + "/")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	buf := make([]byte, 4096)
	n, _ := resp.Body.Read(buf)
	body := string(buf[:n])

	if IsBuilt() {
		if !strings.Contains(body, `<div id="root">`) {
			t.Errorf("built UI should serve the app shell: %q", body[:min(n, 200)])
		}
	} else {
		if !strings.Contains(body, "pf-ui-placeholder") || !strings.Contains(body, "not built") {
			t.Errorf("placeholder not served: %q", body[:min(n, 200)])
		}
	}
}

func TestSPAFallback(t *testing.T) {
	if !IsBuilt() {
		t.Skip("no built UI in this binary")
	}
	srv := httptest.NewServer(Handler())
	defer srv.Close()
	resp, err := http.Get(srv.URL + "/some/spa/route")
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	if resp.StatusCode != 200 {
		t.Fatalf("SPA fallback status = %d", resp.StatusCode)
	}
}
