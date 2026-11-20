package api

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/NitinGavhane/proxyforge/internal/flows"
	"github.com/NitinGavhane/proxyforge/internal/store"
	"github.com/NitinGavhane/proxyforge/internal/tags"
)

func TestAnnotateTabEndpoint(t *testing.T) {
	st, err := store.Open(t.TempDir() + "/tabs.pf.sqlite")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { st.Close() })
	bus := flows.NewBus()
	tm := tags.New()
	s := &Server{Store: st, Bus: bus, Token: "testtoken123", Started: time.Now(), Tags: tm}
	srv := httptest.NewServer(s.Handler())
	t.Cleanup(srv.Close)

	// tag an origin
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/annotate-tab",
		strings.NewReader(`{"origin":"https://api.example.com:8443","minutes":5}`))
	req.Header.Set("Content-Type", "application/json")
	resp, err := http.DefaultClient.Do(bearer(req, "testtoken123"))
	if err != nil {
		t.Fatal(err)
	}
	defer resp.Body.Close()
	var out struct {
		Origin string                   `json:"origin"`
		Active map[string]time.Duration `json:"active"`
	}
	if err := json.NewDecoder(resp.Body).Decode(&out); err != nil {
		t.Fatal(err)
	}
	if out.Origin != "api.example.com:8443" {
		t.Fatalf("origin = %q", out.Origin)
	}
	if !tm.Match("api.example.com:8443") {
		t.Fatal("tag not live")
	}

	// auth + audit
	req2, _ := http.NewRequest("POST", srv.URL+"/api/v1/annotate-tab",
		strings.NewReader(`{"origin":"x"}`))
	req2.Header.Set("Content-Type", "application/json")
	resp2, _ := http.DefaultClient.Do(req2)
	resp2.Body.Close()
	if resp2.StatusCode != http.StatusUnauthorized {
		t.Fatalf("unauthenticated tag status = %d", resp2.StatusCode)
	}
	req3, _ := http.NewRequest("GET", srv.URL+"/api/v1/audit.jsonl", nil)
	resp3, _ := http.DefaultClient.Do(bearer(req3, "testtoken123"))
	body, _ := io.ReadAll(resp3.Body)
	resp3.Body.Close()
	if !strings.Contains(string(body), "tab.tag") {
		t.Error("tag not audited")
	}
	_ = fmt.Sprint()
}
