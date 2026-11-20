package proxy

import (
	"context"
	"io"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"

	"github.com/NitinGavhane/proxyforge/internal/flows"
	"github.com/NitinGavhane/proxyforge/internal/pipeline"
	"github.com/NitinGavhane/proxyforge/internal/store"
	"github.com/NitinGavhane/proxyforge/internal/tags"
)

func TestTaggedOriginHighlightedInHistory(t *testing.T) {
	st, _ := store.Open(filepath.Join(t.TempDir(), "tg.pf.sqlite"))
	t.Cleanup(func() { st.Close() })
	tm := tags.New()
	eng := &Engine{
		Pipeline: pipeline.New(st, flows.NewBus(), nil),
		Tags:     tm,
	}
	proxySrv := httptest.NewServer(eng)
	t.Cleanup(proxySrv.Close)

	up := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(up.Close)

	client := &http.Client{
		Transport: &http.Transport{Proxy: http.ProxyURL(mustURL(t, proxySrv.URL))},
	}
	tm.Set(up.URL, 0) // tag the upstream origin (host:port)

	resp, err := client.Get(up.URL + "/tagged")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp.Body)
	resp.Body.Close()

	// untagged host stays plain
	other := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {}))
	t.Cleanup(other.Close)
	resp2, err := client.Get(other.URL + "/untagged")
	if err != nil {
		t.Fatal(err)
	}
	io.Copy(io.Discard, resp2.Body)
	resp2.Body.Close()

	rows, _ := st.ListFlows(context.Background(), store.Filter{})
	if len(rows) != 2 {
		t.Fatalf("rows = %d", len(rows))
	}
	byPath := map[string]store.FlowRow{}
	for _, r := range rows {
		byPath[r.Path] = r
	}
	if byPath["/tagged"].Highlight != "magenta" || byPath["/tagged"].Comment != "tagged via extension" {
		t.Errorf("tagged flow not marked: %+v", byPath["/tagged"])
	}
	if byPath["/untagged"].Highlight != "" {
		t.Errorf("untagged flow marked: %+v", byPath["/untagged"])
	}
}
