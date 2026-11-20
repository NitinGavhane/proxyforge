package store

import (
	"bytes"
	"context"
	"encoding/base64"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NitinGavhane/proxyforge/internal/flows"
)

func newTestStore(t *testing.T) *Store {
	t.Helper()
	path := filepath.Join(t.TempDir(), "test.pf.sqlite")
	st, err := Open(path)
	if err != nil {
		t.Fatalf("open: %v", err)
	}
	t.Cleanup(func() { st.Close() })
	return st
}

func testFlow() *flows.Flow {
	now := time.Now().Truncate(time.Millisecond)
	return &flows.Flow{
		Started:    now,
		Finished:   now.Add(50 * time.Millisecond),
		DurationMS: 50,
		ClientAddr: "127.0.0.1",
		ServerAddr: "upstream.test:80",
		Origin:     flows.OriginProxy,
		InScope:    true,
		Request: &flows.Request{
			Method:      "POST",
			Scheme:      "http",
			Host:        "upstream.test",
			Port:        80,
			Path:        "/login?redirect=/home",
			HTTPVersion: "HTTP/1.1",
			Headers: flows.Headers{
				{Key: "Host", Value: "upstream.test"},
				{Key: "Content-Type", Value: "application/json"},
				{Key: "X-Session", Value: "s1"},
				{Key: "X-Session", Value: "s2"},
			},
			Body: []byte(`{"u":"admin","p":"secret"}`),
		},
		Response: &flows.Response{
			Status:      302,
			StatusText:  "Found",
			HTTPVersion: "HTTP/1.1",
			Headers:     flows.Headers{{Key: "Set-Cookie", Value: "sid=abc"}, {Key: "Set-Cookie", Value: "sid2=def"}},
			Body:        []byte("moved"),
		},
	}
}

func TestInsertGetRoundTrip(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	f := testFlow()
	if err := st.InsertFlow(ctx, f); err != nil {
		t.Fatalf("insert: %v", err)
	}
	if f.ID == 0 {
		t.Fatal("ID not assigned")
	}
	got, err := st.GetFlow(ctx, f.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Request.Method != "POST" || got.Request.Path != "/login?redirect=/home" {
		t.Errorf("request mismatch: %+v", got.Request)
	}
	if got.Request.Host != "upstream.test" || got.Request.Scheme != "http" {
		t.Errorf("host/scheme mismatch: %+v", got.Request)
	}
	if string(got.Request.Body) != `{"u":"admin","p":"secret"}` {
		t.Errorf("req body mismatch: %q", got.Request.Body)
	}
	if len(got.Request.Headers) != 4 {
		t.Errorf("req headers = %+v", got.Request.Headers)
	}
	if got.Response == nil || got.Response.Status != 302 || got.Response.StatusText != "Found" {
		t.Fatalf("response mismatch: %+v", got.Response)
	}
	if len(got.Response.Headers) != 2 || got.Response.Headers[1].Value != "sid2=def" {
		t.Errorf("resp headers lost order/multi: %+v", got.Response.Headers)
	}
	if string(got.Response.Body) != "moved" {
		t.Errorf("resp body: %q", got.Response.Body)
	}
	if got.DurationMS != 50 {
		t.Errorf("duration = %d", got.DurationMS)
	}
	if got.Origin != flows.OriginProxy {
		t.Errorf("origin = %q", got.Origin)
	}
}

func TestGetFlowNoResponse(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	f := testFlow()
	f.Response = nil
	f.Err = "upstream: connection refused"
	if err := st.InsertFlow(ctx, f); err != nil {
		t.Fatalf("insert: %v", err)
	}
	got, err := st.GetFlow(ctx, f.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if got.Response != nil {
		t.Fatalf("expected nil response, got %+v", got.Response)
	}
	if got.Err != "upstream: connection refused" {
		t.Errorf("err = %q", got.Err)
	}
}

func TestListFiltersAndSort(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	mk := func(method, host, path string, status int, delta time.Duration) *flows.Flow {
		f := testFlow()
		f.Request.Method = method
		f.Request.Host = host
		f.Request.Path = path
		f.Started = time.Now().Add(delta)
		if f.Response != nil {
			f.Response.Status = status
		}
		return f
	}
	for _, f := range []*flows.Flow{
		mk("GET", "a.test", "/one", 200, 0),
		mk("POST", "a.test", "/two", 404, time.Second),
		mk("GET", "b.test", "/three", 500, 2*time.Second),
	} {
		if err := st.InsertFlow(ctx, f); err != nil {
			t.Fatalf("insert: %v", err)
		}
	}
	cases := []struct {
		name  string
		f     Filter
		hosts []string
	}{
		{"host filter", Filter{Host: "b.test"}, []string{"b.test"}},
		{"method filter", Filter{Method: "post"}, []string{"a.test"}},
		{"status exact", Filter{Status: "404"}, []string{"a.test"}},
		{"status class", Filter{Status: "5xx"}, []string{"b.test"}},
		{"search path", Filter{Search: "three"}, []string{"b.test"}},
		{"query one", Filter{Query: "two"}, []string{"a.test"}},
		{"query multi", Filter{Query: "a.test two"}, []string{"a.test"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			rows, err := st.ListFlows(ctx, tc.f)
			if err != nil {
				t.Fatalf("list: %v", err)
			}
			if len(rows) != len(tc.hosts) {
				t.Fatalf("rows = %d (%+v), want %d", len(rows), rows, len(tc.hosts))
			}
			for i, h := range tc.hosts {
				if rows[i].Host != h {
					t.Errorf("row %d host = %q, want %q", i, rows[i].Host, h)
				}
			}
		})
	}
	// default sort: newest first
	rows, err := st.ListFlows(ctx, Filter{})
	if err != nil || len(rows) != 3 {
		t.Fatalf("list all: %v %+v", err, rows)
	}
	if rows[0].Path != "/three" {
		t.Errorf("newest first violated: %+v", rows[0])
	}
	// paging
	page, _ := st.ListFlows(ctx, Filter{Limit: 1, Offset: 1})
	if len(page) != 1 || page[0].Path != "/two" {
		t.Errorf("offset paging broken: %+v", page)
	}
}

func TestFTSMultiValueAndHeaderBodySearch(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	f := testFlow() // header X-Session, body secret, host upstream.test
	if err := st.InsertFlow(ctx, f); err != nil {
		t.Fatalf("insert: %v", err)
	}
	for _, q := range []string{"upstream.test", "secret", "X-Session", "login redirect"} {
		rows, err := st.ListFlows(ctx, Filter{Query: q})
		if err != nil {
			t.Fatalf("query %q: %v", q, err)
		}
		if len(rows) != 1 {
			t.Errorf("query %q: %d rows, want 1", q, len(rows))
		}
	}
	// non-match
	rows, _ := st.ListFlows(ctx, Filter{Query: "zznope"})
	if len(rows) != 0 {
		t.Errorf("unexpected rows for non-match: %+v", rows)
	}
}

func TestSetAnnotationAndMissing(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	f := testFlow()
	if err := st.InsertFlow(ctx, f); err != nil {
		t.Fatalf("insert: %v", err)
	}
	c, h := "reviewed: session cookie missing Secure", "red"
	if err := st.SetAnnotation(ctx, f.ID, &c, &h); err != nil {
		t.Fatalf("annotate: %v", err)
	}
	got, _ := st.GetFlow(ctx, f.ID)
	if got.Comment != c || got.Highlight != h {
		t.Fatalf("annotation not persisted: %q/%q", got.Comment, got.Highlight)
	}
	if err := st.SetAnnotation(ctx, 9999, &c, nil); err == nil {
		t.Fatal("expected not-found error")
	}
}

func TestAuditJSONL(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	if err := st.AppendAudit(ctx, "ui", "flow.annotate", "42", "127.0.0.1:1"); err != nil {
		t.Fatalf("audit: %v", err)
	}
	if err := st.AppendAudit(ctx, "mcp:claude", "intercept.forward", "17", ""); err != nil {
		t.Fatalf("audit: %v", err)
	}
	out, err := st.AuditJSONL(ctx)
	if err != nil {
		t.Fatalf("export: %v", err)
	}
	lines := strings.Split(strings.TrimSpace(out), "\n")
	if len(lines) != 2 {
		t.Fatalf("lines = %d", len(lines))
	}
	if !strings.Contains(lines[1], `"actor":"mcp:claude"`) {
		t.Errorf("second line wrong: %q", lines[1])
	}
}

func TestCompressionRoundTrip(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	f := testFlow()
	// force the zstd path (>256 bytes) on both request and response
	f.Request.Body = []byte(strings.Repeat("A", 4096) + "ENDMARK")
	f.Response.Body = []byte(strings.Repeat("B", 5000) + "ENDMARK")
	if err := st.InsertFlow(ctx, f); err != nil {
		t.Fatalf("insert: %v", err)
	}
	got, err := st.GetFlow(ctx, f.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !strings.HasSuffix(string(got.Request.Body), "ENDMARK") || len(got.Request.Body) != 4096+7 {
		t.Errorf("req body decompress mismatch: len=%d", len(got.Request.Body))
	}
	if !strings.HasSuffix(string(got.Response.Body), "ENDMARK") || len(got.Response.Body) != 5000+7 {
		t.Errorf("resp body decompress mismatch: len=%d", len(got.Response.Body))
	}
}

func TestTunnelAndTLSMetadataRoundTrip(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	now := time.Now()
	f := &flows.Flow{
		Started:   now,
		Finished:  now.Add(3 * time.Second),
		Origin:    flows.OriginProxy,
		Tunnel:    true,
		TLSClient: "TLS 1.3",
		TLSServer: "TLS 1.2",
		InScope:   true,
		Request: &flows.Request{
			Method: "CONNECT", Scheme: "https", Host: "pinned.test", Port: 443,
			Path: "", HTTPVersion: "HTTP/1.1",
		},
		Response: &flows.Response{Status: 200, HTTPVersion: "HTTP/1.1"},
	}
	if err := st.InsertFlow(ctx, f); err != nil {
		t.Fatalf("insert: %v", err)
	}
	got, err := st.GetFlow(ctx, f.ID)
	if err != nil {
		t.Fatalf("get: %v", err)
	}
	if !got.Tunnel || got.TLSClient != "TLS 1.3" || got.TLSServer != "TLS 1.2" {
		t.Fatalf("tunnel/TLS metadata lost: %+v", got)
	}
	if got.Request.Method != "CONNECT" || got.Request.Host != "pinned.test" {
		t.Fatalf("tunnel request mismatch: %+v", got.Request)
	}
	rows, _ := st.ListFlows(ctx, Filter{})
	if len(rows) != 1 || !rows[0].Tunnel || rows[0].MITM {
		t.Fatalf("row tunnel flag wrong: %+v", rows)
	}
}

func TestWSMessagePersistence(t *testing.T) {
	st := newTestStore(t)
	ctx := context.Background()
	f := testFlow()
	if err := st.InsertFlow(ctx, f); err != nil {
		t.Fatal(err)
	}
	payload := []byte(strings.Repeat("w", 1000)) // exercises zstd path
	msgs := []*flows.WSMessage{
		{FlowID: f.ID, TS: 1, Direction: flows.DirC2S, Opcode: 1, FIN: true, Size: len(payload), Payload: payload},
		{FlowID: f.ID, TS: 2, Direction: flows.DirS2C, Opcode: 0, FIN: false, Size: 3, Payload: []byte("abc")},
		{FlowID: f.ID, TS: 3, Direction: flows.DirC2S, Opcode: 8, FIN: true, Size: 2, Payload: []byte{3, 232}},
	}
	for _, m := range msgs {
		if err := st.InsertWSMessage(ctx, m); err != nil {
			t.Fatal(err)
		}
	}
	got, err := st.ListWSMessages(ctx, f.ID, 10, 0)
	if err != nil || len(got) != 3 {
		t.Fatalf("list: %v %+v", err, got)
	}
	if !bytes.Equal(decodeB64T(got[0].PayloadB64), payload) {
		t.Errorf("zstd payload mismatch: %d bytes", len(decodeB64T(got[0].PayloadB64)))
	}
	if got[0].OpcodeName != "text" || got[1].OpcodeName != "continuation" || got[2].OpcodeName != "close" {
		t.Errorf("opcode names: %+v", got)
	}
	if got[1].FIN {
		t.Errorf("FIN flag lost")
	}
	// paging
	page, _ := st.ListWSMessages(ctx, f.ID, 2, 1)
	if len(page) != 2 || page[0].TS != 2 {
		t.Errorf("paging: %+v", page)
	}
	// close update
	if err := st.UpdateFlowWSClose(ctx, f.ID, 99, 42, 3); err != nil {
		t.Fatal(err)
	}
	fgot, _ := st.GetFlow(ctx, f.ID)
	if fgot.WSCount != 3 || fgot.DurationMS != 42 {
		t.Errorf("close update: ws_count=%d dur=%d", fgot.WSCount, fgot.DurationMS)
	}
}

func decodeB64T(s string) []byte {
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return nil
	}
	return b
}

func TestMigrationIdempotent(t *testing.T) {
	path := filepath.Join(t.TempDir(), "m.pf.sqlite")
	st, err := Open(path)
	if err != nil {
		t.Fatalf("open1: %v", err)
	}
	st.Close()
	st2, err := Open(path) // re-open: migrations must not re-run/fail
	if err != nil {
		t.Fatalf("open2: %v", err)
	}
	st2.Close()
}
