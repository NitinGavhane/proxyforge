package report

import (
	"context"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/NitinGavhane/proxyforge/internal/flows"
	"github.com/NitinGavhane/proxyforge/internal/store"
)

func seedIssue(t *testing.T, st *store.Store, withEvidence bool) {
	t.Helper()
	f := &flows.Flow{
		Started: time.Now(), Origin: flows.OriginProxy,
		Request: &flows.Request{
			Method: "GET", Scheme: "http", Host: "vuln.example", Port: 80,
			Path: "/admin", HTTPVersion: "HTTP/1.1",
			Headers: flows.Headers{{Key: "Host", Value: "vuln.example"}},
		},
		Response: &flows.Response{
			Status: 200, StatusText: "OK", HTTPVersion: "HTTP/1.1",
			Headers: flows.Headers{{Key: "Content-Type", Value: "text/html"}},
			Body:    []byte("<html>admin console</html>"),
		},
	}
	if err := st.InsertFlow(context.Background(), f); err != nil {
		t.Fatal(err)
	}
	iss := &store.Issue{
		CheckID: "passive.cors.wildcard-credentials", Title: "CORS wildcard with credentials",
		Severity: "high", Confidence: "certain",
		Host: "vuln.example", Port: 80, Path: "/admin",
		Detail: "Any origin can read credentialed responses.",
	}
	if withEvidence {
		iss.EvidenceFlowID = f.ID
	}
	if err := st.InsertIssue(context.Background(), iss); err != nil {
		t.Fatal(err)
	}
}

func TestRenderMarkdown(t *testing.T) {
	st, err := store.Open(filepath.Join(t.TempDir(), "rep.pf.sqlite"))
	if err != nil {
		t.Fatal(err)
	}
	defer st.Close()
	seedIssue(t, st, true)

	issues, _ := st.ListIssues(context.Background(), store.IssueFilter{})
	md := Render(context.Background(), st, Meta{Target: "vuln.example", When: time.Now()}, issues)
	for _, want := range []string{
		"# ProxyForge Security Report — vuln.example",
		"| high | 1 |",
		"CORS wildcard with credentials",
		"flow #1",
		"```http",
		"GET /admin HTTP/1.1",
		"<html>admin console</html>",
		"authorized testing only",
	} {
		if !strings.Contains(md, want) {
			t.Errorf("md missing %q:\n%s", want, md)
		}
	}
}

func TestRenderHTMLEscapesEvidence(t *testing.T) {
	st, _ := store.Open(filepath.Join(t.TempDir(), "rep2.pf.sqlite"))
	defer st.Close()
	seedIssue(t, st, true)
	issues, _ := st.ListIssues(context.Background(), store.IssueFilter{})
	doc := RenderHTML(context.Background(), st, Meta{}, issues)
	for _, want := range []string{"<h1>", "<pre>", "&lt;html&gt;", "ProxyForge Report"} {
		if !strings.Contains(doc, want) {
			t.Errorf("html missing %q", want)
		}
	}
	// raw HTML from evidence must never appear unescaped
	if strings.Contains(doc, "<html>admin console</html>") {
		t.Error("evidence HTML not escaped")
	}
}

func TestRenderEmpty(t *testing.T) {
	st, _ := store.Open(filepath.Join(t.TempDir(), "rep3.pf.sqlite"))
	defer st.Close()
	md := Render(context.Background(), st, Meta{}, nil)
	if !strings.Contains(md, "No issues recorded") {
		t.Errorf("empty report: %s", md)
	}
}
