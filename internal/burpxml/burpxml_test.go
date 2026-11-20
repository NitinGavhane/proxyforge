package burpxml

import (
	"encoding/base64"
	"encoding/xml"
	"strings"
	"testing"
	"time"

	"github.com/NitinGavhane/proxyforge/internal/flows"
)

func sampleFlow() *flows.Flow {
	return &flows.Flow{
		ID:      7,
		Started: time.Date(2026, 11, 20, 10, 0, 0, 0, time.UTC),
		Request: &flows.Request{
			Method: "POST", Scheme: "http", Host: "api.example.test", Port: 8080,
			Path: "/login?x=1", HTTPVersion: "HTTP/1.1",
			Headers: flows.Headers{{Key: "Host", Value: "api.example.test:8080"}, {Key: "Content-Type", Value: "application/json"}},
			Body:    []byte(`{"a":1}`),
		},
		Response: &flows.Response{
			Status: 200, StatusText: "OK", HTTPVersion: "HTTP/1.1",
			Headers: flows.Headers{{Key: "Content-Type", Value: "application/json"}},
			Body:    []byte(`{"ok":true}`),
		},
	}
}

func TestExportImportRoundTrip(t *testing.T) {
	doc, err := Export([]*flows.Flow{sampleFlow()})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(string(doc), "<items>") || !strings.Contains(string(doc), "api.example.test") {
		t.Fatalf("xml malformed: %.200s", doc)
	}
	items, err := Import(doc)
	if err != nil {
		t.Fatal(err)
	}
	if len(items) != 1 {
		t.Fatalf("items = %d", len(items))
	}
	it := items[0]
	if it.Method != "POST" || it.Host != "api.example.test" || it.Port != 8080 || it.Path != "/login?x=1" {
		t.Fatalf("item: %+v", it)
	}
	if !strings.Contains(string(it.Request), "POST /login?x=1 HTTP/1.1") ||
		!strings.Contains(string(it.Request), `{"a":1}`) {
		t.Errorf("request wire form: %q", it.Request)
	}
	if !strings.Contains(string(it.Response), "200 OK") {
		t.Errorf("response wire form: %q", it.Response)
	}
}

func TestImportToleratesJunk(t *testing.T) {
	if _, err := Import([]byte("not xml")); err == nil {
		t.Fatal("garbage accepted")
	}
	// one broken base64 entry among good ones is skipped
	good := base64.StdEncoding.EncodeToString([]byte("GET / HTTP/1.1\r\nHost: a\r\n"))
	doc := `<?xml version="1.0"?><items>
	<item><time>x</time><url>http://a/</url><host>a</host><port>80</port><protocol>http</protocol><method>GET</method><path>/</path><status>200</status><request>` + good + `</request><response></response></item>
	<item><request>!!!not-base64!!!</request></item>
	</items>`
	items, err := Import([]byte(doc))
	if err != nil || len(items) != 1 {
		t.Fatalf("items = %d err = %v", len(items), err)
	}
	var _ = xml.Header
}
