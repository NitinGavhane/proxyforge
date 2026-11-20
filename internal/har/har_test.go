package har

import (
	"encoding/base64"
	"encoding/json"
	"strings"
	"testing"
	"time"

	"github.com/NitinGavhane/proxyforge/internal/flows"
)

func sampleFlow() *flows.Flow {
	started := time.Date(2026, 11, 19, 10, 30, 0, 0, time.UTC)
	return &flows.Flow{
		ID:         42,
		Started:    started,
		Finished:   started.Add(150 * time.Millisecond),
		DurationMS: 150,
		ServerAddr: "api.example.test:443",
		Origin:     flows.OriginProxy,
		Request: &flows.Request{
			Method:      "POST",
			Scheme:      "https",
			Host:        "api.example.test",
			Port:        443,
			Path:        "/v1/login?next=%2Fhome&flag",
			HTTPVersion: "HTTP/1.1",
			Headers: flows.Headers{
				{Key: "Host", Value: "api.example.test"},
				{Key: "Content-Type", Value: "application/json"},
				{Key: "Cookie", Value: "sid=abc; theme=dark"},
			},
			Body: []byte(`{"email":"a@b.c"}`),
		},
		Response: &flows.Response{
			Status:      302,
			StatusText:  "Found",
			HTTPVersion: "HTTP/1.1",
			Headers: flows.Headers{
				{Key: "Content-Type", Value: "text/html; charset=utf-8"},
				{Key: "Set-Cookie", Value: "session=xyz; Path=/; HttpOnly"},
				{Key: "Location", Value: "/home"},
			},
			Body: []byte("<html>moved</html>"),
		},
	}
}

func TestExportStructure(t *testing.T) {
	raw, err := Export([]*flows.Flow{sampleFlow()})
	if err != nil {
		t.Fatal(err)
	}
	var doc map[string]any
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatalf("export is not valid JSON: %v", err)
	}
	log := doc["log"].(map[string]any)

	// required top-level fields (HAR 1.2)
	if log["version"] != "1.2" {
		t.Errorf("log.version = %v", log["version"])
	}
	creator := log["creator"].(map[string]any)
	if creator["name"] != "ProxyForge" {
		t.Errorf("creator.name = %v", creator["name"])
	}
	entries := log["entries"].([]any)
	if len(entries) != 1 {
		t.Fatalf("entries = %d", len(entries))
	}
	e := entries[0].(map[string]any)

	// entry required fields
	for _, k := range []string{"startedDateTime", "time", "request", "response", "cache", "timings"} {
		if _, ok := e[k]; !ok {
			t.Errorf("entry missing %q", k)
		}
	}
	if e["startedDateTime"] != "2026-11-19T10:30:00.000Z" {
		t.Errorf("startedDateTime = %v", e["startedDateTime"])
	}
	if e["time"].(float64) != 150 {
		t.Errorf("time = %v", e["time"])
	}

	req := e["request"].(map[string]any)
	for _, k := range []string{"method", "url", "httpVersion", "cookies", "headers", "queryString", "headersSize", "bodySize"} {
		if _, ok := req[k]; !ok {
			t.Errorf("request missing %q", k)
		}
	}
	if req["method"] != "POST" || req["url"] != "https://api.example.test/v1/login?next=%2Fhome&flag" {
		t.Errorf("request line wrong: %v %v", req["method"], req["url"])
	}
	// query decoded
	qs := req["queryString"].([]any)
	if len(qs) != 2 || qs[0].(map[string]any)["value"] != "/home" {
		t.Errorf("queryString = %+v", qs)
	}
	// cookies parsed from Cookie header
	cookies := req["cookies"].([]any)
	if len(cookies) != 2 || cookies[1].(map[string]any)["name"] != "theme" {
		t.Errorf("request cookies = %+v", cookies)
	}
	pd := req["postData"].(map[string]any)
	if pd["mimeType"] != "application/json" || pd["text"] != `{"email":"a@b.c"}` {
		t.Errorf("postData = %+v", pd)
	}

	resp := e["response"].(map[string]any)
	for _, k := range []string{"status", "statusText", "httpVersion", "cookies", "headers", "content", "redirectURL", "headersSize", "bodySize"} {
		if _, ok := resp[k]; !ok {
			t.Errorf("response missing %q", k)
		}
	}
	if resp["redirectURL"] != "/home" {
		t.Errorf("redirectURL = %v", resp["redirectURL"])
	}
	content := resp["content"].(map[string]any)
	if content["mimeType"] != "text/html; charset=utf-8" || content["text"] != "<html>moved</html>" {
		t.Errorf("content = %+v", content)
	}
	if content["encoding"] == "base64" {
		t.Error("UTF-8 body must not be base64-encoded")
	}
	rc := resp["cookies"].([]any)
	if len(rc) != 1 || rc[0].(map[string]any)["value"] != "xyz" {
		t.Errorf("response cookies = %+v", rc)
	}
}

func TestExportBinaryBodyBase64(t *testing.T) {
	f := sampleFlow()
	bin := []byte{0x00, 0xff, 0xfe, 0x81}
	f.Response.Body = bin
	raw, _ := Export([]*flows.Flow{f})
	var doc struct {
		Log struct {
			Entries []struct {
				Response struct {
					Content struct {
						Size     int    `json:"size"`
						Text     string `json:"text"`
						Encoding string `json:"encoding"`
					} `json:"content"`
				} `json:"response"`
			} `json:"entries"`
		} `json:"log"`
	}
	if err := json.Unmarshal(raw, &doc); err != nil {
		t.Fatal(err)
	}
	c := doc.Log.Entries[0].Response.Content
	if c.Encoding != "base64" || c.Size != len(bin) {
		t.Fatalf("content = %+v", c)
	}
	dec, err := base64.StdEncoding.DecodeString(c.Text)
	if err != nil || len(dec) != len(bin) {
		t.Fatalf("base64 body not decodable: %v", err)
	}
}

func TestExportSkipsTunnelsAndErrorFlows(t *testing.T) {
	tunnel := sampleFlow()
	tunnel.Tunnel = true
	broken := &flows.Flow{Request: nil}
	normal := sampleFlow()
	normal.ID = 43

	raw, err := Export([]*flows.Flow{tunnel, broken, normal})
	if err != nil {
		t.Fatal(err)
	}
	if strings.Count(string(raw), `"startedDateTime"`) != 1 {
		t.Error("tunnels/nil-request flows must be skipped")
	}
}

func TestExportManyAndEmpty(t *testing.T) {
	if raw, _ := Export(nil); !strings.Contains(string(raw), `"entries": []`) &&
		!strings.Contains(string(raw), `"entries":[]`) {
		t.Error("nil export should produce empty entries")
	}
	fs := []*flows.Flow{}
	for i := 0; i < 3; i++ {
		f := sampleFlow()
		f.ID = int64(i + 1)
		fs = append(fs, f)
	}
	raw, _ := Export(fs)
	if strings.Count(string(raw), `"startedDateTime"`) != 3 {
		t.Error("expected 3 entries")
	}
}
