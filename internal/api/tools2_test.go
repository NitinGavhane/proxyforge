package api

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"strings"
	"testing"
)

func TestDecodeCompareSequencerEndpoints(t *testing.T) {
	srv, _ := newToolsServer(t)

	// decode: base64 round trip + smart
	req, _ := http.NewRequest("POST", srv.URL+"/api/v1/decode",
		strings.NewReader(`{"input":"Zm9vYmFy","format":"base64","mode":"decode"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, _ := http.DefaultClient.Do(bearer(req, "testtoken123"))
	var dec struct {
		Result struct {
			Output string `json:"output"`
			Err    string `json:"err"`
		} `json:"result"`
	}
	readJSON(t, resp, &dec)
	if dec.Result.Output != "foobar" || dec.Result.Err != "" {
		t.Fatalf("decode: %+v", dec.Result)
	}
	req, _ = http.NewRequest("POST", srv.URL+"/api/v1/decode",
		strings.NewReader(`{"input":"eyJhbGciOiJub25lIn0.eyJzdfciOiJhZG1pbiJ9.","format":"smart"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, _ = http.DefaultClient.Do(bearer(req, "testtoken123"))
	readJSON(t, resp, &dec)
	if len(dec.Result.Output) == 0 {
		t.Fatal("smart decode empty")
	}

	// compare raw
	req, _ = http.NewRequest("POST", srv.URL+"/api/v1/compare",
		strings.NewReader(`{"a":"admin user","b":"admin admin","mode":"word"}`))
	req.Header.Set("Content-Type", "application/json")
	resp, _ = http.DefaultClient.Do(bearer(req, "testtoken123"))
	var cmp struct {
		Segments []struct {
			Type string `json:"type"`
			Text string `json:"text"`
		} `json:"segments"`
	}
	readJSON(t, resp, &cmp)
	hasDelete, hasInsert := false, false
	for _, s := range cmp.Segments {
		if s.Type == "delete" && s.Text == "user" {
			hasDelete = true
		}
		if s.Type == "insert" && s.Text == "admin" {
			hasInsert = true
		}
	}
	if !hasDelete || !hasInsert {
		t.Fatalf("compare segments: %+v", cmp.Segments)
	}

	// sequencer: good tokens
	var sb strings.Builder
	for i := 0; i < 64; i++ {
		b := make([]byte, 16)
		rand.Read(b)
		sb.WriteString(hex.EncodeToString(b))
		sb.WriteString("\n")
	}
	req, _ = http.NewRequest("POST", srv.URL+"/api/v1/sequencer/analyze",
		strings.NewReader(fmt.Sprintf(`{"tokens":%q}`, sb.String())))
	req.Header.Set("Content-Type", "application/json")
	resp, _ = http.DefaultClient.Do(bearer(req, "testtoken123"))
	var seq struct {
		Analysis struct {
			Verdict string `json:"verdict"`
			Samples int    `json:"samples"`
		} `json:"analysis"`
	}
	readJSON(t, resp, &seq)
	if seq.Analysis.Samples != 64 || seq.Analysis.Verdict == "" {
		t.Fatalf("sequencer: %+v", seq.Analysis)
	}

	// too few tokens → 400
	req, _ = http.NewRequest("POST", srv.URL+"/api/v1/sequencer/analyze",
		strings.NewReader(`{"tokens":"a\nb"}`))
	resp, _ = http.DefaultClient.Do(bearer(req, "testtoken123"))
	resp.Body.Close()
	if resp.StatusCode != http.StatusBadRequest {
		t.Fatalf("small sample status = %d", resp.StatusCode)
	}
}

func readJSON(t *testing.T, resp *http.Response, v any) {
	t.Helper()
	defer resp.Body.Close()
	if err := json.NewDecoder(resp.Body).Decode(v); err != nil {
		t.Fatal(err)
	}
}
