package tools

import (
	"strings"
	"testing"
)

func TestURLEncodeDecode(t *testing.T) {
	res := Transform("a b&c=d?e", FmtURL, "encode")
	if res.Err != "" || res.Output != "a+b%26c%3Dd%3Fe" {
		t.Fatalf("url encode: %+v", res)
	}
	back := Transform(res.Output, FmtURL, "decode")
	if back.Err != "" || back.Output != "a b&c=d?e" {
		t.Fatalf("url decode: %+v", back)
	}
}

func TestHTMLTransform(t *testing.T) {
	res := Transform(`<a href="x">&amp;</a>`, FmtHTML, "decode")
	if res.Output != `<a href="x">&</a>` {
		t.Fatalf("html decode: %q", res.Output)
	}
	enc := Transform(`<a href="x">&</a>`, FmtHTML, "encode")
	if enc.Output != `&lt;a href=&#34;x&#34;&gt;&amp;&lt;/a&gt;` {
		t.Fatalf("html encode: %q", enc.Output)
	}
}

func TestBase64Variants(t *testing.T) {
	// std
	res := Transform("hello", FmtBase64, "encode")
	if res.Output != "aGVsbG8=" {
		t.Fatalf("b64 encode: %q", res.Output)
	}
	// url-safe without padding decodes via the tolerant path
	res = Transform("aGVsbG8", FmtBase64, "decode")
	if res.Err != "" || res.Output != "hello" {
		t.Fatalf("b64 unpadded: %+v", res)
	}
	res = Transform("-_8", FmtBase64, "decode") // url-safe alphabet
	if res.Err != "" || res.Output != "\xfb\xff" {
		t.Fatalf("b64 urlsafe: %+v", res)
	}
	if res := Transform("!!!", FmtBase64, "decode"); res.Err == "" {
		t.Fatal("invalid b64 accepted")
	}
}

func TestHexTransform(t *testing.T) {
	res := Transform("AB", FmtHex, "encode")
	if res.Output != "4142" {
		t.Fatalf("hex encode: %q", res.Output)
	}
	res = Transform("41 42\n43", FmtHex, "decode")
	if res.Err != "" || res.Output != "ABC" {
		t.Fatalf("hex decode: %+v", res)
	}
	if res := Transform("414", FmtHex, "decode"); res.Err == "" {
		t.Fatal("odd-length hex accepted")
	}
}

func TestGzipRoundTrip(t *testing.T) {
	res := Transform(strings.Repeat("compress me ", 20), FmtGzip, "encode")
	if res.Err != "" {
		t.Fatal(res.Err)
	}
	back := Transform(res.Output, FmtGzip, "decode")
	if back.Err != "" || !strings.Contains(back.Output, "compress me") {
		t.Fatalf("gunzip: %+v", back)
	}
	if res := Transform("not-gzip", FmtGzip, "decode"); res.Err == "" {
		t.Fatal("garbage accepted as gzip")
	}
}

func TestJWTDecode(t *testing.T) {
	// header {"alg":"HS256","typ":"JWT"} payload {"sub":"admin"}
	tok := "eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJhZG1pbiJ9.c2ln"
	res := Transform(tok, FmtJWT, "decode")
	if res.Err != "" {
		t.Fatal(res.Err)
	}
	if !strings.Contains(res.Output, `"alg"`) || !strings.Contains(res.Output, `"sub": "admin"`) {
		t.Fatalf("jwt output: %s", res.Output)
	}
	if !strings.Contains(res.Output, "NOT verified") {
		t.Error("missing signature disclaimer")
	}
	if res := Transform("no.dots", FmtJWT, "decode"); res.Err == "" {
		t.Fatal("non-jwt accepted")
	}
	if res := Transform(tok, FmtJWT, "encode"); res.Err == "" {
		t.Fatal("jwt encode must be refused")
	}
}

func TestSmartDecodeChain(t *testing.T) {
	// double-encoded URL → base64
	inner := Transform("GET /x?a=1", FmtBase64, "encode").Output // R0VU...
	payload := inner                                             // base64 of text: smart should stop after base64 step
	res := Transform(payload, FmtSmart, "decode")
	if res.Err != "" || res.Output != "GET /x?a=1" {
		t.Fatalf("smart b64: %+v", res)
	}
	if len(res.Steps) != 1 || res.Steps[0] != "base64" {
		t.Fatalf("steps = %v", res.Steps)
	}

	// URL layer over a padded base64 body: two chained steps
	b64 := Transform("foobar!", FmtBase64, "encode").Output // Zm9vYmFyIQ==
	double := Transform(b64, FmtURL, "encode").Output       // ...IQ%3D%3D
	res = Transform(double, FmtSmart, "decode")
	if res.Err != "" || res.Output != "foobar!" {
		t.Fatalf("smart url+b64: %+v output=%q", res, res.Output)
	}
	if len(res.Steps) != 2 || res.Steps[0] != "url" || res.Steps[1] != "base64" {
		t.Fatalf("steps = %v", res.Steps)
	}

	// plain text: no steps, unchanged
	res = Transform("plain input text", FmtSmart, "decode")
	if len(res.Steps) != 0 || res.Output != "plain input text" {
		t.Fatalf("smart plain: %+v", res)
	}
}

func TestUnknownFormat(t *testing.T) {
	if res := Transform("x", "rot13", "decode"); res.Err == "" {
		t.Fatal("unknown format accepted")
	}
}
