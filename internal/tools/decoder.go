// Decoder (Phase 3 P4): URL/HTML/Base64/Hex/Gzip/JWT transforms + smart
// chained decoding. Stateless — the API and MCP wrap these directly.
package tools

import (
	"bytes"
	"compress/gzip"
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"html"
	"net/url"
	"regexp"
	"strings"
)

// Decoder formats.
const (
	FmtURL    = "url"
	FmtHTML   = "html"
	FmtBase64 = "base64"
	FmtHex    = "hex"
	FmtGzip   = "gzip"
	FmtJWT    = "jwt"
	FmtSmart  = "smart"
)

// DecodeResult carries the output plus a human-readable chain of steps
// (smart mode applies several).
type DecodeResult struct {
	Input  string   `json:"input"`
	Format string   `json:"format"`
	Mode   string   `json:"mode"` // decode | encode
	Output string   `json:"output"`
	Steps  []string `json:"steps,omitempty"` // smart-mode chain
	IsText bool     `json:"is_text"`         // output is printable text
	Err    string   `json:"err,omitempty"`
}

// Transform runs one decode/encode.
func Transform(input, format, mode string) DecodeResult {
	res := DecodeResult{Input: input, Format: format, Mode: mode}
	var out string
	var err error
	switch format {
	case FmtURL:
		if mode == "encode" {
			out = url.QueryEscape(input)
		} else {
			out, err = url.QueryUnescape(input)
		}
	case FmtHTML:
		if mode == "encode" {
			out = html.EscapeString(input)
		} else {
			out = html.UnescapeString(input)
		}
	case FmtBase64:
		out, err = base64Transform(input, mode)
	case FmtHex:
		if mode == "encode" {
			out = hex.EncodeToString([]byte(input))
		} else {
			clean := strings.Join(strings.Fields(input), "")
			b, derr := hex.DecodeString(clean)
			if derr != nil {
				err = derr
			} else {
				out = string(b)
			}
		}
	case FmtGzip:
		out, err = gzipTransform(input, mode)
	case FmtJWT:
		out, err = jwtDecode(input) // encode not supported (no signing)
		if mode == "encode" && err == nil {
			err = fmt.Errorf("jwt encode requires signing — decode only")
		}
	case FmtSmart:
		return SmartDecode(input)
	default:
		err = fmt.Errorf("unknown format %q", format)
	}
	if err != nil {
		res.Err = err.Error()
		return res
	}
	res.Output = out
	res.IsText = isMostlyPrintable(out)
	return res
}

func base64Transform(input, mode string) (string, error) {
	if mode == "encode" {
		return base64.StdEncoding.EncodeToString([]byte(input)), nil
	}
	s := strings.TrimSpace(input)
	// tolerate URL-safe alphabets and missing padding
	if strings.ContainsAny(s, "-_") {
		s = strings.NewReplacer("-", "+", "_", "/").Replace(s)
	}
	if m := len(s) % 4; m != 0 {
		s += strings.Repeat("=", 4-m)
	}
	b, err := base64.StdEncoding.DecodeString(s)
	if err != nil {
		return "", err
	}
	return string(b), nil
}

func gzipTransform(input, mode string) (string, error) {
	if mode == "encode" {
		var buf bytes.Buffer
		zw := gzip.NewWriter(&buf)
		if _, err := zw.Write([]byte(input)); err != nil {
			return "", err
		}
		if err := zw.Close(); err != nil {
			return "", err
		}
		return base64.StdEncoding.EncodeToString(buf.Bytes()), nil // binary-safe transport
	}
	raw, err := base64Transform(input, "decode") // accept the transport wrapper
	zr, err2 := gzip.NewReader(strings.NewReader(raw))
	if err2 != nil {
		return "", fmt.Errorf("gunzip: %w (input must be base64(gzip(data)))", err2)
	}
	_ = err
	var out bytes.Buffer
	if _, err := out.ReadFrom(zr); err != nil {
		return "", err
	}
	return out.String(), nil
}

var jwtPart = regexp.MustCompile(`^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+(\.[A-Za-z0-9_-]*)?$`)

// jwtDecode pretty-prints the header and payload of a JWS token. It does
// NOT verify the signature (explicitly out of scope).
func jwtDecode(input string) (string, error) {
	trimmed0 := strings.TrimSpace(input)
	parts := strings.Split(trimmed0, ".")
	if len(parts) < 2 || !jwtPart.MatchString(trimmed0) {
		return "", fmt.Errorf("jwt: expected header.payload[.signature]")
	}
	// "no.dots" shape: two alpha parts — still rejected unless both decode
	// to JSON-ish content; check by attempting the pretty step below.
	pretty := func(part string, label string) (string, error) {
		s := strings.NewReplacer("-", "+", "_", "/").Replace(part)
		if m := len(s) % 4; m != 0 {
			s += strings.Repeat("=", 4-m)
		}
		raw, err := base64.StdEncoding.DecodeString(s)
		if err != nil {
			return "", err
		}
		var buf bytes.Buffer
		if err := json.Indent(&buf, raw, "", "  "); err != nil {
			return string(raw), nil // not JSON: show raw
		}
		return buf.String(), nil
	}
	hdr, err := pretty(parts[0], "header")
	if err != nil {
		return "", fmt.Errorf("jwt header: %w", err)
	}
	if !strings.HasPrefix(strings.TrimSpace(hdr), "{") {
		return "", fmt.Errorf("jwt: header is not JSON — not a JWT")
	}
	pld, err := pretty(parts[1], "payload")
	if err != nil {
		return "", fmt.Errorf("jwt payload: %w", err)
	}
	out := "header:\n" + hdr + "\n\npayload:\n" + pld
	if len(parts) > 2 {
		out += "\n\nsignature (NOT verified):\n" + parts[2]
	}
	return out, nil
}

// SmartDecode chains transforms until the output stops changing: URL →
// base64 → hex → gzip → JWT, at most 10 rounds.
func SmartDecode(input string) DecodeResult {
	res := DecodeResult{Input: input, Format: FmtSmart, Mode: "decode"}
	cur := input
	for i := 0; i < 10; i++ {
		next, step, ok := smartStep(cur)
		if !ok || next == cur {
			break
		}
		res.Steps = append(res.Steps, step)
		cur = next
	}
	res.Output = cur
	res.IsText = isMostlyPrintable(cur)
	return res
}

func smartStep(s string) (string, string, bool) {
	cand := []struct {
		name string
		fn   func(string) (string, error)
	}{
		{"url", func(x string) (string, error) { return url.QueryUnescape(x) }},
		{"base64", func(x string) (string, error) { return base64Transform(x, "decode") }},
		{"hex", func(x string) (string, error) {
			t := strings.TrimSpace(x)
			if !regexp.MustCompile(`^[0-9a-fA-F\s]+$`).MatchString(t) || len(t) < 4 || len(t)%2 != 0 {
				return "", fmt.Errorf("not hex")
			}
			b, err := hex.DecodeString(t)
			return string(b), err
		}},
		{"gzip", func(x string) (string, error) {
			raw, err := base64Transform(x, "decode")
			if err != nil {
				return "", err
			}
			zr, err := gzip.NewReader(strings.NewReader(raw))
			if err != nil {
				return "", err
			}
			var out bytes.Buffer
			if _, err := out.ReadFrom(zr); err != nil {
				return "", err
			}
			return out.String(), nil
		}},
		{"jwt", jwtDecode},
	}
	// strict-ish guards so short words don't "decode" as base64 noise
	trimmed := strings.TrimSpace(s)
	for _, c := range cand {
		switch c.name {
		case "base64":
			if len(trimmed) < 8 || !regexp.MustCompile(`^[A-Za-z0-9+/=_-]+$`).MatchString(trimmed) {
				continue
			}
		case "hex":
			if len(trimmed) < 8 {
				continue
			}
		case "url":
			if !strings.ContainsAny(trimmed, "%+") {
				continue
			}
		case "gzip":
			if len(trimmed) < 16 {
				continue
			}
		case "jwt":
			if !strings.Contains(trimmed, ".") {
				continue
			}
		}
		if out, err := c.fn(trimmed); err == nil && len(out) > 0 && isMostlyPrintable(out) {
			return out, c.name, true
		}
	}
	return s, "", false
}

// isMostlyPrintable: ≥90% printable runes and valid UTF-8-ish.
func isMostlyPrintable(s string) bool {
	if len(s) == 0 {
		return true
	}
	printable := 0
	total := 0
	for _, r := range s {
		total++
		if r == '\n' || r == '\t' || r == '\r' || (r >= 0x20 && r != 0x7f) {
			printable++
		}
	}
	return printable*10 >= total*9
}
