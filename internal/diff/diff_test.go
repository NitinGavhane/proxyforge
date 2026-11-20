package diff

import (
	"strings"
	"testing"
)

func reassemble(segs []Segment) (a, b string) {
	for _, s := range segs {
		switch s.Type {
		case SegEqual:
			a += s.Text
			b += s.Text
		case SegDelete:
			a += s.Text
		case SegInsert:
			b += s.Text
		}
	}
	return
}

func TestWordDiffRoundTrip(t *testing.T) {
	a := `{"user":"admin","role":"user","active":true}`
	b := `{"user":"admin","role":"ADMINISTRATOR","active":false}`
	res := Compute(a, b, "word")
	ra, rb := reassemble(res.Segments)
	if ra != a || rb != b {
		t.Fatalf("round trip broken:\n got a=%q\n want a=%q\n got b=%q\n want b=%q", ra, a, rb, b)
	}
	hasDel, hasIns := false, false
	for _, s := range res.Segments {
		if s.Type == SegDelete && strings.Contains(s.Text, "user\"") {
			hasDel = true
		}
		if s.Type == SegInsert && strings.Contains(s.Text, "ADMINISTRATOR") {
			hasIns = true
		}
	}
	if !hasDel || !hasIns {
		t.Fatalf("expected changed words flagged: %+v", res.Segments)
	}
}

func TestWordDiffIdentical(t *testing.T) {
	res := Compute("same text", "same text", "word")
	if len(res.Segments) != 1 || res.Segments[0].Type != SegEqual {
		t.Fatalf("identical inputs must be one equal segment: %+v", res.Segments)
	}
}

func TestWordDiffEmptySides(t *testing.T) {
	res := Compute("", "added", "word")
	if len(res.Segments) != 1 || res.Segments[0].Type != SegInsert {
		t.Fatalf("empty a: %+v", res.Segments)
	}
	res = Compute("gone", "", "word")
	if len(res.Segments) != 1 || res.Segments[0].Type != SegDelete {
		t.Fatalf("empty b: %+v", res.Segments)
	}
}

func TestByteDiff(t *testing.T) {
	res := Compute("prefix-MIDDLE-suffix", "prefix-middle-suffix", "byte")
	ra, rb := reassemble(res.Segments)
	if ra != "prefix-MIDDLE-suffix" || rb != "prefix-middle-suffix" {
		t.Fatalf("round trip broken: %q / %q", ra, rb)
	}
	// common prefix and suffix survive as equals
	first, last := res.Segments[0], res.Segments[len(res.Segments)-1]
	if first.Type != SegEqual || !strings.HasPrefix(first.Text, "prefix-") {
		t.Fatalf("prefix not preserved: %+v", first)
	}
	if last.Type != SegEqual || !strings.HasSuffix(last.Text, "-suffix") {
		t.Fatalf("suffix not preserved: %+v", last)
	}
}

func TestBinaryFallsBackToByte(t *testing.T) {
	a := string([]byte{0x00, 0x01, 0x02, 0xff})
	b := string([]byte{0x00, 0x01, 0x03, 0xff})
	res := Compute(a, b, "word") // invalid UTF-8 → byte mode
	if res.Mode != "byte" {
		t.Fatalf("mode = %s, want byte fallback", res.Mode)
	}
	ra, rb := reassemble(res.Segments)
	if ra != a || rb != b {
		t.Fatalf("binary round trip broken")
	}
}

func TestOversizedInputsCoarse(t *testing.T) {
	a := strings.Repeat("alpha ", 20000)
	b := strings.Repeat("beta ", 20000)
	res := Compute(a, b, "word")
	if len(res.Segments) != 2 {
		t.Fatalf("oversized inputs should be coarse: %d segments", len(res.Segments))
	}
	ra, rb := reassemble(res.Segments)
	if ra != a || rb != b {
		t.Fatal("coarse round trip broken")
	}
}

func TestWhitespaceTokensReassemble(t *testing.T) {
	a := "line1\nline2\n"
	b := "line1\nline2 changed\n"
	res := Compute(a, b, "word")
	ra, rb := reassemble(res.Segments)
	if ra != a || rb != b {
		t.Fatalf("newline tokens lost: %q / %q", ra, rb)
	}
}
