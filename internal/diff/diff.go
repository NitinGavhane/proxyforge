// Package diff computes word- and byte-level diffs between two captured
// bodies (shared by the Phase 1 history view and the Phase 3 Comparer).
package diff

import (
	"strings"
	"unicode/utf8"
)

// Segment types.
const (
	SegEqual  = "equal"
	SegInsert = "insert" // present only in b
	SegDelete = "delete" // present only in a
)

// Segment is one diff region.
type Segment struct {
	Type string `json:"type"` // equal | insert | delete
	Text string `json:"text"`
}

// Result is a computed diff.
type Result struct {
	Mode     string    `json:"mode"` // word | byte
	AMode    string    `json:"a"`    // short label for side a
	BMode    string    `json:"b"`
	Segments []Segment `json:"segments"`
}

// maxTokens bounds the LCS matrix; larger inputs fall back to a single
// replace chunk (keeps the O(n·m) algorithm honest).
const maxTokens = 6000

// Word tokenizes text into words and whitespace runs (both kept, so the
// original text is exactly reassemblable).
func Word(text string) []string {
	var out []string
	var cur strings.Builder
	inSpace := false
	for _, r := range text {
		isSpace := r == ' ' || r == '\t' || r == '\n' || r == '\r'
		if cur.Len() > 0 && isSpace != inSpace {
			out = append(out, cur.String())
			cur.Reset()
		}
		inSpace = isSpace
		cur.WriteRune(r)
	}
	if cur.Len() > 0 {
		out = append(out, cur.String())
	}
	return out
}

// Compute returns a diff of a and b. mode: "word" (default) tokenizes on
// whitespace; "byte" trims the common prefix/suffix and marks the middle.
func Compute(a, b, mode string) Result {
	if mode == "byte" {
		return byteDiff(a, b)
	}
	if !utf8.ValidString(a) || !utf8.ValidString(b) {
		return byteDiff(a, b) // binary bodies: byte mode only
	}
	return wordDiff(a, b)
}

func wordDiff(a, b string) Result {
	at, bt := Word(a), Word(b)
	if len(at) > maxTokens || len(bt) > maxTokens {
		return coarse(a, b, "word")
	}
	// LCS table (uint16 offsets are plenty at this size)
	n, m := len(at), len(bt)
	lcs := make([][]int, n+1)
	for i := range lcs {
		lcs[i] = make([]int, m+1)
	}
	for i := n - 1; i >= 0; i-- {
		for j := m - 1; j >= 0; j-- {
			if at[i] == bt[j] {
				lcs[i][j] = lcs[i+1][j+1] + 1
			} else if lcs[i+1][j] >= lcs[i][j+1] {
				lcs[i][j] = lcs[i+1][j]
			} else {
				lcs[i][j] = lcs[i][j+1]
			}
		}
	}
	var segs []Segment
	flush := func(typ, text string) {
		if text == "" {
			return
		}
		if n := len(segs); n > 0 && segs[n-1].Type == typ {
			segs[n-1].Text += text
			return
		}
		segs = append(segs, Segment{Type: typ, Text: text})
	}
	i, j := 0, 0
	for i < n && j < m {
		switch {
		case at[i] == bt[j]:
			flush(SegEqual, at[i])
			i++
			j++
		case lcs[i+1][j] >= lcs[i][j+1]:
			flush(SegDelete, at[i])
			i++
		default:
			flush(SegInsert, bt[j])
			j++
		}
	}
	for ; i < n; i++ {
		flush(SegDelete, at[i])
	}
	for ; j < m; j++ {
		flush(SegInsert, bt[j])
	}
	return Result{Mode: "word", Segments: segs}
}

func byteDiff(a, b string) Result {
	if a == b {
		return Result{Mode: "byte", Segments: []Segment{{Type: SegEqual, Text: a}}}
	}
	pre := commonPrefix(a, b)
	suf := commonSuffix(a[pre:], b[pre:])
	midA := a[pre : len(a)-suf]
	midB := b[pre : len(b)-suf]
	segs := []Segment{{Type: SegEqual, Text: a[:pre]}}
	if midA != "" {
		segs = append(segs, Segment{Type: SegDelete, Text: midA})
	}
	if midB != "" {
		segs = append(segs, Segment{Type: SegInsert, Text: midB})
	}
	if suf > 0 {
		segs = append(segs, Segment{Type: SegEqual, Text: a[len(a)-suf:]})
	}
	return Result{Mode: "byte", Segments: segs}
}

// coarse handles oversized inputs: one delete + one insert.
func coarse(a, b, mode string) Result {
	segs := []Segment{}
	if a != "" {
		segs = append(segs, Segment{Type: SegDelete, Text: a})
	}
	if b != "" {
		segs = append(segs, Segment{Type: SegInsert, Text: b})
	}
	return Result{Mode: mode + " (oversized, not aligned)", Segments: segs}
}

func commonPrefix(a, b string) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 0; i < n; i++ {
		if a[i] != b[i] {
			return i
		}
	}
	return n
}

func commonSuffix(a, b string) int {
	n := len(a)
	if len(b) < n {
		n = len(b)
	}
	for i := 1; i <= n; i++ {
		if a[len(a)-i] != b[len(b)-i] {
			return i - 1
		}
	}
	return n
}
