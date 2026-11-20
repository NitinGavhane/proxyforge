package tools

import (
	"crypto/rand"
	"encoding/hex"
	"fmt"
	"strings"
	"testing"
)

func randomHexTokens(t *testing.T, n int) []string {
	t.Helper()
	out := make([]string, n)
	for i := range out {
		b := make([]byte, 16)
		if _, err := rand.Read(b); err != nil {
			t.Fatal(err)
		}
		out[i] = hex.EncodeToString(b)
	}
	return out
}

func TestSequencerGoodRandomness(t *testing.T) {
	res, err := AnalyzeTokens(randomHexTokens(t, 200))
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict != "good" {
		t.Fatalf("verdict = %s (entropy=%.2f comp=%.2f monobit=%v)", res.Verdict, res.EntropyBits, res.Compression, res.Monobit)
	}
	if res.Duplicates != 0 || res.Monobit == nil || !res.Monobit.Pass {
		t.Fatalf("dups=%d monobit=%+v", res.Duplicates, res.Monobit)
	}
	// per-position entropy should be ~4 bits (hex charset)
	if len(res.PosEntropy) != 32 {
		t.Fatalf("pos entropy len = %d", len(res.PosEntropy))
	}
	for i, h := range res.PosEntropy {
		if h < 3.0 {
			t.Errorf("position %d entropy %.2f — unexpectedly low for crypto/rand", i, h)
		}
	}
}

func TestSequencerDetectsBadTokens(t *testing.T) {
	// sequential hex counters: constant prefix + counter suffix
	bad := []string{}
	for i := 0; i < 100; i++ {
		bad = append(bad, fmt.Sprintf("deadbeef%08x", i))
	}
	res, err := AnalyzeTokens(bad)
	if err != nil {
		t.Fatal(err)
	}
	if res.Verdict == "good" {
		t.Fatalf("sequential tokens rated good: %+v", res)
	}
	// constant positions flagged
	flagged := false
	for _, n := range res.Notes {
		if strings.Contains(n, "constant or time-ordered") {
			flagged = true
		}
	}
	if !flagged {
		t.Errorf("no constant-position note: %v", res.Notes)
	}

	// duplicates → poor
	dup := []string{}
	for i := 0; i < 20; i++ {
		dup = append(dup, "aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa")
	}
	res, _ = AnalyzeTokens(dup)
	if res.Verdict != "poor" || res.Duplicates != 19 {
		t.Fatalf("dup verdict = %s dups = %d", res.Verdict, res.Duplicates)
	}
}

func TestSequencerLowEntropyAlphabet(t *testing.T) {
	// tokens drawn from {a,b} only
	tokens := make([]string, 64)
	for i := range tokens {
		tokens[i] = "abba" + string(rune('a'+i%2)) + "baab" + string(rune('a'+(i/2)%2)) + "abab" + string(rune('a'+i%2))
	}
	res, err := AnalyzeTokens(tokens)
	if err != nil {
		t.Fatal(err)
	}
	if res.CharsetSize > 4 {
		t.Fatalf("charset = %d", res.CharsetSize)
	}
	if res.EntropyBits > 2.0 {
		t.Fatalf("entropy = %.2f, want ≤ 2 bits for a tiny alphabet", res.EntropyBits)
	}
}

func TestSequencerNeedsSamples(t *testing.T) {
	if _, err := AnalyzeTokens([]string{"a", "b"}); err == nil {
		t.Fatal("small sample accepted")
	}
	if _, err := AnalyzeTokens(nil); err == nil {
		t.Fatal("nil accepted")
	}
}
