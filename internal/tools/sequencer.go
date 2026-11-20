// Sequencer (Phase 3 P4): token randomness analysis — entropy, chi-square
// uniformity, per-position variance, duplicates, compression ratio, and a
// FIPS-style monobit test for hex tokens. Pure analysis; no requests.
package tools

import (
	"bytes"
	"compress/gzip"
	"encoding/hex"
	"fmt"
	"math"
	"sort"
	"strings"
)

// SequencerResult is the analysis of a token sample.
type SequencerResult struct {
	Samples     int     `json:"samples"`
	Unique      int     `json:"unique"`
	Duplicates  int     `json:"duplicates"`
	MinLen      int     `json:"min_len"`
	MaxLen      int     `json:"max_len"`
	AvgLen      float64 `json:"avg_len"`
	CharsetSize int     `json:"charset_size"`
	// EntropyBits is per-character Shannon entropy over the whole corpus.
	EntropyBits float64 `json:"entropy_bits_per_char"`
	// ChiSquare tests character-frequency uniformity (df = charset-1).
	ChiSquare float64 `json:"chi_square"`
	DF        int     `json:"degrees_of_freedom"`
	// PosEntropy is per-position entropy for fixed-length tokens (nil when
	// lengths vary) — low per-position entropy reveals time-ordered or
	// counter-based generation.
	PosEntropy []float64 `json:"per_position_entropy,omitempty"`
	// Monobit applies to hex tokens: FIPS-style bit balance.
	Monobit     *MonobitResult `json:"monobit,omitempty"`
	Compression float64        `json:"compression_ratio"` // compressed/raw (lower = more random)
	Verdict     string         `json:"verdict"`           // poor | weak | acceptable | good
	Notes       []string       `json:"notes"`
}

// MonobitResult is the FIPS-approximate bit balance over the token stream.
type MonobitResult struct {
	TotalBits int     `json:"total_bits"`
	Ones      int     `json:"ones"`
	Ratio     float64 `json:"ones_ratio"`
	Pass      bool    `json:"pass"` // ratio within 0.495–0.505 (relaxed for small samples)
}

// AnalyzeTokens computes the report.
func AnalyzeTokens(tokens []string) (*SequencerResult, error) {
	clean := make([]string, 0, len(tokens))
	for _, t := range tokens {
		t = strings.TrimSpace(t)
		if t != "" {
			clean = append(clean, t)
		}
	}
	if len(clean) < 8 {
		return nil, fmt.Errorf("sequencer: need at least 8 tokens (got %d)", len(clean))
	}
	res := &SequencerResult{Samples: len(clean)}

	// uniques
	seen := map[string]int{}
	for _, t := range clean {
		seen[t]++
	}
	res.Unique = len(seen)
	res.Duplicates = len(clean) - res.Unique
	if res.Duplicates > 0 {
		dupes := map[string]bool{}
		for t, n := range seen {
			if n > 1 {
				dupes[t] = true
			}
		}
		res.Notes = append(res.Notes, fmt.Sprintf("%d duplicate token(s) — tokens are being reused", res.Duplicates))
	}

	// lengths
	minL, maxL := len(clean[0]), len(clean[0])
	sum := 0
	for _, t := range clean {
		if len(t) < minL {
			minL = len(t)
		}
		if len(t) > maxL {
			maxL = len(t)
		}
		sum += len(t)
	}
	res.MinLen, res.MaxLen = minL, maxL
	res.AvgLen = float64(sum) / float64(len(clean))
	if minL != maxL {
		res.Notes = append(res.Notes, "token lengths vary — per-position analysis skipped")
	}

	// char frequency + entropy
	freq := map[rune]int{}
	total := 0
	for _, t := range clean {
		for _, c := range t {
			freq[c]++
			total++
		}
	}
	res.CharsetSize = len(freq)
	for _, n := range freq {
		p := float64(n) / float64(total)
		res.EntropyBits -= p * math.Log2(p)
	}
	// chi-square uniformity
	exp := float64(total) / float64(res.CharsetSize)
	if exp > 0 {
		for _, n := range freq {
			res.ChiSquare += math.Pow(float64(n)-exp, 2) / exp
		}
		res.DF = res.CharsetSize - 1
	}

	// per-position entropy (fixed length only)
	if minL == maxL && minL > 0 {
		positions := make([]map[rune]int, minL)
		for i := range positions {
			positions[i] = map[rune]int{}
		}
		for _, t := range clean {
			for i, c := range []rune(t) {
				positions[i][c]++
			}
		}
		for _, pos := range positions {
			h := 0.0
			for _, n := range pos {
				p := float64(n) / float64(len(clean))
				h -= p * math.Log2(p)
			}
			res.PosEntropy = append(res.PosEntropy, round2(h))
		}
		// a position with near-zero entropy across samples is a tell
		for i, h := range res.PosEntropy {
			if h < 1.0 {
				res.Notes = append(res.Notes, fmt.Sprintf("position %d has ~%.2f bits entropy — constant or time-ordered segment", i+1, h))
			}
		}
	}

	// hex monobit
	if allHex(clean) {
		var ones, bits int
		for _, t := range clean {
			b, err := hex.DecodeString(t)
			if err != nil {
				continue
			}
			for _, by := range b {
				for i := 7; i >= 0; i-- {
					bits++
					if by&(1<<uint(i)) != 0 {
						ones++
					}
				}
			}
		}
		if bits > 0 {
			ratio := float64(ones) / float64(bits)
			res.Monobit = &MonobitResult{
				TotalBits: bits, Ones: ones, Ratio: round2(ratio),
				Pass: ratio > 0.45 && ratio < 0.55, // relaxed vs FIPS 0.495–0.505 for small n
			}
			if !res.Monobit.Pass {
				res.Notes = append(res.Notes, "bit balance skewed — generator may be biased")
			}
		}
	}

	// compression ratio (structured tokens compress)
	var raw bytes.Buffer
	raw.WriteString(strings.Join(clean, "\n"))
	var z bytes.Buffer
	zw := gzip.NewWriter(&z)
	zw.Write(raw.Bytes())
	zw.Close()
	if raw.Len() > 0 {
		res.Compression = round2(float64(z.Len()) / float64(raw.Len()))
	}

	// verdict
	res.Verdict = verdict(res)
	return res, nil
}

func verdict(r *SequencerResult) string {
	// entropy efficiency: how close the observed per-char entropy is to the
	// alphabet's maximum (hex caps at 4 bits — judge proportionally)
	eff := 0.0
	if r.CharsetSize > 1 {
		max := math.Log2(float64(r.CharsetSize))
		eff = r.EntropyBits / max
	}
	score := 0
	switch {
	case eff >= 0.95:
		score += 2
	case eff >= 0.85:
		score += 1
	}
	if r.Duplicates == 0 {
		score++
	}
	if r.Monobit != nil && r.Monobit.Pass {
		score++
		// for small alphabets (hex) the bit-level test is the decisive
		// signal — the compression heuristic cannot apply there
		if r.CharsetSize < 32 {
			score++
		}
	}
	// gzip structure detection only makes sense for large alphabets: hex
	// compresses ~2:1 regardless of randomness (4 bits of info per byte)
	if r.CharsetSize >= 32 {
		if r.Compression > 0.95 {
			score++
		} else if r.Compression < 0.8 && score > 0 {
			score-- // strong structure detected
		}
	} else if r.Compression > 0.95 {
		score++
	}
	switch {
	case r.Duplicates > 0 || eff < 0.6:
		return "poor"
	case score >= 5:
		return "good"
	case score >= 3:
		return "acceptable"
	default:
		return "weak"
	}
}

func allHex(tokens []string) bool {
	for _, t := range tokens {
		t = strings.TrimSpace(t)
		if t == "" || len(t)%2 != 0 {
			return false
		}
		for _, c := range t {
			if !strings.ContainsRune("0123456789abcdefABCDEF", c) {
				return false
			}
		}
	}
	return true
}

func round2(v float64) float64 {
	return math.Round(v*100) / 100
}

var _ = sort.Ints
