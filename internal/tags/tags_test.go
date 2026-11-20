package tags

import (
	"testing"
	"time"
)

func TestNormalizeHost(t *testing.T) {
	cases := map[string]string{
		"https://api.example.com":       "api.example.com",
		"http://api.example.com:8443":   "api.example.com:8443",
		"api.example.com":               "api.example.com",
		"  API.Example.COM/PATH ":       "api.example.com",
		"https://api.example.com/x?q=1": "api.example.com",
	}
	for in, want := range cases {
		if got := NormalizeHost(in); got != want {
			t.Errorf("NormalizeHost(%q) = %q, want %q", in, got, want)
		}
	}
}

func TestSetMatchExpiry(t *testing.T) {
	m := New()
	m.Set("https://api.example.com", 50*time.Millisecond)
	if !m.Match("api.example.com") {
		t.Fatal("live tag not matched")
	}
	if m.Match("other.example.com") {
		t.Fatal("unrelated host matched")
	}
	time.Sleep(60 * time.Millisecond)
	if m.Match("api.example.com") {
		t.Fatal("expired tag matched")
	}
	if len(m.Active()) != 0 {
		t.Fatal("expired tag still listed")
	}
}

func TestDefaultDuration(t *testing.T) {
	m := New()
	m.Set("example.com", 0)
	if len(m.Active()) != 1 {
		t.Fatal("default duration not applied")
	}
	if rem := m.Active()["example.com"]; rem <= 0 || rem > 11*time.Minute {
		t.Fatalf("default remaining = %v", rem)
	}
}
