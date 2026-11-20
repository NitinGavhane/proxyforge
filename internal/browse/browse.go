// Package browse launches a throwaway-profile Chromium-family browser
// preconfigured to use ProxyForge (Phase 2).
package browse

import (
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
)

// osStat adapts os.Stat to the injectable error-only signature.
func osStat(p string) error {
	_, err := os.Stat(p)
	return err
}

// Browser is a located Chromium-family browser.
type Browser struct {
	Path string // executable path
	Name string // "chromium" | "chrome" | "edge" | custom
}

// candidateBinaries in priority order per platform.
func candidateBinaries(goos string) []Browser {
	switch goos {
	case "darwin":
		return []Browser{
			{Path: "/Applications/Chromium.app/Contents/MacOS/Chromium", Name: "chromium"},
			{Path: "/usr/local/bin/chromium", Name: "chromium"},
			{Path: "/opt/homebrew/bin/chromium", Name: "chromium"},
			{Path: "/Applications/Google Chrome.app/Contents/MacOS/Google Chrome", Name: "chrome"},
			{Path: "/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge", Name: "edge"},
		}
	case "windows":
		base := `C:\Program Files`
		base86 := `C:\Program Files (x86)`
		return []Browser{
			{Path: base + `\Chromium\Application\chrome.exe`, Name: "chromium"},
			{Path: base86 + `\Chromium\Application\chrome.exe`, Name: "chromium"},
			{Path: base + `\Google\Chrome\Application\chrome.exe`, Name: "chrome"},
			{Path: base86 + `\Google\Chrome\Application\chrome.exe`, Name: "chrome"},
			{Path: base + `\Microsoft\Edge\Application\msedge.exe`, Name: "edge"},
			{Path: base86 + `\Microsoft\Edge\Application\msedge.exe`, Name: "edge"},
		}
	default: // linux & the bsds
		return []Browser{
			{Path: "/usr/bin/chromium", Name: "chromium"},
			{Path: "/usr/bin/chromium-browser", Name: "chromium"},
			{Path: "/snap/bin/chromium", Name: "chromium"},
			{Path: "/usr/bin/google-chrome", Name: "chrome"},
			{Path: "/usr/bin/google-chrome-stable", Name: "chrome"},
			{Path: "/usr/bin/microsoft-edge", Name: "edge"},
		}
	}
}

// pathNames are PATH-relative names tried before platform paths (in order).
var pathNames = []string{"chromium", "chromium-browser", "google-chrome", "google-chrome-stable", "chrome", "msedge"}

// ErrNoBrowser is returned when no Chromium-family browser is found.
var ErrNoBrowser = errors.New("browse: no Chromium-family browser found (set PROXYFORGE_BROWSER or -browser)")

// Find locates a browser: the explicit override first, then PATH, then
// platform defaults. lookPath/stat are injectable for tests; nil uses the
// real os/exec implementations.
func Find(override string, goos string, lookPath func(string) (string, error), stat func(string) error) (*Browser, error) {
	if lookPath == nil {
		lookPath = exec.LookPath
	}
	if stat == nil {
		stat = osStat
	}
	if override != "" {
		if p, err := lookPath(override); err == nil {
			return &Browser{Path: p, Name: filepath.Base(p)}, nil
		}
		if err := stat(override); err == nil {
			return &Browser{Path: override, Name: filepath.Base(override)}, nil
		}
		return nil, fmt.Errorf("browse: -browser/PROXYFORGE_BROWSER %q not found", override)
	}
	// PATH candidates (platform-appropriate names only)
	for _, name := range pathNames {
		switch name {
		case "msedge":
			if goos != "windows" {
				continue
			}
		case "chromium-browser":
			if goos != "linux" {
				continue
			}
		}
		if p, err := lookPath(name); err == nil {
			return &Browser{Path: p, Name: name}, nil
		}
	}
	for _, c := range candidateBinaries(goos) {
		if err := stat(c.Path); err == nil {
			if p, err := lookPath(c.Path); err == nil && goos != "windows" {
				return &Browser{Path: p, Name: c.Name}, nil // absolute + executable
			}
			return &Browser{Path: c.Path, Name: c.Name}, nil
		}
	}
	return nil, ErrNoBrowser
}

// LaunchOpts describe one browser launch.
type LaunchOpts struct {
	Browser    *Browser
	ProxyAddr  string // e.g. 127.0.0.1:8080
	ProfileDir string // throwaway user-data-dir
	URL        string // optional page to open
	ExtraArgs  []string
	Headless   bool // smoke/CI use
}

// BuildArgs renders the stable launch argument set. Order is fixed so tests
// and users can diff it.
//
// Loopback stays OUTSIDE the proxy (Chrome's default): the UI and the
// daemon's own endpoints are reached directly, while http://proxy.local is
// intercepted by the engine (virtual host).
func BuildArgs(o LaunchOpts) []string {
	args := []string{
		"--user-data-dir=" + o.ProfileDir,
		"--proxy-server=http://" + o.ProxyAddr,
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-fre",
		"--disable-session-crashed-bubble",
		"--disable-background-networking",
		"--homepage=about:blank",
	}
	if o.URL != "" {
		args = append(args, o.URL)
	} else {
		args = append(args, "about:blank") // headless rejects multiple targets
	}
	if o.Headless {
		args = append([]string{"--headless=new"}, args...)
	}
	args = append(args, o.ExtraArgs...)
	return args
}

// HomeArgs is a helper for docs: the minimal manual equivalent.
func HomeArgs(proxyAddr string) string {
	return strings.Join([]string{
		"--proxy-server=http://" + proxyAddr,
		"--user-data-dir=/tmp/proxyforge-profile",
	}, " ")
}
