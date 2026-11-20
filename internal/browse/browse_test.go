package browse

import (
	"errors"
	"os/exec"
	"strings"
	"testing"
)

// fakeFS lets tests dictate which paths exist and which binaries are on PATH.
type fakeFS struct {
	onPath map[string]string // name → resolved path
	exists map[string]bool   // absolute paths
}

func (f fakeFS) lookPath(name string) (string, error) {
	if p, ok := f.onPath[name]; ok {
		return p, nil
	}
	return "", exec.ErrNotFound
}

func (f fakeFS) stat(p string) error {
	if f.exists[p] {
		return nil
	}
	return errors.New("not found")
}

func TestFindPrefersChromiumOverChrome(t *testing.T) {
	fs := fakeFS{
		onPath: map[string]string{
			"google-chrome": "/usr/bin/google-chrome",
			"chromium":      "/usr/bin/chromium",
		},
		exists: map[string]bool{},
	}
	b, err := Find("", "linux", fs.lookPath, fs.stat)
	if err != nil {
		t.Fatal(err)
	}
	if b.Name != "chromium" || b.Path != "/usr/bin/chromium" {
		t.Fatalf("got %+v, want chromium from PATH", b)
	}
}

func TestFindPlatformDefaults(t *testing.T) {
	// nothing on PATH, but the darwin app exists
	fs := fakeFS{
		onPath: map[string]string{},
		exists: map[string]bool{
			"/Applications/Chromium.app/Contents/MacOS/Chromium": true,
		},
	}
	b, err := Find("", "darwin", fs.lookPath, fs.stat)
	if err != nil || b.Name != "chromium" {
		t.Fatalf("darwin default: %+v err=%v", b, err)
	}

	// windows falls through to Chrome when Edge/Chromium absent
	fs = fakeFS{
		onPath: map[string]string{},
		exists: map[string]bool{
			`C:\Program Files\Google\Chrome\Application\chrome.exe`: true,
		},
	}
	b, err = Find("", "windows", fs.lookPath, fs.stat)
	if err != nil || b.Name != "chrome" {
		t.Fatalf("windows default: %+v err=%v", b, err)
	}
}

func TestFindOverrideWins(t *testing.T) {
	fs := fakeFS{
		onPath: map[string]string{"chromium": "/usr/bin/chromium"},
		exists: map[string]bool{"/opt/custom/browser": true},
	}
	b, err := Find("/opt/custom/browser", "linux", fs.lookPath, fs.stat)
	if err != nil {
		t.Fatal(err)
	}
	if b.Path != "/opt/custom/browser" {
		t.Fatalf("override ignored: %+v", b)
	}
}

func TestFindOverrideMissingFails(t *testing.T) {
	fs := fakeFS{onPath: map[string]string{}, exists: map[string]bool{}}
	if _, err := Find("/nope", "linux", fs.lookPath, fs.stat); err == nil {
		t.Fatal("missing override must fail")
	}
}

func TestFindNoneFound(t *testing.T) {
	fs := fakeFS{onPath: map[string]string{}, exists: map[string]bool{}}
	if _, err := Find("", "linux", fs.lookPath, fs.stat); err == nil {
		t.Fatal("expected ErrNoBrowser")
	}
}

func TestFindEdgeOnlyOnWindowsPath(t *testing.T) {
	fs := fakeFS{
		onPath: map[string]string{"msedge": `/C:\Program Files (x86)\Microsoft\Edge\Application\msedge.exe`},
		exists: map[string]bool{},
	}
	// msedge must be skipped on linux even if on PATH
	if b, err := Find("", "linux", fs.lookPath, fs.stat); err == nil {
		t.Fatalf("msedge accepted on linux: %+v", b)
	}
}

func TestBuildArgsStable(t *testing.T) {
	args := BuildArgs(LaunchOpts{
		Browser:    &Browser{Path: "/usr/bin/chromium", Name: "chromium"},
		ProxyAddr:  "127.0.0.1:8080",
		ProfileDir: "/tmp/prof",
	})
	want := []string{
		"--user-data-dir=/tmp/prof",
		"--proxy-server=http://127.0.0.1:8080",
		"--no-first-run",
		"--no-default-browser-check",
		"--disable-fre",
		"--disable-session-crashed-bubble",
		"--disable-background-networking",
		"--homepage=about:blank",
		"about:blank",
	}
	if strings.Join(args, " ") != strings.Join(want, " ") {
		t.Fatalf("args = %v", args)
	}
}

func TestBuildArgsHeadlessAndURL(t *testing.T) {
	args := BuildArgs(LaunchOpts{
		ProxyAddr: "127.0.0.1:9999", ProfileDir: "/p", URL: "http://target.example/", Headless: true,
		ExtraArgs: []string{"--dump-dom"},
	})
	joined := strings.Join(args, " ")
	if !strings.HasPrefix(joined, "--headless=new --user-data-dir=") {
		t.Errorf("headless must lead: %v", args)
	}
	if !strings.HasSuffix(joined, "--dump-dom") {
		t.Errorf("extra args must trail: %v", args)
	}
	for _, a := range args {
		if a == "about:blank" {
			t.Errorf("a URL must replace the about:blank target (headless allows one target): %v", args)
		}
	}
	if !strings.Contains(joined, "http://target.example/") {
		t.Errorf("URL missing: %v", args)
	}
}

func TestCATrustCommandShapes(t *testing.T) {
	t.Setenv("HOME", "/home/tester")
	darwin := NewCATrust("/tmp/root.pem")
	darwin.GOOS = "darwin"
	inst := strings.Join(darwin.InstallArgs(), " ")
	if !strings.Contains(inst, "security add-trusted-cert") ||
		!strings.Contains(inst, "/home/tester/Library/Keychains/login.keychain-db") ||
		!strings.Contains(inst, "/tmp/root.pem") {
		t.Errorf("darwin install: %q", inst)
	}
	if !strings.Contains(strings.Join(darwin.RemoveArgs(), " "), "security remove-trusted-cert") {
		t.Errorf("darwin remove: %v", darwin.RemoveArgs())
	}

	linux := NewCATrust("/tmp/root.pem")
	linux.GOOS = "linux"
	instL := strings.Join(linux.InstallArgs(), " ")
	if !strings.Contains(instL, "certutil -d sql:/home/tester/.pki/nssdb -A") ||
		!strings.Contains(instL, "-t C,,") || !strings.Contains(instL, "ProxyForge Root CA") {
		t.Errorf("linux install: %q", instL)
	}
	if !strings.Contains(strings.Join(linux.RemoveArgs(), " "), "-D -n ProxyForge Root CA") {
		t.Errorf("linux remove: %v", linux.RemoveArgs())
	}

	win := NewCATrust("/tmp/root.pem")
	win.GOOS = "windows"
	if win.InstallArgs() != nil || win.Supported() {
		t.Error("windows must not automate trust")
	}
}
