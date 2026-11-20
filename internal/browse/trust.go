package browse

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
)

// CATrust installs/removes the ProxyForge root into the USER's browser
// trust store for the duration of a browse session (flag-gated: never
// silent). Windows is not supported via CLI — the CA page shows manual
// steps instead.
type CATrust struct {
	GOOS string // runtime override for tests
	cert string // PEM path
}

// NewCATrust builds a trust helper for the given root PEM path.
func NewCATrust(certPath string) *CATrust { return &CATrust{GOOS: runtime.GOOS, cert: certPath} }

// Supported reports whether trust can be automated on this platform.
func (t *CATrust) Supported() bool { return t.GOOS == "darwin" || t.GOOS == "linux" }

// InstallArgs returns the command that installs the cert (nil when
// unsupported). Exported for tests and for showing the user exactly what
// would run.
func (t *CATrust) InstallArgs() []string {
	switch t.GOOS {
	case "darwin":
		return []string{"security", "add-trusted-cert", "-d", "-r", "trustRoot",
			"-k", os.Getenv("HOME") + "/Library/Keychains/login.keychain-db", t.cert}
	case "linux":
		db := os.Getenv("HOME") + "/.pki/nssdb"
		return []string{"certutil", "-d", "sql:" + db, "-A", "-t", "C,,", "-n", "ProxyForge Root CA", "-i", t.cert}
	}
	return nil
}

// RemoveArgs returns the command that removes the cert again.
func (t *CATrust) RemoveArgs() []string {
	switch t.GOOS {
	case "darwin":
		return []string{"security", "remove-trusted-cert", "-d", t.cert}
	case "linux":
		db := os.Getenv("HOME") + "/.pki/nssdb"
		return []string{"certutil", "-d", "sql:" + db, "-D", "-n", "ProxyForge Root CA"}
	}
	return nil
}

// Install runs InstallArgs (a missing certutil on Linux is reported as a
// hint, not a crash).
func (t *CATrust) Install() error {
	args := t.InstallArgs()
	if args == nil {
		return fmt.Errorf("browse: automatic CA trust not supported on %s — see http://proxy.local", t.GOOS)
	}
	cmd := exec.Command(args[0], args[1:]...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("browse: CA trust failed: %v: %s", err, string(out))
	}
	return nil
}

// Remove runs RemoveArgs; failures are returned but cleanup continues.
func (t *CATrust) Remove() error {
	args := t.RemoveArgs()
	if args == nil {
		return nil
	}
	cmd := exec.Command(args[0], args[1:]...)
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("browse: CA untrust failed: %v: %s", err, string(out))
	}
	return nil
}
