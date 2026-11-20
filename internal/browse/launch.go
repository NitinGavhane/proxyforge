package browse

import (
	"fmt"
	"os"
	"os/exec"
	"os/signal"
	"syscall"
)

// Session is one launched browser.
type Session struct {
	cmd      *exec.Cmd
	profile  string
	trust    *CATrust
	keepProf bool
}

// Launch starts the browser and returns the session. Call Wait to block
// until it exits (cleanup happens automatically), or Close early.
func Launch(o LaunchOpts, trustCA bool, rootPEMPath string, keepProfile bool, stdout, stderr *os.File) (*Session, error) {
	if o.Browser == nil {
		return nil, fmt.Errorf("browse: no browser")
	}
	if o.ProfileDir == "" {
		dir, err := os.MkdirTemp("", "proxyforge-profile-*")
		if err != nil {
			return nil, err
		}
		o.ProfileDir = dir
	}
	s := &Session{profile: o.ProfileDir, keepProf: keepProfile}
	if trustCA && rootPEMPath != "" {
		s.trust = NewCATrust(rootPEMPath)
		if err := s.trust.Install(); err != nil {
			return nil, err
		}
	}
	args := BuildArgs(o)
	cmd := exec.Command(o.Browser.Path, args...)
	if stdout != nil {
		cmd.Stdout = stdout
	}
	if stderr != nil {
		cmd.Stderr = stderr
	}
	if err := cmd.Start(); err != nil {
		_ = s.cleanup()
		return nil, fmt.Errorf("browse: launch %s: %w", o.Browser.Path, err)
	}
	s.cmd = cmd
	return s, nil
}

// Pid exposes the browser pid.
func (s *Session) Pid() int { return s.cmd.Process.Pid }

// Wait blocks until the browser exits, cleaning up the profile and the
// trusted CA afterwards. Interrupts (Ctrl-C) terminate the browser first.
func (s *Session) Wait() error {
	sig := make(chan os.Signal, 1)
	signal.Notify(sig, os.Interrupt, syscall.SIGTERM)
	defer signal.Stop(sig)
	done := make(chan error, 1)
	go func() { done <- s.cmd.Wait() }()
	select {
	case err := <-done:
		_ = s.cleanup()
		return err
	case got := <-sig:
		_ = s.cmd.Process.Signal(got)
		err := <-done
		_ = s.cleanup()
		return err
	}
}

// Close terminates the browser and cleans up.
func (s *Session) Close() error {
	if s.cmd.Process != nil {
		_ = s.cmd.Process.Kill()
		_, _ = s.cmd.Process.Wait()
	}
	return s.cleanup()
}

func (s *Session) cleanup() error {
	if s.trust != nil {
		_ = s.trust.Remove()
	}
	if !s.keepProf {
		return os.RemoveAll(s.profile)
	}
	return nil
}
