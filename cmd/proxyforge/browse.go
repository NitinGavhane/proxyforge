package main

import (
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"

	"github.com/NitinGavhane/proxyforge/internal/browse"
	"github.com/NitinGavhane/proxyforge/internal/ca"
	"github.com/NitinGavhane/proxyforge/internal/config"
)

// cmdBrowse launches a Chromium-family browser with a throwaway profile,
// preconfigured for the proxy. Requires the daemon to be running.
//
//	usage: proxyforge browse [flags] [url]
//	  -browser path     explicit browser binary (or PROXYFORGE_BROWSER)
//	  -proxy addr       proxy addr (default from config, e.g. 127.0.0.1:8080)
//	  -trust-ca         trust the ProxyForge root for this session and
//	                    remove it when the browser exits (macOS/Linux)
//	  -headless         headless mode (smoke tests)
//	  -dump             headless + --dump-dom of the URL to stdout
//	  -keep-profile     do not delete the throwaway profile afterwards
func cmdBrowse(args []string) {
	fs := flag.NewFlagSet("browse", flag.ExitOnError)
	browserFlag := fs.String("browser", os.Getenv("PROXYFORGE_BROWSER"), "explicit browser binary")
	proxyFlag := fs.String("proxy", "", "proxy addr (default from config)")
	trustCA := fs.Bool("trust-ca", false, "trust the root CA for this session (reverted on exit)")
	headless := fs.Bool("headless", false, "headless browser (smoke tests)")
	dump := fs.Bool("dump", false, "headless + --dump-dom of the URL to stdout")
	keepProfile := fs.Bool("keep-profile", false, "keep the throwaway profile dir")
	_ = fs.Parse(args)
	url := ""
	if fs.NArg() > 0 {
		url = fs.Arg(0)
	}

	cfgDir, err := config.Dir()
	if err != nil {
		exitErr(err)
	}
	cfg, err := config.Load(cfgDir)
	if err != nil {
		exitErr(err)
	}
	if *proxyFlag != "" {
		cfg.ProxyAddr = *proxyFlag
	}

	b, err := browse.Find(*browserFlag, runtime.GOOS, nil, nil)
	if err != nil {
		fmt.Fprintln(os.Stderr, err)
		fmt.Fprintln(os.Stderr, "browse: manual setup steps: docs/CLIENTS.md · CA page: http://proxy.local")
		os.Exit(1)
	}
	fmt.Printf("browse: using %s (%s)\n", b.Name, b.Path)

	// export the CA so -trust-ca (and the user) can reach it
	caDir := filepath.Join(cfgDir, "ca")
	authority, err := ca.Load(caDir, ca.Options{KeyType: cfg.CAKeyType})
	if err != nil {
		exitErr(fmt.Errorf("load CA: %w", err))
	}
	certPath := filepath.Join(caDir, "exported-root.pem")
	if err := os.WriteFile(certPath, authority.RootPEM(), 0o644); err != nil {
		exitErr(err)
	}

	var extra []string
	if *dump {
		extra = append(extra, "--dump-dom")
	}
	sess, err := browse.Launch(
		browse.LaunchOpts{
			Browser:   b,
			ProxyAddr: cfg.ProxyAddr,
			URL:       url,
			Headless:  *headless || *dump,
			ExtraArgs: extra,
		},
		*trustCA, certPath, *keepProfile, os.Stdout, os.Stderr,
	)
	if err != nil {
		exitErr(err)
	}
	fmt.Printf("browse: pid %d · proxy %s · throwaway profile (removed on exit)\n", sess.Pid(), cfg.ProxyAddr)
	fmt.Printf("browse: CA page: http://proxy.local/  (UI: http://%s/)\n", cfg.APIAddr)
	if *trustCA {
		fmt.Println("browse: root CA trusted for this session — removed when the browser exits")
	} else {
		fmt.Println("browse: NOT trusting the CA automatically; trust it via http://proxy.local or rerun with -trust-ca")
	}
	if err := sess.Wait(); err != nil {
		fmt.Fprintf(os.Stderr, "browse: browser exited: %v\n", err)
	}
	fmt.Println("browse: session cleaned up")
}

func exitErr(err error) {
	fmt.Fprintln(os.Stderr, "proxyforge:", err)
	os.Exit(1)
}
