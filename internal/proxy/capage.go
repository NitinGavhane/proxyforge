// http://proxy.local — a virtual host served by the engine itself for any
// proxied client (the CA page, Phase 2). Traffic to it is never forwarded,
// logged, intercepted, or modified.
package proxy

import (
	"net/http"
	"runtime"
	"strings"
)

// ProxyLocalHost is the reserved virtual hostname.
const ProxyLocalHost = "proxy.local"

// isProxyLocal reports whether the request targets the virtual host.
func isProxyLocal(host string) bool {
	h, _, err := splitHost(host)
	if err != nil {
		return false
	}
	return strings.EqualFold(h, ProxyLocalHost)
}

// splitHost strips an optional :port without importing net here.
func splitHost(hostport string) (string, string, error) {
	i := strings.LastIndexByte(hostport, ':')
	if i < 0 {
		return hostport, "", nil
	}
	return hostport[:i], hostport[i+1:], nil
}

// serveProxyLocal handles the virtual host. It never reveals the API token.
func (e *Engine) serveProxyLocal(w http.ResponseWriter, r *http.Request) {
	switch r.URL.Path {
	case "/ca.pem":
		if e.CA == nil {
			http.Error(w, "MITM CA not configured on this instance", http.StatusServiceUnavailable)
			return
		}
		w.Header().Set("Content-Type", "application/x-pem-file")
		w.Header().Set("Content-Disposition", `attachment; filename="proxyforge-root-ca.pem"`)
		_, _ = w.Write(e.CA.RootPEM())
	case "/health":
		w.Header().Set("Content-Type", "application/json")
		_, _ = w.Write([]byte(`{"ok":true,"service":"proxyforge"}`))
	case "/", "/index.html":
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		_, _ = w.Write([]byte(caPageHTML(r.Header.Get("User-Agent"), runtime.GOOS, e.CA != nil)))
	default:
		http.NotFound(w, r)
	}
}

func caPageHTML(ua, goos string, caReady bool) string {
	firefox := strings.Contains(ua, "Firefox")
	chrome := strings.Contains(ua, "Chrome") && !strings.Contains(ua, "Edg/")
	edge := strings.Contains(ua, "Edg/")
	section := func(name string, on bool, body string) string {
		cls := "section"
		if on {
			cls += " active"
		}
		return `<div class="` + cls + `"><h2>` + name + `</h2>` + body + `</div>`
	}
	var sections string
	sections += section("Firefox"+mark(firefox), firefox, `<ol>
<li>Settings → Privacy &amp; Security → Certificates → <b>Import…</b></li>
<li>Choose <a href="/ca.pem">proxyforge-root-ca.pem</a> (downloaded below)</li>
<li>Check <b>Trust this CA to identify websites</b></li>
<li>Set the proxy: Settings → Network → Manual proxy → <code>127.0.0.1</code> port <code>8080</code></li></ol>`)
	sections += section("Chrome / Chromium"+mark(chrome || edge), chrome || edge, `<ol>
<li>Download <a href="/ca.pem">proxyforge-root-ca.pem</a></li>
<li>`+osTrustStep(goos)+`</li>
<li>Restart the browser, then launch it with
<code>`+HomeArgsDocs()+`</code></li></ol>`)
	sections += section("curl", false, `<pre>curl -x http://127.0.0.1:8080 --cacert proxyforge-root-ca.pem https://target.example/</pre>`)
	ready := `<p class="ok">MITM CA is configured.</p>`
	if !caReady {
		ready = `<p class="warn">This instance has no CA loaded — HTTPS interception is off.</p>`
	}
	return `<!doctype html><html><head><meta charset="utf-8"><title>ProxyForge</title><style>
body{font-family:ui-sans-serif,system-ui,sans-serif;background:#0b0e14;color:#cdd6e1;max-width:44rem;margin:2rem auto;padding:0 1rem}
h1{color:#7dd3fc} a{color:#7dd3fc} code{background:#1a2230;padding:2px 6px;border-radius:4px;color:#a5f3fc}
.section{border:1px solid #1f2733;border-radius:8px;padding:1rem;margin:1rem 0}
.section.active{border-color:#0ea5e9}
.section h2{margin-top:0;font-size:1rem;color:#e2e8f0}
.ok{color:#34d399}.warn{color:#fbbf24}ol,pre{font-size:.9rem}
</style></head><body>
<h1>⚒ ProxyForge</h1>` + ready + `
<p>This page is served by the proxy itself (virtual host <code>proxy.local</code>).
Download the root CA and trust it <b>only for the duration of your
engagement</b>.</p>
<p><a class="dl" href="/ca.pem"><b>⬇ Download proxyforge-root-ca.pem</b></a></p>
` + sections + `
<p class="warn">Remove the trust when finished — see the removal steps in
ProxyForge's <code>docs/CLIENTS.md</code>.</p>
</body></html>`
}

func mark(on bool) string {
	if on {
		return " ← your browser"
	}
	return ""
}

func osTrustStep(goos string) string {
	switch goos {
	case "darwin":
		return `macOS: double-click the PEM → Keychain Access → always trust, or<br>
		<code>security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain-db proxyforge-root-ca.pem</code>`
	case "linux":
		return `Linux (Chrome uses NSS):<br><code>mkdir -p ~/.pki/nssdb && certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "ProxyForge Root CA" -i proxyforge-root-ca.pem</code>`
	default:
		return `Windows: double-click the PEM → Install Certificate → Local Machine → Trusted Root Certification Authorities`
	}
}

func HomeArgsDocs() string {
	return `--proxy-server=http://127.0.0.1:8080 --user-data-dir=/tmp/proxyforge-profile`
}
