# Client setup guide

How to point each client at ProxyForge and trust its CA — and how to undo
both when the engagement ends.

Defaults: proxy `127.0.0.1:8080`, UI/API `127.0.0.1:8765`, CA download
`http://proxy.local/ca.pem` (served through the proxy) or
`proxyforge ca export`.

## One-command browser (Chromium family)

```bash
proxyforge browse                  # throwaway profile, proxied
proxyforge browse -trust-ca https://target.example/   # session CA trust (macOS/Linux)
```

The profile is temporary and deleted on exit; `-trust-ca` removes the trust
when the browser exits. Manual steps for everything else below.

## Firefox

- Proxy: Settings → Network Settings → Manual: HTTP proxy `127.0.0.1`
  port `8080`, check "Also use this proxy for HTTPS".
- CA: Settings → Privacy & Security → Certificates → View Certificates →
  Authorities → Import → `proxyforge-root-ca.pem` → check "Trust this CA to
  identify websites".
- **Remove**: delete the proxy settings; Authorities → ProxyForge Root CA →
  Delete or Distrust.

## Chrome / Chromium / Edge

Chrome-family browsers use the OS trust store (Linux: NSS).

- Proxy: launch with
  `--proxy-server=http://127.0.0.1:8080 --user-data-dir=/tmp/proxyforge-profile`
  (or set the system proxy).
- CA (macOS):
  `security add-trusted-cert -d -r trustRoot -k ~/Library/Keychains/login.keychain-db proxyforge-root-ca.pem`
- CA (Linux):
  `mkdir -p ~/.pki/nssdb && certutil -d sql:$HOME/.pki/nssdb -A -t "C,," -n "ProxyForge Root CA" -i proxyforge-root-ca.pem`
- CA (Windows): double-click the PEM → Install Certificate → Local Machine →
  Trusted Root Certification Authorities.
- **Remove** (macOS): `security remove-trusted-cert -d proxyforge-root-ca.pem`
  (or Keychain Access → System → ProxyForge Root CA → Delete).
- **Remove** (Linux):
  `certutil -d sql:$HOME/.pki/nssdb -D -n "ProxyForge Root CA"`
- **Remove** (Windows): `certmgr.msc` → Trusted Root Certification Authorities →
  Certificates → ProxyForge Root CA → Delete.

## Safari (macOS)

- Proxy: System Settings → Network → Details → Proxies → Web Proxy
  `127.0.0.1:8080`.
- CA: as Chrome (macOS) above, then restart Safari.
- **Remove**: undo both.

## Android

- Proxy: Wi-Fi → network → Advanced → Manual proxy → `127.0.0.1` won't work —
  use your workstation's LAN IP and ProxyForge's proxy listener bound to it
  (`-proxy-addr 0.0.0.0:8080`, firewall accordingly, engagement-only).
- CA: download `http://proxy.local/ca.pem` from the device browser (through
  the proxy), then Settings → Security → Install CA cert. Note: user-installed
  CAs are trusted by Firefox and most apps, but not by Chrome/system apps on
  Android 7+ (needs root or a managed profile).
- **Remove**: uninstall the CA (Settings → Security → Trusted credentials →
  User) and the proxy.

## iOS

- Proxy: Wi-Fi → (i) → HTTP Proxy → Manual → workstation IP, port 8080.
- CA: visit `http://proxy.local/ca.pem` via Safari, allow the profile
  download, then Settings → Profile Downloaded → Install; for HTTPS in
  Safari also enable Settings → General → About → Certificate Trust
  Settings → ProxyForge Root CA.
- **Remove**: remove the profile (Settings → General → VPN & Device
  Management) and the proxy.

## curl

```bash
curl -x http://127.0.0.1:8080 --cacert proxyforge-root-ca.pem https://target.example/
```

## Python (requests)

```python
proxies = {"http": "http://127.0.0.1:8080", "https": "http://127.0.0.1:8080"}
requests.get("https://target.example/", proxies=proxies, verify="proxyforge-root-ca.pem")
```

## Node (undici/fetch)

```js
import { ProxyAgent, Agent } from "undici";
import { readFileSync } from "node:fs";
const ca = readFileSync("proxyforge-root-ca.pem", "utf8");
const proxy = new ProxyAgent({ uri: "http://127.0.0.1:8080", requestTls: { ca } });
fetch("https://target.example/", { dispatcher: proxy });
```

## Go

```go
proxyURL, _ := url.Parse("http://127.0.0.1:8080")
rootPEM, _ := os.ReadFile("proxyforge-root-ca.pem")
pool := x509.NewCertPool()
pool.AppendCertsFromPEM(rootPEM)
client := &http.Client{Transport: &http.Transport{
    Proxy:           http.ProxyURL(proxyURL),
    TLSClientConfig: &tls.Config{RootCAs: pool},
}}
```

## Pinned apps

Certificate pinning will defeat MITM regardless of trust — add the host to
`passthrough` in `~/.proxyforge/config.toml` to tunnel it opaquely instead
of breaking the app.
