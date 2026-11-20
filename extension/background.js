// ProxyForge Tagger — context-menu "tag this site" → POST /api/v1/annotate-tab
// The API token is set once on the options page.

const DEFAULTS = { apiBase: "http://127.0.0.1:8765", minutes: 10 };

chrome.runtime.onInstalled.addListener(() => {
  chrome.contextMenus.create({
    id: "proxyforge-tag",
    title: "Tag this site in ProxyForge (%d min)",
    contexts: ["page", "page_action"],
  });
});

chrome.contextMenus.onClicked.addListener(async (info, tab) => {
  if (info.menuItemId !== "proxyforge-tag" || !tab?.url) return;
  const cfg = await chrome.storage.local.get(DEFAULTS);
  let origin;
  try {
    origin = new URL(tab.url).origin;
  } catch {
    return;
  }
  try {
    const resp = await fetch(`${cfg.apiBase}/api/v1/annotate-tab`, {
      method: "POST",
      headers: {
        "Content-Type": "application/json",
        Authorization: `Bearer ${cfg.token ?? ""}`,
      },
      body: JSON.stringify({ origin, minutes: cfg.minutes }),
    });
    if (resp.status === 401) {
      console.warn("ProxyForge: unauthorized — set the token on the options page");
    }
  } catch (e) {
    console.warn("ProxyForge: tag request failed (is the daemon running?)", e);
  }
});
