const DEFAULTS = { apiBase: "http://127.0.0.1:8765", minutes: 10, token: "" };

async function load() {
  const cfg = await chrome.storage.local.get(DEFAULTS);
  token.value = cfg.token;
  apiBase.value = cfg.apiBase;
  minutes.value = cfg.minutes;
}

async function save() {
  await chrome.storage.local.set({
    token: token.value.trim(),
    apiBase: apiBase.value.trim().replace(/\/$/, ""),
    minutes: Math.max(1, Math.min(240, Number(minutes.value) || 10)),
  });
  status.textContent = "saved ✓";
  setTimeout(() => (status.textContent = ""), 1500);
}

document.getElementById("save").addEventListener("click", save);
load();
