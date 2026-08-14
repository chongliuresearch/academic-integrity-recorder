import { browserDomainAllowed, extensionIsPrivate, send, settings } from "./shared.js";

async function tabIsForeground(tab: chrome.tabs.Tab): Promise<boolean> {
  if (!tab.active || tab.incognito || extensionIsPrivate() || tab.windowId === undefined) return false;
  try {
    const ownerWindow = await chrome.windows.get(tab.windowId);
    return ownerWindow.focused === true;
  } catch {
    return false;
  }
}

function httpUrl(value: string | undefined): URL | undefined {
  if (!value) return undefined;
  try {
    const url = new URL(value);
    return url.protocol === "http:" || url.protocol === "https:" ? url : undefined;
  } catch {
    return undefined;
  }
}

chrome.tabs.onUpdated.addListener(async (_tabId, change, tab) => {
  if (change.status !== "complete" || !(await tabIsForeground(tab))) return;
  const url = httpUrl(tab.url);
  if (!url) return;
  try {
    await send("webNavigation", {
      url: url.href,
      title: tab.title ?? "",
      transition: "active-tab-complete",
    }, { domain: url.hostname, privateMode: tab.incognito });
  } catch { /* rejection is expected for unselected domains or a disarmed project */ }
});

chrome.downloads.onCreated.addListener(async item => {
  if (item.incognito || extensionIsPrivate()) return;
  const tabs = await chrome.tabs.query({ active: true, lastFocusedWindow: true });
  const activeTab = tabs[0];
  if (!activeTab || !(await tabIsForeground(activeTab))) return;
  const downloadUrl = httpUrl(item.url);
  const tabUrl = httpUrl(activeTab.url);
  const referrer = httpUrl(item.referrer);
  if (!downloadUrl || !tabUrl) return;
  // Downloads cannot always be tied to a tab. Only accept a direct same-site/referrer match.
  if (downloadUrl.hostname !== tabUrl.hostname && referrer?.hostname !== tabUrl.hostname) return;
  try {
    await send("download", {
      url: downloadUrl.href,
      filename: item.filename,
      mime: item.mime,
      danger: item.danger,
    }, { domain: downloadUrl.hostname, privateMode: item.incognito });
  } catch { /* rejected when the source/domain is outside the armed scope */ }
});

chrome.runtime.onMessage.addListener((message, sender, respond) => {
  if (message?.type === "AIR_SCOPE_ALLOWED") {
    void (async () => {
      const tab = sender.tab;
      const url = httpUrl(tab?.url);
      const allowed = Boolean(
        tab
        && url
        && await tabIsForeground(tab)
        && await browserDomainAllowed(url.hostname, undefined, true),
      );
      respond({ allowed });
    })();
    return true;
  }
  if (message?.type !== "AIR_CAPTURE_AI" && message?.type !== "AIR_EVENT") return false;
  void (async () => {
    const tab = sender.tab;
    const url = httpUrl(tab?.url);
    if (!tab || !url || (sender.frameId !== undefined && sender.frameId !== 0) || !(await tabIsForeground(tab))) {
      respond({ ok: false, error: "capture is allowed only from the top-level foreground non-private tab" });
      return;
    }
    const contentKinds = new Set(["accessibleTextChanged", "webInteraction"]);
    if (message.type === "AIR_EVENT" && !contentKinds.has(String(message.kind))) {
      respond({ ok: false, error: "unrecognized browser content event kind" });
      return;
    }
    try {
      const kind = message.type === "AIR_CAPTURE_AI" ? "aiDisclosureCreated" : String(message.kind ?? "webInteraction");
      await send(kind, message.payload, {
        domain: url.hostname,
        privateMode: tab.incognito,
        passwordField: Boolean(message.passwordField),
      });
      respond({ ok: true });
    } catch (error) {
      respond({ ok: false, error: String(error) });
    }
  })();
  return true;
});

void settings();
