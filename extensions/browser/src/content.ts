// Content scripts deliberately contain no module imports: Chromium and Firefox
// execute manifest content scripts as classic scripts. All localhost transport,
// signing, and pairing state stays in the extension background context.
type AirEditableElement = HTMLInputElement | HTMLTextAreaElement | HTMLElement;
type AirBlockReason = "authentication-field" | "payment-field" | "unsupported-or-unknown-field";

const airTimers = new WeakMap<EventTarget, number>();
let airSelectedDomain = false;

function airIsEditable(element: EventTarget | null): element is AirEditableElement {
  return element instanceof HTMLInputElement
    || element instanceof HTMLTextAreaElement
    || element instanceof HTMLElement && element.isContentEditable;
}

function airPageIsForeground(): boolean {
  return window.top === window && document.visibilityState === "visible" && document.hasFocus();
}

async function airRefreshScope(): Promise<boolean> {
  if (!airPageIsForeground()) {
    airSelectedDomain = false;
    return false;
  }
  try {
    const response = await chrome.runtime.sendMessage({ type: "AIR_SCOPE_ALLOWED" }) as { allowed?: boolean };
    airSelectedDomain = response?.allowed === true;
  } catch {
    airSelectedDomain = false;
  }
  return airSelectedDomain;
}

function airClassifyField(element: AirEditableElement): AirFieldClassification {
  const form = element.closest("form");
  const inputType = element instanceof HTMLInputElement ? element.type.toLowerCase() : "";
  const descriptor = [
    element.getAttribute("name"), element.id, element.getAttribute("aria-label"),
    element.getAttribute("placeholder"), element.getAttribute("autocomplete"),
    form?.getAttribute("name"), form?.getAttribute("action"), location.hostname, location.pathname,
  ].filter(Boolean).join(" ").toLowerCase();
  return AirFieldPolicy.classify({
    elementKind: element instanceof HTMLInputElement ? "input" : element instanceof HTMLTextAreaElement ? "textarea" : element.isContentEditable ? "contenteditable" : "unknown",
    inputType,
    autocomplete: element.getAttribute("autocomplete") ?? undefined,
    descriptor,
    pageContext: `${location.hostname} ${location.pathname}`,
  });
}

function airValueFor(element: AirEditableElement): string {
  return element instanceof HTMLInputElement || element instanceof HTMLTextAreaElement
    ? element.value
    : element.textContent ?? "";
}

function airSend(kind: string, payload: unknown, passwordField = false): void {
  if (!airPageIsForeground() || !airSelectedDomain) return;
  void chrome.runtime.sendMessage({ type: "AIR_EVENT", kind, payload, passwordField }).catch(() => {});
}

function airSendMetadataOnly(action: string, reason: AirBlockReason): void {
  airSend("webInteraction", { action, fieldClass: reason, contentStored: false, urlStored: false }, true);
}

document.addEventListener("input", event => {
  const element = event.target;
  if (!airIsEditable(element) || !airPageIsForeground()) return;
  window.clearTimeout(airTimers.get(element));
  airTimers.set(element, window.setTimeout(async () => {
    if (!airPageIsForeground() || !(await airRefreshScope())) return;
    const classification = airClassifyField(element);
    if (classification.capture === "metadata-only") {
      airSendMetadataOnly("sensitive-or-unknown-field-input", classification.reason as AirBlockReason);
      return;
    }
    const value = airValueFor(element);
    airSend("accessibleTextChanged", {
      action: "user-input",
      tag: element.tagName.toLowerCase(),
      text: value.slice(0, 200_000),
      truncated: value.length > 200_000,
      url: location.href,
    });
  }, 1200));
}, true);

document.addEventListener("paste", event => {
  const element = event.target;
  if (!airIsEditable(element) || !airPageIsForeground() || !airSelectedDomain) return;
  void (async () => {
    // Reconfirm scope before asking the ClipboardEvent for its text. A stale
    // cached domain decision must fail closed without reading the content.
    if (!(await airRefreshScope())) return;
    const classification = airClassifyField(element);
    if (classification.capture === "metadata-only") {
      airSendMetadataOnly("sensitive-or-unknown-field-paste", classification.reason as AirBlockReason);
      return;
    }
    const pastedText = event.clipboardData?.getData("text/plain") ?? "";
    airSend("webInteraction", {
      action: "paste",
      length: pastedText.length,
      text: pastedText.slice(0, 200_000),
      truncated: pastedText.length > 200_000,
      url: location.href,
    });
  })();
}, true);

window.addEventListener("focus", () => { void airRefreshScope(); });
document.addEventListener("visibilitychange", () => { void airRefreshScope(); });
void airRefreshScope();
