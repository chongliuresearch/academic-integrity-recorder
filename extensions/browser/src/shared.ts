export interface Settings {
  endpoint: string;
  token: string;
  projectId: string;
  sourceId: string;
  enabled: boolean;
}

export interface SendContext {
  domain?: string;
  privateMode?: boolean;
  passwordField?: boolean;
  occurredAt?: string;
}

interface BrowserScope {
  projectId: string;
  accepting: boolean;
  domains: string[];
}

let scopeCache: { key: string; checkedAt: number; value: BrowserScope } | undefined;

export const defaults: Settings = {
  endpoint: "http://127.0.0.1:43119/v1/events",
  token: "",
  projectId: "",
  sourceId: "",
  enabled: false,
};

export async function settings(): Promise<Settings> {
  return { ...defaults, ...(await chrome.storage.local.get(defaults)) } as Settings;
}

/** Stable JSON encoding used for payload hashes. Object keys use UTF-16 order, as JSON/JCS does. */
export function stableJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") return Number.isFinite(value) ? JSON.stringify(value) : "null";
  if (Array.isArray(value)) {
    return `[${value.map(item => item === undefined || typeof item === "function" || typeof item === "symbol" ? "null" : stableJson(item)).join(",")}]`;
  }
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    const entries = Object.keys(record)
      .filter(key => record[key] !== undefined && typeof record[key] !== "function" && typeof record[key] !== "symbol")
      .sort()
      .map(key => `${JSON.stringify(key)}:${stableJson(record[key])}`);
    return `{${entries.join(",")}}`;
  }
  throw new TypeError(`unsupported value in evidence payload: ${typeof value}`);
}

export async function sha256Hex(value: unknown): Promise<string> {
  const bytes = new TextEncoder().encode(stableJson(value));
  const digest = await crypto.subtle.digest("SHA-256", bytes);
  return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, "0")).join("");
}

function bytesToBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary).replace(/\+/g, "-").replace(/\//g, "_").replace(/=+$/, "");
}

async function hmacSha256Base64Url(secret: string, message: string): Promise<string> {
  const encoder = new TextEncoder();
  const key = await crypto.subtle.importKey(
    "raw",
    encoder.encode(secret),
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"],
  );
  const signature = await crypto.subtle.sign("HMAC", key, encoder.encode(message));
  return bytesToBase64Url(new Uint8Array(signature));
}

export function extensionIsPrivate(): boolean {
  return Boolean(chrome.extension?.inIncognitoContext);
}

function scopeEndpoint(endpoint: string): string {
  const value = new URL(endpoint);
  value.pathname = "/v1/scope/browser";
  value.search = "";
  value.hash = "";
  return value.href;
}

export function domainMatchesSelection(domain: string, selections: string[]): boolean {
  const normalized = domain.toLowerCase();
  return selections.some(selected => normalized === selected || normalized.endsWith(`.${selected}`));
}

export async function browserDomainAllowed(domain: string, current?: Settings, fresh = false): Promise<boolean> {
  const config = current ?? await settings();
  if (!config.enabled || !config.token || !config.projectId || extensionIsPrivate()) return false;
  const key = `${config.endpoint}\n${config.projectId}\n${config.token}`;
  const now = Date.now();
  let scope = !fresh && scopeCache?.key === key && now - scopeCache.checkedAt < 2_000 ? scopeCache.value : undefined;
  if (!scope) {
    try {
      const response = await fetch(scopeEndpoint(config.endpoint), {
        method: "GET",
        headers: { "Authorization": `Bearer ${config.token}` },
      });
      if (!response.ok) return false;
      scope = await response.json() as BrowserScope;
      scopeCache = { key, checkedAt: now, value: scope };
    } catch {
      return false;
    }
  }
  return scope.accepting
    && scope.projectId === config.projectId
    && domainMatchesSelection(domain, scope.domains);
}

export async function send(kind: string, payload: unknown, context: SendContext = {}): Promise<boolean> {
  const config = await settings();
  if (!config.enabled || !config.token || !config.projectId || !config.sourceId) return false;

  const privateMode = context.privateMode ?? extensionIsPrivate();
  // Incognito/private activity is excluded entirely, rather than reported with content.
  if (privateMode) return false;
  if (!context.domain || !(await browserDomainAllowed(context.domain, config))) return false;

  const evidencePayload = payload !== null && typeof payload === "object" && !Array.isArray(payload)
    ? { ...(payload as Record<string, unknown>), foreground: true }
    : { value: payload, foreground: true };
  const occurredAt = context.occurredAt ?? new Date().toISOString();
  const payloadHash = await sha256Hex(evidencePayload);
  const messageId = crypto.randomUUID();
  const domain = context.domain ?? "";
  const signatureInput = [
    config.projectId,
    "browser-extension",
    config.sourceId,
    messageId,
    occurredAt,
    kind,
    domain,
    payloadHash,
  ].join("\n");
  const signature = await hmacSha256Base64Url(config.token, signatureInput);
  const response = await fetch(config.endpoint, {
    method: "POST",
    headers: {
      "Authorization": `Bearer ${config.token}`,
      "Content-Type": "application/json",
    },
    body: JSON.stringify({
      projectId: config.projectId,
      source: "browser-extension",
      sourceId: config.sourceId,
      messageId,
      occurredAt,
      payloadHash,
      signature,
      kind,
      domain: context.domain,
      privateMode,
      passwordField: context.passwordField ?? false,
      payload: evidencePayload,
    }),
  });
  if (!response.ok) {
    let message = "recorder rejected event";
    try { message = (await response.json() as { error?: string }).error ?? message; } catch { /* keep generic message */ }
    throw new Error(message);
  }
  return true;
}
