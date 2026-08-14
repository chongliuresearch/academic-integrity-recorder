import { createHash, createHmac, randomUUID } from "node:crypto";

export interface EvidenceEnvelopeInput {
  projectId: string;
  source: "vscode-extension";
  sourceId: string;
  token: string;
  kind: string;
  payload: unknown;
  domain?: string;
  occurredAt?: string;
  messageId?: string;
}

export function stableJson(value: unknown): string {
  if (value === null) return "null";
  if (typeof value === "string" || typeof value === "boolean") return JSON.stringify(value);
  if (typeof value === "number") return Number.isFinite(value) ? JSON.stringify(value) : "null";
  if (Array.isArray(value)) return `[${value.map(item => item === undefined ? "null" : stableJson(item)).join(",")}]`;
  if (typeof value === "object") {
    const record = value as Record<string, unknown>;
    return `{${Object.keys(record).filter(key => record[key] !== undefined).sort().map(key => `${JSON.stringify(key)}:${stableJson(record[key])}`).join(",")}}`;
  }
  throw new TypeError(`unsupported value in evidence payload: ${typeof value}`);
}

export function evidenceEnvelope(input: EvidenceEnvelopeInput): Record<string, unknown> {
  const occurredAt = input.occurredAt ?? new Date().toISOString();
  const messageId = input.messageId ?? randomUUID();
  const domain = input.domain ?? "";
  const payloadHash = createHash("sha256").update(stableJson(input.payload), "utf8").digest("hex");
  const signatureInput = [input.projectId, input.source, input.sourceId, messageId, occurredAt, input.kind, domain, payloadHash].join("\n");
  const signature = createHmac("sha256", input.token).update(signatureInput, "utf8").digest("base64url");
  return {
    projectId: input.projectId,
    source: input.source,
    sourceId: input.sourceId,
    messageId,
    occurredAt,
    payloadHash,
    signature,
    kind: input.kind,
    privateMode: false,
    passwordField: false,
    payload: input.payload,
  };
}
