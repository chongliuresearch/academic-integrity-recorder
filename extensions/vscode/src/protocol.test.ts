import assert from "node:assert/strict";
import test from "node:test";
import { evidenceEnvelope, stableJson } from "./protocol.js";

test("protocol produces deterministic JCS-compatible hashes and HMAC signatures", () => {
  assert.equal(stableJson({ b: 2, a: 1 }), '{"a":1,"b":2}');
  const envelope = evidenceEnvelope({
    projectId: "project",
    source: "vscode-extension",
    sourceId: "source",
    token: "secret",
    kind: "fileModified",
    payload: { b: 2, a: 1 },
    occurredAt: "2026-08-12T00:00:00.000Z",
    messageId: "message",
  });
  assert.equal(envelope.payloadHash, "43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777");
  assert.equal(envelope.signature, "0lu86-PY7KSHbL3FJIQVDup2L9tn3P4P0yGOkylXsls");
});
