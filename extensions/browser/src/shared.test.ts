import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import test from "node:test";
import { runInThisContext } from "node:vm";
import { domainMatchesSelection, sha256Hex, stableJson } from "./shared.js";

// Execute the exact classic script loaded before content.js in the extension.
runInThisContext(readFileSync(new URL("./field-policy.js", import.meta.url), "utf8"));
const fieldPolicy = (globalThis as typeof globalThis & { AirFieldPolicy: typeof AirFieldPolicy }).AirFieldPolicy;

test("stableJson is deterministic and payload hash matches the canonical bytes", async () => {
  assert.equal(stableJson({ b: 2, a: 1 }), '{"a":1,"b":2}');
  assert.equal(
    await sha256Hex({ b: 2, a: 1 }),
    "43258cff783fe7036d8a43033f830adfc60ec037382473548ac742b888292777",
  );
});

test("the shipped field policy blocks credentials, payment, and unknown controls", () => {
  assert.deepEqual(fieldPolicy.classify({ elementKind: "input", inputType: "text", autocomplete: "current-password" }), { capture: "metadata-only", reason: "authentication-field" });
  assert.deepEqual(fieldPolicy.classify({ elementKind: "input", inputType: "text", descriptor: "Card number" }), { capture: "metadata-only", reason: "payment-field" });
  assert.deepEqual(fieldPolicy.classify({ elementKind: "input", inputType: "number" }), { capture: "metadata-only", reason: "unsupported-or-unknown-field" });
  assert.deepEqual(fieldPolicy.classify({ elementKind: "textarea", descriptor: "research notes" }), { capture: "content", reason: "ordinary-text-field" });
});

test("browser domain scope accepts only exact hosts and their subdomains", () => {
  assert.equal(domainMatchesSelection("scholar.google.com", ["scholar.google.com"]), true);
  assert.equal(domainMatchesSelection("accounts.scholar.google.com", ["scholar.google.com"]), true);
  assert.equal(domainMatchesSelection("evil-scholar.google.com", ["scholar.google.com"]), false);
  assert.equal(domainMatchesSelection("google.com", ["scholar.google.com"]), false);
});
