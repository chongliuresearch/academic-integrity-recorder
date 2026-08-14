# evidence-package/v1

Status: implementable v1 specification. Normative terms MUST, MUST NOT, SHOULD,
and MAY have their usual standards meaning.

## Evidence claim

An evidence package is voluntary, tamper-evident process evidence. A successful
verification proves that the packaged bytes match the signed manifest and that
the event chain matches a device key. It does **not** prove legal identity,
authorship, originality, completeness, academic integrity, absence of offline
activity, or correctness of the research.

## Container

The container is a ZIP with these required paths:

```
manifest.json
public/evidence.json
public/report.html
public/report.pdf
public/timestamp-target.json
sensitive/evidence.enc.json
verification/README.txt
```

All JSON covered by signatures or hashes MUST be serialized using RFC 8785 JCS.
All timestamps MUST be RFC 3339 UTC instants; human reports MAY display local
time in addition. Integers that can exceed interoperable JSON number precision
MUST be strings.

## Manifest and identity

`ExportManifest` contains a `ManifestBody` and `manifestSignature`. The body
includes `schemaVersion`, random `packageId`, the `Project`, generation time,
SHA-256 file digests, final `IntegrityCheckpoint`, `CapabilityReport`, evidence
claim, limitations, and report descriptors. Each report descriptor declares its
path, language, and coverage. In v1, `public/report.html` is the complete
bilingual (`zh-CN,en`) public report and `public/report.pdf` is an English-only
summary. The PDF MUST NOT be described as bilingual and MUST NOT silently
replace unsupported project-name characters with question marks. For a
non-ASCII project name the summary prints its SHA-256 commitment and directs
the reviewer to the HTML/JSON report.

The manifest and checkpoint use Ed25519. `devicePublicKey` and its SHA-256
fingerprint identify a key held in the operating-system credential vault. They
MUST NOT be presented as verified personal identity. The author's statement is
self-asserted.

## Optional external timestamp anchoring

Every export MUST include `public/timestamp-target.json`, a JCS-serialized,
content-free commitment to the signed final checkpoint. An external timestamp
protocol MAY timestamp the SHA-256 digest of this file. The default workflow is
fully local and MUST NOT contact a timestamp service, blockchain, wallet, or
network.

OpenTimestamps over Bitcoin is the v1 recommended optional protocol. A receipt
(`.ots`) MAY accompany the evidence ZIP, but is not part of the signed package
unless it was present before export. Implementations MUST distinguish
`prepared`, `pending`, `confirmed`, `invalid`, and `not checked` states. They
MUST NOT claim an exact creation time from a Bitcoin block timestamp or present
the anchor as proof of identity, authorship, originality, completeness, or
academic integrity. No research text, path, screenshot, key, or sensitive-layer
content may be submitted; only the target file digest is eligible.

## Event chain

Each `EvidenceEvent` has an increasing `sequence`, a `payloadHash`,
`previousHash`, and `eventHash`. The first `previousHash` is 64 ASCII zeroes.
The payload hash is SHA-256 over JCS payload bytes. The event hash is SHA-256
over JCS containing these fields:

`id`, `projectId`, `sessionId`, `sequence`, `occurredAt`, `capturedAt`,
`monotonicMillis`, `source`, `kind`, `sensitivity`, `payloadHash`,
`previousHash`, and `capabilityId`.

Public events omit payloads but retain all chain fields required to establish
order. Full events in the sensitive layer MUST reproduce every public event and
payload hash. Corrections are appended events. Existing events MUST NOT be
rewritten.

## Encryption

Local immutable segments and content-addressed objects use
XChaCha20-Poly1305 with unique 192-bit nonces. The sensitive export layer uses a
random 128-bit salt, Argon2id-derived 256-bit key, and XChaCha20-Poly1305. Its
associated data is the package UUID bytes. The review password MUST NOT appear
inside the ZIP and SHOULD be shared through a separate channel.

Project and device secret keys MUST be stored in macOS Keychain, Windows
credential protection, or Linux Secret Service. A sync directory receives
encrypted immutable event segments, encrypted content-addressed objects, and
signed high-water checkpoints. Existing same-name immutable files MUST NOT be
overwritten with different bytes. The mutable SQLite index and project/device
keys MUST NOT be synchronized. A sync copy therefore requires the original
credential vault (or a separately implemented key-recovery export) to restore;
it MUST NOT be presented as a self-contained migration archive.

Each completed append MUST have a device-signed local high-water checkpoint.
Startup recovery MUST enumerate the actual segment and checkpoint directories,
must not trust SQLite as the sole authority, and MUST reject missing, extra,
reordered, or signature-invalid material. A SQLite tail below a valid signed
high-water mark MAY be rebuilt from authenticated segments. A SQLite high-water
mark above authenticated local material MUST be rejected unless a valid pending
append record proves a recoverable interrupted write.

## Core public types

- `Project`: self-asserted author statement, research roots, policy, selected
  tools and domains.
- `RecordingPolicy`: 90-second active window by default, 30-second screenshot
  interval, 50 MiB snapshot threshold, and exclusions.
- `ToolTarget`: explicitly selected software and adapter.
- `CapabilityReport`: runtime platform, permissions, availability, limitations,
  warnings, and adapter identities.
- `Session` and `EvidenceEvent`: append-only process timeline.
- `Artifact`: content digest and whether content is included.
- `ResearchItem`: concept, question, argument, evidence/source, experiment,
  result, objection, decision, AI use, or custom item; history includes revised,
  rejected and superseded states.
- `ManuscriptAnchor`: PDF, DOCX, TeX, or Markdown document hash, locator, quote
  hash, context hashes, and current status.
- `AIUseDisclosure`: declared service/model, encrypted prompt/output artifacts,
  adopted/modified/rejected/reference-only disposition, and human review.
- `GapOrRedaction`: reason, interval, affected count and hashes, actor, and time.
- `IntegrityCheckpoint` and `ExportManifest`: device-signed chain head and file
  manifest.

## Privacy invariants

- Password fields, OS authentication UI, and secure input MUST NOT be stored.
- Unknown field safety MUST produce activity metadata only.
- Clipboard data MUST be captured only on copy/paste in a selected foreground
  tool; the recorder MUST NOT poll clipboard history.
- Private/incognito browser events MUST be rejected.
- Browser events MUST be rejected unless their host matches a project-selected
  domain.
- Browser/editor/shell content MUST be blocked at the semantic integration
  before capture when its domain, workspace, or working directory is outside
  project scope. Server-side rejection is an additional boundary, not permission
  to collect out-of-scope content into extension memory or transport buffers.
- User deletion or redaction MAY remove content permanently but MUST append a
  `GapOrRedaction` with hashes, count, time, actor, and reason.
- Permission loss or an adapter failure MUST be represented in the capability
  report and, if it affects an armed interval, as a gap.

## Local semantic-integration protocol

Browser, VS Code, and opt-in Shell integrations use three distinct random
project-scoped credentials. A credential MUST be bound on first accepted use to
one persistent random installation `sourceId`; one source credential MUST NOT
authenticate another source type. Every message includes canonical project,
source and message UUIDs, source time, kind, normalized domain (when relevant),
JCS payload SHA-256, and a base64url HMAC-SHA256 over those fields. The receiver
MUST verify the currently armed project, source-specific kind allowlist, selected
domain or canonical research path, an explicit foreground observation, a bounded
time skew, HMAC, and message-ID replay state before appending. The local HTTP
body MUST be read through a hard size bound rather than buffered without limit.

Password, authentication, payment, secure-input, and unknown-field messages
MUST discard both original text and content-derived hashes before append, since
a retained hash can permit offline guessing. Private/incognito events MUST be
discarded without sending research content.

## Active-time algorithm v1

Only qualifying observations from a selected foreground tool count. The elapsed
time between consecutive qualifying observations is added once and capped at the
project's timeout (90 seconds by default). A pause, lock, sleep, background
transition, or session end resets continuity. Overlapping tools cannot double
count because the observation stream is ordered globally. The algorithm version
and timeout MUST appear in `public/evidence.json`, together with the calculated
whole-second total and a stable textual rule declaration. The complete
bilingual HTML report MUST repeat the algorithm version, timeout, rule, and
result.

## Public report coverage

`public/evidence.json` is a typed v1 object and MUST contain `schemaVersion`,
the sanitized `Project`, every `PublicEvent`, public research-item relations,
artifact declarations, manuscript-anchor declarations, AI-use declarations,
gaps/redactions, the current capability report, active-time declaration, the
final checkpoint, and report descriptors. Its schema version, project,
capability report, checkpoint, and report descriptors MUST match the signed
manifest.

`public/report.html` MUST expose the active-time method and result, current
capabilities and permissions, capability/permission-change events, all
gaps/redactions, research-item-to-event/artifact/anchor relationships, artifact
and AI/anchor declarations, and the complete public event timeline. The
timeline contains every public event's identifiers, times, kind, source,
sensitivity, capability, payload hash, previous hash, and event hash. The HTML
MUST NOT reveal sensitive payloads or private paths.

The capability report is a snapshot observed at its declared time. Historical
permission and capability transitions are represented by `PermissionChanged`
and `CapabilityChanged` public events; their payload remains sensitive and is
represented publicly by its hash.

## Verification

An offline verifier MUST:

1. reject an unsupported schema;
2. verify manifest and checkpoint Ed25519 signatures;
3. verify every required file size and SHA-256 digest;
4. reject duplicate ZIP entries, undeclared entries, duplicate manifest paths,
   oversized entries, or a report descriptor not covered by the manifest;
5. parse `public/evidence.json` against the v1 typed schema; verify its schema,
   project, capability report, final checkpoint, report declarations, IDs,
   project ownership, hashes, and relationship referential integrity; verify
   sequences, previous hashes, and the signed final chain head;
6. when a password is supplied, authenticate/decrypt the sensitive layer,
   recompute every payload hash and event hash, and compare it with the public
   event; verify its schema and project; project every sensitive entity back to
   its public declaration; and require the artifact-content map to equal exactly
   the set of artifacts marked `contentIncluded` (no missing or undeclared
   content), with matching SHA-256 and byte size;
7. recompute active time from the decrypted event stream and compare it with the
   public total;
8. report skipped sensitive-layer checks if no password is provided;
9. always repeat the evidence-claim limitation in human output; and
10. verify that `public/timestamp-target.json` reproduces the signed checkpoint;
   external `.ots` receipt verification is an optional, separately reported
   check.
