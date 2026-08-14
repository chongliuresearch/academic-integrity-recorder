# Changelog

All notable changes to this project are documented in this file. The format is based
on [Keep a Changelog](https://keepachangelog.com/), and this project adheres to
[Semantic Versioning](https://semver.org/).

## [0.1.0] - 2026-08-14

### Added
- **Evidence core (`crates/evidence-core`)**: RFC 8785 JCS canonicalization, SHA-256
  hash chain, XChaCha20-Poly1305 encryption, Ed25519 device signatures, Argon2id key
  derivation, immutable encrypted segment storage with signed high-water checkpoints,
  crash recovery, and `signed-high-water/v1` migration.
- **Capture adapters (`crates/capture-adapters`)**: macOS native adapter (Accessibility
  / Screen Capture / lock-state) plus honest `Unavailable` reporting for Windows and
  Linux; capability/health/gap model.
- **Desktop app (`apps/desktop`)**: Tauri 2 + React shell with local IPC, tray, global
  shortcut, and monitoring thread.
- **Extensions**: browser (WebExtension) and VS Code semantic-event extensions with
  HMAC protocol, domain/path scoping, and privacy field dropping; shell (zsh) opt-in
  integration.
- **Offline verifier (`tools/verifier`)**: verifies manifest signature, checkpoint
  signature, public chain continuity, per-file SHA-256 digests, and (with the
  sensitive-layer passphrase) payload-to-hash and relationship consistency.
- **Evidence Package v1** (`spec/evidence-package-v1.md`): two-layer (public +
  sensitive) ZIP with signed manifest, bilingual report, and optional OpenTimestamps
  target.
- **Docs**: `docs/THREAT_MODEL.md`, `docs/PLATFORM_CAPABILITIES.md`,
  `docs/OPENTIMESTAMPS.md`.
- **Paper**: `paper/` — "Process Trustworthiness" (English, LaTeX) proposing process
  provenance as a complement to reproducibility, with reference implementation.
- **Repo**: CI workflow, `SECURITY.md`, `CONTRIBUTING.md`, `CHANGELOG.md`.

### Design notes
- The system verifies process *evidence*; it does **not** certify identity, authorship,
  originality, or academic integrity, and it discloses its own coverage limits.

[0.1.0]: https://github.com/chongliuresearch/academic-integrity-recorder/releases/tag/v0.1.0
