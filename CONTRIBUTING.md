# Contributing

Thanks for your interest in improving Academic Integrity Recorder. This project is
local-first, privacy-preserving, and built around **honest disclosure of its own
limits**—please keep that spirit in all contributions.

## Getting started

```bash
npm install
source "$HOME/.cargo/env"
npm test          # Rust tests + TypeScript typecheck + extension tests
cargo test --workspace
```

## Principles every change should respect

1. **Local-first, no exfiltration.** Never add code that sends captured content or
   secrets off the device in cleartext. The only external action is an *optional*,
   voluntary OpenTimestamps commitment of a hash, performed out of band by the user.
2. **Tamper-evidence is sacred.** The hash chain, signed checkpoints, and immutable
   segment storage must remain unspoofable. Any change to `crates/evidence-core`
   must keep the verifier (`tools/verifier`) able to detect tampering.
3. **Honest capability disclosure.** When you add or modify a capture adapter, report
   real capability states (`Available` / `PermissionRequired` / `Degraded` /
   `Unavailable`). Do **not** upgrade an unimplemented capability to appear available.
4. **Privacy by default.** Sensitive fields are dropped or encrypted; new integrations
   must follow the existing field-policy and scope checks (see `extensions/`).
5. **Tests required.** New logic in `crates/` or `extensions/` needs unit/integration
   tests. CI runs `cargo test --workspace`, `npm run typecheck`, and the extension
   test suites.

## Adding a capture adapter

- Implement the `CaptureAdapter` trait in `crates/capture-adapters`.
- Probe capabilities honestly and never fabricate coverage.
- Add tests that assert the adapter does **not** over-claim (mirror the existing
  Windows/Linux `Unavailable` tests).

## Evidence Package format

The exported format is specified in `spec/evidence-package-v1.md`. Changes to the
manifest, layers, or verification rules must be backward-compatible or versioned, and
must keep the offline verifier authoritative. Update `docs/` accordingly.

## Pull requests

- Keep PRs focused; describe the motivation and the honest-disclosure implications.
- Ensure `cargo fmt --all` and `cargo clippy --workspace` are clean.
- Link any related issue or spec change.

By contributing, you agree that your contributions are licensed under AGPL-3.0, the
same as the project.
