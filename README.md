# Academic Integrity Recorder

**Unforgeable process evidence** — a new paradigm of scientific integrity that
complements, rather than replaces, reproducibility.

This repository contains:

1. the **paper** proposing the paradigm (`paper/`);
2. the open **Evidence Package v1** specification (`spec/evidence-package-v1.md`);
3. a **prototype reference implementation** — the *Academic Integrity Recorder* —
   released under the AGPL-3.0 license and open to community contribution.

> **Non-claim.** The recorder produces unforgeable evidence of the research
> *process*. It does not certify originality, authorship, correctness, or academic
> integrity.

## Paper

The repository accompanies a paper arguing for *unforgeability* as a distinct
pillar of scientific integrity, parallel to reproducibility:

> **Unforgeable Process Evidence: A New Paradigm of Scientific Integrity
> Complementing Reproducibility**

- Sources and compiled PDF: `paper/main.tex`, `paper/refs.bib`, `paper/main.pdf`
- Core thesis: reproducibility verifies *what* was claimed — whether the result can
  be rebuilt; unforgeable process evidence verifies *how* the claim was arrived at.
  The two are independent and complementary, not substitutes.
- Non-claim: the evidence package proves process integrity and a device signature
  under stated cryptographic assumptions — not identity, authorship, originality,
  or academic integrity.

## Status

This is a **proof-of-concept prototype**, not a finished product. The
specification is the stable artifact; the code is an evolving demonstration that
the property is attainable, with deliberately partial platform support. It is
released as open source precisely so that others can extend and complete it.
Contributions are welcome — see [`CONTRIBUTING.md`](CONTRIBUTING.md).

## What it does

A local-first, self-reporting recorder of research-process activity. It organizes
research software activity, file versions, research items, AI use, and final
manuscript anchors into an unforgeable, verifiable evidence package.

## Development

```bash
npm install
source "$HOME/.cargo/env"
npm run dev
npm test
```

Run the Tauri desktop container:

```bash
npm run desktop
```

Evidence verifier:

```bash
cargo run -p evidence-verifier -- path/to/package.evidence.zip --password 'review-password'
```

## Repository structure

- `crates/evidence-core` — canonicalization, hash chain, encryption, signing, export.
- Each evidence package contains an external time-anchoring target that carries no
  research content; it is fully offline by default, with optional OpenTimestamps
  Bitcoin attestation of the digest after export.
- `crates/capture-adapters` — platform capability probing and the capture adapter interface.
- `apps/desktop` — Tauri 2 + React desktop application.
- `extensions/browser` — Chrome/Edge/Firefox WebExtension.
- `extensions/vscode` — VS Code semantic-event extension.
- `integrations/shell` — optional zsh/bash command-event integration.
- `spec/evidence-package-v1.md` — the public evidence-package specification.
- `tools/verifier` — offline verifier.

## Architecture

```mermaid
flowchart LR
  A[Capture adapters<br/>macOS native / browser / VS Code / shell] --> B[Evidence core (Rust)<br/>hash chain · RFC 8785<br/>XChaCha20-Poly1305 · Ed25519 · Argon2id]
  B --> C[Local store<br/>SQLite index + immutable encrypted segments<br/>+ signed high-water checkpoints]
  C --> D[Export Evidence Package v1<br/>public layer + sensitive layer]
  D --> E[Offline verifier<br/>manifest signature + chain integrity]
```

The entire pipeline runs on the local machine — no telemetry leaves the device;
sensitive content is encrypted by default, and capability boundaries are honestly
disclosed.

## Privacy and security

The browser, VS Code, and shell extensions use mutually isolated, project-scoped
local tokens. The browser extension re-checks that the current origin is still
authorized before reading field content; VS Code and shell accept only paths
within the selected research directory.

The desktop settings page can exclude real files or directories within the current
research root; exclusions stop the corresponding file observation and append the
scope change itself to the evidence chain.

Synchronized directories back up only encrypted immutable segments, content
objects, and signed checkpoints — no keys or mutable SQLite — and therefore cannot
serve alone as a cross-device migration package.

See [`docs/OPENTIMESTAMPS.md`](docs/OPENTIMESTAMPS.md) for the optional use of
OpenTimestamps and its evidence boundary.

## Platform disclosure

macOS foreground-window and window-screenshot capture require the corresponding
permissions (Accessibility, System Events automation, and Screen Recording). The
v1 native adapter does not request Input Monitoring and does not capture raw
keystrokes. Windows and Linux currently only honestly detect session/interface;
native foreground-window, screenshot, and global input remain reported as
`Unavailable` rather than faking unimplemented capability. See
[`docs/PLATFORM_CAPABILITIES.md`](docs/PLATFORM_CAPABILITIES.md).

The desktop app registers `CommandOrControl+Shift+Alt+R` as a global pause/resume
shortcut; the tray menu also provides pause/resume and a privacy mode, and each
state change is written to the append-only record as a visible gap. The project
screenshot interval can be adjusted in settings (10–3600 s); the values before and
after each change are written to the evidence chain and disclosed per the project's
recording policy.
