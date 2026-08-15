# Security Policy

## Scope of this project

Academic Integrity Recorder is a **local-first** tool that records a researcher's
own study activity on their own machine and exports a tamper-evident, verifiable
evidence package. It is **not** a surveillance system, an identity service, or an
academic-integrity certification authority.

The software is designed around honest bounds:

- Sensitive content is encrypted on the device with XChaCha20-Poly1305 and is never
  transmitted in cleartext.
- Platform capabilities are disclosed truthfully; where capture is not implemented or
  not permitted by the OS, the capability is reported as `Unavailable` rather than
  faked (see `docs/PLATFORM_CAPABILITIES.md`).
- Gaps in coverage are recorded as explicit events; the tool does not silently claim
  completeness it does not have (see `docs/THREAT_MODEL.md`).
- A verified package proves byte integrity and a device signature only. It does **not**
  certify identity, authorship, originality, or academic integrity.

## Reporting a vulnerability

If you discover a vulnerability in the reference implementation (e.g., a way to forge
or tamper with an evidence package without detection, a key-handling flaw, or a
privacy leak that exfiltrates content off-device), please report it privately.

- Open a private security advisory on GitHub, or
- Email the maintainer at [chong.liu.phil@outlook.com](mailto:chong.liu.phil@outlook.com).

Please do **not** open a public issue for security reports.

Include:

1. A description of the affected component and version.
2. Steps to reproduce, or a proof-of-concept.
3. The expected vs. actual behavior regarding integrity, confidentiality, or honest
   disclosure.

We will acknowledge within 5 business days, propose a remediation timeline, and credit
the reporter (unless anonymity is requested) once a fix is released.

## Out of scope

The following are intentional design limits, not vulnerabilities:

- The tool cannot prove that *all* research activity was captured (offline work, use of
  an uninstrumented machine, or delegation can create gaps).
- A device signature attests a key, not a legal identity.
- A determined adversary with local control can disable capture or record on a
  separate machine; the system raises the cost and leaves traces, but is not a
  tamper-proof oracle.

See `docs/THREAT_MODEL.md` for the full threat model.
