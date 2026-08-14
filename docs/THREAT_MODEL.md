# Threat model and non-claims

## Protected properties

- Exported content cannot be changed, removed, inserted, or reordered without
  invalidating a digest, hash chain, checkpoint, or manifest signature.
- Sensitive content is confidential without the separately shared review
  password, assuming its strength and endpoint security are adequate.
- Unselected applications, paths, and domains are outside recording scope.
- Password and system-authentication fields are hard exclusions.
- Declared deletions and redactions reduce content availability without hiding
  the fact that a gap exists.
- An optional external timestamp receipt can make later backdating of a signed
  chain head harder by proving only that its digest existed before an external
  time bound. It does not improve capture completeness or device identity.

## Adversaries and failures considered

- Accidental file corruption or incomplete sync.
- Post-export editing by a researcher, recipient, storage provider, or malware.
- A recipient receiving the ZIP without authorization for sensitive content.
- Browser/editor/shell events from an unpaired installation, replayed message,
  wrong project/source credential, unselected domain, or out-of-root path.
- OS permission withdrawal, process crashes, sleep, clock changes, adapter
  limitations, and Wayland compositor restrictions.

## Explicitly out of scope

- A researcher who controls the device can disable, bypass, reinstall, or
  reconstruct the recorder before an export.
- Device signing keys are not verified legal identities and may be compromised.
- Cameras, paper notes, conversations, other devices, delegated work, and
  offline work are not observed.
- A continuous-looking record does not prove that the research is correct,
  ethical, original, independently authored, or compliant with a journal.
- The software cannot reliably capture raw text from every desktop application
  on every supported OS. Capability and gap reporting is the required response;
silent equivalence is forbidden.
- A blockchain timestamp is neither an identity system nor a substitute for
  the local event chain, signatures, capability report, and visible gaps.

## Abuse resistance

Recording is project-scoped, visually indicated, locally stored, and pausable.
The local IPC listens only on loopback, uses distinct 256-bit project-scoped
credentials for browser, VS Code, and Shell, binds each credential to one
persistent installation identity, and verifies a message HMAC, source time,
kind allowlist, project, selected domain/path, foreground assertion, and replay
identifier. Request bodies are read through a one-MiB hard limit. Browser
content scripts ask the desktop recorder for current domain scope before reading
field content; VS Code and Shell require canonical paths within a selected
research root. Private browsing is discarded. Password, authentication,
payment, secure-input, and unknown fields discard original content and its hash
before append. It is not intended for employee, student, partner, or third-party
surveillance. Organizational centralized monitoring is outside v1.
