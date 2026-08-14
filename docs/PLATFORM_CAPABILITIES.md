# Platform capability matrix

This matrix describes the code shipped in v1. It does not describe planned
adapters. A package's signed `CapabilityReport` is the authority for one
recording, and the native adapter's `status()` binds that report to normalized
health and gap records.

| Capability | macOS | Windows 10/11 | Ubuntu 24.04 X11 | Ubuntu 24.04 Wayland |
|---|---|---|---|---|
| Frontmost app/window | Implemented through Accessibility/System Events and reported `Degraded`; Accessibility plus System Events automation can still block a live query | **Unavailable in v1**; session detection only, no UI Automation client | **Unavailable in v1**; session/display detection only, no EWMH client | **Unavailable in v1**; session/display detection only, no compositor client |
| Selected-window screenshot | Implemented with the system `screencapture -l <window-id>` path; requires Screen Recording plus the foreground-query permissions; secure/unknown/unshareable windows are refused; no whole-screen fallback | **Unavailable in v1**; no Windows Graphics Capture session is created | **Unavailable in v1**; no X11 screenshot client | **Unavailable in v1**; the ScreenCast interface may be discovered, but no user-approved portal session is negotiated |
| Native accessible-text changes | **Unavailable in v1**; Accessibility is used only for foreground and safety classification | **Unavailable in v1**; no UI Automation text-event consumer | **Unavailable in v1**; no AT-SPI event consumer | **Unavailable in v1**; no AT-SPI event consumer |
| Native raw-input content | **Unavailable in v1**; no input hook and no Input Monitoring request | **Unavailable in v1**; no global hook | **Unavailable in v1** | **Unavailable in v1**; InputCapture discovery does not create a consented session |
| Console lock / sleep | Current console lock is queried from `IOConsoleLocked`; sleep is represented after wake by a monitor-interruption record | **Unavailable in v1**; no session notification subscriber | **Unavailable in v1** | **Unavailable in v1** |
| File observation | Cross-platform research-root polling, stable-write hashing, and configured snapshot policy in the desktop runtime | Same runtime path; target-system acceptance still required | Same runtime path; target-system acceptance still required | Same runtime path; target-system acceptance still required |
| Browser semantics | Separate opt-in paired WebExtension; not asserted as connected by the native adapter | Same | Same | Same |
| VS Code semantics | Separate opt-in paired extension; not asserted as connected by the native adapter | Same | Same | Same |
| Shell commands | Separate explicit zsh/bash integration | **Unavailable in v1**; no PowerShell integration | Separate explicit shell integration | Separate explicit shell integration |

## State semantics

- `Available` means the described code path is implemented and its immediate
  prerequisite was observed. It does not mean end-to-end platform acceptance.
- `PermissionRequired` is used only when implemented code is blocked by a user
  permission. It is not used as a placeholder for missing implementation.
- `Degraded` means a working code path has a stated limitation, or a diagnostic
  probe was inconclusive. It does not mean an unimplemented capture path works
  partially.
- `Unavailable` means there is no usable code path in this build or a required
  interface is absent.

`CaptureAdapter::status()` derives a normalized gap for every non-available
capability. Missing/permission-blocked foreground, text, screenshot, raw-input,
or lock-state coverage is marked `blocking`; diagnostic interface-discovery
gaps are not. Persisted deduplication uses
`capture-adapter:{adapter-id}:{gap-code}:{capability-id}` and never uses mutable
human-readable detail.

Linux probe logic records `XDG_SESSION_TYPE`, matching display environment, and
bounded discovery of the XDG ScreenCast/InputCapture D-Bus interfaces. Portal
interface discovery is reported separately from screenshot/input capability:
finding an interface never upgrades an unimplemented client to `Available` or
`PermissionRequired`.

Windows probe logic records the process session context. It does not report UI
Automation or Windows Graphics Capture as available because those clients are
not implemented. The recorder never auto-elevates.

Only macOS has native system-level implementation in this repository. Windows
and Ubuntu acceptance must be executed on those targets after their native
clients are implemented; unit tests of report construction on macOS are not
system acceptance.
