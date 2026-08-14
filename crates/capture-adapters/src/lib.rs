use anyhow::{Context, Result};
use chrono::Utc;
use evidence_core::{
    Capability, CapabilityReport, CapabilityState, EventDraft, EventKind, Sensitivity, ToolTarget,
};
use serde::{Deserialize, Serialize};
use std::{path::Path, process::Command};
use sysinfo::System;
use uuid::Uuid;

const CORE_CAPTURE_CAPABILITIES: &[&str] = &[
    "foreground-window",
    "accessible-text",
    "screen-capture",
    "raw-input",
];

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ForegroundSnapshot {
    pub application_id: String,
    pub application_name: String,
    pub process_id: u32,
    pub window_title: Option<String>,
    /// Native window identifier used to scope captures to exactly this window.
    /// A missing identifier must never cause a whole-screen fallback.
    pub window_id: Option<u32>,
    pub secure_input: bool,
    pub content_capture_available: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, Default, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct SystemCaptureState {
    pub locked: bool,
    pub sleeping: bool,
    /// False means the platform adapter cannot make a trustworthy assertion.
    pub detection_reliable: bool,
}

/// Coarse health of the native capture adapter. This is deliberately separate
/// from process health: a running adapter with no implemented capture path is
/// `Unavailable`, not healthy.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AdapterHealthState {
    Healthy,
    Degraded,
    Unavailable,
}

/// A normalized coverage gap derived from one capability result. Callers may
/// persist these as evidence gaps; the adapter never silently upgrades them.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AdapterGap {
    pub code: String,
    pub capability_id: String,
    pub detail: String,
    /// True only for missing/blocked evidence-capture or lock-state coverage;
    /// diagnostic interface discovery gaps are non-blocking.
    pub blocking: bool,
}

impl AdapterGap {
    /// Stable deduplication key for persisted gap records. Human-readable
    /// detail may evolve between builds and must not be part of the key.
    pub fn actor_key(&self, adapter_id: &str) -> String {
        format!(
            "capture-adapter:{adapter_id}:{}:{}",
            self.code, self.capability_id
        )
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdapterHealth {
    pub adapter_id: String,
    pub observed_at: chrono::DateTime<Utc>,
    pub state: AdapterHealthState,
    pub gaps: Vec<AdapterGap>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AdapterStatus {
    pub capability_report: CapabilityReport,
    pub health: AdapterHealth,
}

pub trait CaptureAdapter: Send + Sync {
    fn id(&self) -> &'static str;
    fn probe(&self) -> CapabilityReport;
    fn foreground(&self) -> Result<Option<ForegroundSnapshot>>;
    fn system_state(&self) -> Result<SystemCaptureState> {
        Ok(SystemCaptureState::default())
    }
    fn capture_screenshot(&self, snapshot: &ForegroundSnapshot, destination: &Path) -> Result<()>;

    /// Produces one coherent capability/health/gap snapshot. Consumers should
    /// prefer this over probing capabilities and health at different times.
    fn status(&self) -> AdapterStatus {
        let capability_report = self.probe();
        let health = capture_health_from_report(self.id(), &capability_report);
        AdapterStatus {
            capability_report,
            health,
        }
    }
}

pub fn capture_health_from_report(adapter_id: &str, report: &CapabilityReport) -> AdapterHealth {
    let gaps = report
        .capabilities
        .iter()
        .filter_map(|capability| {
            let coverage_critical = CORE_CAPTURE_CAPABILITIES.contains(&capability.id.as_str())
                || capability.id == "system-lock-state";
            let (code, blocking) = match &capability.state {
                CapabilityState::Available => return None,
                CapabilityState::PermissionRequired => ("permission-required", coverage_critical),
                CapabilityState::Degraded => ("capability-degraded", false),
                CapabilityState::Unavailable => ("capability-unavailable", coverage_critical),
            };
            Some(AdapterGap {
                code: code.into(),
                capability_id: capability.id.clone(),
                detail: capability
                    .limitation
                    .clone()
                    .unwrap_or_else(|| capability.label.clone()),
                blocking,
            })
        })
        .collect::<Vec<_>>();
    let operational_core_count = report
        .capabilities
        .iter()
        .filter(|capability| CORE_CAPTURE_CAPABILITIES.contains(&capability.id.as_str()))
        .filter(|capability| {
            matches!(
                &capability.state,
                CapabilityState::Available | CapabilityState::Degraded
            )
        })
        .count();
    let state = if operational_core_count == 0 {
        AdapterHealthState::Unavailable
    } else if gaps.is_empty() {
        AdapterHealthState::Healthy
    } else {
        AdapterHealthState::Degraded
    };
    AdapterHealth {
        adapter_id: adapter_id.into(),
        observed_at: report.observed_at.to_owned(),
        state,
        gaps,
    }
}

pub fn native_adapter() -> Box<dyn CaptureAdapter> {
    #[cfg(target_os = "macos")]
    return Box::new(MacOsAdapter);
    #[cfg(target_os = "windows")]
    return Box::new(WindowsAdapter);
    #[cfg(target_os = "linux")]
    return Box::new(LinuxAdapter);
    #[allow(unreachable_code)]
    Box::new(UnsupportedAdapter)
}

pub fn process_is_running(target: &ToolTarget) -> bool {
    let system = System::new_all();
    system.processes().values().any(|process| {
        let name = process.name().to_string_lossy().to_lowercase();
        let app = target.application_id.to_lowercase();
        name.contains(&app)
            || target
                .executable
                .as_ref()
                .is_some_and(|path| process.exe() == Some(path.as_path()))
    })
}

pub fn snapshot_to_event(
    project_id: Uuid,
    session_id: Option<Uuid>,
    snapshot: &ForegroundSnapshot,
    monotonic_millis: u64,
) -> EventDraft {
    EventDraft {
        project_id,
        session_id,
        occurred_at: Utc::now(),
        monotonic_millis,
        source: "desktop:native".into(),
        kind: EventKind::ApplicationFocused,
        sensitivity: Sensitivity::PublicMetadata,
        payload: serde_json::json!({
            "applicationId": snapshot.application_id,
            "applicationName": snapshot.application_name,
            "processId": snapshot.process_id,
            "windowTitle": snapshot.window_title,
            "windowId": snapshot.window_id,
            "secureInput": snapshot.secure_input,
            "contentCaptureAvailable": snapshot.content_capture_available,
        }),
        capability_id: Some("foreground-window".into()),
    }
}

#[cfg(target_os = "macos")]
struct MacOsAdapter;

#[cfg(target_os = "macos")]
#[link(name = "ApplicationServices", kind = "framework")]
extern "C" {
    fn AXIsProcessTrusted() -> bool;
    fn CGPreflightScreenCaptureAccess() -> bool;
}

#[cfg(target_os = "macos")]
#[link(name = "Carbon", kind = "framework")]
extern "C" {
    fn IsSecureEventInputEnabled() -> u8;
}

#[cfg(target_os = "macos")]
fn macos_secure_event_input_enabled() -> bool {
    // Carbon declares this as the one-byte Boolean type.
    unsafe { IsSecureEventInputEnabled() != 0 }
}

#[cfg(target_os = "macos")]
fn macos_front_window_content_is_safe(process_id: u32) -> Result<bool> {
    let script = format!(
        r#"tell application "System Events"
set p to first application process whose unix id is {process_id}
set processName to name of p
if processName is "SecurityAgent" or processName is "loginwindow" or processName is "authorizationhost" then return "unsafe"
set windowSafety to "safe"
try
set allElements to entire contents of front window of p
repeat with uiElement in allElements
try
set roleName to value of attribute "AXRole" of uiElement
if roleName is "AXSecureTextField" then set windowSafety to "unsafe"
set protectedValue to false
try
set protectedValue to value of attribute "AXProtectedContent" of uiElement
end try
if protectedValue is true then set windowSafety to "unsafe"
on error
set windowSafety to "unknown"
exit repeat
end try
end repeat
on error
set windowSafety to "unknown"
end try
return windowSafety
end tell"#
    );
    let output = Command::new("osascript").args(["-e", &script]).output()?;
    anyhow::ensure!(
        output.status.success(),
        "macOS window safety query failed: {}",
        String::from_utf8_lossy(&output.stderr).trim()
    );
    Ok(String::from_utf8_lossy(&output.stdout).trim() == "safe")
}

#[cfg(target_os = "macos")]
fn macos_window_id(process_id: u32, expected_title: Option<&str>) -> Option<u32> {
    use core_foundation::{
        base::{CFType, TCFType},
        dictionary::CFDictionary,
        number::CFNumber,
        string::CFString,
    };
    use core_graphics::window::{
        copy_window_info, kCGNullWindowID, kCGWindowLayer, kCGWindowListExcludeDesktopElements,
        kCGWindowListOptionOnScreenOnly, kCGWindowName, kCGWindowNumber, kCGWindowOwnerPID,
        kCGWindowSharingState,
    };

    fn number(dictionary: &CFDictionary, key: *const std::ffi::c_void) -> Option<i64> {
        let value = *dictionary.find(key)?;
        let value =
            unsafe { CFType::wrap_under_get_rule(value as core_foundation::base::CFTypeRef) };
        value.downcast::<CFNumber>()?.to_i64()
    }

    fn string(dictionary: &CFDictionary, key: *const std::ffi::c_void) -> Option<String> {
        let value = *dictionary.find(key)?;
        let value =
            unsafe { CFType::wrap_under_get_rule(value as core_foundation::base::CFTypeRef) };
        Some(value.downcast::<CFString>()?.to_string())
    }

    let windows = copy_window_info(
        kCGWindowListOptionOnScreenOnly | kCGWindowListExcludeDesktopElements,
        kCGNullWindowID,
    )?;
    let mut candidates = Vec::new();
    for raw in &windows {
        let value =
            unsafe { CFType::wrap_under_get_rule(*raw as core_foundation::base::CFTypeRef) };
        let Some(dictionary) = value.downcast::<CFDictionary>() else {
            continue;
        };
        let owner_pid = number(&dictionary, unsafe { kCGWindowOwnerPID } as _);
        let layer = number(&dictionary, unsafe { kCGWindowLayer } as _);
        let sharing = number(&dictionary, unsafe { kCGWindowSharingState } as _);
        if owner_pid != Some(process_id as i64)
            || layer != Some(0)
            || !sharing.is_some_and(|value| value > 0)
        {
            continue;
        }
        let Some(window_id) = number(&dictionary, unsafe { kCGWindowNumber } as _)
            .and_then(|value| u32::try_from(value).ok())
        else {
            continue;
        };
        candidates.push(window_id);
        if let (Some(expected), Some(actual)) = (
            expected_title.filter(|value| !value.is_empty()),
            string(&dictionary, unsafe { kCGWindowName } as _),
        ) {
            if actual == expected {
                return Some(window_id);
            }
        }
    }
    if expected_title.is_none() && candidates.len() == 1 {
        candidates.first().copied()
    } else {
        None
    }
}

#[cfg(target_os = "macos")]
fn parse_macos_lock_state(output: &str) -> Option<bool> {
    output.lines().find_map(|line| {
        let line = line.trim();
        if !line.starts_with("\"IOConsoleLocked\"") {
            return None;
        }
        if line.ends_with("= Yes") {
            Some(true)
        } else if line.ends_with("= No") {
            Some(false)
        } else {
            None
        }
    })
}

#[cfg(target_os = "macos")]
fn macos_window_capture_args(window_id: u32) -> Vec<String> {
    vec![
        "-x".into(),
        "-t".into(),
        "png".into(),
        "-l".into(),
        window_id.to_string(),
    ]
}

#[cfg(target_os = "macos")]
fn macos_capture_scope_matches(
    expected: &ForegroundSnapshot,
    current: &ForegroundSnapshot,
) -> bool {
    expected.process_id == current.process_id
        && expected.window_id.is_some()
        && expected.window_id == current.window_id
        && !expected.secure_input
        && !current.secure_input
        && expected.content_capture_available
        && current.content_capture_available
}

#[cfg(target_os = "macos")]
impl CaptureAdapter for MacOsAdapter {
    fn id(&self) -> &'static str {
        "macos-accessibility-screencapture"
    }

    fn probe(&self) -> CapabilityReport {
        let accessibility = unsafe { AXIsProcessTrusted() };
        let screen = unsafe { CGPreflightScreenCaptureAccess() };
        let lock_state = self.system_state().is_ok();
        CapabilityReport {
            platform: "macOS".into(),
            platform_version: Command::new("sw_vers").arg("-productVersion").output().ok().map(|out| String::from_utf8_lossy(&out.stdout).trim().to_string()).unwrap_or_else(|| "unknown".into()),
            observed_at: Utc::now(),
            capabilities: vec![
                Capability { id: "foreground-window".into(), label: "Frontmost application and window".into(), state: if accessibility { CapabilityState::Degraded } else { CapabilityState::PermissionRequired }, permission: Some("Accessibility and System Events automation".into()), limitation: Some("The v1 implementation queries System Events rather than using a direct AXUIElement event client. A live query can still be denied and is reported as an adapter gap.".into()) },
                Capability { id: "accessible-text".into(), label: "Accessible text changes".into(), state: CapabilityState::Unavailable, permission: None, limitation: Some("The v1 native macOS adapter uses Accessibility only to identify the front window and refuse secure/unknown content; it does not emit accessible-text change events. Use an explicitly paired semantic integration where available.".into()) },
                Capability { id: "screen-capture".into(), label: "Selected-window capture".into(), state: if screen && accessibility { CapabilityState::Degraded } else { CapabilityState::PermissionRequired }, permission: Some("Screen Recording, Accessibility, and System Events automation".into()), limitation: Some("Capture is refused unless the selected front window has a native window ID and Accessibility can classify the focused element as non-secure. There is no whole-screen fallback; a live System Events query can still be denied.".into()) },
                Capability { id: "raw-input".into(), label: "Raw input content".into(), state: CapabilityState::Unavailable, permission: None, limitation: Some("The v1 native adapter does not install an input hook and does not request Input Monitoring. Text/activity semantics require an explicitly paired browser, VS Code, or shell integration.".into()) },
                Capability { id: "system-lock-state".into(), label: "Console lock-state detection".into(), state: if lock_state { CapabilityState::Available } else { CapabilityState::Unavailable }, permission: None, limitation: Some("Current console lock state is queried through IOConsoleLocked. Sleep is represented by monitor-interruption evidence after wake, not by a live sleeping=true sample.".into()) },
            ],
            adapters: vec![self.id().into(), "filesystem-polling".into(), "browser-extension-opt-in".into(), "vscode-extension-opt-in".into(), "shell-opt-in".into()],
            warnings: vec!["Secure input, unknown focus safety, unshareable windows, lock screen, and system authentication interfaces are refused rather than captured. The native adapter does not capture raw or accessible text in v1.".into()],
        }
    }

    fn foreground(&self) -> Result<Option<ForegroundSnapshot>> {
        let script = r#"tell application "System Events"
set p to first application process whose frontmost is true
set appName to name of p
set appPid to unix id of p
try
set windowName to name of front window of p
on error
set windowName to ""
end try
set safetyState to "unknown"
try
set focusedElement to value of attribute "AXFocusedUIElement" of p
set roleName to value of attribute "AXRole" of focusedElement
set subroleName to ""
try
set subroleName to value of attribute "AXSubrole" of focusedElement
end try
set protectedValue to false
try
set protectedValue to value of attribute "AXProtectedContent" of focusedElement
end try
if roleName is "AXSecureTextField" or subroleName contains "Secure" or protectedValue is true then
set safetyState to "unsafe"
else if roleName is not "" then
set safetyState to "safe"
end if
end try
return appName & linefeed & appPid & linefeed & windowName & linefeed & safetyState
end tell"#;
        let output = Command::new("osascript").args(["-e", script]).output()?;
        anyhow::ensure!(
            output.status.success(),
            "macOS Accessibility front-window query failed: {}",
            String::from_utf8_lossy(&output.stderr).trim()
        );
        let text = String::from_utf8_lossy(&output.stdout);
        let mut lines = text.lines();
        let name = lines.next().unwrap_or_default().trim().to_string();
        if name.is_empty() {
            return Ok(None);
        }
        let process_id = lines.next().unwrap_or("0").trim().parse().unwrap_or(0);
        let title = lines
            .next()
            .map(str::trim)
            .filter(|line| !line.is_empty())
            .map(str::to_string);
        let focus_safety = lines.next().unwrap_or("unknown").trim();
        let secure_input = macos_secure_event_input_enabled() || focus_safety == "unsafe";
        let window_id = macos_window_id(process_id, title.as_deref());
        let screen_permission = unsafe { CGPreflightScreenCaptureAccess() };
        let whole_window_safe = focus_safety == "safe"
            && macos_front_window_content_is_safe(process_id).unwrap_or(false);
        Ok(Some(ForegroundSnapshot {
            application_id: name.to_lowercase(),
            application_name: name,
            process_id,
            window_title: title,
            window_id,
            secure_input,
            content_capture_available: screen_permission
                && window_id.is_some()
                && whole_window_safe
                && !secure_input,
        }))
    }

    fn system_state(&self) -> Result<SystemCaptureState> {
        let output = Command::new("/usr/sbin/ioreg")
            .args(["-n", "Root", "-d1"])
            .output()
            .context("failed to query macOS console lock state")?;
        anyhow::ensure!(output.status.success(), "macOS lock-state query failed");
        let locked = parse_macos_lock_state(&String::from_utf8_lossy(&output.stdout))
            .context("macOS did not report IOConsoleLocked")?;
        Ok(SystemCaptureState {
            locked,
            sleeping: false,
            detection_reliable: true,
        })
    }

    fn capture_screenshot(&self, snapshot: &ForegroundSnapshot, destination: &Path) -> Result<()> {
        anyhow::ensure!(
            !self.system_state()?.locked,
            "screen capture refused while the console is locked"
        );
        anyhow::ensure!(
            unsafe { CGPreflightScreenCaptureAccess() },
            "screen capture permission is unavailable"
        );
        let current = self
            .foreground()?
            .context("screen capture refused because there is no current front window")?;
        anyhow::ensure!(
            !macos_secure_event_input_enabled()
                && macos_capture_scope_matches(snapshot, &current),
            "screen capture refused because the selected front window changed or its content safety is secure or unknown"
        );
        let window_id = current
            .window_id
            .context("screen capture refused because the selected window has no native ID")?;
        let status = Command::new("/usr/sbin/screencapture")
            .args(macos_window_capture_args(window_id))
            .arg(destination)
            .status()?;
        anyhow::ensure!(
            status.success(),
            "macOS screencapture failed or permission was denied"
        );
        Ok(())
    }
}

#[cfg(target_os = "windows")]
struct WindowsAdapter;

#[cfg(any(target_os = "windows", test))]
#[derive(Debug, Clone)]
struct WindowsProbe {
    session_name: Option<String>,
    interactive_session: bool,
}

#[cfg(any(target_os = "windows", test))]
fn windows_capability_report(probe: WindowsProbe) -> CapabilityReport {
    let session_label = probe.session_name.as_deref().unwrap_or("unknown");
    let session_limitation = if probe.interactive_session {
        format!(
            "An interactive Windows session ({session_label}) was detected. This only describes the session; the v1 native UI Automation client is not implemented."
        )
    } else {
        "An interactive Windows session could not be established from the process environment."
            .into()
    };
    let unimplemented =
        "The v1 Windows native capture client is not implemented or target-system accepted.";
    CapabilityReport {
        platform: format!("Windows/{session_label}"),
        platform_version: "runtime-detected".into(),
        observed_at: Utc::now(),
        capabilities: vec![
            capability(
                "session-context",
                "Interactive desktop session detection",
                if probe.interactive_session {
                    CapabilityState::Available
                } else {
                    CapabilityState::Degraded
                },
                None,
                Some(session_limitation.clone()),
            ),
            unavailable_capability(
                "foreground-window",
                "Frontmost application and window",
                format!("{unimplemented} GetForegroundWindow/UI Automation is not wired."),
            ),
            unavailable_capability(
                "accessible-text",
                "Accessible text changes",
                format!("{unimplemented} No UI Automation text events are consumed."),
            ),
            unavailable_capability(
                "screen-capture",
                "Selected-window capture",
                format!("{unimplemented} No Windows Graphics Capture session is created."),
            ),
            unavailable_capability(
                "raw-input",
                "Raw input content",
                format!("{unimplemented} No global input hook is installed."),
            ),
            unavailable_capability(
                "system-lock-state",
                "Lock and sleep state",
                format!("{unimplemented} Session lock notifications are not consumed."),
            ),
        ],
        adapters: vec![
            "windows-native-unimplemented".into(),
            "filesystem-polling".into(),
            "browser-extension-opt-in".into(),
            "vscode-extension-opt-in".into(),
        ],
        warnings: vec![
            session_limitation,
            "Windows native capture is unavailable in v1. The recorder never auto-elevates, and this report is not Windows system acceptance.".into(),
        ],
    }
}

#[cfg(any(target_os = "windows", test))]
fn detect_windows_probe() -> WindowsProbe {
    let session_name = std::env::var("SESSIONNAME")
        .ok()
        .map(|value| value.trim().to_string())
        .filter(|value| !value.is_empty());
    let interactive_session = session_name
        .as_deref()
        .is_some_and(|value| !value.eq_ignore_ascii_case("services"));
    WindowsProbe {
        session_name,
        interactive_session,
    }
}

#[cfg(target_os = "windows")]
impl CaptureAdapter for WindowsAdapter {
    fn id(&self) -> &'static str {
        "windows-native-unimplemented"
    }
    fn probe(&self) -> CapabilityReport {
        let mut report = windows_capability_report(detect_windows_probe());
        report.platform_version = Command::new("cmd")
            .args(["/C", "ver"])
            .output()
            .ok()
            .filter(|output| output.status.success())
            .map(|output| String::from_utf8_lossy(&output.stdout).trim().to_string())
            .filter(|value| !value.is_empty())
            .unwrap_or_else(|| "unknown".into());
        report
    }
    fn foreground(&self) -> Result<Option<ForegroundSnapshot>> {
        anyhow::bail!(
            "Windows foreground observation is unavailable: the v1 UI Automation client is not implemented"
        )
    }
    fn system_state(&self) -> Result<SystemCaptureState> {
        Ok(SystemCaptureState {
            locked: false,
            sleeping: false,
            detection_reliable: false,
        })
    }
    fn capture_screenshot(
        &self,
        _snapshot: &ForegroundSnapshot,
        _destination: &Path,
    ) -> Result<()> {
        anyhow::bail!(
            "Windows selected-window capture is unavailable: the v1 Graphics Capture client is not implemented"
        )
    }
}

#[cfg(target_os = "linux")]
struct LinuxAdapter;

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, PartialEq, Eq)]
enum LinuxSessionType {
    Wayland,
    X11,
    Unknown(String),
}

#[cfg(any(target_os = "linux", test))]
impl LinuxSessionType {
    fn from_value(value: Option<String>) -> Self {
        match value.as_deref().map(str::trim).map(str::to_ascii_lowercase) {
            Some(value) if value == "wayland" => Self::Wayland,
            Some(value) if value == "x11" => Self::X11,
            Some(value) if !value.is_empty() => Self::Unknown(value),
            _ => Self::Unknown("unknown".into()),
        }
    }

    fn label(&self) -> &str {
        match self {
            Self::Wayland => "wayland",
            Self::X11 => "x11",
            Self::Unknown(value) => value,
        }
    }
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
enum InterfaceProbe {
    Present,
    Absent,
    Unknown,
}

#[cfg(any(target_os = "linux", test))]
#[derive(Debug, Clone)]
struct LinuxProbe {
    session_type: LinuxSessionType,
    display_present: bool,
    wayland_display_present: bool,
    session_bus_present: bool,
    screencast_portal: InterfaceProbe,
    input_capture_portal: InterfaceProbe,
}

#[cfg(any(target_os = "linux", test))]
fn interface_capability(
    id: &str,
    label: &str,
    probe: InterfaceProbe,
    missing_detail: &str,
) -> Capability {
    match probe {
        InterfaceProbe::Present => capability(
            id,
            label,
            CapabilityState::Available,
            None,
            Some(
                "The D-Bus interface is discoverable; this does not mean the recorder has opened a user-approved capture session."
                    .into(),
            ),
        ),
        InterfaceProbe::Absent => unavailable_capability(id, label, missing_detail.into()),
        InterfaceProbe::Unknown => capability(
            id,
            label,
            CapabilityState::Degraded,
            None,
            Some("Interface discovery was inconclusive; availability is not assumed.".into()),
        ),
    }
}

#[cfg(any(target_os = "linux", test))]
fn linux_capability_report(probe: LinuxProbe) -> CapabilityReport {
    let session = probe.session_type.label();
    let display_matches_session = match &probe.session_type {
        LinuxSessionType::Wayland => probe.wayland_display_present,
        LinuxSessionType::X11 => probe.display_present,
        LinuxSessionType::Unknown(_) => false,
    };
    let session_detail = if display_matches_session {
        format!(
            "A {session} display endpoint was detected. No native foreground-window client is implemented."
        )
    } else {
        format!(
            "The Linux graphical session could not be established reliably (XDG_SESSION_TYPE={session})."
        )
    };
    let native_unavailable =
        "The v1 Linux native capture client is not implemented or target-system accepted.";
    let mut warnings = vec![session_detail.clone()];
    if !probe.session_bus_present {
        warnings.push(
            "The user D-Bus session could not be established; XDG portal availability was not assumed."
                .into(),
        );
    }
    warnings.push(match &probe.session_type {
        LinuxSessionType::Wayland => "Wayland was detected. Portal interface discovery does not grant consent and the v1 adapter does not negotiate ScreenCast or InputCapture sessions; native capture remains unavailable.".into(),
        LinuxSessionType::X11 => "X11 was detected, but the v1 adapter does not implement EWMH foreground observation or native screenshot/input capture.".into(),
        LinuxSessionType::Unknown(_) => "Linux session type is unknown; no X11 or Wayland behavior is inferred.".into(),
    });

    CapabilityReport {
        platform: format!("Linux/{session}"),
        platform_version: "runtime-detected".into(),
        observed_at: Utc::now(),
        capabilities: vec![
            capability(
                "session-context",
                "Graphical session detection",
                if display_matches_session {
                    CapabilityState::Available
                } else {
                    CapabilityState::Degraded
                },
                None,
                Some(session_detail),
            ),
            interface_capability(
                "xdg-screencast-interface",
                "XDG ScreenCast portal interface",
                probe.screencast_portal,
                "The XDG ScreenCast portal interface was not present on the user session bus.",
            ),
            interface_capability(
                "xdg-input-capture-interface",
                "XDG InputCapture portal interface",
                probe.input_capture_portal,
                "The XDG InputCapture portal interface was not present on the user session bus.",
            ),
            unavailable_capability(
                "foreground-window",
                "Frontmost application and window",
                format!("{native_unavailable} No desktop/compositor foreground client is wired."),
            ),
            unavailable_capability(
                "accessible-text",
                "Accessible text changes",
                format!("{native_unavailable} No AT-SPI text event client is wired."),
            ),
            unavailable_capability(
                "screen-capture",
                "Selected-window capture",
                format!("{native_unavailable} Merely discovering ScreenCast does not create a portal session."),
            ),
            unavailable_capability(
                "raw-input",
                "Raw input content",
                format!("{native_unavailable} No global input hook or approved InputCapture portal session exists."),
            ),
            unavailable_capability(
                "system-lock-state",
                "Lock and sleep state",
                format!("{native_unavailable} No session-manager lock/sleep subscription is wired."),
            ),
        ],
        adapters: vec![
            "linux-native-capture-unimplemented".into(),
            "filesystem-polling".into(),
            "browser-extension-opt-in".into(),
            "vscode-extension-opt-in".into(),
            "shell-opt-in".into(),
        ],
        warnings,
    }
}

#[cfg(any(target_os = "linux", test))]
fn linux_portal_interfaces() -> (InterfaceProbe, InterfaceProbe) {
    if std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_none() {
        return (InterfaceProbe::Unknown, InterfaceProbe::Unknown);
    }
    let child = Command::new("gdbus")
        .args([
            "introspect",
            "--session",
            "--dest",
            "org.freedesktop.portal.Desktop",
            "--object-path",
            "/org/freedesktop/portal/desktop",
        ])
        .stdout(std::process::Stdio::piped())
        .stderr(std::process::Stdio::piped())
        .spawn();
    let Ok(mut child) = child else {
        return (InterfaceProbe::Unknown, InterfaceProbe::Unknown);
    };
    let deadline = std::time::Instant::now() + std::time::Duration::from_millis(750);
    loop {
        match child.try_wait() {
            Ok(Some(_)) => {
                let Ok(output) = child.wait_with_output() else {
                    return (InterfaceProbe::Unknown, InterfaceProbe::Unknown);
                };
                if !output.status.success() {
                    return (InterfaceProbe::Absent, InterfaceProbe::Absent);
                }
                let text = String::from_utf8_lossy(&output.stdout);
                return (
                    if text.contains("org.freedesktop.portal.ScreenCast") {
                        InterfaceProbe::Present
                    } else {
                        InterfaceProbe::Absent
                    },
                    if text.contains("org.freedesktop.portal.InputCapture") {
                        InterfaceProbe::Present
                    } else {
                        InterfaceProbe::Absent
                    },
                );
            }
            Ok(None) if std::time::Instant::now() < deadline => {
                std::thread::sleep(std::time::Duration::from_millis(10));
            }
            Ok(None) => {
                let _ = child.kill();
                let _ = child.wait();
                return (InterfaceProbe::Unknown, InterfaceProbe::Unknown);
            }
            Err(_) => return (InterfaceProbe::Unknown, InterfaceProbe::Unknown),
        }
    }
}

#[cfg(any(target_os = "linux", test))]
fn detect_linux_probe() -> LinuxProbe {
    let session_bus_present = std::env::var_os("DBUS_SESSION_BUS_ADDRESS").is_some();
    let (screencast_portal, input_capture_portal) = linux_portal_interfaces();
    LinuxProbe {
        session_type: LinuxSessionType::from_value(std::env::var("XDG_SESSION_TYPE").ok()),
        display_present: std::env::var_os("DISPLAY").is_some(),
        wayland_display_present: std::env::var_os("WAYLAND_DISPLAY").is_some(),
        session_bus_present,
        screencast_portal,
        input_capture_portal,
    }
}

#[cfg(any(target_os = "linux", test))]
fn linux_platform_version() -> String {
    std::fs::read_to_string("/etc/os-release")
        .ok()
        .and_then(|contents| {
            contents.lines().find_map(|line| {
                line.strip_prefix("PRETTY_NAME=")
                    .map(|value| value.trim_matches('"').to_string())
            })
        })
        .filter(|value| !value.is_empty())
        .unwrap_or_else(|| "unknown".into())
}

#[cfg(target_os = "linux")]
impl CaptureAdapter for LinuxAdapter {
    fn id(&self) -> &'static str {
        "linux-native-unimplemented"
    }
    fn probe(&self) -> CapabilityReport {
        let mut report = linux_capability_report(detect_linux_probe());
        report.platform_version = linux_platform_version();
        report
    }
    fn foreground(&self) -> Result<Option<ForegroundSnapshot>> {
        anyhow::bail!(
            "Linux foreground observation is unavailable: no accepted X11/Wayland client is implemented"
        )
    }
    fn system_state(&self) -> Result<SystemCaptureState> {
        Ok(SystemCaptureState {
            locked: false,
            sleeping: false,
            detection_reliable: false,
        })
    }
    fn capture_screenshot(
        &self,
        _snapshot: &ForegroundSnapshot,
        _destination: &Path,
    ) -> Result<()> {
        anyhow::bail!(
            "Linux selected-window capture is unavailable: the v1 adapter does not create an XDG ScreenCast or X11 capture session"
        )
    }
}

struct UnsupportedAdapter;
impl CaptureAdapter for UnsupportedAdapter {
    fn id(&self) -> &'static str {
        "unsupported"
    }
    fn probe(&self) -> CapabilityReport {
        unavailable_report(
            std::env::consts::OS,
            self.id(),
            "No native adapter is available.",
        )
    }
    fn foreground(&self) -> Result<Option<ForegroundSnapshot>> {
        anyhow::bail!("foreground observation is unavailable on this platform")
    }
    fn capture_screenshot(
        &self,
        _snapshot: &ForegroundSnapshot,
        _destination: &Path,
    ) -> Result<()> {
        anyhow::bail!("unsupported platform")
    }
}

#[cfg(any(target_os = "windows", target_os = "linux", test))]
fn capability(
    id: &str,
    label: &str,
    state: CapabilityState,
    permission: Option<&str>,
    limitation: Option<String>,
) -> Capability {
    Capability {
        id: id.into(),
        label: label.into(),
        state,
        permission: permission.map(str::to_string),
        limitation,
    }
}

#[cfg(any(target_os = "windows", target_os = "linux", test))]
fn unavailable_capability(id: &str, label: &str, limitation: String) -> Capability {
    capability(
        id,
        label,
        CapabilityState::Unavailable,
        None,
        Some(limitation),
    )
}

fn unavailable_report(platform: &str, adapter: &str, warning: &str) -> CapabilityReport {
    CapabilityReport {
        platform: platform.into(),
        platform_version: "runtime-detected".into(),
        observed_at: Utc::now(),
        capabilities: vec![
            Capability {
                id: "foreground-window".into(),
                label: "Frontmost application and window".into(),
                state: CapabilityState::Unavailable,
                permission: None,
                limitation: Some(warning.into()),
            },
            Capability {
                id: "screen-capture".into(),
                label: "Screen capture".into(),
                state: CapabilityState::Unavailable,
                permission: None,
                limitation: Some(warning.into()),
            },
            Capability {
                id: "raw-input".into(),
                label: "Raw input content".into(),
                state: CapabilityState::Unavailable,
                permission: None,
                limitation: Some(warning.into()),
            },
        ],
        adapters: vec![
            adapter.into(),
            "filesystem-polling".into(),
            "browser-extension-opt-in".into(),
            "vscode-extension-opt-in".into(),
            "shell-opt-in".into(),
        ],
        warnings: vec![warning.into()],
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn windows_report_never_upgrades_unimplemented_capture_from_session_detection() {
        let report = windows_capability_report(WindowsProbe {
            session_name: Some("Console".into()),
            interactive_session: true,
        });
        for id in [
            "foreground-window",
            "accessible-text",
            "screen-capture",
            "raw-input",
            "system-lock-state",
        ] {
            let capability = report
                .capabilities
                .iter()
                .find(|capability| capability.id == id)
                .unwrap_or_else(|| panic!("missing {id}"));
            assert_eq!(capability.state, CapabilityState::Unavailable, "{id}");
        }
        let health = capture_health_from_report("windows-test", &report);
        assert_eq!(health.state, AdapterHealthState::Unavailable);
        assert!(health
            .gaps
            .iter()
            .any(|gap| { gap.capability_id == "foreground-window" && gap.blocking }));
        let foreground_gap = health
            .gaps
            .iter()
            .find(|gap| gap.capability_id == "foreground-window")
            .expect("foreground gap");
        assert_eq!(
            foreground_gap.actor_key("windows-native-unimplemented"),
            "capture-adapter:windows-native-unimplemented:capability-unavailable:foreground-window"
        );
    }

    #[test]
    fn linux_portal_discovery_does_not_claim_a_capture_client_exists() {
        let report = linux_capability_report(LinuxProbe {
            session_type: LinuxSessionType::from_value(Some("wayland".into())),
            display_present: false,
            wayland_display_present: true,
            session_bus_present: true,
            screencast_portal: InterfaceProbe::Present,
            input_capture_portal: InterfaceProbe::Present,
        });
        for id in ["foreground-window", "screen-capture", "raw-input"] {
            let capability = report
                .capabilities
                .iter()
                .find(|capability| capability.id == id)
                .unwrap_or_else(|| panic!("missing {id}"));
            assert_eq!(capability.state, CapabilityState::Unavailable, "{id}");
        }
        assert_eq!(
            report
                .capabilities
                .iter()
                .find(|capability| capability.id == "xdg-screencast-interface")
                .map(|capability| &capability.state),
            Some(&CapabilityState::Available)
        );
        assert_eq!(
            capture_health_from_report("linux-test", &report).state,
            AdapterHealthState::Unavailable,
            "a discoverable portal interface is not an operational capture client"
        );
    }

    #[test]
    fn unknown_linux_session_and_portal_probe_results_are_explicit_gaps() {
        let report = linux_capability_report(LinuxProbe {
            session_type: LinuxSessionType::from_value(Some("tty".into())),
            display_present: false,
            wayland_display_present: false,
            session_bus_present: false,
            screencast_portal: InterfaceProbe::Absent,
            input_capture_portal: InterfaceProbe::Unknown,
        });
        let health = capture_health_from_report("linux-test", &report);
        assert_eq!(health.state, AdapterHealthState::Unavailable);
        assert!(health.gaps.iter().any(|gap| {
            gap.code == "capability-unavailable" && gap.capability_id == "foreground-window"
        }));
        assert!(health
            .gaps
            .iter()
            .any(|gap| { gap.capability_id == "xdg-screencast-interface" && !gap.blocking }));
        assert!(report
            .warnings
            .iter()
            .any(|warning| warning.contains("could not be established")));
    }

    #[test]
    fn platform_probe_helpers_compile_without_assuming_capture_availability() {
        let windows = windows_capability_report(detect_windows_probe());
        assert!(windows.capabilities.iter().any(|capability| {
            capability.id == "foreground-window" && capability.state == CapabilityState::Unavailable
        }));

        let linux = linux_capability_report(detect_linux_probe());
        assert!(linux.capabilities.iter().any(|capability| {
            capability.id == "foreground-window" && capability.state == CapabilityState::Unavailable
        }));
        assert!(!linux_platform_version().is_empty());
    }

    #[test]
    fn native_probe_reports_required_capabilities_without_claiming_full_parity() {
        let report = native_adapter().probe();
        for id in ["foreground-window", "screen-capture", "raw-input"] {
            assert!(
                report
                    .capabilities
                    .iter()
                    .any(|capability| capability.id == id),
                "missing {id}"
            );
        }
        assert!(!report.platform.is_empty());
        assert!(!report.adapters.is_empty());
    }

    #[test]
    fn generic_process_matching_does_not_enable_disabled_scope_itself() {
        let target = ToolTarget {
            id: Uuid::new_v4(),
            label: "definitely absent".into(),
            application_id: "air-process-that-cannot-exist-764991".into(),
            executable: None,
            adapter: "generic".into(),
            enabled: false,
        };
        assert!(!process_is_running(&target));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn parses_macos_console_lock_state_without_guessing() {
        assert_eq!(
            parse_macos_lock_state("    \"IOConsoleLocked\" = Yes\n"),
            Some(true)
        );
        assert_eq!(
            parse_macos_lock_state("    \"IOConsoleLocked\" = No\n"),
            Some(false)
        );
        assert_eq!(parse_macos_lock_state("unrelated"), None);
    }

    #[test]
    fn snapshots_without_a_window_id_cannot_claim_capture_availability() {
        let snapshot = ForegroundSnapshot {
            application_id: "example".into(),
            application_name: "Example".into(),
            process_id: 1,
            window_title: None,
            window_id: None,
            secure_input: false,
            content_capture_available: false,
        };
        assert!(snapshot.window_id.is_none());
        assert!(!snapshot.content_capture_available);
        let destination =
            std::env::temp_dir().join(format!("air-invalid-window-capture-{}.png", Uuid::new_v4()));
        assert!(native_adapter()
            .capture_screenshot(&snapshot, &destination)
            .is_err());
        assert!(!destination.exists(), "a refused capture wrote a file");
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_capture_arguments_always_name_one_window() {
        let args = macos_window_capture_args(42);
        assert_eq!(args, ["-x", "-t", "png", "-l", "42"]);
        assert!(args.iter().any(|argument| argument == "-l"));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_capture_scope_must_still_be_the_same_safe_front_window() {
        let expected = ForegroundSnapshot {
            application_id: "editor".into(),
            application_name: "Editor".into(),
            process_id: 10,
            window_title: Some("Paper".into()),
            window_id: Some(42),
            secure_input: false,
            content_capture_available: true,
        };
        assert!(macos_capture_scope_matches(&expected, &expected));

        let mut changed_window = expected.clone();
        changed_window.window_id = Some(43);
        assert!(!macos_capture_scope_matches(&expected, &changed_window));

        let mut newly_secure = expected.clone();
        newly_secure.secure_input = true;
        newly_secure.content_capture_available = false;
        assert!(!macos_capture_scope_matches(&expected, &newly_secure));
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_native_adapter_does_not_claim_text_capture() {
        let report = native_adapter().probe();
        assert_ne!(
            report
                .capabilities
                .iter()
                .find(|capability| capability.id == "foreground-window")
                .map(|capability| &capability.state),
            Some(&CapabilityState::Available),
            "the System Events implementation must retain its degraded/permission boundary"
        );
        for id in ["accessible-text", "raw-input"] {
            assert_eq!(
                report
                    .capabilities
                    .iter()
                    .find(|capability| capability.id == id)
                    .map(|capability| &capability.state),
                Some(&CapabilityState::Unavailable),
                "{id}"
            );
        }
    }

    #[cfg(target_os = "macos")]
    #[test]
    fn macos_console_lock_detection_is_live_and_reliable() {
        let state = native_adapter().system_state().unwrap();
        assert!(state.detection_reliable);
    }
}
