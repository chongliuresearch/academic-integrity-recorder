mod runtime;

use anyhow::Context;
use runtime::{
    CreateAiDisclosureInput, CreateAnchorInput, CreateResearchItemInput, DashboardState,
    LinkAiDisclosureInput, RecorderRuntime, UpdateResearchItemInput,
};
use serde::Serialize;
use std::{
    path::PathBuf,
    sync::{Arc, Mutex},
    thread,
    time::Duration,
};
use tauri::menu::MenuBuilder;
use tauri::tray::{MouseButton, MouseButtonState, TrayIconBuilder, TrayIconEvent};
use tauri::{Manager, State};
use tauri_plugin_global_shortcut::{GlobalShortcutExt, Shortcut, ShortcutState};

type SharedRuntime = Arc<Mutex<RecorderRuntime>>;
const GLOBAL_PAUSE_SHORTCUT: &str = "CommandOrControl+Shift+Alt+R";

#[tauri::command]
fn get_dashboard(state: State<'_, SharedRuntime>) -> Result<DashboardState, String> {
    state
        .lock()
        .map_err(|_| "recorder state lock was poisoned".to_string())?
        .dashboard()
        .map_err(err)
}

#[tauri::command]
fn create_project(
    state: State<'_, SharedRuntime>,
    name: String,
    author_statement: String,
    research_root: Option<String>,
) -> Result<(), String> {
    state
        .lock()
        .map_err(|_| "recorder state lock was poisoned".to_string())?
        .create_project(name, author_statement, research_root.map(PathBuf::from))
        .map_err(err)
}

#[tauri::command]
fn pause_recording(state: State<'_, SharedRuntime>) -> Result<(), String> {
    state
        .lock()
        .map_err(|_| "recorder state lock was poisoned".to_string())?
        .set_paused(true, "user-pause")
        .map_err(err)
}

#[tauri::command]
fn resume_recording(state: State<'_, SharedRuntime>) -> Result<(), String> {
    state
        .lock()
        .map_err(|_| "recorder state lock was poisoned".to_string())?
        .set_paused(false, "user-resume")
        .map_err(err)
}

#[tauri::command]
fn toggle_privacy(state: State<'_, SharedRuntime>) -> Result<(), String> {
    state
        .lock()
        .map_err(|_| "recorder state lock was poisoned".to_string())?
        .toggle_privacy()
        .map_err(err)
}

#[tauri::command]
fn set_tool_enabled(
    state: State<'_, SharedRuntime>,
    tool_id: String,
    enabled: bool,
) -> Result<(), String> {
    state
        .lock()
        .map_err(|_| "recorder state lock was poisoned".to_string())?
        .set_tool_enabled(&tool_id, enabled)
        .map_err(err)
}

#[tauri::command]
fn set_domain_allowed(
    state: State<'_, SharedRuntime>,
    domain: String,
    enabled: bool,
) -> Result<(), String> {
    state
        .lock()
        .map_err(|_| "recorder state lock was poisoned".to_string())?
        .set_domain_allowed(&domain, enabled)
        .map_err(err)
}

#[tauri::command]
fn set_excluded_path(
    state: State<'_, SharedRuntime>,
    path: String,
    enabled: bool,
) -> Result<(), String> {
    state
        .lock()
        .map_err(|_| "recorder state lock was poisoned".to_string())?
        .set_excluded_path(&path, enabled)
        .map_err(err)
}

#[tauri::command]
fn set_screenshot_interval(state: State<'_, SharedRuntime>, seconds: u32) -> Result<(), String> {
    state
        .lock()
        .map_err(|_| "recorder state lock was poisoned".to_string())?
        .set_screenshot_interval(seconds)
        .map_err(err)
}

#[tauri::command]
fn get_extension_pairing(state: State<'_, SharedRuntime>) -> Result<runtime::PairingInfo, String> {
    state
        .lock()
        .map_err(|_| "recorder state lock was poisoned".to_string())?
        .pairing_info()
        .map_err(err)
}

#[tauri::command]
fn set_sync_directory(
    state: State<'_, SharedRuntime>,
    directory: Option<String>,
) -> Result<usize, String> {
    state
        .lock()
        .map_err(|_| "recorder state lock was poisoned".to_string())?
        .set_sync_directory(directory.map(PathBuf::from))
        .map_err(err)
}

#[tauri::command]
fn redact_artifact(
    state: State<'_, SharedRuntime>,
    artifact_id: String,
    reason: String,
) -> Result<(), String> {
    state
        .lock()
        .map_err(|_| "recorder state lock was poisoned".to_string())?
        .redact_artifact(&artifact_id, &reason)
        .map_err(err)
}

#[tauri::command]
fn create_research_item(
    state: State<'_, SharedRuntime>,
    input: CreateResearchItemInput,
) -> Result<(), String> {
    state
        .lock()
        .map_err(|_| "recorder state lock was poisoned".to_string())?
        .create_research_item(input)
        .map_err(err)
}

#[tauri::command]
fn update_research_item(
    state: State<'_, SharedRuntime>,
    input: UpdateResearchItemInput,
) -> Result<(), String> {
    state
        .lock()
        .map_err(|_| "recorder state lock was poisoned".to_string())?
        .update_research_item(input)
        .map_err(err)
}

#[tauri::command]
fn create_manuscript_anchor(
    state: State<'_, SharedRuntime>,
    input: CreateAnchorInput,
) -> Result<(), String> {
    state
        .lock()
        .map_err(|_| "recorder state lock was poisoned".to_string())?
        .create_anchor(input)
        .map_err(err)
}

#[tauri::command]
fn create_ai_disclosure(
    state: State<'_, SharedRuntime>,
    input: CreateAiDisclosureInput,
) -> Result<(), String> {
    state
        .lock()
        .map_err(|_| "recorder state lock was poisoned".to_string())?
        .create_ai_disclosure(input)
        .map_err(err)
}

#[tauri::command]
fn link_ai_disclosure(
    state: State<'_, SharedRuntime>,
    input: LinkAiDisclosureInput,
) -> Result<(), String> {
    state
        .lock()
        .map_err(|_| "recorder state lock was poisoned".to_string())?
        .link_ai_disclosure(input)
        .map_err(err)
}

#[tauri::command]
fn revalidate_manuscript_anchors(
    state: State<'_, SharedRuntime>,
    document_path: Option<String>,
) -> Result<Vec<evidence_core::AnchorRevalidation>, String> {
    state
        .lock()
        .map_err(|_| "recorder state lock was poisoned".to_string())?
        .revalidate_anchors(document_path)
        .map_err(err)
}

#[derive(Serialize)]
#[serde(rename_all = "camelCase")]
struct ExportResponse {
    destination: PathBuf,
    review_password: String,
    package_id: String,
    device_fingerprint: String,
}

#[tauri::command]
fn export_evidence(
    state: State<'_, SharedRuntime>,
    destination: String,
    password: Option<String>,
) -> Result<ExportResponse, String> {
    let result = state
        .lock()
        .map_err(|_| "recorder state lock was poisoned".to_string())?
        .export(PathBuf::from(destination), password)
        .map_err(err)?;
    Ok(ExportResponse {
        destination: result.destination,
        review_password: result.review_password,
        package_id: result.package_id.to_string(),
        device_fingerprint: result.device_fingerprint,
    })
}

fn err(error: anyhow::Error) -> String {
    format!("{error:#}")
}

fn show_main_window(app: &tauri::AppHandle) {
    if let Some(window) = app.get_webview_window("main") {
        let _ = window.show();
        let _ = window.set_focus();
    }
}

fn toggle_recording_from_control(app: &tauri::AppHandle, reason: &str) {
    let state = app.state::<SharedRuntime>();
    match state.lock() {
        Ok(mut runtime) => {
            if let Err(error) = runtime.toggle_paused(reason) {
                eprintln!("quick pause/resume failed: {error:#}");
            }
        }
        Err(_) => eprintln!("quick pause/resume failed: recorder state lock was poisoned"),
    };
}

fn toggle_privacy_from_control(app: &tauri::AppHandle) {
    let state = app.state::<SharedRuntime>();
    match state.lock() {
        Ok(mut runtime) => {
            if let Err(error) = runtime.toggle_privacy() {
                eprintln!("quick privacy toggle failed: {error:#}");
            }
        }
        Err(_) => eprintln!("quick privacy toggle failed: recorder state lock was poisoned"),
    };
}

fn global_pause_shortcut() -> Shortcut {
    GLOBAL_PAUSE_SHORTCUT
        .parse()
        .expect("the built-in pause shortcut must be valid")
}

pub fn run() {
    tauri::Builder::default()
        .plugin(tauri_plugin_dialog::init())
        .plugin(
            tauri_plugin_global_shortcut::Builder::new()
                .with_handler(|app, shortcut, event| {
                    if shortcut == &global_pause_shortcut()
                        && event.state() == ShortcutState::Pressed
                    {
                        toggle_recording_from_control(app, "global-shortcut");
                    }
                })
                .build(),
        )
        .setup(|app| {
            let root = std::env::var_os("AIR_DATA_DIR")
                .map(PathBuf::from)
                .unwrap_or(app.path().app_data_dir()?.join("data-v1"));
            let runtime = Arc::new(Mutex::new(RecorderRuntime::load(root)?));
            let tray_menu = MenuBuilder::new(app)
                .text("show-window", "打开溯研")
                .separator()
                .text("toggle-recording", "暂停 / 恢复录制")
                .text("toggle-privacy", "切换隐私模式")
                .separator()
                .text("quit", "退出")
                .build()?;
            TrayIconBuilder::with_id("recorder-status")
                .icon(
                    app.default_window_icon()
                        .context("application icon is unavailable")?
                        .clone(),
                )
                .menu(&tray_menu)
                .show_menu_on_left_click(false)
                .tooltip("溯研 · 等待已选研究工具")
                .build(app)?;
            app.manage(runtime.clone());
            let shortcut_available = match app.global_shortcut().register(global_pause_shortcut()) {
                Ok(()) => true,
                Err(error) => {
                    eprintln!(
                        "global pause shortcut {GLOBAL_PAUSE_SHORTCUT} is unavailable: {error}"
                    );
                    false
                }
            };
            if let Ok(mut runtime) = runtime.lock() {
                runtime.set_global_pause_available(shortcut_available);
            }
            start_monitor(runtime, app.handle().clone());
            start_ipc(app.state::<SharedRuntime>().inner().clone());
            Ok(())
        })
        .invoke_handler(tauri::generate_handler![
            get_dashboard,
            create_project,
            pause_recording,
            resume_recording,
            toggle_privacy,
            set_tool_enabled,
            set_domain_allowed,
            set_excluded_path,
            set_screenshot_interval,
            get_extension_pairing,
            set_sync_directory,
            redact_artifact,
            create_research_item,
            update_research_item,
            create_manuscript_anchor,
            create_ai_disclosure,
            link_ai_disclosure,
            revalidate_manuscript_anchors,
            export_evidence,
        ])
        .on_menu_event(|app, event| match event.id().as_ref() {
            "show-window" => show_main_window(app),
            "toggle-recording" => toggle_recording_from_control(app, "tray-menu"),
            "toggle-privacy" => toggle_privacy_from_control(app),
            "quit" => app.exit(0),
            _ => {}
        })
        .on_tray_icon_event(|app, event| {
            if matches!(
                event,
                TrayIconEvent::Click {
                    button: MouseButton::Left,
                    button_state: MouseButtonState::Up,
                    ..
                }
            ) {
                show_main_window(app);
            }
        })
        .run(tauri::generate_context!())
        .expect("failed to run Academic Integrity Recorder");
}

fn start_ipc(runtime: SharedRuntime) {
    thread::spawn(move || {
        let server = match tiny_http::Server::http("127.0.0.1:43119") {
            Ok(server) => server,
            Err(error) => {
                eprintln!("local extension IPC unavailable: {error}");
                return;
            }
        };
        for mut request in server.incoming_requests() {
            let response = (|| -> Result<String, String> {
                let authorization = request
                    .headers()
                    .iter()
                    .find(|header| header.field.equiv("Authorization"))
                    .map(|header| header.value.as_str().to_string())
                    .unwrap_or_default();
                let token = authorization
                    .strip_prefix("Bearer ")
                    .ok_or("missing bearer token")?
                    .to_string();
                if request.method().as_str() == "GET" && request.url() == "/v1/scope/browser" {
                    let scope = runtime
                        .lock()
                        .map_err(|_| "recorder state lock was poisoned".to_string())?
                        .browser_scope(&token)
                        .map_err(err)?;
                    return serde_json::to_string(&scope).map_err(|error| error.to_string());
                }
                if request.method().as_str() != "POST" || request.url() != "/v1/events" {
                    return Err("not found".into());
                }
                let mut body = String::new();
                let mut bounded = std::io::Read::take(request.as_reader(), 1_048_577);
                std::io::Read::read_to_string(&mut bounded, &mut body)
                    .map_err(|error| error.to_string())?;
                if body.len() > 1_048_576 {
                    return Err("event exceeds one MiB".into());
                }
                let input: runtime::ExternalEventInput =
                    serde_json::from_str(&body).map_err(|error| error.to_string())?;
                runtime
                    .lock()
                    .map_err(|_| "recorder state lock was poisoned".to_string())?
                    .record_external(&token, input)
                    .map_err(err)?;
                Ok("{\"accepted\":true}".into())
            })();
            let (status, body) = match response {
                Ok(body) => (200, body),
                Err(error) => (
                    403,
                    serde_json::json!({"accepted":false,"error":error}).to_string(),
                ),
            };
            let response = tiny_http::Response::from_string(body)
                .with_status_code(status)
                .with_header(
                    tiny_http::Header::from_bytes(&b"Content-Type"[..], &b"application/json"[..])
                        .unwrap(),
                );
            let _ = request.respond(response);
        }
    });
}

fn start_monitor(runtime: SharedRuntime, app: tauri::AppHandle) {
    thread::spawn(move || loop {
        thread::sleep(Duration::from_secs(2));
        if let Ok(mut runtime) = runtime.lock() {
            if let Err(error) = runtime.poll() {
                eprintln!("capture poll failed: {error:#}");
            }
            if let Some(tray) = app.tray_by_id("recorder-status") {
                let _ = tray.set_tooltip(Some(runtime.status_text()));
            }
        }
    });
}
