use anyhow::{anyhow, Context, Result};
use base64::{
    engine::general_purpose::{STANDARD, URL_SAFE_NO_PAD},
    Engine,
};
use capture_adapters::{
    native_adapter, snapshot_to_event, AdapterGap, CaptureAdapter, ForegroundSnapshot,
    SystemCaptureState,
};
use chrono::{DateTime, Utc};
use evidence_core::{
    calculate_active_time, canonical::to_jcs, create_manuscript_anchor, export_package,
    revalidate_manuscript_anchor, ActivityInterval, AiUseDisclosure, AiUseDisposition,
    AnchorRevalidation, AnchorRevalidationCapability, Artifact, CapabilityReport, CapabilityState,
    DeviceSigner, EventDraft, EventKind, EvidenceEvent, EvidenceStore, ExportOptions, ExportResult,
    GapKind, GapOrRedaction, ManuscriptAnchor, Project, ProjectKey, PublicEvent, ResearchItem,
    ResearchItemStatus, ResearchItemType, Sensitivity, ToolTarget,
};
use hmac::{Hmac, Mac};
use keyring::Entry;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::{
    collections::{HashMap, HashSet},
    fs,
    path::{Path, PathBuf},
    time::{Duration, Instant, SystemTime, UNIX_EPOCH},
};
use uuid::Uuid;
use walkdir::WalkDir;

const KEYRING_SERVICE: &str = "org.openresearch.integrity-recorder";

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct DashboardState {
    initialized: bool,
    project: Option<Project>,
    armed: bool,
    paused: bool,
    privacy_mode: bool,
    recording: bool,
    active_tool: Option<String>,
    active_seconds: i64,
    event_count: usize,
    gap_count: usize,
    recent_events: Vec<PublicEvent>,
    research_items: Vec<ResearchItem>,
    artifacts: Vec<Artifact>,
    anchors: Vec<ManuscriptAnchor>,
    ai_disclosures: Vec<AiUseDisclosure>,
    export_preview: Option<ExportPreview>,
    quick_controls: QuickControlStatus,
    capabilities: CapabilityReport,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct QuickControlStatus {
    global_pause_shortcut: String,
    global_pause_available: bool,
    tray_controls_available: bool,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportPreview {
    total_count: usize,
    total_bytes: u64,
    categories: Vec<ExportMaterialCategory>,
    exclusions: Vec<ExportExclusion>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportMaterialCategory {
    id: String,
    label: String,
    count: usize,
    bytes: u64,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportExclusion {
    id: String,
    label: String,
    count: usize,
    reason: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateResearchItemInput {
    pub item_type: String,
    pub title: String,
    pub description: String,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct UpdateResearchItemInput {
    pub item_id: String,
    #[serde(default)]
    pub title: Option<String>,
    #[serde(default)]
    pub description: Option<String>,
    #[serde(default)]
    pub status: Option<String>,
    #[serde(default)]
    pub event_ids: Vec<String>,
    #[serde(default)]
    pub artifact_ids: Vec<String>,
    #[serde(default)]
    pub anchor_ids: Vec<String>,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingInfo {
    pub endpoint: String,
    pub project_id: String,
    pub sources: PairingSources,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingSources {
    pub browser: PairingCredential,
    pub vscode: PairingCredential,
    pub shell: PairingCredential,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct PairingCredential {
    pub token: String,
}

#[derive(Debug, Clone, Serialize)]
#[serde(rename_all = "camelCase")]
pub struct BrowserScope {
    pub project_id: String,
    pub accepting: bool,
    pub domains: Vec<String>,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalEventInput {
    pub project_id: String,
    pub source: String,
    pub source_id: String,
    pub message_id: String,
    pub occurred_at: String,
    pub payload_hash: String,
    pub signature: String,
    pub kind: String,
    #[serde(default)]
    pub domain: Option<String>,
    #[serde(default)]
    pub private_mode: bool,
    #[serde(default)]
    pub password_field: bool,
    pub payload: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAnchorInput {
    pub research_item_id: String,
    pub document_path: String,
    pub selected_text: String,
    pub locator: serde_json::Value,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CreateAiDisclosureInput {
    pub research_item_id: Option<String>,
    #[serde(default)]
    pub anchor_ids: Vec<String>,
    pub service: String,
    pub model_statement: Option<String>,
    pub prompt: String,
    pub output: String,
    pub disposition: String,
    pub human_review: String,
    #[serde(default)]
    pub source_is_user_supplied: bool,
}

#[derive(Debug, Clone, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LinkAiDisclosureInput {
    pub disclosure_id: String,
    #[serde(default)]
    pub research_item_id: Option<String>,
    #[serde(default)]
    pub anchor_ids: Vec<String>,
}

#[derive(Debug, Clone, PartialEq, Eq)]
struct FileSignature {
    modified_nanos: u128,
    size: u64,
}

#[derive(Debug, Clone)]
struct PendingFile {
    signature: FileSignature,
    first_seen: Instant,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PersistedRecorderState {
    armed: bool,
    paused: bool,
    privacy_mode: bool,
    paused_before_privacy: bool,
    updated_at: chrono::DateTime<Utc>,
}

impl Default for PersistedRecorderState {
    fn default() -> Self {
        Self {
            armed: false,
            paused: true,
            privacy_mode: false,
            paused_before_privacy: true,
            updated_at: Utc::now(),
        }
    }
}

pub struct RecorderRuntime {
    root: PathBuf,
    project: Option<Project>,
    store: Option<EvidenceStore>,
    project_key: Option<ProjectKey>,
    signer: Option<DeviceSigner>,
    adapter: Box<dyn CaptureAdapter>,
    capabilities: CapabilityReport,
    armed: bool,
    paused: bool,
    privacy_mode: bool,
    paused_before_privacy: bool,
    system_locked: bool,
    recording: bool,
    active_tool: Option<String>,
    active_session: Option<Uuid>,
    activity: Vec<ActivityInterval>,
    research_items: Vec<ResearchItem>,
    artifacts: Vec<Artifact>,
    anchors: Vec<ManuscriptAnchor>,
    ai_disclosures: Vec<AiUseDisclosure>,
    gaps: Vec<GapOrRedaction>,
    started: Instant,
    last_screenshot: Option<Instant>,
    last_file_scan: Option<Instant>,
    last_capability_probe: Option<Instant>,
    last_state_heartbeat: Option<Instant>,
    last_poll: Option<Instant>,
    last_foreground_key: Option<String>,
    known_files: HashMap<PathBuf, FileSignature>,
    pending_files: HashMap<PathBuf, PendingFile>,
    file_index_initialized: bool,
    seen_external_messages: HashSet<Uuid>,
    bound_external_sources: HashMap<String, Uuid>,
    global_pause_available: bool,
}

impl RecorderRuntime {
    pub fn status_text(&self) -> String {
        if self.recording {
            format!(
                "溯研 · 正在记录 {}",
                self.active_tool.as_deref().unwrap_or("研究工具")
            )
        } else if self.paused || self.privacy_mode {
            "溯研 · 已暂停（缺口将被披露）".into()
        } else if self.armed {
            "溯研 · 等待已选研究工具".into()
        } else {
            "溯研 · 未布防".into()
        }
    }
    pub fn load(root: PathBuf) -> Result<Self> {
        fs::create_dir_all(&root)?;
        let adapter = native_adapter();
        let capabilities = adapter.status().capability_report;
        let mut runtime = Self {
            root,
            project: None,
            store: None,
            project_key: None,
            signer: None,
            adapter,
            capabilities,
            armed: false,
            paused: false,
            privacy_mode: false,
            paused_before_privacy: false,
            system_locked: false,
            recording: false,
            active_tool: None,
            active_session: None,
            activity: Vec::new(),
            research_items: Vec::new(),
            artifacts: Vec::new(),
            anchors: Vec::new(),
            ai_disclosures: Vec::new(),
            gaps: Vec::new(),
            started: Instant::now(),
            last_screenshot: None,
            last_file_scan: None,
            last_capability_probe: None,
            last_state_heartbeat: None,
            last_poll: None,
            last_foreground_key: None,
            known_files: HashMap::new(),
            pending_files: HashMap::new(),
            file_index_initialized: false,
            seen_external_messages: HashSet::new(),
            bound_external_sources: HashMap::new(),
            global_pause_available: false,
        };
        runtime.load_current_project()?;
        Ok(runtime)
    }

    pub fn dashboard(&self) -> Result<DashboardState> {
        let events = self
            .store
            .as_ref()
            .map(EvidenceStore::events)
            .transpose()?
            .unwrap_or_default();
        let mut recent_events = events.iter().map(PublicEvent::from).collect::<Vec<_>>();
        let event_count = recent_events.len();
        recent_events.reverse();
        recent_events.truncate(100);
        let active_seconds = self
            .project
            .as_ref()
            .map(|project| {
                calculate_active_time(
                    &self.activity,
                    project.recording_policy.active_window_seconds,
                )
                .num_seconds()
            })
            .unwrap_or(0);
        Ok(DashboardState {
            initialized: self.project.is_some(),
            project: self.project.clone(),
            armed: self.armed,
            paused: self.paused,
            privacy_mode: self.privacy_mode,
            recording: self.recording,
            active_tool: self.active_tool.clone(),
            active_seconds,
            event_count,
            gap_count: self.gaps.len(),
            recent_events,
            research_items: self.research_items.clone(),
            artifacts: self.artifacts.clone(),
            anchors: self.anchors.clone(),
            ai_disclosures: self.ai_disclosures.clone(),
            export_preview: self
                .project
                .as_ref()
                .map(|project| self.build_export_preview(project, &events))
                .transpose()?,
            quick_controls: QuickControlStatus {
                global_pause_shortcut: "CommandOrControl+Shift+Alt+R".into(),
                global_pause_available: self.global_pause_available,
                tray_controls_available: true,
            },
            capabilities: self.capabilities.clone(),
        })
    }

    pub fn set_global_pause_available(&mut self, available: bool) {
        self.global_pause_available = available;
    }

    fn build_export_preview(
        &self,
        project: &Project,
        events: &[EvidenceEvent],
    ) -> Result<ExportPreview> {
        let event_bytes = events.iter().try_fold(0_u64, |total, event| {
            Ok::<_, anyhow::Error>(total.saturating_add(to_jcs(&event.payload)?.len() as u64))
        })?;
        let artifact_category = |id: &str, label: &str, kinds: &[&str]| {
            let matching = self.artifacts.iter().filter(|artifact| {
                artifact.content_included && kinds.contains(&artifact.kind.as_str())
            });
            ExportMaterialCategory {
                id: id.into(),
                label: label.into(),
                count: matching.clone().count(),
                bytes: matching.map(|artifact| artifact.size).sum(),
            }
        };
        let known_artifact_kinds = ["screenshot", "file-snapshot", "ai-prompt", "ai-output"];
        let other_artifacts = self.artifacts.iter().filter(|artifact| {
            artifact.content_included && !known_artifact_kinds.contains(&artifact.kind.as_str())
        });
        let structured_count =
            1 + self.research_items.len() + self.anchors.len() + self.ai_disclosures.len();
        let structured_bytes = to_jcs(project)?.len() as u64
            + to_jcs(&self.research_items)?.len() as u64
            + to_jcs(&self.anchors)?.len() as u64
            + to_jcs(&self.ai_disclosures)?.len() as u64;
        let mut categories = vec![
            ExportMaterialCategory {
                id: "event-payloads".into(),
                label: "事件负载（含原文、命令与活动元数据）".into(),
                count: events.len(),
                bytes: event_bytes,
            },
            artifact_category("screenshots", "获选窗口截图", &["screenshot"]),
            artifact_category("file-snapshots", "研究文件快照", &["file-snapshot"]),
            artifact_category("ai-dialogues", "AI 提示与输出", &["ai-prompt", "ai-output"]),
            ExportMaterialCategory {
                id: "other-artifacts".into(),
                label: "其他内容附件".into(),
                count: other_artifacts.clone().count(),
                bytes: other_artifacts.map(|artifact| artifact.size).sum(),
            },
            ExportMaterialCategory {
                id: "structured-research".into(),
                label: "项目、研究条目、锚点与 AI 披露记录".into(),
                count: structured_count,
                bytes: structured_bytes,
            },
        ];
        categories.retain(|category| category.count > 0 || category.id == "event-payloads");
        let redacted_hashes = self
            .gaps
            .iter()
            .filter(|gap| gap.kind == GapKind::ContentRedacted)
            .flat_map(|gap| gap.affected_hashes.iter())
            .collect::<HashSet<_>>();
        let redacted_count = self
            .gaps
            .iter()
            .filter(|gap| gap.kind == GapKind::ContentRedacted)
            .map(|gap| gap.affected_count as usize)
            .sum();
        let hash_only_count = self
            .artifacts
            .iter()
            .filter(|artifact| {
                !artifact.content_included && !redacted_hashes.contains(&artifact.sha256)
            })
            .count();
        let blocked_count = events
            .iter()
            .filter(|event| event.payload["blocked"].as_bool() == Some(true))
            .count();
        let exclusions = vec![
            ExportExclusion {
                id: "never-captured".into(),
                label: "密码、认证、支付、未知字段与隐私浏览内容".into(),
                count: blocked_count,
                reason: "字段内容永不采集；隐私浏览事件被直接拒绝，发生次数不可知".into(),
            },
            ExportExclusion {
                id: "redacted".into(),
                label: "已主动删除或遮盖的内容".into(),
                count: redacted_count,
                reason: "内容不可恢复，仅保留签名化缺口、数量、理由与允许保留的哈希".into(),
            },
            ExportExclusion {
                id: "hash-only".into(),
                label: "只保留哈希的材料".into(),
                count: hash_only_count,
                reason: "超过快照阈值或未主动纳入完整副本".into(),
            },
            ExportExclusion {
                id: "excluded-paths".into(),
                label: "项目排除路径".into(),
                count: project.recording_policy.excluded_paths.len(),
                reason: "排除范围不扫描，因而无法统计其中未采集内容".into(),
            },
        ];
        Ok(ExportPreview {
            total_count: categories.iter().map(|category| category.count).sum(),
            total_bytes: categories.iter().map(|category| category.bytes).sum(),
            categories,
            exclusions,
        })
    }

    pub fn create_project(
        &mut self,
        name: String,
        author_statement: String,
        research_root: Option<PathBuf>,
    ) -> Result<()> {
        if name.trim().is_empty() || author_statement.trim().is_empty() {
            return Err(anyhow!("project name and author statement are required"));
        }
        let mut project = Project::new(name.trim(), author_statement.trim());
        if let Some(root) = research_root.filter(|path| !path.as_os_str().is_empty()) {
            if !root.is_dir() {
                return Err(anyhow!(
                    "the selected research root is not an existing directory"
                ));
            }
            project.research_roots.push(
                root.canonicalize()
                    .context("failed to resolve the selected research root")?,
            );
        }
        project.selected_tools = default_tools();
        let project_dir = self.project_dir(project.id);
        fs::create_dir_all(&project_dir)?;
        let key = ProjectKey::generate();
        let signer = DeviceSigner::generate();
        store_secret(&format!("project-key:{}", project.id), key.as_bytes())?;
        store_secret(
            &format!("device-key:{}", project.id),
            &signer.secret_bytes(),
        )?;
        let mut store =
            EvidenceStore::open(project_dir.join("evidence"), key.clone(), signer.clone())?;
        let event = store.append(EventDraft {
            project_id: project.id, session_id: None, occurred_at: Utc::now(), monotonic_millis: 0,
            source: "desktop:project".into(), kind: EventKind::Annotation, sensitivity: Sensitivity::PublicMetadata,
            payload: serde_json::json!({"action":"project-created","evidenceClaim":"process-evidence-not-certification","authorStatementHash": evidence_core::crypto::sha256_hex(author_statement.as_bytes())}),
            capability_id: None,
        })?;
        self.project = Some(project);
        self.store = Some(store);
        self.project_key = Some(key);
        self.signer = Some(signer);
        self.armed = true;
        self.paused = false;
        self.privacy_mode = false;
        self.paused_before_privacy = false;
        self.seen_external_messages.clear();
        self.bound_external_sources.clear();
        self.persist_all()?;
        fs::write(
            self.root.join("current-project"),
            self.project.as_ref().unwrap().id.to_string(),
        )?;
        let _ = event;
        self.initialize_file_index();
        Ok(())
    }

    pub fn set_paused(&mut self, paused: bool, reason: &str) -> Result<()> {
        if self.project.is_none() || self.paused == paused {
            return Ok(());
        }
        self.paused = paused;
        self.recording = false;
        let now = Utc::now();
        if paused {
            self.end_session("user-pause")?;
            self.activity.push(boundary_activity_at(now, false, true));
            self.gaps.push(GapOrRedaction {
                id: Uuid::new_v4(),
                project_id: self.project_id()?,
                kind: GapKind::UserPaused,
                started_at: now,
                ended_at: None,
                affected_count: 0,
                affected_hashes: vec![],
                reason: reason.into(),
                actor: "local-user".into(),
                recorded_at: now,
            });
        } else if let Some(gap) = self
            .gaps
            .iter_mut()
            .rev()
            .find(|gap| gap.kind == GapKind::UserPaused && gap.ended_at.is_none())
        {
            gap.ended_at = Some(now);
        }
        self.append(
            EventKind::Gap,
            Sensitivity::PublicMetadata,
            serde_json::json!({"paused":paused,"reason":reason}),
            None,
        )?;
        self.persist_all()
    }

    pub fn toggle_paused(&mut self, reason: &str) -> Result<bool> {
        let paused = !self.paused;
        self.set_paused(paused, reason)?;
        Ok(self.paused)
    }

    pub fn toggle_privacy(&mut self) -> Result<()> {
        if !self.privacy_mode {
            self.paused_before_privacy = self.paused;
            self.privacy_mode = true;
            self.persist_runtime_state()?;
            if !self.paused {
                self.set_paused(true, "privacy-mode")?;
            } else {
                self.append(
                    EventKind::Gap,
                    Sensitivity::PublicMetadata,
                    serde_json::json!({"privacyMode":true,"paused":true,"reason":"privacy-mode"}),
                    None,
                )?;
                self.persist_all()?;
            }
        } else {
            self.privacy_mode = false;
            self.persist_runtime_state()?;
            if !self.paused_before_privacy {
                self.set_paused(false, "privacy-mode-ended")?;
            } else {
                self.append(
                    EventKind::Gap,
                    Sensitivity::PublicMetadata,
                    serde_json::json!({"privacyMode":false,"paused":true,"reason":"privacy-mode-ended-user-pause-preserved"}),
                    None,
                )?;
                self.persist_all()?;
            }
        }
        Ok(())
    }

    pub fn set_tool_enabled(&mut self, tool_id: &str, enabled: bool) -> Result<()> {
        let project = self.project.as_mut().context("no active project")?;
        let tool = project
            .selected_tools
            .iter_mut()
            .find(|tool| tool.id.to_string() == tool_id)
            .context("unknown tool")?;
        tool.enabled = enabled;
        self.persist_all()?;
        self.append(
            EventKind::Annotation,
            Sensitivity::PublicMetadata,
            serde_json::json!({"action":"tool-scope-changed","toolId":tool_id,"enabled":enabled}),
            None,
        )?;
        Ok(())
    }

    pub fn set_domain_allowed(&mut self, domain: &str, enabled: bool) -> Result<()> {
        let candidate = domain
            .trim()
            .trim_start_matches("https://")
            .trim_start_matches("http://")
            .split('/')
            .next()
            .unwrap_or("");
        let normalized = normalize_domain(candidate)?;
        let project = self.project.as_mut().context("no active project")?;
        project
            .selected_domains
            .retain(|value| value != &normalized);
        if enabled {
            project.selected_domains.push(normalized.clone());
            project.selected_domains.sort();
            project.selected_domains.dedup();
        }
        self.persist_all()?;
        self.append(EventKind::Annotation, Sensitivity::PublicMetadata, serde_json::json!({"action":"domain-scope-changed","domain":normalized,"enabled":enabled}), None)?;
        Ok(())
    }

    pub fn set_excluded_path(&mut self, path: &str, enabled: bool) -> Result<()> {
        let raw = PathBuf::from(path.trim());
        if raw.as_os_str().is_empty() {
            return Err(anyhow!("excluded path is required"));
        }
        let canonical = if enabled {
            raw.canonicalize()
                .context("excluded path does not exist or cannot be resolved")?
        } else {
            raw.canonicalize().unwrap_or(raw)
        };
        let project = self.project.as_ref().context("no active project")?;
        if !project
            .research_roots
            .iter()
            .any(|root| canonical.starts_with(root))
        {
            return Err(anyhow!(
                "excluded path must be inside a selected research root"
            ));
        }

        let project = self.project.as_mut().context("no active project")?;
        if enabled {
            project
                .recording_policy
                .excluded_paths
                .push(canonical.clone());
            project.recording_policy.excluded_paths.sort();
            project.recording_policy.excluded_paths.dedup();
        } else {
            project
                .recording_policy
                .excluded_paths
                .retain(|value| value != &canonical);
        }
        self.persist_all()?;
        self.append(
            EventKind::Annotation,
            Sensitivity::PublicMetadata,
            serde_json::json!({
                "action":"path-exclusion-changed",
                "path":canonical,
                "enabled":enabled
            }),
            None,
        )?;
        self.initialize_file_index();
        Ok(())
    }

    pub fn set_screenshot_interval(&mut self, seconds: u32) -> Result<()> {
        if !(10..=3_600).contains(&seconds) {
            return Err(anyhow!(
                "screenshot interval must be between 10 and 3600 seconds"
            ));
        }
        let project = self.project.as_mut().context("no active project")?;
        let previous = project.recording_policy.screenshot_interval_seconds;
        if previous == seconds {
            return Ok(());
        }
        project.recording_policy.screenshot_interval_seconds = seconds;
        self.persist_all()?;
        self.append(
            EventKind::Annotation,
            Sensitivity::PublicMetadata,
            serde_json::json!({
                "action":"recording-policy-changed",
                "field":"screenshotIntervalSeconds",
                "previous":previous,
                "current":seconds
            }),
            None,
        )?;
        Ok(())
    }

    pub fn pairing_info(&self) -> Result<PairingInfo> {
        let id = self.project_id()?;
        Ok(PairingInfo {
            endpoint: "http://127.0.0.1:43119/v1/events".into(),
            project_id: id.to_string(),
            sources: PairingSources {
                browser: PairingCredential {
                    token: self.source_token("browser-extension")?,
                },
                vscode: PairingCredential {
                    token: self.source_token("vscode-extension")?,
                },
                shell: PairingCredential {
                    token: self.source_token("shell-opt-in")?,
                },
            },
        })
    }

    fn source_token(&self, source: &str) -> Result<String> {
        let account = format!("ipc-token:{}:{source}", self.project_id()?);
        let entry = Entry::new(KEYRING_SERVICE, &account)?;
        match entry.get_password() {
            Ok(value) => Ok(value),
            Err(keyring::Error::NoEntry) => {
                let value = format!("{}{}", Uuid::new_v4().simple(), Uuid::new_v4().simple());
                entry.set_password(&value)?;
                Ok(value)
            }
            Err(error) => Err(error).context("failed to read source pairing token"),
        }
    }

    pub fn browser_scope(&self, bearer_token: &str) -> Result<BrowserScope> {
        let token = self.source_token("browser-extension")?;
        if !constant_time_token_match(&token, bearer_token)? {
            return Err(anyhow!("invalid browser bearer token"));
        }
        let project = self.project.as_ref().context("no active project")?;
        Ok(BrowserScope {
            project_id: project.id.to_string(),
            accepting: self.armed && !self.paused && !self.privacy_mode && !self.system_locked,
            domains: project.selected_domains.clone(),
        })
    }

    pub fn set_sync_directory(&mut self, directory: Option<PathBuf>) -> Result<usize> {
        if let Some(path) = &directory {
            fs::create_dir_all(path)?;
        }
        self.project
            .as_mut()
            .context("no active project")?
            .sync_directory = directory;
        self.persist_all()?;
        let copied = self.sync_segments()?;
        self.append(EventKind::Annotation,Sensitivity::PublicMetadata,serde_json::json!({"action":"sync-directory-changed","encryptedImmutableSegmentsOnly":true,"copiedSegments":copied}),None)?;
        Ok(copied)
    }

    pub fn redact_artifact(&mut self, artifact_id: &str, reason: &str) -> Result<()> {
        if reason.trim().is_empty() {
            return Err(anyhow!("a redaction reason is required"));
        }
        let id: Uuid = artifact_id.parse()?;
        let hash = self
            .artifacts
            .iter()
            .find(|artifact| artifact.id == id)
            .context("unknown artifact")?
            .sha256
            .clone();
        let affected = self
            .artifacts
            .iter()
            .filter(|artifact| artifact.sha256 == hash && artifact.content_included)
            .map(|artifact| artifact.id)
            .collect::<Vec<_>>();
        if affected.is_empty() {
            return Err(anyhow!("artifact content has already been removed"));
        }
        let operation_id = Uuid::new_v4();
        // Phase 1 is immutable and precedes the destructive operation. Startup
        // recovery completes any intent that lacks a matching completion event.
        self.append(
            EventKind::Redaction,
            Sensitivity::PublicMetadata,
            serde_json::json!({
                "phase":"intent",
                "operationId":operation_id,
                "artifactIds":affected.clone(),
                "contentHash":hash.clone(),
                "reason":reason.trim(),
                "contentDeleted":false
            }),
            None,
        )?;
        let deletion = self
            .store
            .as_ref()
            .context("evidence store unavailable")?
            .delete_artifact_content(&hash);
        if let Err(error) = deletion {
            self.append(
                EventKind::Redaction,
                Sensitivity::PublicMetadata,
                serde_json::json!({
                    "phase":"failed",
                    "operationId":operation_id,
                    "contentHash":hash.clone(),
                    "reason":reason.trim(),
                    "contentDeleted":false,
                    "error":error.to_string()
                }),
                None,
            )?;
            return Err(error);
        }
        for artifact in self
            .artifacts
            .iter_mut()
            .filter(|artifact| artifact.sha256 == hash && artifact.content_included)
        {
            artifact.content_included = false;
        }
        let now = Utc::now();
        self.gaps.push(GapOrRedaction {
            id: Uuid::new_v4(),
            project_id: self.project_id()?,
            kind: GapKind::ContentRedacted,
            started_at: now,
            ended_at: Some(now),
            affected_count: affected.len() as u64,
            affected_hashes: vec![hash.clone()],
            reason: reason.trim().into(),
            actor: format!("redaction-operation:{operation_id}"),
            recorded_at: now,
        });
        // Persist the material state before phase 2. If this fails, the intent
        // remains available for idempotent recovery on the next startup.
        self.persist_all()?;
        self.append(
            EventKind::Redaction,
            Sensitivity::PublicMetadata,
            serde_json::json!({
                "phase":"completed",
                "operationId":operation_id,
                "artifactIds":affected,
                "contentHash":hash,
                "reason":reason.trim(),
                "contentDeleted":true
            }),
            None,
        )?;
        Ok(())
    }

    pub fn record_external(&mut self, bearer_token: &str, input: ExternalEventInput) -> Result<()> {
        if !self.armed || self.paused || self.privacy_mode || self.system_locked {
            return Err(anyhow!("project is not accepting events"));
        }
        if !matches!(
            input.source.as_str(),
            "browser-extension" | "vscode-extension" | "shell-opt-in"
        ) {
            return Err(anyhow!("untrusted event source"));
        }
        if input.private_mode {
            return Err(anyhow!("private/incognito events are excluded"));
        }
        let project_id = parse_canonical_uuid(&input.project_id, "project ID")?;
        if project_id != self.project_id()? {
            return Err(anyhow!(
                "event is for a project that is not currently armed"
            ));
        }
        let source_id = parse_canonical_uuid(&input.source_id, "source ID")?;
        let message_id = parse_canonical_uuid(&input.message_id, "message ID")?;
        if self.seen_external_messages.contains(&message_id) {
            return Err(anyhow!("replayed external message"));
        }
        if self
            .bound_external_sources
            .get(&input.source)
            .is_some_and(|bound| *bound != source_id)
        {
            return Err(anyhow!(
                "source token is already bound to another installation"
            ));
        }
        let token = self.source_token(&input.source)?;
        if !constant_time_token_match(&token, bearer_token)? {
            return Err(anyhow!("invalid source-specific bearer token"));
        }
        let occurred_at = verify_external_auth(&token, project_id, &input)?;
        self.verify_external_scope(&input)?;
        if input.source == "browser-extension" {
            let raw_domain = input
                .domain
                .as_deref()
                .context("browser event has no domain")?;
            let domain = normalize_domain(raw_domain)?;
            if domain != raw_domain {
                return Err(anyhow!("browser domain must be normalized before signing"));
            }
            let allowed = self
                .project
                .as_ref()
                .unwrap()
                .selected_domains
                .iter()
                .any(|value| domain == *value || domain.ends_with(&format!(".{value}")));
            if !allowed {
                return Err(anyhow!("domain is not selected for this project"));
            }
        }
        let kind = parse_external_kind(&input.source, &input.kind)?;
        let mut sensitivity = Sensitivity::SensitiveContent;
        let secure_field = input.password_field || payload_indicates_secure_field(&input.payload);
        let payload = if secure_field {
            sensitivity = Sensitivity::PublicMetadata;
            // Do not retain a password-derived content hash: even a hash can
            // become an offline guessing oracle. The transport identity and
            // the fact of a blocked field are sufficient for the public gap.
            serde_json::json!({
                "blocked":true,
                "reason":"password-authentication-payment-or-unknown-field",
                "contentStored":false,
                "originalPayloadHashStored":false,
                "_transport":{
                    "messageId":message_id,
                    "sourceId":source_id,
                    "sourceOccurredAt":input.occurred_at,
                    "domain":input.domain,
                }
            })
        } else {
            attach_transport(
                input.payload,
                serde_json::json!({
                    "messageId":message_id,
                    "sourceId":source_id,
                    "sourceOccurredAt":input.occurred_at,
                    "payloadHash":input.payload_hash,
                    "signature":input.signature,
                    "domain":input.domain,
                }),
            )
        };
        let monotonic_millis = self.elapsed_millis();
        let event = self
            .store
            .as_mut()
            .context("evidence store unavailable")?
            .append(EventDraft {
                project_id,
                session_id: self.active_session,
                occurred_at,
                monotonic_millis,
                source: input.source.clone(),
                kind,
                sensitivity,
                payload,
                capability_id: Some("semantic-extension".into()),
            })?;
        self.seen_external_messages.insert(message_id);
        self.bound_external_sources
            .entry(input.source)
            .or_insert(source_id);
        if event_is_qualifying(&event) {
            self.activity.push(activity_for_event(&event));
        }
        Ok(())
    }

    fn verify_external_scope(&self, input: &ExternalEventInput) -> Result<()> {
        let project = self.project.as_ref().context("no active project")?;
        if input.payload["foreground"].as_bool() != Some(true) {
            return Err(anyhow!(
                "semantic event lacks an explicit foreground observation"
            ));
        }
        let enabled = match input.source.as_str() {
            "browser-extension" => !project.selected_domains.is_empty(),
            "vscode-extension" => project
                .selected_tools
                .iter()
                .any(|tool| tool.enabled && tool.adapter == "vscode"),
            "shell-opt-in" => project
                .selected_tools
                .iter()
                .any(|tool| tool.enabled && tool.adapter == "shell"),
            _ => false,
        };
        if !enabled {
            return Err(anyhow!("event source is not enabled for the armed project"));
        }
        match input.source.as_str() {
            "vscode-extension" => self.verify_research_path(
                input.payload["workspaceRoot"]
                    .as_str()
                    .context("VS Code event has no workspace root")?,
            )?,
            "shell-opt-in" => self.verify_research_path(
                input.payload["workingDirectory"]
                    .as_str()
                    .context("Shell event has no working directory")?,
            )?,
            _ => {}
        }
        Ok(())
    }

    fn verify_research_path(&self, candidate: &str) -> Result<()> {
        let candidate = Path::new(candidate)
            .canonicalize()
            .context("semantic event path does not resolve")?;
        let project = self.project.as_ref().context("no active project")?;
        let within_scope = project.research_roots.iter().any(|root| {
            root.canonicalize()
                .is_ok_and(|resolved| candidate == resolved || candidate.starts_with(resolved))
        });
        if !within_scope || self.is_excluded(&candidate) {
            return Err(anyhow!(
                "semantic event path is outside the selected research roots"
            ));
        }
        Ok(())
    }

    pub fn create_research_item(&mut self, input: CreateResearchItemInput) -> Result<()> {
        let project_id = self.project_id()?;
        let item_type = parse_item_type(&input.item_type);
        let mut item = ResearchItem {
            id: Uuid::new_v4(),
            project_id,
            item_type,
            custom_type: None,
            title: input.title.trim().into(),
            description: input.description.trim().into(),
            status: ResearchItemStatus::Active,
            created_at: Utc::now(),
            updated_at: Utc::now(),
            event_ids: vec![],
            artifact_ids: vec![],
            anchor_ids: vec![],
            parent_item_id: None,
        };
        if item.title.is_empty() {
            return Err(anyhow!("research item title is required"));
        }
        let event = self.append(
            EventKind::ResearchItemCreated,
            Sensitivity::SensitiveContent,
            serde_json::to_value(&item)?,
            None,
        )?;
        item.event_ids.push(event.id);
        self.research_items.push(item);
        self.persist_all()
    }

    pub fn update_research_item(&mut self, input: UpdateResearchItemInput) -> Result<()> {
        let item_id = parse_uuid(&input.item_id, "research item ID")?;
        let item_index = self
            .research_items
            .iter()
            .position(|item| item.id == item_id)
            .context("unknown research item")?;
        let event_ids = parse_uuid_list(&input.event_ids, "event ID")?;
        let artifact_ids = parse_uuid_list(&input.artifact_ids, "artifact ID")?;
        let anchor_ids = parse_uuid_list(&input.anchor_ids, "anchor ID")?;

        let known_events = self
            .store
            .as_ref()
            .context("evidence store unavailable")?
            .events()?
            .into_iter()
            .map(|event| event.id)
            .collect::<HashSet<_>>();
        if let Some(unknown) = event_ids.iter().find(|id| !known_events.contains(id)) {
            return Err(anyhow!("unknown event ID {unknown}"));
        }
        if let Some(unknown) = artifact_ids
            .iter()
            .find(|id| !self.artifacts.iter().any(|artifact| artifact.id == **id))
        {
            return Err(anyhow!("unknown artifact ID {unknown}"));
        }
        if let Some(unknown) = anchor_ids
            .iter()
            .find(|id| !self.anchors.iter().any(|anchor| anchor.id == **id))
        {
            return Err(anyhow!("unknown anchor ID {unknown}"));
        }
        if let Some(other_item_anchor) = anchor_ids.iter().find(|id| {
            self.anchors
                .iter()
                .any(|anchor| anchor.id == **id && anchor.research_item_id != item_id)
        }) {
            return Err(anyhow!(
                "anchor {other_item_anchor} belongs to a different research item"
            ));
        }

        let previous = self.research_items[item_index].clone();
        let mut updated = previous.clone();
        if let Some(title) = input.title {
            let title = title.trim();
            if title.is_empty() {
                return Err(anyhow!("research item title cannot be empty"));
            }
            updated.title = title.into();
        }
        if let Some(description) = input.description {
            updated.description = description.trim().into();
        }
        if let Some(status) = input.status {
            updated.status = parse_item_status(&status)?;
        }
        extend_unique(&mut updated.event_ids, event_ids);
        extend_unique(&mut updated.artifact_ids, artifact_ids);
        extend_unique(&mut updated.anchor_ids, anchor_ids);
        updated.updated_at = Utc::now();

        let event = self.append(
            EventKind::ResearchItemUpdated,
            Sensitivity::SensitiveContent,
            serde_json::json!({
                "itemId": item_id,
                "previous": previous,
                "updated": updated,
                "changeSemantics": "append-only-history"
            }),
            None,
        )?;
        extend_unique(&mut updated.event_ids, [event.id]);
        self.research_items[item_index] = updated;
        self.persist_all()
    }

    pub fn create_anchor(&mut self, input: CreateAnchorInput) -> Result<()> {
        let project_id = self.project_id()?;
        let research_item_id: Uuid = input.research_item_id.parse()?;
        if !self
            .research_items
            .iter()
            .any(|item| item.id == research_item_id)
        {
            return Err(anyhow!("unknown research item"));
        }
        let anchor = create_manuscript_anchor(
            project_id,
            research_item_id,
            Path::new(&input.document_path),
            &input.selected_text,
            input.locator,
        )?;
        let event = self.append(
            EventKind::AnchorCreated,
            Sensitivity::SensitiveContent,
            serde_json::to_value(&anchor)?,
            None,
        )?;
        if let Some(item) = self
            .research_items
            .iter_mut()
            .find(|item| item.id == research_item_id)
        {
            item.anchor_ids.push(anchor.id);
            item.event_ids.push(event.id);
            item.updated_at = Utc::now();
        }
        self.anchors.push(anchor);
        self.persist_all()
    }

    pub fn create_ai_disclosure(&mut self, input: CreateAiDisclosureInput) -> Result<()> {
        if input.service.trim().is_empty()
            || input.prompt.trim().is_empty()
            || input.output.trim().is_empty()
            || input.human_review.trim().is_empty()
        {
            return Err(anyhow!(
                "AI service, prompt, output, and human review are required"
            ));
        }
        let project_id = self.project_id()?;
        let research_item_id = input
            .research_item_id
            .as_deref()
            .map(|id| parse_uuid(id, "research item ID"))
            .transpose()?;
        if research_item_id.is_some_and(|id| !self.research_items.iter().any(|item| item.id == id))
        {
            return Err(anyhow!("unknown research item"));
        }
        let anchor_ids = parse_uuid_list(&input.anchor_ids, "anchor ID")?;
        self.validate_disclosure_anchors(research_item_id, &anchor_ids)?;
        let prompt_artifact = self.add_text_artifact("ai-prompt", &input.prompt)?;
        let output_artifact = self.add_text_artifact("ai-output", &input.output)?;
        let disposition = match input.disposition.as_str() {
            "adopted" => AiUseDisposition::Adopted,
            "modified" => AiUseDisposition::Modified,
            "rejected" => AiUseDisposition::Rejected,
            _ => AiUseDisposition::ReferenceOnly,
        };
        let disclosure = AiUseDisclosure {
            id: Uuid::new_v4(),
            project_id,
            research_item_id,
            service: input.service.trim().into(),
            model_statement: input.model_statement,
            prompt_artifact_id: Some(prompt_artifact.id),
            output_artifact_id: Some(output_artifact.id),
            disposition,
            human_review: input.human_review.trim().into(),
            source_is_user_supplied: input.source_is_user_supplied,
            anchor_ids: anchor_ids.clone(),
            created_at: Utc::now(),
        };
        let event = self.append(
            EventKind::AiDisclosureCreated,
            Sensitivity::SensitiveContent,
            serde_json::to_value(&disclosure)?,
            Some("semantic-extension".into()),
        )?;
        let mut prompt_artifact = prompt_artifact;
        let mut output_artifact = output_artifact;
        prompt_artifact.event_id = Some(event.id);
        output_artifact.event_id = Some(event.id);
        let linked_artifact_ids = vec![prompt_artifact.id, output_artifact.id];
        self.artifacts.push(prompt_artifact);
        self.artifacts.push(output_artifact);
        if let Some(id) = research_item_id {
            if let Some(item) = self.research_items.iter_mut().find(|item| item.id == id) {
                extend_unique(&mut item.event_ids, [event.id]);
                extend_unique(&mut item.artifact_ids, linked_artifact_ids);
                extend_unique(&mut item.anchor_ids, anchor_ids);
                item.updated_at = Utc::now();
            }
        }
        self.ai_disclosures.push(disclosure);
        self.persist_all()
    }

    pub fn link_ai_disclosure(&mut self, input: LinkAiDisclosureInput) -> Result<()> {
        let disclosure_id = parse_uuid(&input.disclosure_id, "AI disclosure ID")?;
        let disclosure_index = self
            .ai_disclosures
            .iter()
            .position(|disclosure| disclosure.id == disclosure_id)
            .context("unknown AI disclosure")?;
        let requested_item_id = input
            .research_item_id
            .as_deref()
            .map(|id| parse_uuid(id, "research item ID"))
            .transpose()?;
        let previous_item_id = self.ai_disclosures[disclosure_index].research_item_id;
        if previous_item_id.is_some()
            && requested_item_id.is_some()
            && previous_item_id != requested_item_id
        {
            return Err(anyhow!(
                "an AI disclosure cannot be reassigned; create an additional disclosure instead"
            ));
        }
        let research_item_id = requested_item_id.or(previous_item_id);
        if research_item_id.is_some_and(|id| !self.research_items.iter().any(|item| item.id == id))
        {
            return Err(anyhow!("unknown research item"));
        }
        let anchor_ids = parse_uuid_list(&input.anchor_ids, "anchor ID")?;
        self.validate_disclosure_anchors(research_item_id, &anchor_ids)?;

        let previous = self.ai_disclosures[disclosure_index].clone();
        let mut updated = previous.clone();
        updated.research_item_id = research_item_id;
        extend_unique(&mut updated.anchor_ids, anchor_ids);
        let event = self.append(
            EventKind::AiDisclosureUpdated,
            Sensitivity::SensitiveContent,
            serde_json::json!({
                "disclosureId": disclosure_id,
                "previous": previous,
                "updated": updated,
                "changeSemantics": "additional-link"
            }),
            Some("semantic-extension".into()),
        )?;
        self.ai_disclosures[disclosure_index] = updated.clone();

        if let Some(item_id) = research_item_id {
            let linked_artifacts = [updated.prompt_artifact_id, updated.output_artifact_id]
                .into_iter()
                .flatten();
            if let Some(item) = self
                .research_items
                .iter_mut()
                .find(|item| item.id == item_id)
            {
                extend_unique(&mut item.event_ids, [event.id]);
                extend_unique(&mut item.artifact_ids, linked_artifacts);
                extend_unique(&mut item.anchor_ids, updated.anchor_ids);
                item.updated_at = Utc::now();
            }
        }
        self.persist_all()
    }

    fn validate_disclosure_anchors(
        &self,
        research_item_id: Option<Uuid>,
        anchor_ids: &[Uuid],
    ) -> Result<()> {
        for anchor_id in anchor_ids {
            let anchor = self
                .anchors
                .iter()
                .find(|anchor| anchor.id == *anchor_id)
                .with_context(|| format!("unknown anchor ID {anchor_id}"))?;
            if research_item_id.is_some_and(|item_id| anchor.research_item_id != item_id) {
                return Err(anyhow!(
                    "anchor {anchor_id} belongs to a different research item"
                ));
            }
        }
        Ok(())
    }

    pub fn revalidate_anchors(
        &mut self,
        document_path: Option<String>,
    ) -> Result<Vec<AnchorRevalidation>> {
        let selected_path = document_path.map(PathBuf::from);
        let indices = self
            .anchors
            .iter()
            .enumerate()
            .filter(|(_, anchor)| {
                selected_path
                    .as_ref()
                    .is_none_or(|path| anchor.document_path == *path)
            })
            .map(|(index, _)| index)
            .collect::<Vec<_>>();
        if indices.is_empty() {
            return Err(anyhow!("no manuscript anchors match the requested path"));
        }

        let mut outcomes = Vec::with_capacity(indices.len());
        for index in indices {
            let outcome = revalidate_manuscript_anchor(&self.anchors[index])?;
            let previous_status = self.anchors[index].status.clone();
            let research_item_id = self.anchors[index].research_item_id;
            let event = self.append(
                EventKind::AnchorRevalidated,
                Sensitivity::PublicMetadata,
                serde_json::json!({
                    "anchorId":outcome.anchor_id,
                    "researchItemId":research_item_id,
                    "previousStatus":previous_status,
                    "status":outcome.status,
                    "capability":outcome.capability,
                    "currentDocumentSha256":outcome.current_document_sha256,
                    "detail":outcome.detail
                }),
                None,
            )?;
            self.anchors[index].status = outcome.status.clone();
            self.anchors[index].last_validated_at = Some(Utc::now());
            self.anchors[index].last_validated_document_sha256 =
                outcome.current_document_sha256.clone();
            self.anchors[index].validation_capability =
                Some(anchor_capability_name(&outcome.capability).into());
            self.anchors[index].validation_detail = Some(outcome.detail.clone());
            if let Some(item) = self
                .research_items
                .iter_mut()
                .find(|item| item.id == research_item_id)
            {
                extend_unique(&mut item.event_ids, [event.id]);
                item.updated_at = Utc::now();
            }
            outcomes.push(outcome);
        }
        self.persist_all()?;
        Ok(outcomes)
    }

    pub fn export(
        &mut self,
        destination: PathBuf,
        password: Option<String>,
    ) -> Result<ExportResult> {
        let project = self.project.clone().context("no active project")?;
        let destination = if destination.is_absolute() {
            destination
        } else {
            self.project_dir(project.id)
                .join("exports")
                .join(destination)
        };
        let store = self
            .store
            .as_ref()
            .context("evidence store is unavailable")?;
        let signer = self
            .signer
            .as_ref()
            .context("device signing key is unavailable")?;
        export_package(
            store,
            signer,
            ExportOptions {
                destination,
                password: password.filter(|value| !value.is_empty()),
                project,
                capability_report: self.capabilities.clone(),
                research_items: self.research_items.clone(),
                artifacts: self.artifacts.clone(),
                anchors: self.anchors.clone(),
                ai_disclosures: self.ai_disclosures.clone(),
                gaps: self.gaps.clone(),
                language: "bilingual".into(),
            },
        )
    }

    pub fn poll(&mut self) -> Result<()> {
        let poll_started = Instant::now();
        if let Some(previous) = self.last_poll.replace(poll_started) {
            let interruption = previous.elapsed();
            if self.project.is_some()
                && self.armed
                && !self.paused
                && interruption > Duration::from_secs(10)
            {
                self.record_monitor_interruption(interruption)?;
            }
        }
        if self.project.is_none() {
            self.recording = false;
            return Ok(());
        }

        if self
            .last_capability_probe
            .map(|time| time.elapsed() >= Duration::from_secs(30))
            .unwrap_or(true)
        {
            self.reprobe_capabilities()?;
            self.last_capability_probe = Some(Instant::now());
        }

        match self.adapter.system_state() {
            Ok(state) => {
                self.close_gap_by_actor("adapter:system-state", "system-state-query-restored")?;
                self.handle_system_state(state)?;
            }
            Err(error) => {
                self.stop_recording("system-state-query-failed")?;
                self.open_gap_once(
                    GapKind::AdapterFailure,
                    format!("system state cannot be determined: {error}"),
                    "adapter:system-state",
                )?;
                self.heartbeat_if_due()?;
                return Ok(());
            }
        }

        if !self.armed || self.paused || self.privacy_mode || self.system_locked {
            self.recording = false;
            self.heartbeat_if_due()?;
            return Ok(());
        }

        let snapshot = match self.adapter.foreground() {
            Ok(snapshot) => {
                self.close_gap_by_actor(
                    "adapter:foreground-window",
                    "foreground-observation-restored",
                )?;
                snapshot
            }
            Err(error) => {
                self.stop_recording("foreground-observation-failed")?;
                self.open_gap_once(
                    GapKind::PermissionDenied,
                    format!("foreground observation unavailable: {error}"),
                    "adapter:foreground-window",
                )?;
                self.heartbeat_if_due()?;
                return Ok(());
            }
        };
        let matched = snapshot.as_ref().and_then(|snapshot| {
            self.matching_tool(snapshot)
                .map(|tool| (snapshot.clone(), tool.label.clone()))
        });
        match matched {
            Some((snapshot, label)) => self.poll_active(snapshot, label)?,
            None => {
                let was_active = self.recording
                    || self.active_session.is_some()
                    || self.last_foreground_key.is_some();
                self.recording = false;
                self.active_tool = None;
                self.last_foreground_key = None;
                self.end_session("target-tool-left-foreground")?;
                if was_active {
                    self.activity
                        .push(boundary_activity_at(Utc::now(), false, false));
                }
            }
        }
        if self
            .last_file_scan
            .map(|time| time.elapsed() >= Duration::from_secs(4))
            .unwrap_or(true)
        {
            self.scan_files()?;
            self.last_file_scan = Some(Instant::now());
        }
        let _ = self.sync_segments();
        self.heartbeat_if_due()?;
        Ok(())
    }

    fn poll_active(&mut self, snapshot: ForegroundSnapshot, label: String) -> Result<()> {
        if self.active_session.is_none() {
            self.start_session(&label)?;
        }
        self.recording = true;
        self.active_tool = Some(label.clone());
        let key = format!(
            "{}:{}:{:?}",
            snapshot.application_id, snapshot.process_id, snapshot.window_title
        );
        if self.last_foreground_key.as_deref() != Some(&key) {
            let draft = snapshot_to_event(
                self.project_id()?,
                self.active_session,
                &snapshot,
                self.elapsed_millis(),
            );
            self.store.as_mut().unwrap().append(draft)?;
            self.last_foreground_key = Some(key);
        }
        // Foreground polling proves scope, not user activity. It must never
        // create InputActivity or extend effective time by itself.
        let screenshot_interval = self
            .project
            .as_ref()
            .unwrap()
            .recording_policy
            .screenshot_interval_seconds as u64;
        if self
            .last_screenshot
            .map(|time| time.elapsed() >= Duration::from_secs(screenshot_interval))
            .unwrap_or(true)
        {
            self.capture_screenshot(&snapshot)?;
            self.last_screenshot = Some(Instant::now());
        }
        Ok(())
    }

    fn capture_screenshot(&mut self, snapshot: &ForegroundSnapshot) -> Result<()> {
        let temp = self
            .project_dir(self.project_id()?)
            .join(format!("capture-{}.png", Uuid::new_v4()));
        if snapshot.secure_input
            || !snapshot.content_capture_available
            || snapshot.window_id.is_none()
        {
            self.record_instant_gap(
                GapKind::PlatformLimitation,
                "selected-window screenshot refused: native window ID or focused-content safety is unavailable",
                "screen-capture:scope-refused",
                1,
            )?;
            return Ok(());
        }
        match self.adapter.capture_screenshot(snapshot, &temp) {
            Ok(()) => {
                let bytes = fs::read(&temp)?;
                let hash = self.store.as_ref().unwrap().add_artifact(&bytes)?;
                self.artifacts.push(Artifact {
                    id: Uuid::new_v4(),
                    project_id: self.project_id()?,
                    event_id: None,
                    kind: "screenshot".into(),
                    original_path: None,
                    media_type: "image/png".into(),
                    size: bytes.len() as u64,
                    sha256: hash.clone(),
                    captured_at: Utc::now(),
                    content_included: true,
                });
                let _ = fs::remove_file(&temp);
                self.append(EventKind::Screenshot, Sensitivity::SensitiveContent, serde_json::json!({"artifactHash":hash,"size":bytes.len(),"mediaType":"image/png","captureScope":"selected-front-window","windowId":snapshot.window_id,"applicationId":snapshot.application_id}), Some("screen-capture".into()))?;
                self.persist_all()?;
            }
            Err(error) => {
                let _ = fs::remove_file(&temp);
                self.record_instant_gap(
                    GapKind::PermissionDenied,
                    format!("selected-window screen capture failed: {error}"),
                    "screen-capture:failure",
                    1,
                )?;
            }
        }
        Ok(())
    }

    fn scan_files(&mut self) -> Result<()> {
        let Some(project) = self.project.clone() else {
            return Ok(());
        };
        let now = Instant::now();
        let first_scan = !self.file_index_initialized;
        let mut seen = HashSet::new();
        let mut actions: Vec<(PathBuf, FileSignature, EventKind)> = Vec::new();
        let all_roots_available = project.research_roots.iter().all(|root| root.exists());
        for root in project.research_roots.clone() {
            if !root.exists() {
                continue;
            }
            for entry in WalkDir::new(root)
                .follow_links(false)
                .into_iter()
                .filter_map(Result::ok)
                .filter(|entry| entry.file_type().is_file())
            {
                let path = entry.path().to_path_buf();
                if self.is_excluded(&path) {
                    continue;
                }
                let metadata = entry.metadata()?;
                let signature = FileSignature {
                    modified_nanos: metadata
                        .modified()
                        .unwrap_or(SystemTime::UNIX_EPOCH)
                        .duration_since(UNIX_EPOCH)
                        .unwrap_or_default()
                        .as_nanos(),
                    size: metadata.len(),
                };
                seen.insert(path.clone());
                if first_scan {
                    self.known_files.insert(path, signature);
                    continue;
                }
                let changed = self.known_files.get(&path) != Some(&signature);
                if !changed {
                    self.pending_files.remove(&path);
                    continue;
                }
                let ready = self.pending_files.get(&path).is_some_and(|pending| {
                    pending.signature == signature
                        && pending.first_seen.elapsed() >= Duration::from_secs(2)
                });
                if ready {
                    let kind = if self.known_files.contains_key(&path) {
                        EventKind::FileModified
                    } else {
                        EventKind::FileCreated
                    };
                    actions.push((path.clone(), signature.clone(), kind));
                    self.pending_files.remove(&path);
                } else if self
                    .pending_files
                    .get(&path)
                    .is_none_or(|pending| pending.signature != signature)
                {
                    self.pending_files.insert(
                        path,
                        PendingFile {
                            signature,
                            first_seen: now,
                        },
                    );
                }
            }
        }
        if !first_scan && all_roots_available {
            let deleted = self
                .known_files
                .keys()
                .filter(|path| !seen.contains(*path))
                .cloned()
                .collect::<Vec<_>>();
            for path in deleted {
                self.append(
                    EventKind::FileDeleted,
                    Sensitivity::SensitiveContent,
                    serde_json::json!({"path":path,"contentUnavailable":true}),
                    Some("filesystem".into()),
                )?;
                self.known_files.remove(&path);
            }
        }
        for (path, signature, kind) in actions {
            self.record_stable_file(
                &path,
                &signature,
                project.recording_policy.snapshot_limit_bytes,
                kind,
            )?;
        }
        self.file_index_initialized = true;
        Ok(())
    }

    fn record_stable_file(
        &mut self,
        path: &Path,
        signature: &FileSignature,
        limit: u64,
        kind: EventKind,
    ) -> Result<()> {
        let bytes = fs::read(path)?;
        let sha256 = evidence_core::crypto::sha256_hex(&bytes);
        let artifact_hash = if signature.size <= limit {
            Some(self.store.as_ref().unwrap().add_artifact(&bytes)?)
        } else {
            None
        };
        self.artifacts.push(Artifact {
            id: Uuid::new_v4(),
            project_id: self.project_id()?,
            event_id: None,
            kind: "file-snapshot".into(),
            original_path: Some(path.to_path_buf()),
            media_type: "application/octet-stream".into(),
            size: signature.size,
            sha256: sha256.clone(),
            captured_at: Utc::now(),
            content_included: artifact_hash.is_some(),
        });
        let qualifying_activity = self.recording && self.active_tool.is_some();
        let event = self.append(kind, Sensitivity::SensitiveContent, serde_json::json!({"path":path,"size":signature.size,"sha256":sha256,"snapshotIncluded":artifact_hash.is_some(),"artifactHash":artifact_hash,"qualifyingActivity":qualifying_activity,"tool":self.active_tool}), Some("filesystem".into()))?;
        if event_is_qualifying(&event) {
            self.activity.push(activity_for_event(&event));
        }
        self.known_files
            .insert(path.to_path_buf(), signature.clone());
        if self
            .anchors
            .iter()
            .any(|anchor| anchor.document_path == path)
        {
            self.revalidate_anchors(Some(path.display().to_string()))?;
        }
        self.persist_all()?;
        Ok(())
    }

    fn start_session(&mut self, tool: &str) -> Result<()> {
        let session = Uuid::new_v4();
        self.active_session = Some(session);
        self.append(
            EventKind::SessionStarted,
            Sensitivity::PublicMetadata,
            serde_json::json!({"trigger":"target-application-opened-or-focused","tool":tool}),
            None,
        )?;
        Ok(())
    }

    fn end_session(&mut self, reason: &str) -> Result<()> {
        if self.active_session.is_some() {
            self.append(
                EventKind::SessionEnded,
                Sensitivity::PublicMetadata,
                serde_json::json!({"reason":reason}),
                None,
            )?;
            self.active_session = None;
        }
        Ok(())
    }

    fn append(
        &mut self,
        kind: EventKind,
        sensitivity: Sensitivity,
        payload: serde_json::Value,
        capability_id: Option<String>,
    ) -> Result<evidence_core::EvidenceEvent> {
        let project_id = self.project_id()?;
        let monotonic_millis = self.elapsed_millis();
        self.store
            .as_mut()
            .context("evidence store unavailable")?
            .append(EventDraft {
                project_id,
                session_id: self.active_session,
                occurred_at: Utc::now(),
                monotonic_millis,
                source: "desktop:recorder".into(),
                kind,
                sensitivity,
                payload,
                capability_id,
            })
    }

    fn add_text_artifact(&self, kind: &str, text: &str) -> Result<Artifact> {
        let bytes = text.as_bytes();
        let sha256 = self
            .store
            .as_ref()
            .context("evidence store unavailable")?
            .add_artifact(bytes)?;
        Ok(Artifact {
            id: Uuid::new_v4(),
            project_id: self.project_id()?,
            event_id: None,
            kind: kind.into(),
            original_path: None,
            media_type: "text/plain; charset=utf-8".into(),
            size: bytes.len() as u64,
            sha256,
            captured_at: Utc::now(),
            content_included: true,
        })
    }

    fn matching_tool(&self, snapshot: &ForegroundSnapshot) -> Option<&ToolTarget> {
        let project = self.project.as_ref()?;
        project
            .selected_tools
            .iter()
            .find(|tool| tool_matches_snapshot(tool, snapshot))
    }

    fn is_excluded(&self, path: &Path) -> bool {
        self.project.as_ref().is_none_or(|project| {
            project
                .recording_policy
                .excluded_paths
                .iter()
                .any(|excluded| path.starts_with(excluded))
        })
    }

    fn initialize_file_index(&mut self) {
        self.known_files.clear();
        self.pending_files.clear();
        self.file_index_initialized = false;
        let _ = self.scan_files();
    }

    fn stop_recording(&mut self, reason: &str) -> Result<bool> {
        let was_active =
            self.recording || self.active_session.is_some() || self.last_foreground_key.is_some();
        self.recording = false;
        self.active_tool = None;
        self.last_foreground_key = None;
        self.end_session(reason)?;
        Ok(was_active)
    }

    fn handle_system_state(&mut self, state: SystemCaptureState) -> Result<()> {
        let unavailable = state.locked || state.sleeping;
        if unavailable && !self.system_locked {
            let was_active = self.stop_recording(if state.sleeping {
                "system-sleep"
            } else {
                "system-locked"
            })?;
            self.system_locked = true;
            let now = Utc::now();
            if was_active {
                self.activity.push(boundary_activity_at(now, true, false));
            }
            self.open_gap_once(
                GapKind::DataUnavailable,
                if state.sleeping {
                    "recording stopped because the system is sleeping"
                } else {
                    "recording stopped because the macOS console is locked"
                },
                "system:lock-or-sleep",
            )?;
        } else if !unavailable && self.system_locked {
            self.system_locked = false;
            self.close_gap_by_actor("system:lock-or-sleep", "system-unlocked-or-woke")?;
        }
        if !state.detection_reliable && cfg!(target_os = "macos") {
            self.stop_recording("lock-state-detection-unreliable")?;
            self.open_gap_once(
                GapKind::AdapterFailure,
                "macOS lock state could not be determined reliably",
                "adapter:system-state-reliability",
            )?;
        } else {
            self.close_gap_by_actor(
                "adapter:system-state-reliability",
                "system-state-reliability-restored",
            )?;
        }
        Ok(())
    }

    fn reprobe_capabilities(&mut self) -> Result<()> {
        let status = self.adapter.status();
        let next = status.capability_report;
        let previous = self
            .capabilities
            .capabilities
            .iter()
            .map(|capability| (capability.id.clone(), capability.state.clone()))
            .collect::<HashMap<_, _>>();
        let changes = next
            .capabilities
            .iter()
            .filter_map(|capability| {
                let old = previous.get(&capability.id)?;
                (old != &capability.state).then(|| {
                    (
                        capability.id.clone(),
                        old.clone(),
                        capability.state.clone(),
                        capability.permission.clone(),
                    )
                })
            })
            .collect::<Vec<_>>();
        self.capabilities = next;
        for (id, previous_state, current_state, permission) in changes {
            self.append(
                if permission.is_some() {
                    EventKind::PermissionChanged
                } else {
                    EventKind::CapabilityChanged
                },
                Sensitivity::PublicMetadata,
                serde_json::json!({
                    "capabilityId":id,
                    "previousState":previous_state,
                    "currentState":current_state,
                    "permission":permission,
                    "observedAt":self.capabilities.observed_at
                }),
                Some(id.clone()),
            )?;
            let unavailable = matches!(
                current_state,
                CapabilityState::PermissionRequired | CapabilityState::Unavailable
            );
            let actor = format!("capability:{id}");
            if unavailable {
                if id == "foreground-window" {
                    let was_active = self.stop_recording("foreground-permission-revoked")?;
                    if was_active {
                        self.activity
                            .push(boundary_activity_at(Utc::now(), false, false));
                    }
                }
                self.open_gap_once(
                    GapKind::PermissionDenied,
                    format!("capability became unavailable: {id}"),
                    &actor,
                )?;
            } else {
                self.close_gap_by_actor(&actor, "capability-restored")?;
            }
        }
        self.reconcile_adapter_status_gaps(&status.health.adapter_id, &status.health.gaps)?;
        Ok(())
    }

    fn persist_adapter_status_gaps(&mut self) -> Result<()> {
        let status = self.adapter.status();
        self.capabilities = status.capability_report;
        self.reconcile_adapter_status_gaps(&status.health.adapter_id, &status.health.gaps)
    }

    fn reconcile_adapter_status_gaps(
        &mut self,
        adapter_id: &str,
        gaps: &[AdapterGap],
    ) -> Result<()> {
        let active_actors = gaps
            .iter()
            .filter(|gap| gap.blocking)
            .map(|gap| gap.actor_key(adapter_id))
            .collect::<HashSet<_>>();
        for gap in gaps.iter().filter(|gap| gap.blocking) {
            self.open_gap_once(
                if gap.code == "permission-required" {
                    GapKind::PermissionDenied
                } else {
                    GapKind::PlatformLimitation
                },
                gap.detail.clone(),
                &gap.actor_key(adapter_id),
            )?;
        }
        let prefix = format!("capture-adapter:{adapter_id}:");
        let stale = self
            .gaps
            .iter()
            .filter(|gap| {
                gap.ended_at.is_none()
                    && gap.actor.starts_with(&prefix)
                    && !active_actors.contains(&gap.actor)
            })
            .map(|gap| gap.actor.clone())
            .collect::<Vec<_>>();
        for actor in stale {
            self.close_gap_by_actor(&actor, "native-capture-capability-restored")?;
        }
        Ok(())
    }

    fn record_monitor_interruption(&mut self, elapsed: Duration) -> Result<()> {
        let now = Utc::now();
        let started_at = chrono::Duration::from_std(elapsed)
            .ok()
            .map(|duration| now - duration)
            .unwrap_or(now);
        let reason = format!(
            "recorder monitor was not scheduled for {:.1} seconds; system sleep or process stall may have occurred",
            elapsed.as_secs_f64()
        );
        let gap_id = Uuid::new_v4();
        self.append(
            EventKind::Gap,
            Sensitivity::PublicMetadata,
            serde_json::json!({
                "gapId":gap_id,
                "recordingInterrupted":true,
                "startedAt":started_at,
                "endedAt":now,
                "reason":reason
            }),
            Some("monitor-heartbeat".into()),
        )?;
        self.gaps.push(GapOrRedaction {
            id: gap_id,
            project_id: self.project_id()?,
            kind: GapKind::DataUnavailable,
            started_at,
            ended_at: Some(now),
            affected_count: 0,
            affected_hashes: vec![],
            reason,
            actor: "system:monitor-interruption".into(),
            recorded_at: now,
        });
        self.activity
            .push(boundary_activity_at(started_at, true, false));
        self.persist_all()
    }

    fn open_gap_once(
        &mut self,
        kind: GapKind,
        reason: impl Into<String>,
        actor: &str,
    ) -> Result<()> {
        if self
            .gaps
            .iter()
            .any(|gap| gap.actor == actor && gap.ended_at.is_none())
        {
            return Ok(());
        }
        let reason = reason.into();
        let now = Utc::now();
        let gap_id = Uuid::new_v4();
        self.append(
            EventKind::Gap,
            Sensitivity::PublicMetadata,
            serde_json::json!({
                "gapId":gap_id,
                "open":true,
                "kind":kind,
                "reason":reason,
                "actor":actor,
                "systemLocked":actor == "system:lock-or-sleep",
                "recordingInterrupted":actor == "adapter:foreground-window"
                    || actor == "adapter:system-state"
            }),
            None,
        )?;
        self.gaps.push(GapOrRedaction {
            id: gap_id,
            project_id: self.project_id()?,
            kind,
            started_at: now,
            ended_at: None,
            affected_count: 0,
            affected_hashes: vec![],
            reason,
            actor: actor.into(),
            recorded_at: now,
        });
        self.persist_all()
    }

    fn close_gap_by_actor(&mut self, actor: &str, reason: &str) -> Result<()> {
        let Some((index, gap_id)) = self
            .gaps
            .iter()
            .enumerate()
            .rev()
            .find(|(_, gap)| gap.actor == actor && gap.ended_at.is_none())
            .map(|(index, gap)| (index, gap.id))
        else {
            return Ok(());
        };
        let now = Utc::now();
        self.append(
            EventKind::Gap,
            Sensitivity::PublicMetadata,
            serde_json::json!({
                "gapId":gap_id,
                "open":false,
                "reason":reason,
                "actor":actor,
                "endedAt":now
            }),
            None,
        )?;
        self.gaps[index].ended_at = Some(now);
        self.persist_all()
    }

    fn record_instant_gap(
        &mut self,
        kind: GapKind,
        reason: impl Into<String>,
        actor: &str,
        affected_count: u64,
    ) -> Result<()> {
        let reason = reason.into();
        let now = Utc::now();
        let gap_id = Uuid::new_v4();
        self.append(
            EventKind::Gap,
            Sensitivity::PublicMetadata,
            serde_json::json!({
                "gapId":gap_id,
                "open":false,
                "kind":kind,
                "reason":reason,
                "actor":actor,
                "affectedCount":affected_count,
                "endedAt":now
            }),
            None,
        )?;
        self.gaps.push(GapOrRedaction {
            id: gap_id,
            project_id: self.project_id()?,
            kind,
            started_at: now,
            ended_at: Some(now),
            affected_count,
            affected_hashes: vec![],
            reason,
            actor: actor.into(),
            recorded_at: now,
        });
        self.persist_all()
    }

    fn heartbeat_if_due(&mut self) -> Result<()> {
        if self
            .last_state_heartbeat
            .map(|time| time.elapsed() >= Duration::from_secs(15))
            .unwrap_or(true)
        {
            self.persist_runtime_state()?;
            self.last_state_heartbeat = Some(Instant::now());
        }
        Ok(())
    }

    fn sync_segments(&self) -> Result<usize> {
        match self
            .project
            .as_ref()
            .and_then(|project| project.sync_directory.as_ref())
        {
            Some(directory) => self
                .store
                .as_ref()
                .context("evidence store unavailable")?
                .sync_segments(directory),
            None => Ok(0),
        }
    }
    fn elapsed_millis(&self) -> u64 {
        self.started.elapsed().as_millis().min(u64::MAX as u128) as u64
    }
    fn project_id(&self) -> Result<Uuid> {
        self.project
            .as_ref()
            .map(|project| project.id)
            .context("no active project")
    }
    fn project_dir(&self, id: Uuid) -> PathBuf {
        self.root.join("projects").join(id.to_string())
    }

    fn persist_all(&self) -> Result<()> {
        let Some(project) = &self.project else {
            return Ok(());
        };
        let dir = self.project_dir(project.id);
        fs::create_dir_all(&dir)?;
        write_json(dir.join("project.json"), project)?;
        write_json(dir.join("research-items.json"), &self.research_items)?;
        write_json(dir.join("artifacts.json"), &self.artifacts)?;
        write_json(dir.join("anchors.json"), &self.anchors)?;
        write_json(dir.join("ai-disclosures.json"), &self.ai_disclosures)?;
        write_json(dir.join("gaps.json"), &self.gaps)?;
        self.persist_runtime_state()?;
        Ok(())
    }

    fn persist_runtime_state(&self) -> Result<()> {
        let Some(project) = &self.project else {
            return Ok(());
        };
        let dir = self.project_dir(project.id);
        fs::create_dir_all(&dir)?;
        write_json(
            dir.join("recorder-state.json"),
            &PersistedRecorderState {
                armed: self.armed,
                paused: self.paused,
                privacy_mode: self.privacy_mode,
                paused_before_privacy: self.paused_before_privacy,
                updated_at: Utc::now(),
            },
        )
    }

    fn recover_pending_redactions(&mut self) -> Result<()> {
        let events = self
            .store
            .as_ref()
            .context("evidence store unavailable")?
            .events()?;
        let mut intents = HashMap::<Uuid, (String, Vec<Uuid>, String)>::new();
        let mut terminal = HashSet::<Uuid>::new();
        for event in events
            .iter()
            .filter(|event| event.kind == EventKind::Redaction)
        {
            let Some(operation_id) = event.payload["operationId"]
                .as_str()
                .and_then(|value| value.parse().ok())
            else {
                continue;
            };
            match event.payload["phase"].as_str() {
                Some("intent") => {
                    let Some(hash) = event.payload["contentHash"].as_str() else {
                        continue;
                    };
                    let affected = event.payload["artifactIds"]
                        .as_array()
                        .into_iter()
                        .flatten()
                        .filter_map(|value| value.as_str()?.parse().ok())
                        .collect::<Vec<_>>();
                    let reason = event.payload["reason"]
                        .as_str()
                        .unwrap_or("recovered redaction")
                        .to_string();
                    intents.insert(operation_id, (hash.into(), affected, reason));
                }
                Some("completed" | "failed") => {
                    terminal.insert(operation_id);
                }
                _ => {}
            }
        }
        for (operation_id, (hash, affected, reason)) in intents {
            if terminal.contains(&operation_id) {
                continue;
            }
            self.store
                .as_ref()
                .context("evidence store unavailable")?
                .delete_artifact_content(&hash)?;
            for artifact in self
                .artifacts
                .iter_mut()
                .filter(|artifact| artifact.sha256 == hash)
            {
                artifact.content_included = false;
            }
            let actor = format!("redaction-operation:{operation_id}");
            if !self.gaps.iter().any(|gap| gap.actor == actor) {
                let now = Utc::now();
                self.gaps.push(GapOrRedaction {
                    id: Uuid::new_v4(),
                    project_id: self.project_id()?,
                    kind: GapKind::ContentRedacted,
                    started_at: now,
                    ended_at: Some(now),
                    affected_count: affected.len() as u64,
                    affected_hashes: vec![hash.clone()],
                    reason: reason.clone(),
                    actor,
                    recorded_at: now,
                });
            }
            self.persist_all()?;
            self.append(
                EventKind::Redaction,
                Sensitivity::PublicMetadata,
                serde_json::json!({
                    "phase":"completed",
                    "operationId":operation_id,
                    "artifactIds":affected,
                    "contentHash":hash,
                    "reason":reason,
                    "contentDeleted":true,
                    "recoveredAfterInterruption":true
                }),
                None,
            )?;
        }
        Ok(())
    }

    fn load_current_project(&mut self) -> Result<()> {
        let pointer = self.root.join("current-project");
        if !pointer.exists() {
            return Ok(());
        }
        let id: Uuid = fs::read_to_string(pointer)?.trim().parse()?;
        let dir = self.project_dir(id);
        let project: Project = read_json(dir.join("project.json"))?;
        let state_path = dir.join("recorder-state.json");
        let migrated_without_state = !state_path.exists();
        let mut persisted_state: PersistedRecorderState = read_json_or_default(state_path)?;
        if migrated_without_state {
            // Existing v1 projects had no state file. Keep them armed but
            // require an explicit resume after migration.
            persisted_state.armed = true;
            persisted_state.paused = true;
        }
        let key_bytes = load_secret(&format!("project-key:{id}"))?;
        let signer_bytes = load_secret(&format!("device-key:{id}"))?;
        let key = ProjectKey::from_bytes(
            key_bytes
                .try_into()
                .map_err(|_| anyhow!("invalid project key length"))?,
        );
        let signer = DeviceSigner::from_bytes(
            &signer_bytes
                .try_into()
                .map_err(|_| anyhow!("invalid device key length"))?,
        );
        let store = EvidenceStore::open(dir.join("evidence"), key.clone(), signer.clone())?;
        store.verify_local_chain()?;
        self.project = Some(project);
        self.project_key = Some(key);
        self.signer = Some(signer);
        self.store = Some(store);
        self.armed = persisted_state.armed;
        self.paused = persisted_state.paused || persisted_state.armed;
        self.privacy_mode = persisted_state.privacy_mode;
        self.paused_before_privacy = persisted_state.paused_before_privacy;
        self.research_items = read_json_or_default(dir.join("research-items.json"))?;
        self.artifacts = read_json_or_default(dir.join("artifacts.json"))?;
        self.anchors = read_json_or_default(dir.join("anchors.json"))?;
        self.ai_disclosures = read_json_or_default(dir.join("ai-disclosures.json"))?;
        self.gaps = read_json_or_default(dir.join("gaps.json"))?;
        self.recover_pending_redactions()?;

        let events_before_recovery = self
            .store
            .as_ref()
            .context("evidence store unavailable")?
            .events()?;
        if let Some(session_id) = open_session(&events_before_recovery) {
            self.active_session = Some(session_id);
            self.end_session("startup-recovery-after-unverified-shutdown")?;
        }

        if persisted_state.armed && !persisted_state.paused {
            let now = Utc::now();
            let gap_id = Uuid::new_v4();
            self.append(
                EventKind::Gap,
                Sensitivity::PublicMetadata,
                serde_json::json!({
                    "gapId":gap_id,
                    "open":true,
                    "paused":true,
                    "reason":"startup-fail-safe-after-unverified-shutdown",
                    "startedAt":persisted_state.updated_at
                }),
                None,
            )?;
            self.gaps.push(GapOrRedaction {
                id: gap_id,
                project_id: id,
                kind: GapKind::UserPaused,
                started_at: persisted_state.updated_at,
                ended_at: None,
                affected_count: 0,
                affected_hashes: vec![],
                reason: "startup fail-safe after an unverified shutdown; explicit resume required"
                    .into(),
                actor: "system:startup-fail-safe".into(),
                recorded_at: now,
            });
        }
        let events = self
            .store
            .as_ref()
            .context("evidence store unavailable")?
            .events()?;
        self.rebuild_external_transport_state(&events)?;
        self.activity = rebuild_activity(&events);
        self.persist_adapter_status_gaps()?;
        self.persist_all()?;
        self.initialize_file_index();
        Ok(())
    }

    fn rebuild_external_transport_state(&mut self, events: &[EvidenceEvent]) -> Result<()> {
        self.seen_external_messages.clear();
        self.bound_external_sources.clear();
        for event in events.iter().filter(|event| {
            matches!(
                event.source.as_str(),
                "browser-extension" | "vscode-extension" | "shell-opt-in"
            )
        }) {
            let transport = &event.payload["_transport"];
            if let Some(message) = transport["messageId"].as_str() {
                let message_id = parse_canonical_uuid(message, "stored message ID")?;
                if !self.seen_external_messages.insert(message_id) {
                    return Err(anyhow!("duplicate external message ID in signed history"));
                }
            }
            if let Some(source) = transport["sourceId"].as_str() {
                let source_id = parse_canonical_uuid(source, "stored source ID")?;
                match self.bound_external_sources.entry(event.source.clone()) {
                    std::collections::hash_map::Entry::Vacant(entry) => {
                        entry.insert(source_id);
                    }
                    std::collections::hash_map::Entry::Occupied(entry)
                        if *entry.get() != source_id =>
                    {
                        return Err(anyhow!(
                            "external source installation changed within signed history"
                        ));
                    }
                    std::collections::hash_map::Entry::Occupied(_) => {}
                }
            }
        }
        Ok(())
    }
}

fn boundary_activity_at(
    occurred_at: chrono::DateTime<Utc>,
    system_locked: bool,
    paused: bool,
) -> ActivityInterval {
    ActivityInterval {
        occurred_at,
        tool_id: "boundary".into(),
        foreground: false,
        qualifying: false,
        paused,
        system_locked,
    }
}

fn event_is_qualifying(event: &EvidenceEvent) -> bool {
    if event.payload["blocked"].as_bool() == Some(true)
        || event.payload["contentStored"].as_bool() == Some(false)
            && event.payload["action"]
                .as_str()
                .is_some_and(|action| action.starts_with("secure-field"))
    {
        return false;
    }
    if let Some(explicit) = event.payload["qualifyingActivity"].as_bool() {
        return explicit;
    }
    match event.kind {
        EventKind::InputActivity => {
            event.payload["userGenerated"].as_bool() == Some(true)
                || event.payload["explicit"].as_bool() == Some(true)
        }
        EventKind::AccessibleTextChanged | EventKind::ClipboardAction => {
            event.payload["foreground"].as_bool() == Some(true)
                && matches!(
                    event.source.as_str(),
                    "browser-extension" | "vscode-extension"
                )
        }
        EventKind::CommandExecuted => {
            event.payload["foreground"].as_bool() == Some(true)
                && matches!(event.source.as_str(), "vscode-extension" | "shell-opt-in")
        }
        EventKind::FileCreated | EventKind::FileModified => {
            event.source == "vscode-extension"
                && event.payload["foreground"].as_bool() == Some(true)
        }
        EventKind::WebInteraction => {
            event.payload["foreground"].as_bool() == Some(true)
                && event.payload["action"].as_str().is_some_and(|action| {
                    matches!(
                        action,
                        "user-input" | "paste" | "scroll" | "reading-confirmed"
                    )
                })
        }
        EventKind::Annotation => {
            event.payload["explicitReadingConfirmation"].as_bool() == Some(true)
                || event.payload["action"].as_str() == Some("reading-confirmed")
        }
        _ => false,
    }
}

fn activity_for_event(event: &EvidenceEvent) -> ActivityInterval {
    ActivityInterval {
        occurred_at: event.occurred_at,
        tool_id: event.payload["tool"]
            .as_str()
            .unwrap_or(&event.source)
            .into(),
        foreground: true,
        qualifying: true,
        paused: false,
        system_locked: false,
    }
}

fn rebuild_activity(events: &[EvidenceEvent]) -> Vec<ActivityInterval> {
    let mut activity = Vec::new();
    for event in events {
        if event_is_qualifying(event) {
            activity.push(activity_for_event(event));
            continue;
        }
        let gap_boundary = event.kind == EventKind::Gap
            && (event.payload["paused"].as_bool() == Some(true)
                || event.payload["systemLocked"].as_bool() == Some(true)
                || event.payload["recordingInterrupted"].as_bool() == Some(true));
        if matches!(
            event.kind,
            EventKind::SessionPaused | EventKind::SessionEnded
        ) || gap_boundary
        {
            activity.push(boundary_activity_at(
                event.occurred_at,
                event.payload["systemLocked"].as_bool() == Some(true),
                event.payload["paused"].as_bool() == Some(true),
            ));
        }
    }
    activity
}

fn open_session(events: &[EvidenceEvent]) -> Option<Uuid> {
    let mut active = None;
    for event in events {
        match event.kind {
            EventKind::SessionStarted => active = event.session_id,
            EventKind::SessionEnded if event.session_id == active => active = None,
            _ => {}
        }
    }
    active
}
fn parse_item_type(value: &str) -> ResearchItemType {
    match value {
        "keyConcept" => ResearchItemType::KeyConcept,
        "researchQuestion" => ResearchItemType::ResearchQuestion,
        "keyArgument" => ResearchItemType::KeyArgument,
        "evidenceOrSource" => ResearchItemType::EvidenceOrSource,
        "experiment" => ResearchItemType::Experiment,
        "dataResult" => ResearchItemType::DataResult,
        "objection" => ResearchItemType::Objection,
        "researchDecision" => ResearchItemType::ResearchDecision,
        "aiUse" => ResearchItemType::AiUse,
        _ => ResearchItemType::Custom,
    }
}

fn parse_item_status(value: &str) -> Result<ResearchItemStatus> {
    match value {
        "forming" => Ok(ResearchItemStatus::Forming),
        "active" => Ok(ResearchItemStatus::Active),
        "revised" => Ok(ResearchItemStatus::Revised),
        "rejected" => Ok(ResearchItemStatus::Rejected),
        "superseded" => Ok(ResearchItemStatus::Superseded),
        "final" => Ok(ResearchItemStatus::Final),
        _ => Err(anyhow!(
            "invalid research item status; expected forming, active, revised, rejected, superseded, or final"
        )),
    }
}

fn parse_uuid(value: &str, label: &str) -> Result<Uuid> {
    value
        .parse()
        .with_context(|| format!("invalid {label}: {value}"))
}

fn parse_uuid_list(values: &[String], label: &str) -> Result<Vec<Uuid>> {
    values
        .iter()
        .map(|value| parse_uuid(value, label))
        .collect()
}

fn extend_unique<I>(target: &mut Vec<Uuid>, values: I)
where
    I: IntoIterator<Item = Uuid>,
{
    for value in values {
        if !target.contains(&value) {
            target.push(value);
        }
    }
}

fn anchor_capability_name(capability: &AnchorRevalidationCapability) -> &'static str {
    match capability {
        AnchorRevalidationCapability::ExactDocumentHash => "exactDocumentHash",
        AnchorRevalidationCapability::TextFingerprint => "textFingerprint",
        AnchorRevalidationCapability::ManualReanchorRequired => "manualReanchorRequired",
        AnchorRevalidationCapability::DocumentUnavailable => "documentUnavailable",
    }
}
fn parse_external_kind(source: &str, value: &str) -> Result<EventKind> {
    let kind = match (source, value) {
        ("browser-extension", "webNavigation") => EventKind::WebNavigation,
        ("browser-extension", "webInteraction") => EventKind::WebInteraction,
        ("browser-extension", "download") => EventKind::Download,
        ("browser-extension", "accessibleTextChanged") => EventKind::AccessibleTextChanged,
        ("browser-extension", "aiDisclosureCreated") => EventKind::AiDisclosureCreated,
        ("vscode-extension", "annotation") => EventKind::Annotation,
        ("vscode-extension", "fileModified") => EventKind::FileModified,
        ("vscode-extension", "commandExecuted") => EventKind::CommandExecuted,
        ("shell-opt-in", "commandExecuted") => EventKind::CommandExecuted,
        _ => return Err(anyhow!("event kind is not permitted for this source")),
    };
    Ok(kind)
}

fn parse_canonical_uuid(value: &str, label: &str) -> Result<Uuid> {
    let parsed = Uuid::parse_str(value).with_context(|| format!("invalid {label}"))?;
    if parsed.to_string() != value {
        return Err(anyhow!("{label} must use canonical lowercase UUID form"));
    }
    Ok(parsed)
}

fn normalize_domain(value: &str) -> Result<String> {
    let normalized = value.to_ascii_lowercase();
    if normalized.is_empty()
        || normalized.len() > 253
        || !normalized.is_ascii()
        || normalized.starts_with('.')
        || normalized.ends_with('.')
        || normalized.split('.').any(|label| {
            label.is_empty()
                || label.len() > 63
                || label.starts_with('-')
                || label.ends_with('-')
                || !label
                    .bytes()
                    .all(|byte| byte.is_ascii_alphanumeric() || byte == b'-')
        })
    {
        return Err(anyhow!("invalid browser domain"));
    }
    Ok(normalized)
}

fn tool_matches_snapshot(tool: &ToolTarget, snapshot: &ForegroundSnapshot) -> bool {
    let expected = tool.application_id.trim().to_lowercase();
    tool.enabled
        && tool.adapter == "generic"
        && (snapshot.application_id.trim().to_lowercase() == expected
            || snapshot.application_name.trim().to_lowercase() == expected)
}

fn payload_indicates_secure_field(payload: &serde_json::Value) -> bool {
    payload["blocked"].as_bool() == Some(true)
        || payload["contentStored"].as_bool() == Some(false)
        || payload["action"].as_str().is_some_and(|action| {
            action.contains("secure-field") || action.contains("sensitive-or-unknown-field")
        })
        || payload["fieldClass"].as_str().is_some_and(|class| {
            matches!(
                class,
                "authentication-field" | "payment-field" | "unsupported-or-unknown-field"
            )
        })
}

fn attach_transport(payload: serde_json::Value, transport: serde_json::Value) -> serde_json::Value {
    match payload {
        serde_json::Value::Object(mut object) => {
            object.insert("_transport".into(), transport);
            serde_json::Value::Object(object)
        }
        value => serde_json::json!({"value":value,"_transport":transport}),
    }
}

fn verify_external_auth(
    token: &str,
    project_id: Uuid,
    input: &ExternalEventInput,
) -> Result<DateTime<Utc>> {
    if input.project_id != project_id.to_string() {
        return Err(anyhow!("signed project ID is not canonical"));
    }
    if input.payload_hash.len() != 64
        || !input
            .payload_hash
            .bytes()
            .all(|byte| byte.is_ascii_hexdigit() && !byte.is_ascii_uppercase())
    {
        return Err(anyhow!("payload hash must be lowercase SHA-256 hex"));
    }
    let payload_bytes = to_jcs(&input.payload)?;
    let computed_hash = hex::encode(Sha256::digest(payload_bytes));
    if computed_hash != input.payload_hash {
        return Err(anyhow!("external payload hash mismatch"));
    }
    let occurred_at = DateTime::parse_from_rfc3339(&input.occurred_at)
        .context("external event time is not RFC 3339")?
        .with_timezone(&Utc);
    if (Utc::now() - occurred_at).num_seconds().unsigned_abs() > 300 {
        return Err(anyhow!(
            "external event time is outside the five-minute acceptance window"
        ));
    }
    let signing_input = [
        input.project_id.as_str(),
        input.source.as_str(),
        input.source_id.as_str(),
        input.message_id.as_str(),
        input.occurred_at.as_str(),
        input.kind.as_str(),
        input.domain.as_deref().unwrap_or(""),
        input.payload_hash.as_str(),
    ]
    .join("\n");
    let signature = URL_SAFE_NO_PAD
        .decode(&input.signature)
        .context("external signature is not base64url")?;
    let mut mac = Hmac::<Sha256>::new_from_slice(token.as_bytes())
        .map_err(|_| anyhow!("invalid HMAC key"))?;
    mac.update(signing_input.as_bytes());
    mac.verify_slice(&signature)
        .map_err(|_| anyhow!("external event HMAC is invalid"))?;
    Ok(occurred_at)
}

fn constant_time_token_match(expected: &str, supplied: &str) -> Result<bool> {
    let mut supplied_mac = Hmac::<Sha256>::new_from_slice(supplied.as_bytes())
        .map_err(|_| anyhow!("invalid bearer token"))?;
    supplied_mac.update(b"academic-integrity-recorder/bearer-check/v1");
    let supplied_tag = supplied_mac.finalize().into_bytes();
    let mut expected_mac = Hmac::<Sha256>::new_from_slice(expected.as_bytes())
        .map_err(|_| anyhow!("invalid stored pairing token"))?;
    expected_mac.update(b"academic-integrity-recorder/bearer-check/v1");
    Ok(expected_mac.verify_slice(&supplied_tag).is_ok())
}
fn default_tools() -> Vec<ToolTarget> {
    [
        ("Microsoft Word", "Microsoft Word", "generic"),
        ("LibreOffice", "LibreOffice", "generic"),
        ("Zotero", "Zotero", "generic"),
        ("VS Code", "Code", "vscode"),
        ("Terminal", "Terminal", "shell"),
        ("Jupyter", "Jupyter", "browser"),
        ("RStudio", "RStudio", "generic"),
        ("Excel / Calc", "Excel", "generic"),
    ]
    .into_iter()
    .map(|(label, application_id, adapter)| ToolTarget {
        id: Uuid::new_v4(),
        label: label.into(),
        application_id: application_id.into(),
        executable: None,
        adapter: adapter.into(),
        enabled: false,
    })
    .collect()
}
fn store_secret(account: &str, bytes: &[u8]) -> Result<()> {
    Entry::new(KEYRING_SERVICE, account)?
        .set_password(&STANDARD.encode(bytes))
        .context("failed to store key in operating-system credential vault")
}
fn load_secret(account: &str) -> Result<Vec<u8>> {
    STANDARD
        .decode(
            Entry::new(KEYRING_SERVICE, account)?
                .get_password()
                .context("failed to retrieve key from operating-system credential vault")?,
        )
        .context("stored key is invalid base64")
}
fn write_json(path: PathBuf, value: &impl Serialize) -> Result<()> {
    let temp = path.with_extension("json.tmp");
    fs::write(&temp, serde_json::to_vec_pretty(value)?)?;
    fs::rename(temp, path)?;
    Ok(())
}
fn read_json<T: for<'de> Deserialize<'de>>(path: PathBuf) -> Result<T> {
    Ok(serde_json::from_slice(&fs::read(path)?)?)
}
fn read_json_or_default<T: for<'de> Deserialize<'de> + Default>(path: PathBuf) -> Result<T> {
    if path.exists() {
        read_json(path)
    } else {
        Ok(T::default())
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use chrono::TimeZone;
    use tempfile::tempdir;

    fn research_runtime() -> (tempfile::TempDir, RecorderRuntime) {
        let dir = tempdir().unwrap();
        let project = Project::new("test project", "voluntary test statement");
        let store = EvidenceStore::open(
            dir.path().join("store"),
            ProjectKey::generate(),
            DeviceSigner::generate(),
        )
        .unwrap();
        let mut runtime = RecorderRuntime::load(dir.path().join("runtime")).unwrap();
        runtime.project = Some(project);
        runtime.store = Some(store);
        (dir, runtime)
    }

    fn signed_external_input(token: &str, payload: serde_json::Value) -> ExternalEventInput {
        let project_id = Uuid::new_v4().to_string();
        let source_id = Uuid::new_v4().to_string();
        let message_id = Uuid::new_v4().to_string();
        let occurred_at = Utc::now().to_rfc3339_opts(chrono::SecondsFormat::Millis, true);
        let payload_hash = hex::encode(Sha256::digest(to_jcs(&payload).unwrap()));
        let kind = "fileModified".to_string();
        let signing_input = [
            project_id.as_str(),
            "vscode-extension",
            source_id.as_str(),
            message_id.as_str(),
            occurred_at.as_str(),
            kind.as_str(),
            "",
            payload_hash.as_str(),
        ]
        .join("\n");
        let mut mac = Hmac::<Sha256>::new_from_slice(token.as_bytes()).unwrap();
        mac.update(signing_input.as_bytes());
        let signature = URL_SAFE_NO_PAD.encode(mac.finalize().into_bytes());
        ExternalEventInput {
            project_id,
            source: "vscode-extension".into(),
            source_id,
            message_id,
            occurred_at,
            payload_hash,
            signature,
            kind,
            domain: None,
            private_mode: false,
            password_field: false,
            payload,
        }
    }

    fn event(
        seconds: i64,
        kind: EventKind,
        source: &str,
        payload: serde_json::Value,
    ) -> EvidenceEvent {
        let occurred_at = Utc.timestamp_opt(seconds, 0).unwrap();
        EvidenceEvent {
            id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            session_id: None,
            sequence: seconds.max(0) as u64 + 1,
            occurred_at,
            captured_at: occurred_at,
            monotonic_millis: seconds.max(0) as u64 * 1_000,
            source: source.into(),
            kind,
            sensitivity: Sensitivity::PublicMetadata,
            payload,
            payload_hash: "a".repeat(64),
            previous_hash: "0".repeat(64),
            event_hash: "b".repeat(64),
            capability_id: None,
        }
    }

    #[test]
    fn foreground_polling_metadata_never_qualifies_as_activity() {
        let legacy_poll = event(
            0,
            EventKind::InputActivity,
            "desktop:recorder",
            serde_json::json!({
                "tool":"Word",
                "activityOnly":true,
                "plaintextCaptured":false
            }),
        );
        let focused = event(
            10,
            EventKind::ApplicationFocused,
            "desktop:native",
            serde_json::json!({"tool":"Word"}),
        );
        assert!(!event_is_qualifying(&legacy_poll));
        assert!(!event_is_qualifying(&focused));
        assert!(rebuild_activity(&[legacy_poll, focused]).is_empty());
    }

    #[test]
    fn semantic_events_and_explicit_file_saves_rebuild_active_time() {
        let events = vec![
            event(
                0,
                EventKind::AccessibleTextChanged,
                "browser-extension",
                serde_json::json!({"action":"user-input","foreground":true}),
            ),
            event(
                30,
                EventKind::WebInteraction,
                "browser-extension",
                serde_json::json!({"action":"scroll","foreground":true}),
            ),
            event(
                50,
                EventKind::FileModified,
                "desktop:recorder",
                serde_json::json!({"qualifyingActivity":true,"tool":"Word"}),
            ),
        ];
        let rebuilt = rebuild_activity(&events);
        assert_eq!(rebuilt.len(), 3);
        assert_eq!(calculate_active_time(&rebuilt, 90).num_seconds(), 50);
    }

    #[test]
    fn pause_and_lock_events_break_activity_continuity() {
        let events = vec![
            event(
                0,
                EventKind::CommandExecuted,
                "shell-opt-in",
                serde_json::json!({"foreground":true}),
            ),
            event(
                20,
                EventKind::Gap,
                "desktop:recorder",
                serde_json::json!({"systemLocked":true}),
            ),
            event(
                40,
                EventKind::CommandExecuted,
                "shell-opt-in",
                serde_json::json!({"foreground":true}),
            ),
            event(
                60,
                EventKind::CommandExecuted,
                "shell-opt-in",
                serde_json::json!({"foreground":true}),
            ),
        ];
        assert_eq!(
            calculate_active_time(&rebuild_activity(&events), 90).num_seconds(),
            20
        );
    }

    #[test]
    fn secure_or_blocked_semantic_events_never_qualify() {
        let secure = event(
            0,
            EventKind::WebInteraction,
            "browser-extension",
            serde_json::json!({
                "action":"secure-field-input",
                "contentStored":false
            }),
        );
        let blocked = event(
            1,
            EventKind::AccessibleTextChanged,
            "browser-extension",
            serde_json::json!({"blocked":true}),
        );
        assert!(!event_is_qualifying(&secure));
        assert!(!event_is_qualifying(&blocked));
    }

    #[test]
    fn missing_recorder_state_is_fail_safe() {
        let state = PersistedRecorderState::default();
        assert!(!state.armed);
        assert!(state.paused);
    }

    #[test]
    fn quick_control_toggles_pause_and_preserves_a_visible_gap() {
        let (_dir, mut runtime) = research_runtime();

        runtime.set_global_pause_available(true);
        let dashboard = runtime.dashboard().unwrap();
        assert!(dashboard.quick_controls.global_pause_available);
        assert!(dashboard.quick_controls.tray_controls_available);

        assert!(runtime.toggle_paused("global-shortcut").unwrap());
        assert!(runtime.paused);
        assert!(runtime.gaps.iter().any(|gap| {
            gap.kind == GapKind::UserPaused
                && gap.reason == "global-shortcut"
                && gap.ended_at.is_none()
        }));

        assert!(!runtime.toggle_paused("global-shortcut").unwrap());
        assert!(!runtime.paused);
        assert!(runtime.gaps.iter().any(|gap| {
            gap.kind == GapKind::UserPaused
                && gap.reason == "global-shortcut"
                && gap.ended_at.is_some()
        }));
    }

    #[test]
    fn path_exclusions_are_canonical_scoped_and_audited() {
        let (_dir, mut runtime) = research_runtime();
        let research_root = runtime.root.join("research");
        let excluded = research_root.join("private-notes");
        let outside = runtime.root.join("outside");
        fs::create_dir_all(&excluded).unwrap();
        fs::create_dir_all(&outside).unwrap();
        runtime.project.as_mut().unwrap().research_roots =
            vec![research_root.canonicalize().unwrap()];

        runtime
            .set_excluded_path(excluded.to_str().unwrap(), true)
            .unwrap();
        let canonical = excluded.canonicalize().unwrap();
        assert!(runtime.is_excluded(&canonical.join("draft.md")));
        assert!(runtime
            .set_excluded_path(outside.to_str().unwrap(), true)
            .unwrap_err()
            .to_string()
            .contains("inside a selected research root"));

        runtime
            .set_excluded_path(excluded.to_str().unwrap(), false)
            .unwrap();
        assert!(!runtime.is_excluded(&canonical.join("draft.md")));
        let events = runtime.store.as_ref().unwrap().events().unwrap();
        assert_eq!(
            events
                .iter()
                .filter(|event| event.payload["action"] == "path-exclusion-changed")
                .count(),
            2
        );
    }

    #[test]
    fn screenshot_interval_changes_are_bounded_and_audited() {
        let (_dir, mut runtime) = research_runtime();

        runtime.set_screenshot_interval(45).unwrap();
        assert_eq!(
            runtime
                .project
                .as_ref()
                .unwrap()
                .recording_policy
                .screenshot_interval_seconds,
            45
        );
        assert!(runtime.set_screenshot_interval(9).is_err());
        assert!(runtime.set_screenshot_interval(3_601).is_err());

        let events = runtime.store.as_ref().unwrap().events().unwrap();
        let policy_events = events
            .iter()
            .filter(|event| event.payload["action"] == "recording-policy-changed")
            .collect::<Vec<_>>();
        assert_eq!(policy_events.len(), 1);
        assert_eq!(policy_events[0].payload["previous"], 30);
        assert_eq!(policy_events[0].payload["current"], 45);
    }

    #[test]
    fn crash_recovery_detects_an_unclosed_session() {
        let session = Uuid::new_v4();
        let mut started = event(
            0,
            EventKind::SessionStarted,
            "desktop:recorder",
            serde_json::json!({}),
        );
        started.session_id = Some(session);
        assert_eq!(open_session(&[started.clone()]), Some(session));
        let mut ended = event(
            1,
            EventKind::SessionEnded,
            "desktop:recorder",
            serde_json::json!({}),
        );
        ended.session_id = Some(session);
        assert_eq!(open_session(&[started, ended]), None);
    }

    #[test]
    fn external_hmac_binds_project_source_message_time_kind_and_payload() {
        let token = "source-specific-test-token";
        let input = signed_external_input(
            token,
            serde_json::json!({"path":"workspace/paper.md","foreground":true}),
        );
        let project_id = Uuid::parse_str(&input.project_id).unwrap();
        assert!(verify_external_auth(token, project_id, &input).is_ok());

        let mut modified = input;
        modified.payload["path"] = serde_json::json!("workspace/other.md");
        assert!(verify_external_auth(token, project_id, &modified)
            .unwrap_err()
            .to_string()
            .contains("payload hash mismatch"));
    }

    #[test]
    fn external_protocol_rejects_cross_source_kinds_and_secure_content() {
        assert!(parse_external_kind("shell-opt-in", "webNavigation").is_err());
        assert!(payload_indicates_secure_field(&serde_json::json!({
            "fieldClass":"authentication-field",
            "foreground":true,
            "text":"must-never-be-retained"
        })));
        assert!(default_tools().iter().all(|tool| !tool.enabled));
    }

    #[test]
    fn native_tool_matching_is_exact_and_excludes_semantic_adapters() {
        let snapshot = ForegroundSnapshot {
            application_id: "com.apple.dt.Xcode".into(),
            application_name: "Xcode".into(),
            process_id: 42,
            window_title: Some("Project".into()),
            window_id: Some(7),
            secure_input: false,
            content_capture_available: true,
        };
        let generic_code = ToolTarget {
            id: Uuid::new_v4(),
            label: "Code".into(),
            application_id: "Code".into(),
            executable: None,
            adapter: "generic".into(),
            enabled: true,
        };
        let mut exact_xcode = generic_code.clone();
        exact_xcode.application_id = "Xcode".into();
        let mut semantic_xcode = exact_xcode.clone();
        semantic_xcode.adapter = "vscode".into();

        assert!(!tool_matches_snapshot(&generic_code, &snapshot));
        assert!(tool_matches_snapshot(&exact_xcode, &snapshot));
        assert!(!tool_matches_snapshot(&semantic_xcode, &snapshot));
    }

    #[test]
    fn research_item_status_update_appends_history_and_preserves_links() {
        let (_dir, mut runtime) = research_runtime();
        runtime
            .create_research_item(CreateResearchItemInput {
                item_type: "keyArgument".into(),
                title: "Initial argument".into(),
                description: "First formulation".into(),
            })
            .unwrap();
        let item_id = runtime.research_items[0].id;
        let creation_event = runtime.research_items[0].event_ids[0];

        runtime
            .update_research_item(UpdateResearchItemInput {
                item_id: item_id.to_string(),
                title: Some("Rejected argument".into()),
                description: Some("Counterexample defeats it".into()),
                status: Some("rejected".into()),
                event_ids: vec![creation_event.to_string()],
                artifact_ids: vec![],
                anchor_ids: vec![],
            })
            .unwrap();

        let item = &runtime.research_items[0];
        assert_eq!(item.status, ResearchItemStatus::Rejected);
        assert_eq!(item.title, "Rejected argument");
        assert!(item.event_ids.contains(&creation_event));
        let events = runtime.store.as_ref().unwrap().events().unwrap();
        assert_eq!(events.last().unwrap().kind, EventKind::ResearchItemUpdated);
        assert!(item.event_ids.contains(&events.last().unwrap().id));
    }

    #[test]
    fn ai_disclosure_links_anchors_and_artifacts_to_the_research_item() {
        let (_dir, mut runtime) = research_runtime();
        runtime
            .create_research_item(CreateResearchItemInput {
                item_type: "aiUse".into(),
                title: "Terminology review".into(),
                description: "AI-assisted terminology check".into(),
            })
            .unwrap();
        let item_id = runtime.research_items[0].id;
        let manuscript = runtime.root.join("paper.md");
        fs::write(&manuscript, "The selected terminology appears here.").unwrap();
        runtime
            .create_anchor(CreateAnchorInput {
                research_item_id: item_id.to_string(),
                document_path: manuscript.display().to_string(),
                selected_text: "selected terminology".into(),
                locator: serde_json::json!({"lineStart":1}),
            })
            .unwrap();
        let anchor_id = runtime.anchors[0].id;

        runtime
            .create_ai_disclosure(CreateAiDisclosureInput {
                research_item_id: Some(item_id.to_string()),
                anchor_ids: vec![anchor_id.to_string()],
                service: "example local model".into(),
                model_statement: None,
                prompt: "Check terminology".into(),
                output: "Suggested wording".into(),
                disposition: "modified".into(),
                human_review: "Compared against the manuscript".into(),
                source_is_user_supplied: true,
            })
            .unwrap();

        let disclosure = &runtime.ai_disclosures[0];
        let item = &runtime.research_items[0];
        assert_eq!(disclosure.anchor_ids, vec![anchor_id]);
        assert_eq!(item.artifact_ids.len(), 2);
        assert!(item.anchor_ids.contains(&anchor_id));
    }

    #[test]
    fn a_disclosure_can_be_linked_after_creation() {
        let (_dir, mut runtime) = research_runtime();
        runtime
            .create_research_item(CreateResearchItemInput {
                item_type: "aiUse".into(),
                title: "Later link".into(),
                description: "Created after importing the conversation".into(),
            })
            .unwrap();
        let item_id = runtime.research_items[0].id;
        runtime
            .create_ai_disclosure(CreateAiDisclosureInput {
                research_item_id: None,
                anchor_ids: vec![],
                service: "imported service".into(),
                model_statement: None,
                prompt: "prompt".into(),
                output: "output".into(),
                disposition: "referenceOnly".into(),
                human_review: "No content adopted".into(),
                source_is_user_supplied: true,
            })
            .unwrap();
        let disclosure_id = runtime.ai_disclosures[0].id;

        runtime
            .link_ai_disclosure(LinkAiDisclosureInput {
                disclosure_id: disclosure_id.to_string(),
                research_item_id: Some(item_id.to_string()),
                anchor_ids: vec![],
            })
            .unwrap();

        assert_eq!(runtime.ai_disclosures[0].research_item_id, Some(item_id));
        assert_eq!(runtime.research_items[0].artifact_ids.len(), 2);
        assert_eq!(
            runtime
                .store
                .as_ref()
                .unwrap()
                .events()
                .unwrap()
                .last()
                .unwrap()
                .kind,
            EventKind::AiDisclosureUpdated
        );
    }

    #[test]
    fn manuscript_revalidation_updates_status_and_item_history() {
        let (_dir, mut runtime) = research_runtime();
        runtime
            .create_research_item(CreateResearchItemInput {
                item_type: "keyConcept".into(),
                title: "Anchored concept".into(),
                description: "Definition in final text".into(),
            })
            .unwrap();
        let item_id = runtime.research_items[0].id;
        let manuscript = runtime.root.join("paper.tex");
        fs::write(&manuscript, "A stable selected definition appears here.").unwrap();
        runtime
            .create_anchor(CreateAnchorInput {
                research_item_id: item_id.to_string(),
                document_path: manuscript.display().to_string(),
                selected_text: "selected definition appears".into(),
                locator: serde_json::json!({"sourcePath":"paper.tex"}),
            })
            .unwrap();
        let before_events = runtime.research_items[0].event_ids.len();
        fs::write(
            &manuscript,
            "New introduction. A stable selected definition appears here. New conclusion.",
        )
        .unwrap();

        let outcomes = runtime
            .revalidate_anchors(Some(manuscript.display().to_string()))
            .unwrap();

        assert_eq!(outcomes[0].status, evidence_core::AnchorStatus::Relocatable);
        assert_eq!(
            runtime.anchors[0].status,
            evidence_core::AnchorStatus::Relocatable
        );
        assert_eq!(runtime.research_items[0].event_ids.len(), before_events + 1);
    }
}
