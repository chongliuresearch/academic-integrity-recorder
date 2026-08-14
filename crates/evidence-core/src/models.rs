use chrono::{DateTime, Utc};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::path::PathBuf;
use uuid::Uuid;

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Project {
    pub id: Uuid,
    pub name: String,
    pub author_statement: String,
    pub created_at: DateTime<Utc>,
    pub research_roots: Vec<PathBuf>,
    pub sync_directory: Option<PathBuf>,
    pub recording_policy: RecordingPolicy,
    pub selected_tools: Vec<ToolTarget>,
    pub selected_domains: Vec<String>,
}

impl Project {
    pub fn new(name: impl Into<String>, author_statement: impl Into<String>) -> Self {
        Self {
            id: Uuid::new_v4(),
            name: name.into(),
            author_statement: author_statement.into(),
            created_at: Utc::now(),
            research_roots: Vec::new(),
            sync_directory: None,
            recording_policy: RecordingPolicy::default(),
            selected_tools: Vec::new(),
            selected_domains: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct RecordingPolicy {
    pub active_window_seconds: u32,
    pub screenshot_interval_seconds: u32,
    pub snapshot_limit_bytes: u64,
    pub capture_plaintext_in_safe_fields: bool,
    pub capture_clipboard_on_action: bool,
    pub automatic_start: bool,
    pub excluded_applications: Vec<String>,
    pub excluded_domains: Vec<String>,
    pub excluded_paths: Vec<PathBuf>,
}

impl Default for RecordingPolicy {
    fn default() -> Self {
        Self {
            active_window_seconds: 90,
            screenshot_interval_seconds: 30,
            snapshot_limit_bytes: 50 * 1024 * 1024,
            capture_plaintext_in_safe_fields: true,
            capture_clipboard_on_action: true,
            automatic_start: true,
            excluded_applications: vec![
                "com.apple.SecurityAgent".into(),
                "com.apple.loginwindow".into(),
                "CredentialUIBroker.exe".into(),
            ],
            excluded_domains: Vec::new(),
            excluded_paths: Vec::new(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ToolTarget {
    pub id: Uuid,
    pub label: String,
    pub application_id: String,
    pub executable: Option<PathBuf>,
    pub adapter: String,
    pub enabled: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum CapabilityState {
    Available,
    PermissionRequired,
    Degraded,
    Unavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Capability {
    pub id: String,
    pub label: String,
    pub state: CapabilityState,
    pub permission: Option<String>,
    pub limitation: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CapabilityReport {
    pub platform: String,
    pub platform_version: String,
    pub observed_at: DateTime<Utc>,
    pub capabilities: Vec<Capability>,
    pub adapters: Vec<String>,
    pub warnings: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Session {
    pub id: Uuid,
    pub project_id: Uuid,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub trigger: String,
    pub ended_reason: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum EventKind {
    SessionStarted,
    SessionPaused,
    SessionResumed,
    SessionEnded,
    ApplicationFocused,
    WindowChanged,
    InputActivity,
    AccessibleTextChanged,
    ClipboardAction,
    Screenshot,
    FileCreated,
    FileModified,
    FileRenamed,
    FileDeleted,
    CommandExecuted,
    WebNavigation,
    WebInteraction,
    Download,
    ResearchItemCreated,
    ResearchItemUpdated,
    AnchorCreated,
    AnchorRevalidated,
    AiDisclosureCreated,
    AiDisclosureUpdated,
    Annotation,
    Gap,
    Redaction,
    PermissionChanged,
    CapabilityChanged,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum Sensitivity {
    PublicMetadata,
    SensitiveContent,
    RestrictedResearchData,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EventDraft {
    pub project_id: Uuid,
    pub session_id: Option<Uuid>,
    pub occurred_at: DateTime<Utc>,
    pub monotonic_millis: u64,
    pub source: String,
    pub kind: EventKind,
    pub sensitivity: Sensitivity,
    pub payload: Value,
    pub capability_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct EvidenceEvent {
    pub id: Uuid,
    pub project_id: Uuid,
    pub session_id: Option<Uuid>,
    pub sequence: u64,
    pub occurred_at: DateTime<Utc>,
    pub captured_at: DateTime<Utc>,
    pub monotonic_millis: u64,
    pub source: String,
    pub kind: EventKind,
    pub sensitivity: Sensitivity,
    pub payload: Value,
    pub payload_hash: String,
    pub previous_hash: String,
    pub event_hash: String,
    pub capability_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct PublicEvent {
    pub id: Uuid,
    pub project_id: Uuid,
    pub session_id: Option<Uuid>,
    pub sequence: u64,
    pub occurred_at: DateTime<Utc>,
    pub captured_at: DateTime<Utc>,
    pub monotonic_millis: u64,
    pub source: String,
    pub kind: EventKind,
    pub sensitivity: Sensitivity,
    pub payload_hash: String,
    pub previous_hash: String,
    pub event_hash: String,
    pub capability_id: Option<String>,
}

impl From<&EvidenceEvent> for PublicEvent {
    fn from(event: &EvidenceEvent) -> Self {
        Self {
            id: event.id,
            project_id: event.project_id,
            session_id: event.session_id,
            sequence: event.sequence,
            occurred_at: event.occurred_at,
            captured_at: event.captured_at,
            monotonic_millis: event.monotonic_millis,
            source: event.source.clone(),
            kind: event.kind.clone(),
            sensitivity: event.sensitivity.clone(),
            payload_hash: event.payload_hash.clone(),
            previous_hash: event.previous_hash.clone(),
            event_hash: event.event_hash.clone(),
            capability_id: event.capability_id.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct Artifact {
    pub id: Uuid,
    pub project_id: Uuid,
    pub event_id: Option<Uuid>,
    pub kind: String,
    pub original_path: Option<PathBuf>,
    pub media_type: String,
    pub size: u64,
    pub sha256: String,
    pub captured_at: DateTime<Utc>,
    pub content_included: bool,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ResearchItemType {
    KeyConcept,
    ResearchQuestion,
    KeyArgument,
    EvidenceOrSource,
    Experiment,
    DataResult,
    Objection,
    ResearchDecision,
    AiUse,
    Custom,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum ResearchItemStatus {
    Forming,
    Active,
    Revised,
    Rejected,
    Superseded,
    Final,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ResearchItem {
    pub id: Uuid,
    pub project_id: Uuid,
    pub item_type: ResearchItemType,
    pub custom_type: Option<String>,
    pub title: String,
    pub description: String,
    pub status: ResearchItemStatus,
    pub created_at: DateTime<Utc>,
    pub updated_at: DateTime<Utc>,
    pub event_ids: Vec<Uuid>,
    pub artifact_ids: Vec<Uuid>,
    pub anchor_ids: Vec<Uuid>,
    pub parent_item_id: Option<Uuid>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AnchorFormat {
    Pdf,
    Docx,
    Tex,
    Markdown,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AnchorStatus {
    Valid,
    Relocatable,
    Stale,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManuscriptAnchor {
    pub id: Uuid,
    pub project_id: Uuid,
    pub research_item_id: Uuid,
    pub format: AnchorFormat,
    pub document_path: PathBuf,
    pub document_sha256: String,
    pub locator: Value,
    pub quote_hash: String,
    #[serde(default)]
    pub quote_word_count: Option<u32>,
    pub context_before_hash: Option<String>,
    pub context_after_hash: Option<String>,
    pub status: AnchorStatus,
    pub created_at: DateTime<Utc>,
    #[serde(default)]
    pub last_validated_at: Option<DateTime<Utc>>,
    #[serde(default)]
    pub last_validated_document_sha256: Option<String>,
    #[serde(default)]
    pub validation_capability: Option<String>,
    #[serde(default)]
    pub validation_detail: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AiUseDisposition {
    Adopted,
    Modified,
    Rejected,
    ReferenceOnly,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct AiUseDisclosure {
    pub id: Uuid,
    pub project_id: Uuid,
    pub research_item_id: Option<Uuid>,
    pub service: String,
    pub model_statement: Option<String>,
    pub prompt_artifact_id: Option<Uuid>,
    pub output_artifact_id: Option<Uuid>,
    pub disposition: AiUseDisposition,
    pub human_review: String,
    pub source_is_user_supplied: bool,
    pub anchor_ids: Vec<Uuid>,
    pub created_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum GapKind {
    PermissionDenied,
    PlatformLimitation,
    AdapterFailure,
    UserPaused,
    UserExcluded,
    ContentDeleted,
    ContentRedacted,
    DataUnavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct GapOrRedaction {
    pub id: Uuid,
    pub project_id: Uuid,
    pub kind: GapKind,
    pub started_at: DateTime<Utc>,
    pub ended_at: Option<DateTime<Utc>>,
    pub affected_count: u64,
    pub affected_hashes: Vec<String>,
    pub reason: String,
    pub actor: String,
    pub recorded_at: DateTime<Utc>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct CheckpointBody {
    pub project_id: Uuid,
    pub sequence: u64,
    pub final_event_hash: String,
    pub created_at: DateTime<Utc>,
    pub device_public_key: String,
    pub device_fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct IntegrityCheckpoint {
    pub body: CheckpointBody,
    pub signature: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct FileDigest {
    pub path: String,
    pub size: u64,
    pub sha256: String,
}

/// Human-readable report language and coverage declaration. A report marked
/// `summary` MUST NOT be presented as the complete report for the package.
#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct ReportDescriptor {
    pub path: String,
    pub language: String,
    pub coverage: String,
}

/// Stable, content-free commitment that MAY be submitted to an external
/// timestamping service. The service receives only the hash of this file.
#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExternalTimestampTarget {
    pub schema_version: String,
    pub purpose: String,
    pub project_id: Uuid,
    pub sequence: u64,
    pub final_event_hash: String,
    pub checkpoint_signature: String,
    pub device_fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ManifestBody {
    pub schema_version: String,
    pub package_id: Uuid,
    pub project: Project,
    pub generated_at: DateTime<Utc>,
    pub public_files: Vec<FileDigest>,
    pub reports: Vec<ReportDescriptor>,
    pub sensitive_layer: FileDigest,
    pub final_checkpoint: IntegrityCheckpoint,
    pub capability_report: CapabilityReport,
    pub evidence_claim: String,
    pub limitations: Vec<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportManifest {
    pub body: ManifestBody,
    pub manifest_signature: String,
}
