use crate::{
    canonical::to_jcs,
    crypto::{
        decrypt, derive_key, encrypt, random_passphrase, random_salt, sha256_hex, DeviceSigner,
        EncryptedEnvelope,
    },
    store::event_hash_material,
    AiUseDisclosure, Artifact, CapabilityReport, EvidenceEvent, EvidenceStore, ExportManifest,
    ExternalTimestampTarget, FileDigest, GapOrRedaction, ManifestBody, ManuscriptAnchor, Project,
    PublicEvent, ReportDescriptor, ResearchItem, SCHEMA_VERSION,
};
use anyhow::{anyhow, Context, Result};
use base64::{engine::general_purpose::STANDARD, Engine};
use chrono::Utc;
use serde::{Deserialize, Serialize};
use std::{
    collections::{BTreeMap, BTreeSet, HashSet},
    fs::{self, File},
    io::{Read, Seek, SeekFrom, Write},
    path::{Path, PathBuf},
};
use uuid::Uuid;
use zip::{write::SimpleFileOptions, CompressionMethod, ZipArchive, ZipWriter};

#[derive(Debug, Clone)]
pub struct ExportOptions {
    pub destination: PathBuf,
    pub password: Option<String>,
    pub project: Project,
    pub capability_report: CapabilityReport,
    pub research_items: Vec<ResearchItem>,
    pub artifacts: Vec<Artifact>,
    pub anchors: Vec<ManuscriptAnchor>,
    pub ai_disclosures: Vec<AiUseDisclosure>,
    pub gaps: Vec<GapOrRedaction>,
    pub language: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct ExportResult {
    pub destination: PathBuf,
    pub review_password: String,
    pub package_id: Uuid,
    pub device_fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct SensitiveLayer {
    schema_version: String,
    project: Project,
    events: Vec<EvidenceEvent>,
    research_items: Vec<ResearchItem>,
    artifacts: Vec<Artifact>,
    anchors: Vec<ManuscriptAnchor>,
    ai_disclosures: Vec<AiUseDisclosure>,
    gaps: Vec<GapOrRedaction>,
    artifact_contents_base64: BTreeMap<String, String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicEvidence {
    schema_version: String,
    project: Project,
    events: Vec<PublicEvent>,
    research_items: Vec<PublicResearchItem>,
    artifacts: Vec<PublicArtifact>,
    anchors: Vec<PublicAnchor>,
    ai_disclosures: Vec<PublicAiDisclosure>,
    gaps: Vec<GapOrRedaction>,
    capability_report: CapabilityReport,
    active_time_algorithm: ActiveTimeAlgorithm,
    active_time_seconds: i64,
    final_checkpoint: crate::IntegrityCheckpoint,
    reports: Vec<ReportDescriptor>,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicResearchItem {
    id: Uuid,
    project_id: Uuid,
    item_type: crate::ResearchItemType,
    status: crate::ResearchItemStatus,
    title_hash: String,
    description_hash: String,
    event_ids: Vec<Uuid>,
    artifact_ids: Vec<Uuid>,
    anchor_ids: Vec<Uuid>,
    parent_item_id: Option<Uuid>,
}

impl From<&ResearchItem> for PublicResearchItem {
    fn from(item: &ResearchItem) -> Self {
        Self {
            id: item.id,
            project_id: item.project_id,
            item_type: item.item_type.clone(),
            status: item.status.clone(),
            title_hash: sha256_hex(item.title.as_bytes()),
            description_hash: sha256_hex(item.description.as_bytes()),
            event_ids: item.event_ids.clone(),
            artifact_ids: item.artifact_ids.clone(),
            anchor_ids: item.anchor_ids.clone(),
            parent_item_id: item.parent_item_id,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicArtifact {
    id: Uuid,
    project_id: Uuid,
    event_id: Option<Uuid>,
    kind: String,
    media_type: String,
    size: u64,
    sha256: String,
    content_included: bool,
    captured_at: chrono::DateTime<Utc>,
}

impl From<&Artifact> for PublicArtifact {
    fn from(artifact: &Artifact) -> Self {
        Self {
            id: artifact.id,
            project_id: artifact.project_id,
            event_id: artifact.event_id,
            kind: artifact.kind.clone(),
            media_type: artifact.media_type.clone(),
            size: artifact.size,
            sha256: artifact.sha256.clone(),
            content_included: artifact.content_included,
            captured_at: artifact.captured_at,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicAnchor {
    id: Uuid,
    project_id: Uuid,
    research_item_id: Uuid,
    format: crate::AnchorFormat,
    document_sha256: String,
    quote_hash: String,
    quote_word_count: Option<u32>,
    status: crate::AnchorStatus,
    last_validated_at: Option<chrono::DateTime<Utc>>,
    last_validated_document_sha256: Option<String>,
    validation_capability: Option<String>,
    validation_detail: Option<String>,
}

impl From<&ManuscriptAnchor> for PublicAnchor {
    fn from(anchor: &ManuscriptAnchor) -> Self {
        Self {
            id: anchor.id,
            project_id: anchor.project_id,
            research_item_id: anchor.research_item_id,
            format: anchor.format.clone(),
            document_sha256: anchor.document_sha256.clone(),
            quote_hash: anchor.quote_hash.clone(),
            quote_word_count: anchor.quote_word_count,
            status: anchor.status.clone(),
            last_validated_at: anchor.last_validated_at,
            last_validated_document_sha256: anchor.last_validated_document_sha256.clone(),
            validation_capability: anchor.validation_capability.clone(),
            validation_detail: anchor.validation_detail.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PublicAiDisclosure {
    id: Uuid,
    project_id: Uuid,
    research_item_id: Option<Uuid>,
    service: String,
    model_statement: Option<String>,
    prompt_artifact_id: Option<Uuid>,
    output_artifact_id: Option<Uuid>,
    disposition: crate::AiUseDisposition,
    human_review_hash: String,
    source_is_user_supplied: bool,
    anchor_ids: Vec<Uuid>,
}

impl From<&AiUseDisclosure> for PublicAiDisclosure {
    fn from(ai: &AiUseDisclosure) -> Self {
        Self {
            id: ai.id,
            project_id: ai.project_id,
            research_item_id: ai.research_item_id,
            service: ai.service.clone(),
            model_statement: ai.model_statement.clone(),
            prompt_artifact_id: ai.prompt_artifact_id,
            output_artifact_id: ai.output_artifact_id,
            disposition: ai.disposition.clone(),
            human_review_hash: sha256_hex(ai.human_review.as_bytes()),
            source_is_user_supplied: ai.source_is_user_supplied,
            anchor_ids: ai.anchor_ids.clone(),
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct ActiveTimeAlgorithm {
    version: String,
    timeout_seconds: u32,
    rule: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase", deny_unknown_fields)]
struct PasswordEnvelope {
    kdf: String,
    salt: String,
    encrypted: EncryptedEnvelope,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct VerificationReport {
    pub valid: bool,
    pub package_id: Option<Uuid>,
    pub project_name: Option<String>,
    pub device_fingerprint: Option<String>,
    pub event_count: usize,
    pub sensitive_layer_decrypted: bool,
    pub checks: Vec<String>,
    pub errors: Vec<String>,
    pub warnings: Vec<String>,
}

const ACTIVE_TIME_RULE: &str = "Add elapsed time between consecutive qualifying selected-foreground observations once, capped at timeout; reset on pause, lock, sleep, background transition, or session end.";

pub fn export_package(
    store: &EvidenceStore,
    signer: &DeviceSigner,
    options: ExportOptions,
) -> Result<ExportResult> {
    store.verify_local_chain()?;
    let public_events = store.public_events()?;
    let events = store.events()?;
    let checkpoint = store.checkpoint(options.project.id)?;
    let package_id = Uuid::new_v4();
    let password = options
        .password
        .as_deref()
        .map(str::to_owned)
        .unwrap_or_else(random_passphrase);
    let public_project = sanitize_project(&options.project);
    let reports = vec![
        ReportDescriptor {
            path: "public/report.html".into(),
            language: "zh-CN,en".into(),
            coverage: "full-public-report".into(),
        },
        ReportDescriptor {
            path: "public/report.pdf".into(),
            language: "en".into(),
            coverage: "summary".into(),
        },
    ];
    let active_time_seconds = crate::calculate_active_time(
        &activity_from_events(&events),
        options.project.recording_policy.active_window_seconds,
    )
    .num_seconds();
    let public_data = PublicEvidence {
        schema_version: SCHEMA_VERSION.into(),
        project: public_project.clone(),
        events: public_events.clone(),
        research_items: options
            .research_items
            .iter()
            .map(PublicResearchItem::from)
            .collect(),
        artifacts: options.artifacts.iter().map(PublicArtifact::from).collect(),
        anchors: options.anchors.iter().map(PublicAnchor::from).collect(),
        ai_disclosures: options
            .ai_disclosures
            .iter()
            .map(PublicAiDisclosure::from)
            .collect(),
        gaps: options.gaps.clone(),
        capability_report: options.capability_report.clone(),
        active_time_algorithm: ActiveTimeAlgorithm {
            version: "1".into(),
            timeout_seconds: options.project.recording_policy.active_window_seconds,
            rule: ACTIVE_TIME_RULE.into(),
        },
        active_time_seconds,
        final_checkpoint: checkpoint.clone(),
        reports: reports.clone(),
    };
    let public_json = to_jcs(&public_data)?;
    let report_html = render_report(
        &options,
        &public_events,
        &checkpoint.body.device_fingerprint,
        active_time_seconds,
        &reports,
    );
    let report_pdf = minimal_pdf_report(
        &options.project.name,
        public_events.len(),
        options.gaps.len(),
        &checkpoint.body.device_fingerprint,
        active_time_seconds,
        options.project.recording_policy.active_window_seconds,
    );
    let timestamp_target = ExternalTimestampTarget {
        schema_version: SCHEMA_VERSION.into(),
        purpose: "Optional external existence timestamp for the signed evidence-chain head; not identity, authorship, completeness, or integrity certification.".into(),
        project_id: options.project.id,
        sequence: checkpoint.body.sequence,
        final_event_hash: checkpoint.body.final_event_hash.clone(),
        checkpoint_signature: checkpoint.signature.clone(),
        device_fingerprint: checkpoint.body.device_fingerprint.clone(),
    };
    let timestamp_target_bytes = to_jcs(&timestamp_target)?;

    let artifact_contents_base64 = options
        .artifacts
        .iter()
        .filter(|artifact| artifact.content_included)
        .map(|artifact| {
            Ok((
                artifact.sha256.clone(),
                STANDARD.encode(store.read_artifact(&artifact.sha256)?),
            ))
        })
        .collect::<Result<BTreeMap<_, _>>>()?;
    let sensitive = SensitiveLayer {
        schema_version: SCHEMA_VERSION.into(),
        project: options.project.clone(),
        events,
        research_items: options.research_items,
        artifacts: options.artifacts,
        anchors: options.anchors,
        ai_disclosures: options.ai_disclosures,
        gaps: options.gaps,
        artifact_contents_base64,
    };
    let salt = random_salt();
    let password_key = derive_key(&password, &salt)?;
    let encrypted = encrypt(&password_key, &to_jcs(&sensitive)?, package_id.as_bytes())?;
    let password_envelope = PasswordEnvelope {
        kdf: "Argon2id-v19-default".into(),
        salt: STANDARD.encode(salt),
        encrypted,
    };
    let sensitive_bytes = to_jcs(&password_envelope)?;

    let public_files = vec![
        digest("public/evidence.json", &public_json),
        digest("public/report.html", report_html.as_bytes()),
        digest("public/report.pdf", &report_pdf),
        digest("public/timestamp-target.json", &timestamp_target_bytes),
        digest("verification/README.txt", VERIFICATION_README.as_bytes()),
    ];
    let sensitive_digest = digest("sensitive/evidence.enc.json", &sensitive_bytes);
    let body = ManifestBody {
        schema_version: SCHEMA_VERSION.into(),
        package_id,
        project: public_project,
        generated_at: Utc::now(),
        public_files: public_files.clone(),
        reports,
        sensitive_layer: sensitive_digest.clone(),
        final_checkpoint: checkpoint,
        capability_report: options.capability_report,
        evidence_claim: "Voluntary, tamper-evident process evidence; not identity, authorship, originality, or integrity certification.".into(),
        limitations: vec![
            "The recorder cannot prove that all research activity was captured.".into(),
            "Device signatures are not verified legal identities.".into(),
            "Offline work, delegation, reconstruction before recording, and platform limitations may create gaps.".into(),
        ],
    };
    let manifest = ExportManifest {
        manifest_signature: signer.sign(&body)?,
        body,
    };
    let manifest_bytes = to_jcs(&manifest)?;

    if let Some(parent) = options.destination.parent() {
        fs::create_dir_all(parent)?;
    }
    let file = File::create(&options.destination)?;
    let mut zip = ZipWriter::new(file);
    let zip_options = SimpleFileOptions::default()
        .compression_method(CompressionMethod::Deflated)
        .unix_permissions(0o644);
    write_zip_file(&mut zip, "manifest.json", &manifest_bytes, zip_options)?;
    write_zip_file(&mut zip, "public/evidence.json", &public_json, zip_options)?;
    write_zip_file(
        &mut zip,
        "public/report.html",
        report_html.as_bytes(),
        zip_options,
    )?;
    write_zip_file(&mut zip, "public/report.pdf", &report_pdf, zip_options)?;
    write_zip_file(
        &mut zip,
        "public/timestamp-target.json",
        &timestamp_target_bytes,
        zip_options,
    )?;
    write_zip_file(
        &mut zip,
        "sensitive/evidence.enc.json",
        &sensitive_bytes,
        zip_options,
    )?;
    write_zip_file(
        &mut zip,
        "verification/README.txt",
        VERIFICATION_README.as_bytes(),
        zip_options,
    )?;
    zip.finish()?.sync_all()?;

    Ok(ExportResult {
        destination: options.destination,
        review_password: password,
        package_id,
        device_fingerprint: signer.fingerprint(),
    })
}

fn sanitize_project(project: &Project) -> Project {
    let mut public = project.clone();
    public.research_roots = project
        .research_roots
        .iter()
        .map(|path| {
            PathBuf::from(format!(
                "sha256:{}",
                sha256_hex(path.to_string_lossy().as_bytes())
            ))
        })
        .collect();
    public.sync_directory = None;
    public.recording_policy.excluded_paths = project
        .recording_policy
        .excluded_paths
        .iter()
        .map(|path| {
            PathBuf::from(format!(
                "sha256:{}",
                sha256_hex(path.to_string_lossy().as_bytes())
            ))
        })
        .collect();
    public
}

pub fn verify_package(path: impl AsRef<Path>, password: Option<&str>) -> VerificationReport {
    match verify_package_inner(path.as_ref(), password) {
        Ok(report) => report,
        Err(error) => VerificationReport {
            valid: false,
            package_id: None,
            project_name: None,
            device_fingerprint: None,
            event_count: 0,
            sensitive_layer_decrypted: false,
            checks: Vec::new(),
            errors: vec![format!("{error:#}")],
            warnings: Vec::new(),
        },
    }
}

fn verify_package_inner(path: &Path, password: Option<&str>) -> Result<VerificationReport> {
    let raw_names = central_directory_names(path)?;
    let mut raw_seen = std::collections::HashSet::new();
    for name in raw_names {
        if !raw_seen.insert(name.clone()) {
            return Err(anyhow!("duplicate ZIP entry: {name}"));
        }
    }
    let file = File::open(path).with_context(|| format!("cannot open {}", path.display()))?;
    let mut zip = ZipArchive::new(file)?;
    let manifest_bytes = read_zip_file(&mut zip, "manifest.json")?;
    let manifest: ExportManifest = serde_json::from_slice(&manifest_bytes)?;
    if manifest.body.schema_version != SCHEMA_VERSION {
        return Err(anyhow!(
            "unsupported schema {}",
            manifest.body.schema_version
        ));
    }
    DeviceSigner::verify(
        &manifest.body.final_checkpoint.body.device_public_key,
        &manifest.body,
        &manifest.manifest_signature,
    )
    .context("manifest signature is invalid")?;
    DeviceSigner::verify(
        &manifest.body.final_checkpoint.body.device_public_key,
        &manifest.body.final_checkpoint.body,
        &manifest.body.final_checkpoint.signature,
    )
    .context("checkpoint signature is invalid")?;
    let decoded_public_key = STANDARD
        .decode(&manifest.body.final_checkpoint.body.device_public_key)
        .context("device public key is invalid base64")?;
    if sha256_hex(&decoded_public_key) != manifest.body.final_checkpoint.body.device_fingerprint {
        return Err(anyhow!("device public-key fingerprint does not match"));
    }
    if manifest.body.final_checkpoint.body.project_id != manifest.body.project.id {
        return Err(anyhow!(
            "checkpoint project does not match manifest project"
        ));
    }
    validate_report_descriptors(&manifest.body.reports)?;
    for report in &manifest.body.reports {
        if !manifest
            .body
            .public_files
            .iter()
            .any(|file| file.path == report.path)
        {
            return Err(anyhow!(
                "report descriptor is not covered by manifest: {}",
                report.path
            ));
        }
    }

    let mut checks = vec![
        "Manifest Ed25519 signature is valid".into(),
        "Final checkpoint signature is valid".into(),
    ];
    let mut declared_paths = std::collections::HashSet::new();
    for digest in manifest
        .body
        .public_files
        .iter()
        .chain(std::iter::once(&manifest.body.sensitive_layer))
    {
        if !declared_paths.insert(digest.path.as_str()) {
            return Err(anyhow!("duplicate manifest file path: {}", digest.path));
        }
    }
    for required in [
        "public/evidence.json",
        "public/report.html",
        "public/report.pdf",
        "public/timestamp-target.json",
        "verification/README.txt",
    ] {
        if !manifest
            .body
            .public_files
            .iter()
            .any(|file| file.path == required)
        {
            return Err(anyhow!(
                "required file is not covered by manifest: {required}"
            ));
        }
    }
    let declared = manifest
        .body
        .public_files
        .iter()
        .map(|file| file.path.as_str())
        .chain(std::iter::once(manifest.body.sensitive_layer.path.as_str()))
        .chain(std::iter::once("manifest.json"))
        .collect::<std::collections::HashSet<_>>();
    let mut seen_zip_paths = std::collections::HashSet::new();
    for index in 0..zip.len() {
        let entry = zip.by_index(index)?;
        if !seen_zip_paths.insert(entry.name().to_string()) {
            return Err(anyhow!("duplicate ZIP entry: {}", entry.name()));
        }
        if !declared.contains(entry.name()) {
            return Err(anyhow!("undeclared ZIP entry: {}", entry.name()));
        }
        if entry.size() > max_entry_size(entry.name()) {
            return Err(anyhow!(
                "ZIP entry exceeds verifier size limit: {}",
                entry.name()
            ));
        }
    }
    for digest in manifest
        .body
        .public_files
        .iter()
        .chain(std::iter::once(&manifest.body.sensitive_layer))
    {
        let bytes = read_zip_file(&mut zip, &digest.path)?;
        if bytes.len() as u64 != digest.size || sha256_hex(&bytes) != digest.sha256 {
            return Err(anyhow!("digest mismatch for {}", digest.path));
        }
    }
    checks.push("All manifest file sizes and SHA-256 digests match".into());

    let public_bytes = read_zip_file(&mut zip, "public/evidence.json")?;
    let public: PublicEvidence = serde_json::from_slice(&public_bytes)
        .context("public/evidence.json does not match the v1 public schema")?;
    validate_public_evidence(&public, &manifest)?;
    checks.push(
        "Public schema, project, checkpoint, report declarations, and relationships match".into(),
    );
    let timestamp_target_bytes = read_zip_file(&mut zip, "public/timestamp-target.json")?;
    let timestamp_target: ExternalTimestampTarget =
        serde_json::from_slice(&timestamp_target_bytes)?;
    verify_timestamp_target(&timestamp_target, &manifest)?;
    checks.push("External timestamp target matches the signed checkpoint".into());
    checks.push(format!(
        "Public event chain is continuous ({} events)",
        public.events.len()
    ));

    let mut sensitive_layer_decrypted = false;
    if let Some(password) = password {
        let envelope_bytes = read_zip_file(&mut zip, "sensitive/evidence.enc.json")?;
        let envelope: PasswordEnvelope = serde_json::from_slice(&envelope_bytes)?;
        if envelope.kdf != "Argon2id-v19-default" {
            return Err(anyhow!("unsupported sensitive-layer KDF"));
        }
        let salt = STANDARD.decode(envelope.salt)?;
        if salt.len() != 16 {
            return Err(anyhow!("sensitive-layer salt must be 16 bytes"));
        }
        let key = derive_key(password, &salt)?;
        let decrypted = decrypt(
            &key,
            &envelope.encrypted,
            manifest.body.package_id.as_bytes(),
        )
        .context("sensitive layer password is wrong or data was modified")?;
        let layer: SensitiveLayer = serde_json::from_slice(&decrypted)?;
        validate_sensitive_layer(&layer, &public, &manifest)?;
        sensitive_layer_decrypted = true;
        checks.push(format!("Sensitive schema, project, declarations, payload hashes, complete event chain, active time, and exactly {} declared artifact contents match the public layer", layer.artifact_contents_base64.len()));
    }

    Ok(VerificationReport {
        valid: true,
        package_id: Some(manifest.body.package_id),
        project_name: Some(manifest.body.project.name),
        device_fingerprint: Some(manifest.body.final_checkpoint.body.device_fingerprint),
        event_count: public.events.len(),
        sensitive_layer_decrypted,
        checks,
        errors: Vec::new(),
        warnings: if password.is_none() {
            vec![
                "Sensitive layer was not decrypted; payload-to-hash verification was skipped."
                    .into(),
            ]
        } else {
            Vec::new()
        },
    })
}

fn validate_report_descriptors(reports: &[ReportDescriptor]) -> Result<()> {
    if reports.len() != 2 {
        return Err(anyhow!("manifest must declare exactly two reports"));
    }
    let mut paths = HashSet::new();
    for report in reports {
        if !paths.insert(report.path.as_str()) {
            return Err(anyhow!("duplicate report descriptor: {}", report.path));
        }
    }
    let html = reports
        .iter()
        .find(|report| report.path == "public/report.html")
        .context("manifest is missing the HTML report descriptor")?;
    if html.language != "zh-CN,en" || html.coverage != "full-public-report" {
        return Err(anyhow!(
            "HTML report must be declared as full bilingual zh-CN,en"
        ));
    }
    let pdf = reports
        .iter()
        .find(|report| report.path == "public/report.pdf")
        .context("manifest is missing the PDF report descriptor")?;
    if pdf.language != "en" || pdf.coverage != "summary" {
        return Err(anyhow!(
            "PDF report must be honestly declared as an English summary"
        ));
    }
    Ok(())
}

fn validate_public_evidence(public: &PublicEvidence, manifest: &ExportManifest) -> Result<()> {
    if public.schema_version != SCHEMA_VERSION
        || public.schema_version != manifest.body.schema_version
    {
        return Err(anyhow!("public evidence schema does not match manifest"));
    }
    if to_jcs(&public.project)? != to_jcs(&manifest.body.project)? {
        return Err(anyhow!("public evidence project does not match manifest"));
    }
    if to_jcs(&public.final_checkpoint)? != to_jcs(&manifest.body.final_checkpoint)? {
        return Err(anyhow!(
            "public evidence checkpoint does not match manifest"
        ));
    }
    if to_jcs(&public.capability_report)? != to_jcs(&manifest.body.capability_report)? {
        return Err(anyhow!("public capability report does not match manifest"));
    }
    if public.reports != manifest.body.reports {
        return Err(anyhow!("public report declarations do not match manifest"));
    }
    validate_report_descriptors(&public.reports)?;
    if public.active_time_algorithm.version != "1"
        || public.active_time_algorithm.timeout_seconds
            != public.project.recording_policy.active_window_seconds
        || public.active_time_algorithm.rule != ACTIVE_TIME_RULE
        || public.active_time_seconds < 0
    {
        return Err(anyhow!("public active-time declaration is invalid"));
    }
    verify_public_chain(&public.events, manifest)?;
    validate_public_relationships(public, manifest.body.project.id)
}

fn unique_ids(values: impl IntoIterator<Item = Uuid>, label: &str) -> Result<HashSet<Uuid>> {
    let mut ids = HashSet::new();
    for id in values {
        if !ids.insert(id) {
            return Err(anyhow!("duplicate {label} id: {id}"));
        }
    }
    Ok(ids)
}

fn is_sha256(value: &str) -> bool {
    value.len() == 64
        && value
            .bytes()
            .all(|byte| byte.is_ascii_digit() || (b'a'..=b'f').contains(&byte))
}

fn validate_public_relationships(public: &PublicEvidence, project_id: Uuid) -> Result<()> {
    let event_ids = unique_ids(public.events.iter().map(|event| event.id), "event")?;
    let item_ids = unique_ids(
        public.research_items.iter().map(|item| item.id),
        "research item",
    )?;
    let artifact_ids = unique_ids(
        public.artifacts.iter().map(|artifact| artifact.id),
        "artifact",
    )?;
    let anchor_ids = unique_ids(public.anchors.iter().map(|anchor| anchor.id), "anchor")?;
    unique_ids(
        public.ai_disclosures.iter().map(|disclosure| disclosure.id),
        "AI disclosure",
    )?;
    unique_ids(public.gaps.iter().map(|gap| gap.id), "gap/redaction")?;

    for event in &public.events {
        if !is_sha256(&event.payload_hash)
            || !is_sha256(&event.previous_hash)
            || !is_sha256(&event.event_hash)
        {
            return Err(anyhow!("public event contains an invalid SHA-256 value"));
        }
    }

    for item in &public.research_items {
        if item.project_id != project_id {
            return Err(anyhow!("research item belongs to another project"));
        }
        if !is_sha256(&item.title_hash) || !is_sha256(&item.description_hash) {
            return Err(anyhow!("research item contains an invalid content hash"));
        }
        if item.event_ids.iter().any(|id| !event_ids.contains(id))
            || item
                .artifact_ids
                .iter()
                .any(|id| !artifact_ids.contains(id))
            || item.anchor_ids.iter().any(|id| !anchor_ids.contains(id))
            || item
                .parent_item_id
                .is_some_and(|id| !item_ids.contains(&id))
        {
            return Err(anyhow!("research item contains a dangling relationship"));
        }
    }
    for artifact in &public.artifacts {
        if artifact.project_id != project_id
            || artifact.event_id.is_some_and(|id| !event_ids.contains(&id))
            || !is_sha256(&artifact.sha256)
        {
            return Err(anyhow!("artifact declaration is invalid"));
        }
    }
    for anchor in &public.anchors {
        if anchor.project_id != project_id
            || !item_ids.contains(&anchor.research_item_id)
            || !is_sha256(&anchor.document_sha256)
            || !is_sha256(&anchor.quote_hash)
            || anchor
                .last_validated_document_sha256
                .as_deref()
                .is_some_and(|hash| !is_sha256(hash))
        {
            return Err(anyhow!("manuscript anchor declaration is invalid"));
        }
    }
    for disclosure in &public.ai_disclosures {
        if disclosure.project_id != project_id
            || disclosure
                .research_item_id
                .is_some_and(|id| !item_ids.contains(&id))
            || disclosure
                .anchor_ids
                .iter()
                .any(|id| !anchor_ids.contains(id))
            || disclosure
                .prompt_artifact_id
                .is_some_and(|id| !artifact_ids.contains(&id))
            || disclosure
                .output_artifact_id
                .is_some_and(|id| !artifact_ids.contains(&id))
            || !is_sha256(&disclosure.human_review_hash)
        {
            return Err(anyhow!("AI disclosure declaration is invalid"));
        }
    }
    if public.gaps.iter().any(|gap| gap.project_id != project_id) {
        return Err(anyhow!("gap/redaction belongs to another project"));
    }
    Ok(())
}

fn validate_sensitive_layer(
    layer: &SensitiveLayer,
    public: &PublicEvidence,
    manifest: &ExportManifest,
) -> Result<()> {
    if layer.schema_version != SCHEMA_VERSION
        || layer.schema_version != manifest.body.schema_version
    {
        return Err(anyhow!("sensitive layer schema does not match manifest"));
    }
    if layer.project.id != manifest.body.project.id
        || to_jcs(&sanitize_project(&layer.project))? != to_jcs(&manifest.body.project)?
    {
        return Err(anyhow!("sensitive layer project does not match manifest"));
    }
    verify_sensitive_chain(&layer.events, &public.events)?;

    let projected_items = layer
        .research_items
        .iter()
        .map(PublicResearchItem::from)
        .collect::<Vec<_>>();
    let projected_artifacts = layer
        .artifacts
        .iter()
        .map(PublicArtifact::from)
        .collect::<Vec<_>>();
    let projected_anchors = layer
        .anchors
        .iter()
        .map(PublicAnchor::from)
        .collect::<Vec<_>>();
    let projected_ai = layer
        .ai_disclosures
        .iter()
        .map(PublicAiDisclosure::from)
        .collect::<Vec<_>>();
    if projected_items != public.research_items
        || projected_artifacts != public.artifacts
        || projected_anchors != public.anchors
        || projected_ai != public.ai_disclosures
        || to_jcs(&layer.gaps)? != to_jcs(&public.gaps)?
    {
        return Err(anyhow!(
            "sensitive declarations do not reproduce the public layer"
        ));
    }

    let project_id = manifest.body.project.id;
    if layer
        .research_items
        .iter()
        .any(|item| item.project_id != project_id)
        || layer
            .artifacts
            .iter()
            .any(|artifact| artifact.project_id != project_id)
        || layer
            .anchors
            .iter()
            .any(|anchor| anchor.project_id != project_id)
        || layer
            .ai_disclosures
            .iter()
            .any(|disclosure| disclosure.project_id != project_id)
        || layer.gaps.iter().any(|gap| gap.project_id != project_id)
    {
        return Err(anyhow!("sensitive entity belongs to another project"));
    }
    let artifact_ids = layer
        .artifacts
        .iter()
        .map(|artifact| artifact.id)
        .collect::<HashSet<_>>();
    let event_ids = layer
        .events
        .iter()
        .map(|event| event.id)
        .collect::<HashSet<_>>();
    let item_ids = layer
        .research_items
        .iter()
        .map(|item| item.id)
        .collect::<HashSet<_>>();
    let anchor_ids = layer
        .anchors
        .iter()
        .map(|anchor| anchor.id)
        .collect::<HashSet<_>>();
    for artifact in &layer.artifacts {
        if artifact.event_id.is_some_and(|id| !event_ids.contains(&id)) {
            return Err(anyhow!("artifact references a missing event"));
        }
    }
    for item in &layer.research_items {
        if item.event_ids.iter().any(|id| !event_ids.contains(id))
            || item
                .artifact_ids
                .iter()
                .any(|id| !artifact_ids.contains(id))
            || item.anchor_ids.iter().any(|id| {
                !layer
                    .anchors
                    .iter()
                    .any(|anchor| anchor.id == *id && anchor.research_item_id == item.id)
            })
        {
            return Err(anyhow!(
                "research item contains a dangling or cross-item link"
            ));
        }
    }
    for anchor in &layer.anchors {
        if !item_ids.contains(&anchor.research_item_id)
            || !layer.research_items.iter().any(|item| {
                item.id == anchor.research_item_id && item.anchor_ids.contains(&anchor.id)
            })
        {
            return Err(anyhow!("manuscript anchor is not linked bidirectionally"));
        }
    }
    for disclosure in &layer.ai_disclosures {
        for artifact_id in [disclosure.prompt_artifact_id, disclosure.output_artifact_id]
            .into_iter()
            .flatten()
        {
            if !artifact_ids.contains(&artifact_id) {
                return Err(anyhow!("AI disclosure references a missing artifact"));
            }
        }
        if disclosure
            .anchor_ids
            .iter()
            .any(|anchor_id| !anchor_ids.contains(anchor_id))
        {
            return Err(anyhow!("AI disclosure references a missing anchor"));
        }
        if let Some(item_id) = disclosure.research_item_id {
            let item = layer
                .research_items
                .iter()
                .find(|item| item.id == item_id)
                .context("AI disclosure references a missing research item")?;
            if [disclosure.prompt_artifact_id, disclosure.output_artifact_id]
                .into_iter()
                .flatten()
                .any(|artifact_id| !item.artifact_ids.contains(&artifact_id))
                || disclosure
                    .anchor_ids
                    .iter()
                    .any(|anchor_id| !item.anchor_ids.contains(anchor_id))
            {
                return Err(anyhow!(
                    "AI disclosure links are not reflected by its research item"
                ));
            }
        }
    }

    let expected_contents = layer
        .artifacts
        .iter()
        .filter(|artifact| artifact.content_included)
        .map(|artifact| artifact.sha256.as_str())
        .collect::<BTreeSet<_>>();
    let actual_contents = layer
        .artifact_contents_base64
        .keys()
        .map(String::as_str)
        .collect::<BTreeSet<_>>();
    if expected_contents != actual_contents {
        return Err(anyhow!(
            "artifact content set does not match sensitive declarations"
        ));
    }
    if layer.artifacts.iter().any(|artifact| {
        layer
            .artifact_contents_base64
            .contains_key(&artifact.sha256)
            != artifact.content_included
    }) {
        return Err(anyhow!(
            "artifact content inclusion flag does not match content availability"
        ));
    }
    for (expected_hash, encoded) in &layer.artifact_contents_base64 {
        let bytes = STANDARD
            .decode(encoded)
            .with_context(|| format!("artifact content is not base64: {expected_hash}"))?;
        if !is_sha256(expected_hash) || sha256_hex(&bytes) != *expected_hash {
            return Err(anyhow!(
                "artifact content hash mismatch for {expected_hash}"
            ));
        }
        if layer
            .artifacts
            .iter()
            .filter(|artifact| artifact.content_included && artifact.sha256 == *expected_hash)
            .any(|artifact| artifact.size != bytes.len() as u64)
        {
            return Err(anyhow!(
                "artifact content size mismatch for {expected_hash}"
            ));
        }
    }
    let recomputed_active_time = crate::calculate_active_time(
        &activity_from_events(&layer.events),
        layer.project.recording_policy.active_window_seconds,
    )
    .num_seconds();
    if recomputed_active_time != public.active_time_seconds {
        return Err(anyhow!(
            "public active time does not match the sensitive event stream"
        ));
    }
    Ok(())
}

fn verify_timestamp_target(
    target: &ExternalTimestampTarget,
    manifest: &ExportManifest,
) -> Result<()> {
    let checkpoint = &manifest.body.final_checkpoint;
    if target.schema_version != manifest.body.schema_version
        || target.project_id != manifest.body.project.id
        || target.sequence != checkpoint.body.sequence
        || target.final_event_hash != checkpoint.body.final_event_hash
        || target.checkpoint_signature != checkpoint.signature
        || target.device_fingerprint != checkpoint.body.device_fingerprint
    {
        return Err(anyhow!(
            "external timestamp target does not match the signed checkpoint"
        ));
    }
    Ok(())
}

fn verify_public_chain(events: &[PublicEvent], manifest: &ExportManifest) -> Result<()> {
    let mut previous = "0".repeat(64);
    for (index, event) in events.iter().enumerate() {
        if event.sequence != index as u64 + 1 || event.previous_hash != previous {
            return Err(anyhow!(
                "public event chain breaks at sequence {}",
                event.sequence
            ));
        }
        if event.project_id != manifest.body.project.id {
            return Err(anyhow!(
                "event project mismatch at sequence {}",
                event.sequence
            ));
        }
        previous = event.event_hash.clone();
    }
    let checkpoint = &manifest.body.final_checkpoint.body;
    if checkpoint.sequence != events.len() as u64 || checkpoint.final_event_hash != previous {
        return Err(anyhow!(
            "final checkpoint does not match public event chain"
        ));
    }
    Ok(())
}

fn verify_sensitive_chain(events: &[EvidenceEvent], public: &[PublicEvent]) -> Result<()> {
    if events.len() != public.len() {
        return Err(anyhow!("sensitive and public event counts differ"));
    }
    for (event, public_event) in events.iter().zip(public) {
        if PublicEvent::from(event) != *public_event {
            return Err(anyhow!(
                "public and sensitive event metadata differ at sequence {}",
                event.sequence
            ));
        }
        if sha256_hex(&to_jcs(&event.payload)?) != event.payload_hash {
            return Err(anyhow!(
                "payload hash mismatch at sequence {}",
                event.sequence
            ));
        }
        let material = event_hash_material(
            event.id,
            event.project_id,
            event.session_id,
            event.sequence,
            event.occurred_at,
            event.captured_at,
            event.monotonic_millis,
            &event.source,
            &event.kind,
            &event.sensitivity,
            &event.payload_hash,
            &event.previous_hash,
            event.capability_id.as_deref(),
        );
        if sha256_hex(&to_jcs(&material)?) != event.event_hash
            || event.event_hash != public_event.event_hash
            || event.payload_hash != public_event.payload_hash
        {
            return Err(anyhow!(
                "event hash mismatch at sequence {}",
                event.sequence
            ));
        }
    }
    Ok(())
}

fn digest(path: &str, bytes: &[u8]) -> FileDigest {
    FileDigest {
        path: path.into(),
        size: bytes.len() as u64,
        sha256: sha256_hex(bytes),
    }
}

fn write_zip_file<W: Write + std::io::Seek>(
    zip: &mut ZipWriter<W>,
    name: &str,
    bytes: &[u8],
    options: SimpleFileOptions,
) -> Result<()> {
    zip.start_file(name, options)?;
    zip.write_all(bytes)?;
    Ok(())
}

fn read_zip_file<R: Read + std::io::Seek>(zip: &mut ZipArchive<R>, name: &str) -> Result<Vec<u8>> {
    let file = zip
        .by_name(name)
        .with_context(|| format!("missing package file {name}"))?;
    let limit = max_entry_size(name);
    if file.size() > limit {
        return Err(anyhow!("ZIP entry exceeds verifier size limit: {name}"));
    }
    let mut bytes = Vec::with_capacity(file.size().min(8 * 1024 * 1024) as usize);
    file.take(limit + 1).read_to_end(&mut bytes)?;
    if bytes.len() as u64 > limit {
        return Err(anyhow!("ZIP entry exceeds verifier size limit: {name}"));
    }
    Ok(bytes)
}

fn max_entry_size(name: &str) -> u64 {
    if name == "sensitive/evidence.enc.json" {
        2 * 1024 * 1024 * 1024
    } else if name == "public/report.pdf" {
        64 * 1024 * 1024
    } else {
        128 * 1024 * 1024
    }
}

fn central_directory_names(path: &Path) -> Result<Vec<String>> {
    const EOCD_MIN_SIZE: usize = 22;
    const EOCD_MAX_SEARCH: u64 = EOCD_MIN_SIZE as u64 + u16::MAX as u64;
    const MAX_CENTRAL_DIRECTORY_SIZE: u64 = 16 * 1024 * 1024;
    let mut file = File::open(path)?;
    let file_size = file.metadata()?.len();
    if file_size < EOCD_MIN_SIZE as u64 {
        return Err(anyhow!("ZIP end-of-central-directory record is missing"));
    }
    let tail_size = file_size.min(EOCD_MAX_SEARCH) as usize;
    file.seek(SeekFrom::End(-(tail_size as i64)))?;
    let mut tail = vec![0_u8; tail_size];
    file.read_exact(&mut tail)?;
    let eocd = (0..=tail.len() - EOCD_MIN_SIZE)
        .rev()
        .find(|offset| {
            tail[*offset..].starts_with(b"PK\x05\x06")
                && *offset + EOCD_MIN_SIZE + le_u16(&tail[*offset + 20..*offset + 22]) as usize
                    == tail.len()
        })
        .context("ZIP end-of-central-directory record is invalid")?;
    let disk = le_u16(&tail[eocd + 4..eocd + 6]);
    let central_disk = le_u16(&tail[eocd + 6..eocd + 8]);
    let entries_on_disk = le_u16(&tail[eocd + 8..eocd + 10]);
    let entries = le_u16(&tail[eocd + 10..eocd + 12]);
    let central_size = le_u32(&tail[eocd + 12..eocd + 16]) as u64;
    let central_offset = le_u32(&tail[eocd + 16..eocd + 20]) as u64;
    if disk != 0
        || central_disk != 0
        || entries_on_disk != entries
        || entries == u16::MAX
        || central_size == u32::MAX as u64
        || central_offset == u32::MAX as u64
    {
        return Err(anyhow!("multi-disk or ZIP64 packages are not supported"));
    }
    if central_size > MAX_CENTRAL_DIRECTORY_SIZE
        || central_offset
            .checked_add(central_size)
            .is_none_or(|end| end > file_size)
    {
        return Err(anyhow!("ZIP central directory exceeds verifier limits"));
    }
    file.seek(SeekFrom::Start(central_offset))?;
    let mut directory = vec![0_u8; central_size as usize];
    file.read_exact(&mut directory)?;
    let mut cursor = 0_usize;
    let mut names = Vec::with_capacity(entries as usize);
    for _ in 0..entries {
        if cursor + 46 > directory.len() || !directory[cursor..].starts_with(b"PK\x01\x02") {
            return Err(anyhow!("ZIP central directory entry is malformed"));
        }
        let name_len = le_u16(&directory[cursor + 28..cursor + 30]) as usize;
        let extra_len = le_u16(&directory[cursor + 30..cursor + 32]) as usize;
        let comment_len = le_u16(&directory[cursor + 32..cursor + 34]) as usize;
        let end = cursor
            .checked_add(46)
            .and_then(|value| value.checked_add(name_len))
            .and_then(|value| value.checked_add(extra_len))
            .and_then(|value| value.checked_add(comment_len))
            .filter(|end| *end <= directory.len())
            .context("ZIP central directory lengths overflow")?;
        let name = std::str::from_utf8(&directory[cursor + 46..cursor + 46 + name_len])
            .context("ZIP entry name is not UTF-8")?;
        names.push(name.to_string());
        cursor = end;
    }
    if cursor != directory.len() {
        return Err(anyhow!("ZIP central directory contains trailing data"));
    }
    Ok(names)
}

fn le_u16(bytes: &[u8]) -> u16 {
    u16::from_le_bytes([bytes[0], bytes[1]])
}

fn le_u32(bytes: &[u8]) -> u32 {
    u32::from_le_bytes([bytes[0], bytes[1], bytes[2], bytes[3]])
}

fn activity_from_events(events: &[EvidenceEvent]) -> Vec<crate::ActivityInterval> {
    events
        .iter()
        .map(|event| {
            let boundary = matches!(
                event.kind,
                crate::EventKind::SessionPaused
                    | crate::EventKind::SessionEnded
                    | crate::EventKind::Gap
            );
            let blocked = event.payload["blocked"].as_bool() == Some(true)
                || event.payload["contentStored"].as_bool() == Some(false)
                    && event.payload["action"]
                        .as_str()
                        .is_some_and(|action| action.starts_with("secure-field"));
            let semantic_foreground = event.payload["foreground"].as_bool() == Some(true);
            let qualifying = !blocked
                && event.payload["qualifyingActivity"]
                    .as_bool()
                    .unwrap_or_else(|| match event.kind {
                        crate::EventKind::InputActivity => {
                            event.payload["userGenerated"].as_bool() == Some(true)
                                || event.payload["explicit"].as_bool() == Some(true)
                        }
                        crate::EventKind::AccessibleTextChanged
                        | crate::EventKind::ClipboardAction => {
                            semantic_foreground
                                && matches!(
                                    event.source.as_str(),
                                    "browser-extension" | "vscode-extension"
                                )
                        }
                        crate::EventKind::CommandExecuted => {
                            semantic_foreground
                                && matches!(
                                    event.source.as_str(),
                                    "vscode-extension" | "shell-opt-in"
                                )
                        }
                        crate::EventKind::FileCreated | crate::EventKind::FileModified => {
                            semantic_foreground && event.source == "vscode-extension"
                        }
                        crate::EventKind::WebInteraction => {
                            semantic_foreground
                                && event.payload["action"].as_str().is_some_and(|action| {
                                    matches!(
                                        action,
                                        "user-input" | "paste" | "scroll" | "reading-confirmed"
                                    )
                                })
                        }
                        crate::EventKind::Annotation => {
                            event.payload["explicitReadingConfirmation"].as_bool() == Some(true)
                                || event.payload["action"].as_str() == Some("reading-confirmed")
                        }
                        _ => false,
                    });
            crate::ActivityInterval {
                occurred_at: event.occurred_at,
                tool_id: event.source.clone(),
                foreground: !boundary && qualifying,
                qualifying,
                paused: boundary,
                system_locked: event.payload["systemLocked"].as_bool().unwrap_or(false),
            }
        })
        .collect()
}

fn escape_html(value: &str) -> String {
    value
        .replace('&', "&amp;")
        .replace('<', "&lt;")
        .replace('>', "&gt;")
        .replace('"', "&quot;")
}

fn comma_separated_ids(ids: &[Uuid]) -> String {
    if ids.is_empty() {
        "—".into()
    } else {
        ids.iter()
            .map(Uuid::to_string)
            .collect::<Vec<_>>()
            .join(", ")
    }
}

fn render_report(
    options: &ExportOptions,
    events: &[PublicEvent],
    fingerprint: &str,
    active_time_seconds: i64,
    reports: &[ReportDescriptor],
) -> String {
    let project = &options.project;
    let capabilities = &options.capability_report;
    let gaps = &options.gaps;
    let items = &options.research_items;
    let artifacts = &options.artifacts;
    let anchors = &options.anchors;
    let ai_disclosures = &options.ai_disclosures;
    let warnings = capabilities
        .warnings
        .iter()
        .map(|warning| format!("<li>{}</li>", escape_html(warning)))
        .collect::<String>();
    let capability_rows = capabilities
        .capabilities
        .iter()
        .map(|capability| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{:?}</td><td>{}</td><td>{}</td></tr>",
                escape_html(&capability.id),
                escape_html(&capability.label),
                capability.state,
                capability
                    .permission
                    .as_deref()
                    .map(escape_html)
                    .unwrap_or_else(|| "—".into()),
                capability
                    .limitation
                    .as_deref()
                    .map(escape_html)
                    .unwrap_or_else(|| "—".into())
            )
        })
        .collect::<String>();
    let permission_change_rows = events
        .iter()
        .filter(|event| {
            matches!(
                event.kind,
                crate::EventKind::PermissionChanged | crate::EventKind::CapabilityChanged
            )
        })
        .map(|event| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{:?}</td><td>{}</td><td><code>{}</code></td></tr>",
                event.sequence,
                event.occurred_at.to_rfc3339(),
                event.kind,
                event
                    .capability_id
                    .as_deref()
                    .map(escape_html)
                    .unwrap_or_else(|| "—".into()),
                event.payload_hash
            )
        })
        .collect::<String>();
    let permission_change_rows = if permission_change_rows.is_empty() {
        "<tr><td colspan=\"5\">No capability or permission change event was recorded. / 未记录到能力或权限变化事件。</td></tr>".into()
    } else {
        permission_change_rows
    };
    let gap_rows = gaps
        .iter()
        .map(|gap| {
            format!(
                "<tr><td>{:?}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td></tr>",
                gap.kind,
                gap.started_at.to_rfc3339(),
                gap.ended_at
                    .map(|value| value.to_rfc3339())
                    .unwrap_or_else(|| "open".into()),
                gap.affected_count,
                escape_html(&gap.reason),
                escape_html(&gap.actor),
                escape_html(&gap.affected_hashes.join(", "))
            )
        })
        .collect::<String>();
    let item_rows = items
        .iter()
        .map(|item| {
            format!(
                "<tr><td><code>{}</code></td><td>{:?}</td><td><code>{}</code></td><td>{:?}</td><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code></td></tr>",
                item.id,
                item.item_type,
                sha256_hex(item.title.as_bytes()),
                item.status,
                comma_separated_ids(&item.event_ids),
                comma_separated_ids(&item.artifact_ids),
                comma_separated_ids(&item.anchor_ids),
                item.parent_item_id
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "—".into())
            )
        })
        .collect::<String>();
    let artifact_rows = artifacts
        .iter()
        .map(|artifact| {
            format!(
                "<tr><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td><code>{}</code></td><td>{}</td><td><code>{}</code></td></tr>",
                artifact.id,
                escape_html(&artifact.kind),
                escape_html(&artifact.media_type),
                artifact.size,
                artifact.sha256,
                artifact.content_included,
                artifact
                    .event_id
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "—".into())
            )
        })
        .collect::<String>();
    let anchor_rows = anchors
        .iter()
        .map(|anchor| {
            format!(
                "<tr><td><code>{}</code></td><td><code>{}</code></td><td>{:?}</td><td>{:?}</td><td><code>{}</code></td><td><code>{}</code></td><td>{}</td><td>{}</td></tr>",
                anchor.id,
                anchor.research_item_id,
                anchor.format,
                anchor.status,
                anchor.document_sha256,
                anchor.quote_hash,
                anchor
                    .validation_capability
                    .as_deref()
                    .map(escape_html)
                    .unwrap_or_else(|| "—".into()),
                anchor
                    .last_validated_at
                    .map(|value| value.to_rfc3339())
                    .unwrap_or_else(|| "—".into())
            )
        })
        .collect::<String>();
    let ai_rows = ai_disclosures
        .iter()
        .map(|ai| {
            format!(
                "<tr><td><code>{}</code></td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{:?}</td><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code></td><td>{}</td></tr>",
                ai.id,
                ai.research_item_id
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "—".into()),
                escape_html(&ai.service),
                ai.model_statement
                    .as_deref()
                    .map(escape_html)
                    .unwrap_or_else(|| "—".into()),
                ai.disposition,
                ai.prompt_artifact_id
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "—".into()),
                ai.output_artifact_id
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "—".into()),
                sha256_hex(ai.human_review.as_bytes()),
                comma_separated_ids(&ai.anchor_ids),
                ai.source_is_user_supplied
            )
        })
        .collect::<String>();
    let timeline_rows = events
        .iter()
        .map(|event| {
            format!(
                "<tr><td>{}</td><td><code>{}</code></td><td><code>{}</code></td><td>{}</td><td>{}</td><td>{}</td><td>{:?}</td><td>{}</td><td>{:?}</td><td><code>{}</code></td><td><code>{}</code></td><td><code>{}</code></td><td>{}</td></tr>",
                event.sequence,
                event.id,
                event
                    .session_id
                    .map(|id| id.to_string())
                    .unwrap_or_else(|| "—".into()),
                event.occurred_at.to_rfc3339(),
                event.captured_at.to_rfc3339(),
                event.monotonic_millis,
                event.kind,
                escape_html(&event.source),
                event.sensitivity,
                event.payload_hash,
                event.previous_hash,
                event.event_hash,
                event
                    .capability_id
                    .as_deref()
                    .map(escape_html)
                    .unwrap_or_else(|| "—".into())
            )
        })
        .collect::<String>();
    let report_rows = reports
        .iter()
        .map(|report| {
            format!(
                "<tr><td>{}</td><td>{}</td><td>{}</td></tr>",
                escape_html(&report.path),
                escape_html(&report.language),
                escape_html(&report.coverage)
            )
        })
        .collect::<String>();
    format!(
        r#"<!doctype html><html lang="zh-CN"><head><meta charset="utf-8"><meta http-equiv="content-language" content="zh-CN,en"><title>Research process evidence / 研究过程证据</title><style>body{{font:14px system-ui;max-width:1400px;margin:48px auto;color:#15251f}}h1{{font-size:30px}}.notice{{padding:18px;background:#f3efe4;border-left:5px solid #c68b35}}table{{border-collapse:collapse;width:100%;margin-bottom:28px;display:block;overflow-x:auto}}td,th{{padding:8px;border-bottom:1px solid #ddd;text-align:left;vertical-align:top;white-space:nowrap}}code{{overflow-wrap:anywhere;font-size:10px;white-space:normal}}</style></head><body><h1>Research process evidence<br>学术研究过程证据</h1><p class="notice">Voluntary, tamper-evident process evidence; not identity, authorship, originality, or integrity certification.<br>本报告是主动提交、可校验完整性的过程佐证，不是身份、作者资格、原创性或学术诚信认证。</p><table><tr><th>Project / 项目</th><td>{}</td></tr><tr><th>Author statement / 作者声明</th><td>{}</td></tr><tr><th>Events / 事件</th><td>{}</td></tr><tr><th>Gaps / 缺口</th><td>{}</td></tr><tr><th>Artifacts / 材料</th><td>{}</td></tr><tr><th>Anchors / 终稿锚点</th><td>{}</td></tr><tr><th>AI disclosures / AI 披露</th><td>{}</td></tr><tr><th>Platform / 平台</th><td>{} {}</td></tr><tr><th>Capability observed at / 能力观测时间</th><td>{}</td></tr><tr><th>Active time / 有效累计时间</th><td>{} seconds</td></tr><tr><th>Device fingerprint / 设备指纹</th><td><code>{}</code></td></tr></table><h2>Active-time method / 有效时间方法</h2><p>Algorithm v1; timeout {} seconds. Elapsed time is added only between consecutive qualifying observations in a selected foreground tool, once per globally ordered stream and capped at the timeout. Pause, lock, sleep, background transition, or session end resets continuity.</p><p>算法 v1；超时阈值 {} 秒。仅对已选前台工具中相邻的有效活动观测累计时间，全局时间线只计一次并受阈值限制；暂停、锁屏、休眠、转入后台或会话结束会中断连续性。</p><h2>Report language declaration / 报告语言声明</h2><table><tr><th>Path</th><th>Language</th><th>Coverage</th></tr>{}</table><p>The PDF is an English summary, not a bilingual or complete report. The HTML and JSON are authoritative for the complete public timeline.<br>PDF 仅为英文摘要，不是双语或完整报告；完整公开时间线以 HTML 和 JSON 为准。</p><h2>Current capabilities and permissions / 当前能力与权限</h2><table><tr><th>ID</th><th>Label</th><th>State</th><th>Permission</th><th>Limitation</th></tr>{}</table><h3>Warnings / 警告</h3><ul>{}</ul><h3>Capability and permission change events / 能力与权限变化事件</h3><table><tr><th>#</th><th>Time</th><th>Kind</th><th>Capability</th><th>Payload hash</th></tr>{}</table><h2>Research items and relations / 研究条目及关系</h2><table><tr><th>ID</th><th>Type</th><th>Title hash</th><th>Status</th><th>Event IDs</th><th>Artifact IDs</th><th>Anchor IDs</th><th>Parent item</th></tr>{}</table><h3>Artifacts / 材料</h3><table><tr><th>ID</th><th>Kind</th><th>Media type</th><th>Bytes</th><th>SHA-256</th><th>Content included</th><th>Event ID</th></tr>{}</table><h3>Manuscript anchors / 终稿锚点</h3><table><tr><th>ID</th><th>Research item</th><th>Format</th><th>Status</th><th>Document SHA-256</th><th>Quote hash</th><th>Validation capability</th><th>Last validated</th></tr>{}</table><h3>AI disclosures / AI 披露</h3><table><tr><th>ID</th><th>Research item</th><th>Service</th><th>Model statement</th><th>Disposition</th><th>Prompt artifact</th><th>Output artifact</th><th>Human-review hash</th><th>Anchor IDs</th><th>User supplied</th></tr>{}</table><h2>Gaps and redactions / 缺口与删改</h2><table><tr><th>Kind</th><th>Start</th><th>End</th><th>Affected count</th><th>Reason</th><th>Actor</th><th>Affected hashes</th></tr>{}</table><h2>Complete public timeline / 完整公开时间线</h2><table><tr><th>#</th><th>Event ID</th><th>Session ID</th><th>Occurred</th><th>Captured</th><th>Monotonic ms</th><th>Kind</th><th>Source</th><th>Sensitivity</th><th>Payload hash</th><th>Previous hash</th><th>Event hash</th><th>Capability</th></tr>{}</table><h2>Interpretation / 解释边界</h2><p>The package can reveal missing intervals and later modifications. It cannot prove that unrecorded activity did not occur.</p><p>证据包可以显示记录缺口和导出后的修改，但不能证明未记录的研究活动从未发生。</p></body></html>"#,
        escape_html(&project.name),
        escape_html(&project.author_statement),
        events.len(),
        gaps.len(),
        artifacts.len(),
        anchors.len(),
        ai_disclosures.len(),
        escape_html(&capabilities.platform),
        escape_html(&capabilities.platform_version),
        capabilities.observed_at.to_rfc3339(),
        active_time_seconds,
        fingerprint,
        project.recording_policy.active_window_seconds,
        project.recording_policy.active_window_seconds,
        report_rows,
        capability_rows,
        warnings,
        permission_change_rows,
        item_rows,
        artifact_rows,
        anchor_rows,
        ai_rows,
        gap_rows,
        timeline_rows,
    )
}

fn minimal_pdf_report(
    project_name: &str,
    event_count: usize,
    gap_count: usize,
    fingerprint: &str,
    active_time_seconds: i64,
    timeout_seconds: u32,
) -> Vec<u8> {
    let mut lines = vec!["Research Process Evidence - English summary".to_string()];
    if project_name.is_ascii() {
        lines.push(format!("Project: {project_name}"));
    } else {
        lines.push("Project name omitted because this PDF embeds no CJK font.".into());
        lines.push(format!(
            "Project name SHA-256: {}",
            sha256_hex(project_name.as_bytes())
        ));
    }
    lines.extend([
        format!("Events: {event_count}"),
        format!("Gaps and redactions: {gap_count}"),
        format!("Active time: {active_time_seconds} seconds"),
        format!("Active-time algorithm: v1; timeout: {timeout_seconds} seconds"),
        format!("Device fingerprint: {fingerprint}"),
        "This PDF is an English summary, not a bilingual or complete report.".into(),
        "See report.html and evidence.json for the complete bilingual public report.".into(),
        "Voluntary tamper-evident process evidence; not integrity certification.".into(),
    ]);
    let mut content = "BT /F1 17 Tf 50 760 Td".to_string();
    for (index, line) in lines.iter().enumerate() {
        if index == 1 {
            content.push_str(" /F1 10 Tf");
        }
        if index > 0 {
            content.push_str(" 0 -22 Td");
        }
        content.push_str(&format!(" ({}) Tj", pdf_ascii_literal(line)));
    }
    content.push_str(" ET");
    let objects = [
        "<< /Type /Catalog /Pages 2 0 R /Lang (en-US) >>".to_string(),
        "<< /Type /Pages /Kids [3 0 R] /Count 1 >>".to_string(),
        "<< /Type /Page /Parent 2 0 R /MediaBox [0 0 612 792] /Resources << /Font << /F1 5 0 R >> >> /Contents 4 0 R >>".to_string(),
        format!("<< /Length {} >>\nstream\n{}\nendstream", content.len(), content),
        "<< /Type /Font /Subtype /Type1 /BaseFont /Helvetica >>".to_string(),
    ];
    let mut pdf = b"%PDF-1.4\n".to_vec();
    let mut offsets = vec![0usize];
    for (index, object) in objects.iter().enumerate() {
        offsets.push(pdf.len());
        pdf.extend_from_slice(format!("{} 0 obj\n{}\nendobj\n", index + 1, object).as_bytes());
    }
    let xref = pdf.len();
    pdf.extend_from_slice(
        format!("xref\n0 {}\n0000000000 65535 f \n", objects.len() + 1).as_bytes(),
    );
    for offset in offsets.iter().skip(1) {
        pdf.extend_from_slice(format!("{offset:010} 00000 n \n").as_bytes());
    }
    pdf.extend_from_slice(
        format!(
            "trailer << /Size {} /Root 1 0 R >>\nstartxref\n{xref}\n%%EOF\n",
            objects.len() + 1
        )
        .as_bytes(),
    );
    pdf
}

fn pdf_ascii_literal(value: &str) -> String {
    value
        .chars()
        .map(|character| {
            if character.is_ascii_graphic() || character == ' ' {
                character
            } else {
                ' '
            }
        })
        .collect::<String>()
        .replace('\\', "\\\\")
        .replace('(', "\\(")
        .replace(')', "\\)")
}

const VERIFICATION_README: &str = "Academic Integrity Recorder evidence-package/v1\n\nRun the open-source evidence-verifier against this ZIP. Verification proves byte integrity and a device signature, not identity, authorship, completeness, or academic integrity. The sensitive password must be shared separately.\n\nReport languages: public/report.html is the complete bilingual zh-CN/en public report; public/report.pdf is an English-only summary. public/evidence.json is the authoritative machine-readable public record.\n";

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{Capability, CapabilityState, EventDraft, EventKind, ProjectKey, Sensitivity};
    use tempfile::tempdir;

    type JsonMutation = Box<dyn Fn(&mut serde_json::Value)>;

    fn read_zip_entries(path: &Path) -> BTreeMap<String, Vec<u8>> {
        let mut archive = ZipArchive::new(File::open(path).unwrap()).unwrap();
        let mut entries = BTreeMap::new();
        for index in 0..archive.len() {
            let mut entry = archive.by_index(index).unwrap();
            let mut bytes = Vec::new();
            entry.read_to_end(&mut bytes).unwrap();
            entries.insert(entry.name().to_string(), bytes);
        }
        entries
    }

    fn write_zip_entries(path: &Path, entries: &BTreeMap<String, Vec<u8>>) {
        let mut writer = ZipWriter::new(File::create(path).unwrap());
        let options = SimpleFileOptions::default().compression_method(CompressionMethod::Deflated);
        for (name, bytes) in entries {
            writer.start_file(name, options).unwrap();
            writer.write_all(bytes).unwrap();
        }
        writer.finish().unwrap();
    }

    fn replace_signed_entry(
        source: &Path,
        destination: &Path,
        name: &str,
        replacement: Vec<u8>,
        signer: &DeviceSigner,
    ) {
        let mut entries = read_zip_entries(source);
        entries.insert(name.to_string(), replacement.clone());
        let mut manifest: ExportManifest =
            serde_json::from_slice(entries.get("manifest.json").unwrap()).unwrap();
        let file = manifest
            .body
            .public_files
            .iter_mut()
            .chain(std::iter::once(&mut manifest.body.sensitive_layer))
            .find(|file| file.path == name)
            .unwrap();
        *file = digest(name, &replacement);
        manifest.manifest_signature = signer.sign(&manifest.body).unwrap();
        entries.insert("manifest.json".into(), to_jcs(&manifest).unwrap());
        write_zip_entries(destination, &entries);
    }

    fn mutate_sensitive_layer(
        source: &Path,
        destination: &Path,
        password: &str,
        signer: &DeviceSigner,
        mutate: impl FnOnce(&mut serde_json::Value),
    ) {
        let entries = read_zip_entries(source);
        let manifest: ExportManifest =
            serde_json::from_slice(entries.get("manifest.json").unwrap()).unwrap();
        let mut envelope: PasswordEnvelope =
            serde_json::from_slice(entries.get("sensitive/evidence.enc.json").unwrap()).unwrap();
        let salt = STANDARD.decode(&envelope.salt).unwrap();
        let key = derive_key(password, &salt).unwrap();
        let decrypted = decrypt(
            &key,
            &envelope.encrypted,
            manifest.body.package_id.as_bytes(),
        )
        .unwrap();
        let mut layer: serde_json::Value = serde_json::from_slice(&decrypted).unwrap();
        mutate(&mut layer);
        envelope.encrypted = encrypt(
            &key,
            &to_jcs(&layer).unwrap(),
            manifest.body.package_id.as_bytes(),
        )
        .unwrap();
        replace_signed_entry(
            source,
            destination,
            "sensitive/evidence.enc.json",
            to_jcs(&envelope).unwrap(),
            signer,
        );
    }

    fn export_fixture_with_artifact(
        directory: &Path,
        project_name: &str,
    ) -> (PathBuf, DeviceSigner, Project, String, String) {
        let project = Project::new(project_name, "Researcher declaration");
        let signer = DeviceSigner::generate();
        let mut store = EvidenceStore::open(
            directory.join("store"),
            ProjectKey::generate(),
            signer.clone(),
        )
        .unwrap();
        store
            .append(EventDraft {
                project_id: project.id,
                session_id: None,
                occurred_at: Utc::now(),
                monotonic_millis: 1,
                source: "test".into(),
                kind: EventKind::Annotation,
                sensitivity: Sensitivity::SensitiveContent,
                payload: serde_json::json!({"text": "secret"}),
                capability_id: None,
            })
            .unwrap();
        let artifact_bytes = b"declared artifact";
        let artifact_hash = store.add_artifact(artifact_bytes).unwrap();
        let artifact = Artifact {
            id: Uuid::new_v4(),
            project_id: project.id,
            event_id: None,
            kind: "file-snapshot".into(),
            original_path: Some(PathBuf::from("private/research.txt")),
            media_type: "text/plain".into(),
            size: artifact_bytes.len() as u64,
            sha256: artifact_hash.clone(),
            captured_at: Utc::now(),
            content_included: true,
        };
        let password = "correct horse".to_string();
        let package = directory.join("fixture.evidence.zip");
        export_package(
            &store,
            &signer,
            ExportOptions {
                destination: package.clone(),
                password: Some(password.clone()),
                project: project.clone(),
                capability_report: capabilities(),
                research_items: vec![],
                artifacts: vec![artifact],
                anchors: vec![],
                ai_disclosures: vec![],
                gaps: vec![],
                language: "bilingual".into(),
            },
        )
        .unwrap();
        (package, signer, project, password, artifact_hash)
    }

    fn add_zip_entry(source: &Path, destination: &Path, name: &str, contents: &[u8]) {
        let input = File::open(source).unwrap();
        let mut reader = ZipArchive::new(input).unwrap();
        let output = File::create(destination).unwrap();
        let mut writer = ZipWriter::new(output);
        for index in 0..reader.len() {
            let file = reader.by_index_raw(index).unwrap();
            writer.raw_copy_file(file).unwrap();
        }
        writer
            .start_file(name, SimpleFileOptions::default())
            .unwrap();
        writer.write_all(contents).unwrap();
        writer.finish().unwrap();
    }

    fn remove_zip_entry(source: &Path, destination: &Path, name: &str) {
        let mut entries = read_zip_entries(source);
        assert!(entries.remove(name).is_some());
        write_zip_entries(destination, &entries);
    }

    fn add_duplicate_zip_entry(
        source: &Path,
        destination: &Path,
        name: &str,
        alias: &str,
        contents: &[u8],
    ) {
        assert_eq!(name.len(), alias.len());
        add_zip_entry(source, destination, alias, contents);
        let mut archive = fs::read(destination).unwrap();
        let mut replacements = 0;
        for offset in 0..=archive.len() - alias.len() {
            if &archive[offset..offset + alias.len()] == alias.as_bytes() {
                archive[offset..offset + name.len()].copy_from_slice(name.as_bytes());
                replacements += 1;
            }
        }
        // A ZIP filename occurs once in its local header and once in the
        // central directory. Renaming both creates the malformed duplicate
        // that the verifier must reject, while keeping the archive readable.
        assert_eq!(replacements, 2);
        fs::write(destination, archive).unwrap();
    }

    fn capabilities() -> CapabilityReport {
        CapabilityReport {
            platform: "test".into(),
            platform_version: "1".into(),
            observed_at: Utc::now(),
            capabilities: vec![Capability {
                id: "input".into(),
                label: "Input".into(),
                state: CapabilityState::Available,
                permission: None,
                limitation: None,
            }],
            adapters: vec!["test".into()],
            warnings: vec![],
        }
    }

    #[test]
    fn exports_and_detects_wrong_password_and_modified_package() {
        let dir = tempdir().unwrap();
        let project = Project::new("Test", "Researcher declaration");
        let signer = DeviceSigner::generate();
        let mut store = EvidenceStore::open(
            dir.path().join("store"),
            ProjectKey::generate(),
            signer.clone(),
        )
        .unwrap();
        store
            .append(EventDraft {
                project_id: project.id,
                session_id: None,
                occurred_at: Utc::now(),
                monotonic_millis: 1,
                source: "test".into(),
                kind: EventKind::Annotation,
                sensitivity: Sensitivity::SensitiveContent,
                payload: serde_json::json!({"text": "secret"}),
                capability_id: None,
            })
            .unwrap();
        let package = dir.path().join("test.evidence.zip");
        export_package(
            &store,
            &signer,
            ExportOptions {
                destination: package.clone(),
                password: Some("correct horse".into()),
                project,
                capability_report: capabilities(),
                research_items: vec![],
                artifacts: vec![],
                anchors: vec![],
                ai_disclosures: vec![],
                gaps: vec![],
                language: "bilingual".into(),
            },
        )
        .unwrap();
        assert!(verify_package(&package, Some("correct horse")).valid);
        assert!(!verify_package(&package, Some("wrong")).valid);
        let mut bytes = fs::read(&package).unwrap();
        let index = bytes.len() / 2;
        bytes[index] ^= 0x01;
        fs::write(dir.path().join("tampered.zip"), bytes).unwrap();
        assert!(!verify_package(dir.path().join("tampered.zip"), Some("correct horse")).valid);

        let extra = dir.path().join("extra.zip");
        add_zip_entry(&package, &extra, "untrusted.txt", b"not in manifest");
        let report = verify_package(&extra, Some("correct horse"));
        assert!(!report.valid);
        assert!(report.errors.join(" ").contains("undeclared ZIP entry"));

        let duplicate = dir.path().join("duplicate.zip");
        add_duplicate_zip_entry(
            &package,
            &duplicate,
            "public/evidence.json",
            "public/evidencf.json",
            b"replacement",
        );
        let report = verify_package(&duplicate, Some("correct horse"));
        assert!(!report.valid);
        let errors = report.errors.join(" ");
        assert!(errors.contains("duplicate ZIP entry"), "{errors}");

        let missing = dir.path().join("missing-sensitive-layer.zip");
        remove_zip_entry(&package, &missing, "sensitive/evidence.enc.json");
        let report = verify_package(&missing, Some("correct horse"));
        assert!(!report.valid);
        let errors = report.errors.join(" ");
        assert!(errors.contains("missing package file"), "{errors}");
    }

    #[test]
    fn sensitive_verification_rejects_public_metadata_divergence() {
        let dir = tempdir().unwrap();
        let project = Project::new("Test", "Researcher declaration");
        let signer = DeviceSigner::generate();
        let mut store =
            EvidenceStore::open(dir.path().join("store"), ProjectKey::generate(), signer).unwrap();
        let event = store
            .append(EventDraft {
                project_id: project.id,
                session_id: Some(Uuid::new_v4()),
                occurred_at: Utc::now(),
                monotonic_millis: 7,
                source: "test".into(),
                kind: EventKind::InputActivity,
                sensitivity: Sensitivity::SensitiveContent,
                payload: serde_json::json!({"text": "secret"}),
                capability_id: Some("test-input".into()),
            })
            .unwrap();
        let mut public = PublicEvent::from(&event);
        public.captured_at += chrono::Duration::seconds(1);

        let error = verify_sensitive_chain(&[event], &[public]).unwrap_err();
        assert!(error
            .to_string()
            .contains("public and sensitive event metadata differ"));
    }

    #[test]
    fn exported_active_time_requires_real_foreground_activity() {
        let project_id = Uuid::new_v4();
        let at = |seconds: i64, kind: EventKind, source: &str, payload: serde_json::Value| {
            EvidenceEvent {
                id: Uuid::new_v4(),
                project_id,
                session_id: None,
                sequence: seconds as u64 + 1,
                occurred_at: chrono::DateTime::from_timestamp(seconds, 0).unwrap(),
                captured_at: chrono::DateTime::from_timestamp(seconds, 0).unwrap(),
                monotonic_millis: seconds as u64 * 1_000,
                source: source.into(),
                kind,
                sensitivity: Sensitivity::PublicMetadata,
                payload,
                payload_hash: "a".repeat(64),
                previous_hash: "0".repeat(64),
                event_hash: "b".repeat(64),
                capability_id: None,
            }
        };
        let events = vec![
            at(
                0,
                EventKind::ApplicationFocused,
                "desktop:native",
                serde_json::json!({"tool":"Word"}),
            ),
            at(
                10,
                EventKind::WebInteraction,
                "browser-extension",
                serde_json::json!({"action":"scroll","foreground":false}),
            ),
            at(
                20,
                EventKind::WebInteraction,
                "browser-extension",
                serde_json::json!({"action":"scroll","foreground":true}),
            ),
            at(
                50,
                EventKind::AccessibleTextChanged,
                "browser-extension",
                serde_json::json!({"foreground":true}),
            ),
        ];

        assert_eq!(
            crate::calculate_active_time(&activity_from_events(&events), 90).num_seconds(),
            30
        );
    }

    #[test]
    fn exported_reports_declare_languages_without_silent_cjk_replacement() {
        let dir = tempdir().unwrap();
        let (package, _signer, project, _password, _artifact_hash) =
            export_fixture_with_artifact(dir.path(), "中文研究项目");
        let entries = read_zip_entries(&package);
        let manifest: serde_json::Value =
            serde_json::from_slice(entries.get("manifest.json").unwrap()).unwrap();
        assert_eq!(
            manifest["body"]["reports"][1]["language"],
            serde_json::json!("en")
        );
        let public: serde_json::Value =
            serde_json::from_slice(entries.get("public/evidence.json").unwrap()).unwrap();
        assert_eq!(
            public["finalCheckpoint"]["body"]["projectId"],
            serde_json::json!(project.id)
        );
        let pdf = String::from_utf8_lossy(entries.get("public/report.pdf").unwrap());
        assert!(!pdf.contains('?'));
        assert!(pdf.contains("Project name SHA-256:"));
        let html = String::from_utf8_lossy(entries.get("public/report.html").unwrap());
        assert!(html.contains("Active-time method / 有效时间方法"));
        assert!(html.contains("Current capabilities and permissions / 当前能力与权限"));
        assert!(html.contains("Capability and permission change events / 能力与权限变化事件"));
        assert!(html.contains("Research items and relations / 研究条目及关系"));
        assert!(html.contains("Gaps and redactions / 缺口与删改"));
        assert!(html.contains("Complete public timeline / 完整公开时间线"));
    }

    #[test]
    fn pdf_summary_is_parseable_and_english_only() {
        let pdf = minimal_pdf_report("中文研究项目", 12, 2, &"a".repeat(64), 300, 90);
        let text = pdf_extract::extract_text_from_mem(&pdf).unwrap();
        assert!(text.contains("Research Process Evidence - English summary"));
        assert!(text.contains("Project name SHA-256:"));
        assert!(text.contains("Active time: 300 seconds"));
        assert!(text.contains("not a bilingual or complete report"));
        assert!(!text.contains('?'));
        assert!(text.is_ascii());
        if let Some(output) = std::env::var_os("AIR_PDF_QA_OUTPUT") {
            fs::write(output, pdf).unwrap();
        }
    }

    #[test]
    fn verifier_rejects_signed_public_schema_and_project_mismatch() {
        let dir = tempdir().unwrap();
        let (package, signer, _project, password, _artifact_hash) =
            export_fixture_with_artifact(dir.path(), "Test");
        for (label, mutate) in [
            (
                "schema",
                Box::new(|value: &mut serde_json::Value| {
                    value["schemaVersion"] = serde_json::json!("evidence-package/v999");
                }) as Box<dyn Fn(&mut serde_json::Value)>,
            ),
            (
                "project",
                Box::new(|value: &mut serde_json::Value| {
                    value["project"]["id"] = serde_json::json!(Uuid::new_v4());
                }),
            ),
        ] {
            let mut public: serde_json::Value = serde_json::from_slice(
                read_zip_entries(&package)
                    .get("public/evidence.json")
                    .unwrap(),
            )
            .unwrap();
            mutate(&mut public);
            let altered = dir.path().join(format!("public-{label}.zip"));
            replace_signed_entry(
                &package,
                &altered,
                "public/evidence.json",
                to_jcs(&public).unwrap(),
                &signer,
            );
            let report = verify_package(&altered, Some(&password));
            assert!(!report.valid, "signed public {label} mismatch was accepted");
        }
    }

    #[test]
    fn verifier_rejects_signed_sensitive_schema_project_and_content_set_mismatch() {
        let dir = tempdir().unwrap();
        let (package, signer, _project, password, artifact_hash) =
            export_fixture_with_artifact(dir.path(), "Test");
        let cases: Vec<(&str, JsonMutation)> = vec![
            (
                "schema",
                Box::new(|layer| {
                    layer["schemaVersion"] = serde_json::json!("evidence-package/v999");
                }),
            ),
            (
                "project",
                Box::new(|layer| {
                    layer["project"]["id"] = serde_json::json!(Uuid::new_v4());
                }),
            ),
            (
                "missing-content",
                Box::new(move |layer| {
                    layer["artifactContentsBase64"]
                        .as_object_mut()
                        .unwrap()
                        .remove(&artifact_hash);
                }),
            ),
            (
                "extra-content",
                Box::new(|layer| {
                    let bytes = b"undeclared content";
                    layer["artifactContentsBase64"]
                        .as_object_mut()
                        .unwrap()
                        .insert(sha256_hex(bytes), serde_json::json!(STANDARD.encode(bytes)));
                }),
            ),
        ];
        for (label, mutate) in cases {
            let altered = dir.path().join(format!("sensitive-{label}.zip"));
            mutate_sensitive_layer(&package, &altered, &password, &signer, mutate);
            let report = verify_package(&altered, Some(&password));
            assert!(
                !report.valid,
                "signed sensitive-layer {label} mismatch was accepted"
            );
        }
    }
}
