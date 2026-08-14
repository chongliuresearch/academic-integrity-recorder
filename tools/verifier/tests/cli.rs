use chrono::Utc;
use evidence_core::{
    export_package, Artifact, CapabilityReport, DeviceSigner, EventDraft, EventKind, EvidenceStore,
    ExportOptions, Project, ProjectKey, Sensitivity,
};
use std::process::Command;
use tempfile::tempdir;
use uuid::Uuid;

#[test]
fn cli_verifies_public_and_sensitive_layers_and_rejects_wrong_password() {
    let directory = tempdir().unwrap();
    let project = Project::new("CLI QA", "Self-declared test author");
    let signer = DeviceSigner::generate();
    let mut store = EvidenceStore::open(
        directory.path().join("store"),
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
            kind: EventKind::FileModified,
            sensitivity: Sensitivity::SensitiveContent,
            payload: serde_json::json!({"path":"private/research.txt","text":"sensitive"}),
            capability_id: Some("filesystem".into()),
        })
        .unwrap();
    let bytes = b"artifact content";
    let hash = store.add_artifact(bytes).unwrap();
    let artifact = Artifact {
        id: Uuid::new_v4(),
        project_id: project.id,
        event_id: None,
        kind: "file-snapshot".into(),
        original_path: None,
        media_type: "text/plain".into(),
        size: bytes.len() as u64,
        sha256: hash,
        captured_at: Utc::now(),
        content_included: true,
    };
    let package = directory.path().join("fixture.evidence.zip");
    export_package(
        &store,
        &signer,
        ExportOptions {
            destination: package.clone(),
            password: Some("review-secret".into()),
            project,
            capability_report: CapabilityReport {
                platform: "test".into(),
                platform_version: "1".into(),
                observed_at: Utc::now(),
                capabilities: vec![],
                adapters: vec!["test".into()],
                warnings: vec![],
            },
            research_items: vec![],
            artifacts: vec![artifact],
            anchors: vec![],
            ai_disclosures: vec![],
            gaps: vec![],
            language: "bilingual".into(),
        },
    )
    .unwrap();
    let binary = env!("CARGO_BIN_EXE_evidence-verifier");
    let public_only = Command::new(binary).arg(&package).output().unwrap();
    assert!(public_only.status.success());
    let public_output = String::from_utf8(public_only.stdout).unwrap();
    assert!(public_output.contains("VALID PUBLIC LAYER ONLY"));
    assert!(public_output.contains("Sensitive layer was not decrypted"));
    assert!(Command::new(binary)
        .args([
            package.to_str().unwrap(),
            "--password",
            "review-secret",
            "--json"
        ])
        .status()
        .unwrap()
        .success());
    assert_eq!(
        Command::new(binary)
            .args([package.to_str().unwrap(), "--password", "wrong"])
            .status()
            .unwrap()
            .code(),
        Some(2)
    );
}
