//! Cryptographic evidence primitives for Academic Integrity Recorder.
//!
//! This crate deliberately separates integrity from interpretation: a valid
//! signature proves that bytes are unchanged since a device signed them. It
//! does not prove authorship, completeness, research quality, or honesty.

pub mod active_time;
pub mod anchors;
pub mod canonical;
pub mod crypto;
pub mod export;
pub mod models;
pub mod store;

pub use active_time::{calculate_active_time, ActivityInterval};
pub use anchors::{
    create_manuscript_anchor, revalidate_manuscript_anchor, AnchorRevalidation,
    AnchorRevalidationCapability,
};
pub use crypto::{DeviceSigner, ProjectKey};
pub use export::{export_package, verify_package, ExportOptions, ExportResult, VerificationReport};
pub use models::*;
pub use store::{EvidenceStore, LegacyMigrationReport};

pub const SCHEMA_VERSION: &str = "evidence-package/v1";
