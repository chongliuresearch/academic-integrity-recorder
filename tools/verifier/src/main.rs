use anyhow::Result;
use clap::Parser;
use evidence_core::verify_package;
use std::{path::PathBuf, process::ExitCode};

#[derive(Parser)]
#[command(
    name = "evidence-verifier",
    about = "Offline verifier for evidence-package/v1. Verification is not academic integrity certification."
)]
struct Arguments {
    /// Evidence ZIP created by Academic Integrity Recorder.
    package: PathBuf,
    /// Sensitive-layer review password, shared separately from the package.
    #[arg(long, env = "AIR_REVIEW_PASSWORD", hide_env_values = true)]
    password: Option<String>,
    /// Emit machine-readable JSON.
    #[arg(long)]
    json: bool,
}

fn main() -> ExitCode {
    match run() {
        Ok(valid) => {
            if valid {
                ExitCode::SUCCESS
            } else {
                ExitCode::from(2)
            }
        }
        Err(error) => {
            eprintln!("verifier error: {error:#}");
            ExitCode::from(1)
        }
    }
}

fn run() -> Result<bool> {
    let arguments = Arguments::parse();
    let report = verify_package(&arguments.package, arguments.password.as_deref());
    if arguments.json {
        println!("{}", serde_json::to_string_pretty(&report)?);
    } else {
        println!("Academic Integrity Recorder — offline verification");
        let result_label = if !report.valid {
            "INVALID"
        } else if report.sensitive_layer_decrypted {
            "VALID (PUBLIC AND SENSITIVE LAYERS)"
        } else {
            "VALID PUBLIC LAYER ONLY (SENSITIVE LAYER NOT CHECKED)"
        };
        println!("Result: {result_label}");
        if let Some(project) = &report.project_name {
            println!("Project: {project}");
        }
        if let Some(fingerprint) = &report.device_fingerprint {
            println!("Device fingerprint: {fingerprint}");
        }
        println!("Events: {}", report.event_count);
        for check in &report.checks {
            println!("  [ok] {check}");
        }
        for warning in &report.warnings {
            println!("  [warning] {warning}");
        }
        for error in &report.errors {
            println!("  [error] {error}");
        }
        println!("\nA valid result proves package integrity and a device signature only; it does not certify identity, authorship, originality, completeness, or academic integrity.");
    }
    Ok(report.valid)
}
