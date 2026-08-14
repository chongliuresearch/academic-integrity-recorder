use crate::{crypto::sha256_hex, AnchorFormat, AnchorStatus, ManuscriptAnchor};
use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use quick_xml::{events::Event, Reader};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{fs, io::Read, path::Path};
use uuid::Uuid;
use zip::ZipArchive;

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub enum AnchorRevalidationCapability {
    ExactDocumentHash,
    TextFingerprint,
    ManualReanchorRequired,
    DocumentUnavailable,
}

#[derive(Debug, Clone, Serialize, Deserialize, PartialEq, Eq)]
#[serde(rename_all = "camelCase")]
pub struct AnchorRevalidation {
    pub anchor_id: Uuid,
    pub status: AnchorStatus,
    pub capability: AnchorRevalidationCapability,
    pub current_document_sha256: Option<String>,
    pub detail: String,
}

pub fn create_manuscript_anchor(
    project_id: Uuid,
    research_item_id: Uuid,
    path: &Path,
    selected_text: &str,
    locator: Value,
) -> Result<ManuscriptAnchor> {
    let bytes =
        fs::read(path).with_context(|| format!("cannot read manuscript {}", path.display()))?;
    let extension = path
        .extension()
        .and_then(|value| value.to_str())
        .unwrap_or("")
        .to_lowercase();
    let format = match extension.as_str() {
        "pdf" => AnchorFormat::Pdf,
        "docx" => AnchorFormat::Docx,
        "tex" => AnchorFormat::Tex,
        "md" | "markdown" => AnchorFormat::Markdown,
        _ => {
            return Err(anyhow!(
                "only PDF, DOCX, TeX, and Markdown anchors are supported"
            ))
        }
    };
    let extracted = match format {
        AnchorFormat::Pdf => {
            pdf_extract::extract_text_from_mem(&bytes).context("PDF text extraction failed")?
        }
        AnchorFormat::Docx => extract_docx_text(&bytes)?,
        AnchorFormat::Tex | AnchorFormat::Markdown => {
            String::from_utf8(bytes.clone()).context("manuscript source is not UTF-8")?
        }
    };
    let selected = normalize(selected_text);
    if selected.is_empty() {
        return Err(anyhow!("selected anchor text cannot be empty"));
    }
    let haystack = normalize(&extracted);
    let occurrence = haystack.find(&selected);
    let (before, after) = if let Some(index) = occurrence {
        let before_start = haystack.floor_char_boundary(index.saturating_sub(160));
        let after_end =
            haystack.ceil_char_boundary((index + selected.len() + 160).min(haystack.len()));
        (
            Some(sha256_hex(&haystack.as_bytes()[before_start..index])),
            Some(sha256_hex(
                &haystack.as_bytes()[index + selected.len()..after_end],
            )),
        )
    } else {
        (None, None)
    };
    let now = Utc::now();
    let document_sha256 = sha256_hex(&bytes);
    Ok(ManuscriptAnchor {
        id: Uuid::new_v4(),
        project_id,
        research_item_id,
        format,
        document_path: path.to_path_buf(),
        document_sha256: document_sha256.clone(),
        locator,
        quote_hash: sha256_hex(selected.as_bytes()),
        quote_word_count: Some(selected.split_whitespace().count().min(u32::MAX as usize) as u32),
        context_before_hash: before,
        context_after_hash: after,
        status: if occurrence.is_some() {
            AnchorStatus::Valid
        } else {
            AnchorStatus::Stale
        },
        created_at: now,
        last_validated_at: Some(now),
        last_validated_document_sha256: Some(document_sha256),
        validation_capability: Some("exactDocumentHash".into()),
        validation_detail: Some("anchor created against these exact manuscript bytes".into()),
    })
}

/// Rechecks an anchor against the current manuscript without claiming more
/// parsing support than is available. TeX and Markdown can be relocated by
/// the stored normalized-text fingerprint. A changed PDF or DOCX needs manual
/// re-anchoring because the selected text itself is intentionally not stored
/// in the public anchor model.
pub fn revalidate_manuscript_anchor(anchor: &ManuscriptAnchor) -> Result<AnchorRevalidation> {
    let bytes = match fs::read(&anchor.document_path) {
        Ok(bytes) => bytes,
        Err(error) if error.kind() == std::io::ErrorKind::NotFound => {
            return Ok(AnchorRevalidation {
                anchor_id: anchor.id,
                status: AnchorStatus::Stale,
                capability: AnchorRevalidationCapability::DocumentUnavailable,
                current_document_sha256: None,
                detail: "manuscript file is unavailable at its recorded path".into(),
            })
        }
        Err(error) => {
            return Err(error).with_context(|| {
                format!("cannot read manuscript {}", anchor.document_path.display())
            })
        }
    };
    let current_document_sha256 = sha256_hex(&bytes);
    if current_document_sha256 == anchor.document_sha256 {
        return Ok(AnchorRevalidation {
            anchor_id: anchor.id,
            status: AnchorStatus::Valid,
            capability: AnchorRevalidationCapability::ExactDocumentHash,
            current_document_sha256: Some(current_document_sha256),
            detail: "manuscript bytes still match the recorded document hash".into(),
        });
    }

    match anchor.format {
        AnchorFormat::Tex | AnchorFormat::Markdown => {
            let current = String::from_utf8(bytes).context("manuscript source is not UTF-8")?;
            let normalized = normalize(&current);
            let status = if anchor.quote_word_count.is_some_and(|word_count| {
                contains_normalized_fingerprint(&normalized, &anchor.quote_hash, word_count)
            }) {
                AnchorStatus::Relocatable
            } else {
                AnchorStatus::Stale
            };
            Ok(AnchorRevalidation {
                anchor_id: anchor.id,
                status: status.clone(),
                capability: AnchorRevalidationCapability::TextFingerprint,
                current_document_sha256: Some(current_document_sha256),
                detail: if status == AnchorStatus::Relocatable {
                    "selected normalized text still exists in the changed source".into()
                } else {
                    "selected normalized text fingerprint is absent from the changed source".into()
                },
            })
        }
        AnchorFormat::Pdf | AnchorFormat::Docx => Ok(AnchorRevalidation {
            anchor_id: anchor.id,
            status: AnchorStatus::Stale,
            capability: AnchorRevalidationCapability::ManualReanchorRequired,
            current_document_sha256: Some(current_document_sha256),
            detail: "binary manuscript changed; v1 cannot safely relocate from hashes alone".into(),
        }),
    }
}

fn contains_normalized_fingerprint(normalized: &str, wanted_hash: &str, word_count: u32) -> bool {
    let words = normalized.split_whitespace().collect::<Vec<_>>();
    let Ok(window_size) = usize::try_from(word_count) else {
        return false;
    };
    window_size > 0
        && words
            .windows(window_size)
            .any(|window| sha256_hex(window.join(" ").as_bytes()) == wanted_hash)
}

fn normalize(value: &str) -> String {
    value.split_whitespace().collect::<Vec<_>>().join(" ")
}

fn extract_docx_text(bytes: &[u8]) -> Result<String> {
    let mut archive = ZipArchive::new(std::io::Cursor::new(bytes))?;
    let mut xml = String::new();
    archive
        .by_name("word/document.xml")?
        .read_to_string(&mut xml)?;
    let mut reader = Reader::from_str(&xml);
    reader.config_mut().trim_text(true);
    let mut output = String::new();
    loop {
        match reader.read_event() {
            Ok(Event::Text(text)) => {
                output.push_str(&text.unescape()?);
                output.push(' ');
            }
            Ok(Event::End(end)) if end.name().as_ref() == b"w:p" => output.push('\n'),
            Ok(Event::Eof) => break,
            Err(error) => return Err(error.into()),
            _ => {}
        }
    }
    Ok(output)
}

#[cfg(test)]
mod tests {
    use super::*;
    use tempfile::tempdir;

    #[test]
    fn anchors_markdown_with_quote_and_context_hashes() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("paper.md");
        fs::write(
            &path,
            "Before context. Key causal argument here. After context.",
        )
        .unwrap();
        let anchor = create_manuscript_anchor(
            Uuid::new_v4(),
            Uuid::new_v4(),
            &path,
            "Key causal argument here.",
            serde_json::json!({"lineStart":1,"lineEnd":1}),
        )
        .unwrap();
        assert_eq!(anchor.status, AnchorStatus::Valid);
        assert!(anchor.context_before_hash.is_some());
    }

    #[test]
    fn changed_markdown_relocates_by_the_stored_text_fingerprint() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("paper.md");
        fs::write(&path, "Before. Key causal argument here. After.").unwrap();
        let anchor = create_manuscript_anchor(
            Uuid::new_v4(),
            Uuid::new_v4(),
            &path,
            "Key causal argument here.",
            serde_json::json!({"lineStart":1}),
        )
        .unwrap();

        fs::write(
            &path,
            "A new introduction. Before. Key causal argument here. After.",
        )
        .unwrap();
        let outcome = revalidate_manuscript_anchor(&anchor).unwrap();

        assert_eq!(outcome.status, AnchorStatus::Relocatable);
        assert_eq!(
            outcome.capability,
            AnchorRevalidationCapability::TextFingerprint
        );
    }

    #[test]
    fn changed_markdown_is_stale_when_the_fingerprint_disappears() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("paper.tex");
        fs::write(&path, "Before. Key causal argument here. After.").unwrap();
        let anchor = create_manuscript_anchor(
            Uuid::new_v4(),
            Uuid::new_v4(),
            &path,
            "Key causal argument here.",
            serde_json::json!({"sourcePath":"paper.tex"}),
        )
        .unwrap();

        fs::write(&path, "The argument was removed from this revision.").unwrap();
        let outcome = revalidate_manuscript_anchor(&anchor).unwrap();

        assert_eq!(outcome.status, AnchorStatus::Stale);
    }

    #[test]
    fn changed_binary_manuscripts_require_manual_reanchoring() {
        let dir = tempdir().unwrap();
        let path = dir.path().join("paper.docx");
        fs::write(&path, b"changed docx bytes").unwrap();
        let anchor = ManuscriptAnchor {
            id: Uuid::new_v4(),
            project_id: Uuid::new_v4(),
            research_item_id: Uuid::new_v4(),
            format: AnchorFormat::Docx,
            document_path: path,
            document_sha256: sha256_hex(b"original docx bytes"),
            locator: serde_json::json!({"paragraphFingerprint":"abc"}),
            quote_hash: sha256_hex(b"selected text"),
            quote_word_count: Some(2),
            context_before_hash: None,
            context_after_hash: None,
            status: AnchorStatus::Valid,
            created_at: Utc::now(),
            last_validated_at: None,
            last_validated_document_sha256: None,
            validation_capability: None,
            validation_detail: None,
        };

        let outcome = revalidate_manuscript_anchor(&anchor).unwrap();

        assert_eq!(outcome.status, AnchorStatus::Stale);
        assert_eq!(
            outcome.capability,
            AnchorRevalidationCapability::ManualReanchorRequired
        );
    }
}
