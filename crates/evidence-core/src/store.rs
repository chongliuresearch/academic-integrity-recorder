use crate::{
    canonical::to_jcs,
    crypto::{encrypt, sha256_hex, DeviceSigner, EncryptedEnvelope, ProjectKey},
    CheckpointBody, EventDraft, EvidenceEvent, IntegrityCheckpoint, PublicEvent,
};
use anyhow::{anyhow, Context, Result};
use chrono::Utc;
use rusqlite::{params, Connection};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::{
    collections::BTreeMap,
    fs::{self, File, OpenOptions},
    io::{BufRead, BufReader, Write},
    path::{Path, PathBuf},
};
use uuid::Uuid;

const INTEGRITY_FORMAT_KEY: &str = "local_integrity_format";
const INTEGRITY_FORMAT_VERSION: &str = "signed-high-water/v1";
const PENDING_APPEND_FILE: &str = "append.pending.json";

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PendingAppendBody {
    format: String,
    sequence: u64,
    event_id: Uuid,
    project_id: Uuid,
    event_hash: String,
    previous_hash: String,
    segment_name: String,
    segment_sha256: String,
    device_public_key: String,
    device_fingerprint: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
struct PendingAppend {
    body: PendingAppendBody,
    signature: String,
}

pub struct EvidenceStore {
    root: PathBuf,
    connection: Connection,
    project_key: ProjectKey,
    signer: DeviceSigner,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
#[serde(rename_all = "camelCase")]
pub struct LegacyMigrationReport {
    pub events_sealed: u64,
    pub final_event_hash: String,
    pub trust_boundary_note: String,
}

impl EvidenceStore {
    pub fn open(
        root: impl AsRef<Path>,
        project_key: ProjectKey,
        signer: DeviceSigner,
    ) -> Result<Self> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("segments"))?;
        fs::create_dir_all(root.join("objects"))?;
        fs::create_dir_all(root.join("checkpoints"))?;
        let connection = Connection::open(root.join("index.sqlite3"))?;
        connection.execute_batch(
            "PRAGMA journal_mode=WAL;
             CREATE TABLE IF NOT EXISTS events (
               sequence INTEGER PRIMARY KEY,
               event_id TEXT NOT NULL UNIQUE,
               project_id TEXT NOT NULL,
               occurred_at TEXT NOT NULL,
               kind TEXT NOT NULL,
               source TEXT NOT NULL,
               event_hash TEXT NOT NULL UNIQUE,
               segment_path TEXT NOT NULL
             );
             CREATE TABLE IF NOT EXISTS state (
               key TEXT PRIMARY KEY,
               value TEXT NOT NULL
             );",
        )?;
        let mut store = Self {
            root,
            connection,
            project_key,
            signer,
        };
        store.initialize_integrity_format()?;
        store.reconcile_on_open()?;
        Ok(store)
    }

    /// Explicitly seals a pre-signed-high-water/v1 store after validating
    /// every SQLite row against the enumerated encrypted segment directory.
    ///
    /// Migration is deliberately never automatic: the resulting signatures
    /// attest only that the device sealed the history at migration time.
    pub fn migrate_legacy(
        root: impl AsRef<Path>,
        project_key: ProjectKey,
        signer: DeviceSigner,
    ) -> Result<LegacyMigrationReport> {
        let root = root.as_ref().to_path_buf();
        fs::create_dir_all(root.join("segments"))?;
        fs::create_dir_all(root.join("objects"))?;
        fs::create_dir_all(root.join("checkpoints"))?;
        let connection = Connection::open(root.join("index.sqlite3"))?;
        let mut store = Self {
            root,
            connection,
            project_key,
            signer,
        };
        if store.state(INTEGRITY_FORMAT_KEY)?.is_some() {
            return Err(anyhow!("store already uses signed high-water integrity"));
        }
        if store.root.join(PENDING_APPEND_FILE).exists() {
            return Err(anyhow!(
                "cannot migrate while an unverified pending append exists"
            ));
        }

        let indexed = {
            let mut statement = store.connection.prepare(
                "SELECT sequence,event_id,project_id,event_hash,segment_path
                 FROM events ORDER BY sequence ASC",
            )?;
            let rows = statement
                .query_map([], |row| {
                    Ok((
                        row.get::<_, u64>(0)?,
                        row.get::<_, String>(1)?,
                        row.get::<_, String>(2)?,
                        row.get::<_, String>(3)?,
                        row.get::<_, String>(4)?,
                    ))
                })?
                .collect::<rusqlite::Result<Vec<_>>>()?;
            rows
        };
        let segments = enumerate_sequence_files(&store.root.join("segments"), ".segment")?;
        if indexed.len() != segments.len() {
            return Err(anyhow!(
                "legacy SQLite index and segment directory have different counts"
            ));
        }

        let mut events = Vec::with_capacity(indexed.len());
        let mut previous = "0".repeat(64);
        for (index, (sequence, event_id, project_id, event_hash, segment_name)) in
            indexed.iter().enumerate()
        {
            let expected_sequence = index as u64 + 1;
            if *sequence != expected_sequence {
                return Err(anyhow!(
                    "legacy index is missing or reordered at sequence {expected_sequence}"
                ));
            }
            let enumerated_name = segments
                .get(sequence)
                .with_context(|| format!("missing legacy segment at sequence {sequence}"))?;
            if segment_name != enumerated_name {
                return Err(anyhow!(
                    "legacy index path disagrees with segment directory at sequence {sequence}"
                ));
            }
            let project_id = Uuid::parse_str(project_id)?;
            let bytes = fs::read(store.root.join("segments").join(segment_name))?;
            let event = store.decrypt_segment_bytes(&bytes, project_id, *sequence)?;
            validate_event(&event)?;
            if event.id.to_string() != *event_id
                || event.project_id != project_id
                || event.event_hash != *event_hash
                || event.previous_hash != previous
            {
                return Err(anyhow!(
                    "legacy index or chain metadata mismatch at sequence {sequence}"
                ));
            }
            previous = event.event_hash.clone();
            events.push(event);
        }

        for event in &events {
            store.write_local_checkpoint(event)?;
        }
        store.set_state(INTEGRITY_FORMAT_KEY, INTEGRITY_FORMAT_VERSION)?;
        store.rebuild_index(&events)?;
        store.verify_local_chain()?;

        Ok(LegacyMigrationReport {
            events_sealed: events.len() as u64,
            final_event_hash: events
                .last()
                .map(|event| event.event_hash.clone())
                .unwrap_or_else(|| "0".repeat(64)),
            trust_boundary_note:
                "Migration seals validated local bytes at migration time; it does not prove earlier existence or completeness."
                    .into(),
        })
    }

    pub fn root(&self) -> &Path {
        &self.root
    }

    pub fn append(&mut self, draft: EventDraft) -> Result<EvidenceEvent> {
        self.append_inner(draft, false)
    }

    fn append_inner(
        &mut self,
        draft: EventDraft,
        interrupt_after_segment: bool,
    ) -> Result<EvidenceEvent> {
        self.verify_local_chain()?;
        let sequence = self.last_sequence()? + 1;
        let previous_hash = self.state("last_hash")?.unwrap_or_else(|| "0".repeat(64));
        let payload_bytes = to_jcs(&draft.payload)?;
        let payload_hash = sha256_hex(&payload_bytes);
        let id = Uuid::new_v4();
        let captured_at = Utc::now();
        let hash_material = event_hash_material(
            id,
            draft.project_id,
            draft.session_id,
            sequence,
            draft.occurred_at,
            captured_at,
            draft.monotonic_millis,
            &draft.source,
            &draft.kind,
            &draft.sensitivity,
            &payload_hash,
            &previous_hash,
            draft.capability_id.as_deref(),
        );
        let event_hash = sha256_hex(&to_jcs(&hash_material)?);
        let event = EvidenceEvent {
            id,
            project_id: draft.project_id,
            session_id: draft.session_id,
            sequence,
            occurred_at: draft.occurred_at,
            captured_at,
            monotonic_millis: draft.monotonic_millis,
            source: hash_material["source"].as_str().unwrap_or_default().into(),
            kind: serde_json::from_value(hash_material["kind"].clone())?,
            sensitivity: serde_json::from_value(hash_material["sensitivity"].clone())?,
            payload: draft.payload,
            payload_hash,
            previous_hash,
            event_hash,
            capability_id: draft.capability_id,
        };

        let segment_name = format!("{:020}.segment", sequence);
        let segment_path = self.root.join("segments").join(&segment_name);
        let aad = format!("{}:{}", event.project_id, event.sequence);
        let envelope = encrypt(&self.project_key, &to_jcs(&event)?, aad.as_bytes())?;
        let segment_bytes = to_jcs(&envelope)?;
        let pending = self.create_pending_append(&event, &segment_name, &segment_bytes)?;
        let pending_path = self.root.join(PENDING_APPEND_FILE);
        write_create_new(&pending_path, &to_jcs(&pending)?)?;
        sync_parent_directory(&pending_path)?;
        write_create_new(&segment_path, &segment_bytes)?;
        sync_parent_directory(&segment_path)?;

        if interrupt_after_segment {
            return Err(anyhow!("simulated interruption after segment sync"));
        }

        self.index_event(&event, &segment_name)?;
        self.write_local_checkpoint(&event)?;
        remove_file_durable(&pending_path)?;
        Ok(event)
    }

    #[cfg(test)]
    fn append_interrupted_after_segment_for_test(
        &mut self,
        draft: EventDraft,
    ) -> Result<EvidenceEvent> {
        self.append_inner(draft, true)
    }

    fn initialize_integrity_format(&mut self) -> Result<()> {
        match self.state(INTEGRITY_FORMAT_KEY)? {
            Some(value) if value == INTEGRITY_FORMAT_VERSION => Ok(()),
            Some(value) => Err(anyhow!("unsupported local integrity format: {value}")),
            None => {
                let event_count: u64 =
                    self.connection
                        .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))?;
                let has_segments = directory_has_entries(&self.root.join("segments"))?;
                let has_checkpoints = directory_has_entries(&self.root.join("checkpoints"))?;
                if event_count != 0
                    || has_segments
                    || has_checkpoints
                    || self.root.join(PENDING_APPEND_FILE).exists()
                {
                    return Err(anyhow!(
                        "legacy or unsealed evidence store requires an explicit integrity migration"
                    ));
                }
                self.set_state(INTEGRITY_FORMAT_KEY, INTEGRITY_FORMAT_VERSION)
            }
        }
    }

    fn create_pending_append(
        &self,
        event: &EvidenceEvent,
        segment_name: &str,
        segment_bytes: &[u8],
    ) -> Result<PendingAppend> {
        let body = PendingAppendBody {
            format: INTEGRITY_FORMAT_VERSION.into(),
            sequence: event.sequence,
            event_id: event.id,
            project_id: event.project_id,
            event_hash: event.event_hash.clone(),
            previous_hash: event.previous_hash.clone(),
            segment_name: segment_name.into(),
            segment_sha256: sha256_hex(segment_bytes),
            device_public_key: self.signer.public_key(),
            device_fingerprint: self.signer.fingerprint(),
        };
        Ok(PendingAppend {
            signature: self.signer.sign(&body)?,
            body,
        })
    }

    fn verify_pending_append(&self, pending: &PendingAppend) -> Result<()> {
        if pending.body.format != INTEGRITY_FORMAT_VERSION {
            return Err(anyhow!("unsupported pending append format"));
        }
        if pending.body.device_public_key != self.signer.public_key()
            || pending.body.device_fingerprint != self.signer.fingerprint()
        {
            return Err(anyhow!("pending append was signed by a different device"));
        }
        DeviceSigner::verify(
            &pending.body.device_public_key,
            &pending.body,
            &pending.signature,
        )
        .context("invalid pending append signature")?;
        let expected_name = format!("{:020}.segment", pending.body.sequence);
        if pending.body.segment_name != expected_name {
            return Err(anyhow!("pending append segment name mismatch"));
        }
        Ok(())
    }

    fn reconcile_on_open(&mut self) -> Result<()> {
        let had_pending_append = self.read_pending_append()?;
        if let Some(pending) = had_pending_append.as_ref() {
            self.recover_pending_append(pending)?;
        }
        let events = self.load_committed_events()?;
        let indexed_high_water = self.last_sequence()?;
        let signed_high_water = events.len() as u64;
        if had_pending_append.is_none() && indexed_high_water > signed_high_water {
            return Err(anyhow!(
                "signed evidence tail was truncated: SQLite high-water {indexed_high_water} exceeds signed checkpoint high-water {signed_high_water}"
            ));
        }
        self.rebuild_index(&events)?;
        Ok(())
    }

    fn read_pending_append(&self) -> Result<Option<PendingAppend>> {
        let path = self.root.join(PENDING_APPEND_FILE);
        if !path.exists() {
            return Ok(None);
        }
        let pending: PendingAppend = serde_json::from_slice(&fs::read(&path)?)?;
        self.verify_pending_append(&pending)?;
        Ok(Some(pending))
    }

    fn recover_pending_append(&mut self, pending: &PendingAppend) -> Result<()> {
        let checkpoints = self.read_local_checkpoints()?;
        let high_water = checkpoints.keys().next_back().copied().unwrap_or(0);
        let pending_path = self.root.join(PENDING_APPEND_FILE);
        let segment_path = self.root.join("segments").join(&pending.body.segment_name);

        if pending.body.sequence == high_water + 1 {
            if !segment_path.exists() {
                remove_file_durable(&pending_path)?;
                return Ok(());
            }
            let event = self.read_pending_segment(pending, &segment_path)?;
            let expected_previous = checkpoints
                .get(&high_water)
                .map(|checkpoint| checkpoint.body.final_event_hash.as_str())
                .unwrap_or_else(|| "");
            let genesis = "0".repeat(64);
            let expected_previous = if high_water == 0 {
                genesis.as_str()
            } else {
                expected_previous
            };
            if event.previous_hash != expected_previous {
                return Err(anyhow!(
                    "pending append does not continue signed high-water checkpoint"
                ));
            }
            validate_event(&event)?;
            self.write_local_checkpoint(&event)?;
            remove_file_durable(&pending_path)?;
            return Ok(());
        }

        if pending.body.sequence == high_water && high_water != 0 {
            let checkpoint = checkpoints
                .get(&high_water)
                .context("missing high-water checkpoint")?;
            let event = self.read_pending_segment(pending, &segment_path)?;
            if event.event_hash != checkpoint.body.final_event_hash {
                return Err(anyhow!("pending append disagrees with signed checkpoint"));
            }
            remove_file_durable(&pending_path)?;
            return Ok(());
        }

        Err(anyhow!(
            "pending append sequence {} is inconsistent with signed high-water {}",
            pending.body.sequence,
            high_water
        ))
    }

    fn read_pending_segment(&self, pending: &PendingAppend, path: &Path) -> Result<EvidenceEvent> {
        let bytes = fs::read(path)
            .with_context(|| format!("missing pending segment {}", path.display()))?;
        if sha256_hex(&bytes) != pending.body.segment_sha256 {
            return Err(anyhow!("pending segment digest mismatch"));
        }
        let event =
            self.decrypt_segment_bytes(&bytes, pending.body.project_id, pending.body.sequence)?;
        if event.id != pending.body.event_id
            || event.project_id != pending.body.project_id
            || event.sequence != pending.body.sequence
            || event.event_hash != pending.body.event_hash
            || event.previous_hash != pending.body.previous_hash
        {
            return Err(anyhow!(
                "pending segment content does not match signed intent"
            ));
        }
        Ok(event)
    }

    fn index_event(&mut self, event: &EvidenceEvent, segment_name: &str) -> Result<()> {
        let transaction = self.connection.transaction()?;
        insert_event_row(&transaction, event, segment_name)?;
        set_transaction_state(&transaction, "last_hash", &event.event_hash)?;
        set_transaction_state(&transaction, "last_sequence", &event.sequence.to_string())?;
        transaction.commit()?;
        Ok(())
    }

    fn rebuild_index(&mut self, events: &[EvidenceEvent]) -> Result<()> {
        let transaction = self.connection.transaction()?;
        transaction.execute("DELETE FROM events", [])?;
        for event in events {
            insert_event_row(
                &transaction,
                event,
                &format!("{:020}.segment", event.sequence),
            )?;
        }
        let final_hash = events
            .last()
            .map(|event| event.event_hash.as_str())
            .unwrap_or_else(|| "");
        let genesis = "0".repeat(64);
        set_transaction_state(
            &transaction,
            "last_hash",
            if events.is_empty() {
                genesis.as_str()
            } else {
                final_hash
            },
        )?;
        set_transaction_state(&transaction, "last_sequence", &events.len().to_string())?;
        transaction.commit()?;
        Ok(())
    }

    fn write_local_checkpoint(&self, event: &EvidenceEvent) -> Result<()> {
        let path = self
            .root
            .join("checkpoints")
            .join(format!("{:020}.checkpoint", event.sequence));
        if path.exists() {
            let checkpoint: IntegrityCheckpoint = serde_json::from_slice(&fs::read(&path)?)?;
            if checkpoint.body.sequence != event.sequence
                || checkpoint.body.project_id != event.project_id
                || checkpoint.body.final_event_hash != event.event_hash
                || checkpoint.body.device_public_key != self.signer.public_key()
                || checkpoint.body.device_fingerprint != self.signer.fingerprint()
            {
                return Err(anyhow!(
                    "existing signed checkpoint conflicts at sequence {}",
                    event.sequence
                ));
            }
            DeviceSigner::verify(
                &checkpoint.body.device_public_key,
                &checkpoint.body,
                &checkpoint.signature,
            )
            .context("existing checkpoint signature is invalid")?;
            return Ok(());
        }
        let body = CheckpointBody {
            project_id: event.project_id,
            sequence: event.sequence,
            final_event_hash: event.event_hash.clone(),
            created_at: Utc::now(),
            device_public_key: self.signer.public_key(),
            device_fingerprint: self.signer.fingerprint(),
        };
        let checkpoint = IntegrityCheckpoint {
            signature: self.signer.sign(&body)?,
            body,
        };
        write_create_new(&path, &to_jcs(&checkpoint)?)?;
        sync_parent_directory(&path)
    }

    pub fn add_artifact(&self, bytes: &[u8]) -> Result<String> {
        let hash = sha256_hex(bytes);
        let destination = self.root.join("objects").join(&hash);
        if !destination.exists() {
            let aad = format!("artifact:{hash}");
            let envelope = encrypt(&self.project_key, bytes, aad.as_bytes())?;
            write_create_new(&destination, &to_jcs(&envelope)?)?;
        }
        Ok(hash)
    }

    pub fn read_artifact(&self, hash: &str) -> Result<Vec<u8>> {
        if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(anyhow!("invalid artifact hash"));
        }
        let envelope: EncryptedEnvelope =
            serde_json::from_slice(&fs::read(self.root.join("objects").join(hash))?)?;
        let aad = format!("artifact:{hash}");
        let bytes = crate::crypto::decrypt(&self.project_key, &envelope, aad.as_bytes())?;
        if sha256_hex(&bytes) != hash {
            return Err(anyhow!("artifact plaintext hash mismatch"));
        }
        Ok(bytes)
    }

    pub fn delete_artifact_content(&self, hash: &str) -> Result<bool> {
        if hash.len() != 64 || !hash.bytes().all(|byte| byte.is_ascii_hexdigit()) {
            return Err(anyhow!("invalid artifact hash"));
        }
        let path = self.root.join("objects").join(hash);
        if path.exists() {
            fs::remove_file(path)?;
            Ok(true)
        } else {
            Ok(false)
        }
    }

    pub fn checkpoint(&self, project_id: Uuid) -> Result<IntegrityCheckpoint> {
        let sequence = self.last_sequence()?;
        let body = CheckpointBody {
            project_id,
            sequence,
            final_event_hash: self.state("last_hash")?.unwrap_or_else(|| "0".repeat(64)),
            created_at: Utc::now(),
            device_public_key: self.signer.public_key(),
            device_fingerprint: self.signer.fingerprint(),
        };
        Ok(IntegrityCheckpoint {
            signature: self.signer.sign(&body)?,
            body,
        })
    }

    pub fn public_events(&self) -> Result<Vec<PublicEvent>> {
        Ok(self.events()?.iter().map(PublicEvent::from).collect())
    }

    pub fn events(&self) -> Result<Vec<EvidenceEvent>> {
        self.load_committed_events()
    }

    pub fn sync_segments(&self, sync_directory: impl AsRef<Path>) -> Result<usize> {
        let destination = sync_directory.as_ref().join("encrypted-evidence");
        let segment_destination = destination.join("segments");
        let object_destination = destination.join("objects");
        let checkpoint_destination = destination.join("checkpoints");
        fs::create_dir_all(&segment_destination)?;
        fs::create_dir_all(&object_destination)?;
        fs::create_dir_all(&checkpoint_destination)?;
        let mut copied = 0;
        for entry in fs::read_dir(self.root.join("segments"))? {
            let entry = entry?;
            let target = segment_destination.join(entry.file_name());
            if copy_or_verify_immutable(&entry.path(), &target)? {
                copied += 1;
            }
        }
        for entry in fs::read_dir(self.root.join("objects"))? {
            let entry = entry?;
            let target = object_destination.join(entry.file_name());
            if copy_or_verify_immutable(&entry.path(), &target)? {
                copied += 1;
            }
        }
        for entry in fs::read_dir(self.root.join("checkpoints"))? {
            let entry = entry?;
            let target = checkpoint_destination.join(entry.file_name());
            if copy_or_verify_immutable(&entry.path(), &target)? {
                copied += 1;
            }
        }
        Ok(copied)
    }

    pub fn verify_local_chain(&self) -> Result<()> {
        let events = self.load_committed_events()?;
        let indexed_count: u64 =
            self.connection
                .query_row("SELECT COUNT(*) FROM events", [], |row| row.get(0))?;
        if indexed_count != events.len() as u64 {
            return Err(anyhow!(
                "SQLite event index count disagrees with signed segments"
            ));
        }
        let indexed_sequence = self.last_sequence()?;
        if indexed_sequence != events.len() as u64 {
            return Err(anyhow!(
                "SQLite high-water sequence disagrees with signed segments"
            ));
        }
        let indexed_hash = self.state("last_hash")?.unwrap_or_else(|| "0".repeat(64));
        let expected_hash = events
            .last()
            .map(|event| event.event_hash.clone())
            .unwrap_or_else(|| "0".repeat(64));
        if indexed_hash != expected_hash {
            return Err(anyhow!(
                "SQLite high-water hash disagrees with signed segments"
            ));
        }
        Ok(())
    }

    fn load_committed_events(&self) -> Result<Vec<EvidenceEvent>> {
        let checkpoints = self.read_local_checkpoints()?;
        let segments = enumerate_sequence_files(&self.root.join("segments"), ".segment")?;
        let high_water = checkpoints.keys().next_back().copied().unwrap_or(0);

        if high_water == 0 && !segments.is_empty() {
            return Err(anyhow!(
                "signed high-water checkpoint missing for unsigned extra segment"
            ));
        }
        for sequence in 1..=high_water {
            if !segments.contains_key(&sequence) {
                return Err(anyhow!("missing segment at sequence {sequence}"));
            }
        }
        if let Some(sequence) = segments.keys().find(|sequence| **sequence > high_water) {
            return Err(anyhow!(
                "unsigned extra segment at sequence {sequence} exceeds signed high-water {high_water}"
            ));
        }

        let mut events = Vec::with_capacity(high_water as usize);
        let mut previous = "0".repeat(64);
        let mut project_id = None;
        for sequence in 1..=high_water {
            let checkpoint = checkpoints
                .get(&sequence)
                .with_context(|| format!("missing signed checkpoint at sequence {sequence}"))?;
            if let Some(expected_project) = project_id {
                if checkpoint.body.project_id != expected_project {
                    return Err(anyhow!("project changed within local evidence chain"));
                }
            } else {
                project_id = Some(checkpoint.body.project_id);
            }
            let segment_name = segments
                .get(&sequence)
                .context("missing enumerated segment")?;
            let bytes = fs::read(self.root.join("segments").join(segment_name))?;
            let event = self.decrypt_segment_bytes(&bytes, checkpoint.body.project_id, sequence)?;
            validate_event(&event)?;
            if event.sequence != sequence {
                return Err(anyhow!("reordered event at sequence {sequence}"));
            }
            if event.project_id != checkpoint.body.project_id {
                return Err(anyhow!("segment project does not match signed checkpoint"));
            }
            if event.previous_hash != previous {
                return Err(anyhow!("broken previous hash at sequence {sequence}"));
            }
            if event.event_hash != checkpoint.body.final_event_hash {
                return Err(anyhow!(
                    "segment hash does not match signed checkpoint at sequence {sequence}"
                ));
            }
            previous = event.event_hash.clone();
            events.push(event);
        }
        Ok(events)
    }

    fn read_local_checkpoints(&self) -> Result<BTreeMap<u64, IntegrityCheckpoint>> {
        let files = enumerate_sequence_files(&self.root.join("checkpoints"), ".checkpoint")?;
        let mut checkpoints = BTreeMap::new();
        for (sequence, name) in files {
            let checkpoint: IntegrityCheckpoint =
                serde_json::from_slice(&fs::read(self.root.join("checkpoints").join(name))?)?;
            if checkpoint.body.sequence != sequence {
                return Err(anyhow!(
                    "reordered signed checkpoint at sequence {sequence}"
                ));
            }
            if checkpoint.body.device_public_key != self.signer.public_key()
                || checkpoint.body.device_fingerprint != self.signer.fingerprint()
            {
                return Err(anyhow!(
                    "signed checkpoint at sequence {sequence} belongs to a different device"
                ));
            }
            DeviceSigner::verify(
                &checkpoint.body.device_public_key,
                &checkpoint.body,
                &checkpoint.signature,
            )
            .with_context(|| format!("invalid checkpoint signature at sequence {sequence}"))?;
            checkpoints.insert(sequence, checkpoint);
        }
        if let Some(high_water) = checkpoints.keys().next_back().copied() {
            for sequence in 1..=high_water {
                if !checkpoints.contains_key(&sequence) {
                    return Err(anyhow!(
                        "missing signed high-water checkpoint at sequence {sequence}"
                    ));
                }
            }
        }
        Ok(checkpoints)
    }

    fn decrypt_segment_bytes(
        &self,
        bytes: &[u8],
        project_id: Uuid,
        sequence: u64,
    ) -> Result<EvidenceEvent> {
        let envelope: EncryptedEnvelope = serde_json::from_slice(bytes)?;
        let aad = format!("{}:{}", project_id, sequence);
        let bytes = crate::crypto::decrypt(&self.project_key, &envelope, aad.as_bytes())?;
        Ok(serde_json::from_slice(&bytes)?)
    }

    fn last_sequence(&self) -> Result<u64> {
        Ok(self
            .state("last_sequence")?
            .map(|value| value.parse())
            .transpose()?
            .unwrap_or(0))
    }

    fn state(&self, key: &str) -> Result<Option<String>> {
        let mut statement = self
            .connection
            .prepare("SELECT value FROM state WHERE key=?1")?;
        let mut rows = statement.query(params![key])?;
        Ok(rows.next()?.map(|row| row.get(0)).transpose()?)
    }

    fn set_state(&self, key: &str, value: &str) -> Result<()> {
        self.connection.execute(
            "INSERT INTO state(key,value) VALUES(?1,?2)
             ON CONFLICT(key) DO UPDATE SET value=excluded.value",
            params![key, value],
        )?;
        Ok(())
    }
}

#[allow(clippy::too_many_arguments)]
pub fn event_hash_material(
    id: Uuid,
    project_id: Uuid,
    session_id: Option<Uuid>,
    sequence: u64,
    occurred_at: chrono::DateTime<Utc>,
    captured_at: chrono::DateTime<Utc>,
    monotonic_millis: u64,
    source: &str,
    kind: &crate::EventKind,
    sensitivity: &crate::Sensitivity,
    payload_hash: &str,
    previous_hash: &str,
    capability_id: Option<&str>,
) -> Value {
    serde_json::json!({
        "id": id,
        "projectId": project_id,
        "sessionId": session_id,
        "sequence": sequence,
        "occurredAt": occurred_at,
        "capturedAt": captured_at,
        "monotonicMillis": monotonic_millis,
        "source": source,
        "kind": kind,
        "sensitivity": sensitivity,
        "payloadHash": payload_hash,
        "previousHash": previous_hash,
        "capabilityId": capability_id,
    })
}

fn validate_event(event: &EvidenceEvent) -> Result<()> {
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
    if sha256_hex(&to_jcs(&material)?) != event.event_hash {
        return Err(anyhow!(
            "event hash mismatch at sequence {}",
            event.sequence
        ));
    }
    Ok(())
}

fn insert_event_row(
    transaction: &rusqlite::Transaction<'_>,
    event: &EvidenceEvent,
    segment_name: &str,
) -> Result<()> {
    transaction.execute(
        "DELETE FROM events WHERE sequence=?1 OR event_id=?2 OR event_hash=?3",
        params![event.sequence, event.id.to_string(), event.event_hash],
    )?;
    transaction.execute(
        "INSERT INTO events(sequence,event_id,project_id,occurred_at,kind,source,event_hash,segment_path)
         VALUES (?1,?2,?3,?4,?5,?6,?7,?8)",
        params![
            event.sequence,
            event.id.to_string(),
            event.project_id.to_string(),
            event.occurred_at.to_rfc3339(),
            serde_json::to_string(&event.kind)?,
            event.source,
            event.event_hash,
            segment_name,
        ],
    )?;
    Ok(())
}

fn set_transaction_state(
    transaction: &rusqlite::Transaction<'_>,
    key: &str,
    value: &str,
) -> Result<()> {
    transaction.execute(
        "INSERT INTO state(key,value) VALUES(?1,?2)
         ON CONFLICT(key) DO UPDATE SET value=excluded.value",
        params![key, value],
    )?;
    Ok(())
}

fn enumerate_sequence_files(directory: &Path, suffix: &str) -> Result<BTreeMap<u64, String>> {
    let mut files = BTreeMap::new();
    for entry in fs::read_dir(directory)? {
        let entry = entry?;
        if !entry.file_type()?.is_file() {
            return Err(anyhow!(
                "unexpected non-file entry in immutable directory: {}",
                entry.path().display()
            ));
        }
        let name = entry
            .file_name()
            .into_string()
            .map_err(|_| anyhow!("non-UTF-8 immutable evidence filename"))?;
        let prefix = name
            .strip_suffix(suffix)
            .with_context(|| format!("unexpected immutable evidence file: {name}"))?;
        if prefix.len() != 20 || !prefix.bytes().all(|byte| byte.is_ascii_digit()) {
            return Err(anyhow!("invalid immutable evidence filename: {name}"));
        }
        let sequence = prefix.parse::<u64>()?;
        if sequence == 0 || files.insert(sequence, name).is_some() {
            return Err(anyhow!("duplicate or zero evidence sequence {sequence}"));
        }
    }
    Ok(files)
}

fn directory_has_entries(directory: &Path) -> Result<bool> {
    Ok(fs::read_dir(directory)?.next().transpose()?.is_some())
}

fn write_create_new(path: &Path, bytes: &[u8]) -> Result<()> {
    let mut file = OpenOptions::new()
        .write(true)
        .create_new(true)
        .open(path)
        .with_context(|| format!("refusing to overwrite immutable file {}", path.display()))?;
    file.write_all(bytes)?;
    file.sync_all()?;
    Ok(())
}

fn remove_file_durable(path: &Path) -> Result<()> {
    fs::remove_file(path)?;
    sync_parent_directory(path)
}

#[cfg(unix)]
fn sync_parent_directory(path: &Path) -> Result<()> {
    File::open(path.parent().context("path has no parent directory")?)?.sync_all()?;
    Ok(())
}

#[cfg(not(unix))]
fn sync_parent_directory(_path: &Path) -> Result<()> {
    Ok(())
}

fn copy_or_verify_immutable(source: &Path, destination: &Path) -> Result<bool> {
    let source_bytes = fs::read(source)?;
    if destination.exists() {
        if fs::read(destination)? != source_bytes {
            return Err(anyhow!(
                "immutable sync conflict at {}; refusing to overwrite",
                destination.display()
            ));
        }
        return Ok(false);
    }
    let temp = destination.with_extension("partial");
    if temp.exists() {
        fs::remove_file(&temp)?;
    }
    write_create_new(&temp, &source_bytes)?;
    if fs::read(&temp)? != source_bytes {
        let _ = fs::remove_file(&temp);
        return Err(anyhow!(
            "sync copy verification failed for {}",
            source.display()
        ));
    }
    fs::rename(&temp, destination)?;
    sync_parent_directory(destination)?;
    Ok(true)
}

pub fn read_json_lines<T: serde::de::DeserializeOwned>(path: &Path) -> Result<Vec<T>> {
    let file = File::open(path)?;
    BufReader::new(file)
        .lines()
        .map(|line| Ok(serde_json::from_str(&line?)?))
        .collect()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::{EventKind, Sensitivity};
    use rusqlite::Connection;
    use tempfile::tempdir;

    fn draft(project_id: Uuid, value: &str) -> EventDraft {
        EventDraft {
            project_id,
            session_id: None,
            occurred_at: Utc::now(),
            monotonic_millis: 1,
            source: "test".into(),
            kind: EventKind::Annotation,
            sensitivity: Sensitivity::SensitiveContent,
            payload: serde_json::json!({"value": value}),
            capability_id: None,
        }
    }

    fn open_error(root: &Path, key: ProjectKey, signer: DeviceSigner) -> anyhow::Error {
        match EvidenceStore::open(root, key, signer) {
            Ok(_) => panic!("store unexpectedly opened"),
            Err(error) => error,
        }
    }

    #[test]
    fn appends_immutable_encrypted_segments_and_verifies_chain() {
        let dir = tempdir().unwrap();
        let mut store =
            EvidenceStore::open(dir.path(), ProjectKey::generate(), DeviceSigner::generate())
                .unwrap();
        let project = Uuid::new_v4();
        let first = store.append(draft(project, "one")).unwrap();
        let second = store.append(draft(project, "two")).unwrap();
        assert_eq!(second.previous_hash, first.event_hash);
        store.verify_local_chain().unwrap();
        let raw = fs::read(dir.path().join("segments/00000000000000000001.segment")).unwrap();
        assert!(!String::from_utf8_lossy(&raw).contains("one"));
    }

    #[test]
    fn recovers_an_append_interrupted_after_the_segment_was_synced() {
        let dir = tempdir().unwrap();
        let key = ProjectKey::generate();
        let signer = DeviceSigner::generate();
        let project = Uuid::new_v4();
        {
            let mut store = EvidenceStore::open(dir.path(), key.clone(), signer.clone()).unwrap();
            let error = store
                .append_interrupted_after_segment_for_test(draft(project, "durable"))
                .unwrap_err();
            assert!(error.to_string().contains("simulated interruption"));
        }

        let mut recovered = EvidenceStore::open(dir.path(), key, signer).unwrap();
        let events = recovered.events().unwrap();
        assert_eq!(events.len(), 1);
        assert_eq!(events[0].payload["value"], "durable");
        assert!(!dir.path().join("append.pending.json").exists());
        recovered.append(draft(project, "next")).unwrap();
        recovered.verify_local_chain().unwrap();
    }

    #[test]
    fn restores_a_sqlite_tail_from_signed_high_water_and_segments() {
        let dir = tempdir().unwrap();
        let key = ProjectKey::generate();
        let signer = DeviceSigner::generate();
        let project = Uuid::new_v4();
        let first_hash;
        {
            let mut store = EvidenceStore::open(dir.path(), key.clone(), signer.clone()).unwrap();
            first_hash = store.append(draft(project, "one")).unwrap().event_hash;
            store.append(draft(project, "two")).unwrap();
        }
        let index = Connection::open(dir.path().join("index.sqlite3")).unwrap();
        index
            .execute("DELETE FROM events WHERE sequence=2", [])
            .unwrap();
        index
            .execute("UPDATE state SET value='1' WHERE key='last_sequence'", [])
            .unwrap();
        index
            .execute(
                "UPDATE state SET value=?1 WHERE key='last_hash'",
                params![first_hash],
            )
            .unwrap();
        drop(index);

        let recovered = EvidenceStore::open(dir.path(), key, signer).unwrap();
        assert_eq!(recovered.events().unwrap().len(), 2);
        recovered.verify_local_chain().unwrap();
    }

    #[test]
    fn legacy_store_requires_explicit_migration_and_reports_the_trust_boundary() {
        let dir = tempdir().unwrap();
        let key = ProjectKey::generate();
        let signer = DeviceSigner::generate();
        let project = Uuid::new_v4();
        let final_hash;
        {
            let mut store = EvidenceStore::open(dir.path(), key.clone(), signer.clone()).unwrap();
            final_hash = store.append(draft(project, "legacy")).unwrap().event_hash;
        }
        fs::remove_dir_all(dir.path().join("checkpoints")).unwrap();
        let index = Connection::open(dir.path().join("index.sqlite3")).unwrap();
        index
            .execute(
                "DELETE FROM state WHERE key=?1",
                params![INTEGRITY_FORMAT_KEY],
            )
            .unwrap();
        drop(index);

        let error = open_error(dir.path(), key.clone(), signer.clone());
        assert!(error.to_string().contains("explicit integrity migration"));
        let report =
            EvidenceStore::migrate_legacy(dir.path(), key.clone(), signer.clone()).unwrap();
        assert_eq!(report.events_sealed, 1);
        assert_eq!(report.final_event_hash, final_hash);
        assert!(report
            .trust_boundary_note
            .contains("does not prove earlier existence"));
        EvidenceStore::open(dir.path(), key, signer)
            .unwrap()
            .verify_local_chain()
            .unwrap();
    }

    #[test]
    fn rejects_an_unsigned_extra_segment() {
        let dir = tempdir().unwrap();
        let key = ProjectKey::generate();
        let signer = DeviceSigner::generate();
        let project = Uuid::new_v4();
        {
            let mut store = EvidenceStore::open(dir.path(), key.clone(), signer.clone()).unwrap();
            store.append(draft(project, "one")).unwrap();
        }
        fs::copy(
            dir.path().join("segments/00000000000000000001.segment"),
            dir.path().join("segments/00000000000000000002.segment"),
        )
        .unwrap();

        let error = open_error(dir.path(), key, signer);
        assert!(error.to_string().contains("unsigned extra segment"));
    }

    #[test]
    fn rejects_missing_or_reordered_segments() {
        let missing_dir = tempdir().unwrap();
        let missing_key = ProjectKey::generate();
        let missing_signer = DeviceSigner::generate();
        let project = Uuid::new_v4();
        {
            let mut store = EvidenceStore::open(
                missing_dir.path(),
                missing_key.clone(),
                missing_signer.clone(),
            )
            .unwrap();
            store.append(draft(project, "one")).unwrap();
            store.append(draft(project, "two")).unwrap();
        }
        fs::remove_file(
            missing_dir
                .path()
                .join("segments/00000000000000000002.segment"),
        )
        .unwrap();
        let error = open_error(missing_dir.path(), missing_key, missing_signer);
        assert!(error.to_string().contains("missing segment"));

        let reordered_dir = tempdir().unwrap();
        let reordered_key = ProjectKey::generate();
        let reordered_signer = DeviceSigner::generate();
        {
            let mut store = EvidenceStore::open(
                reordered_dir.path(),
                reordered_key.clone(),
                reordered_signer.clone(),
            )
            .unwrap();
            store.append(draft(project, "one")).unwrap();
            store.append(draft(project, "two")).unwrap();
        }
        let first = reordered_dir
            .path()
            .join("segments/00000000000000000001.segment");
        let second = reordered_dir
            .path()
            .join("segments/00000000000000000002.segment");
        let temporary = reordered_dir.path().join("segments/swap.tmp");
        fs::rename(&first, &temporary).unwrap();
        fs::rename(&second, &first).unwrap();
        fs::rename(&temporary, &second).unwrap();
        let error = open_error(reordered_dir.path(), reordered_key, reordered_signer);
        assert!(error.to_string().contains("authentication failed"));
    }

    #[test]
    fn rejects_removal_of_the_signed_high_water_checkpoint() {
        let dir = tempdir().unwrap();
        let key = ProjectKey::generate();
        let signer = DeviceSigner::generate();
        let project = Uuid::new_v4();
        {
            let mut store = EvidenceStore::open(dir.path(), key.clone(), signer.clone()).unwrap();
            store.append(draft(project, "one")).unwrap();
        }
        fs::remove_file(
            dir.path()
                .join("checkpoints/00000000000000000001.checkpoint"),
        )
        .unwrap();

        let error = open_error(dir.path(), key, signer);
        assert!(error.to_string().contains("signed high-water checkpoint"));
    }

    #[test]
    fn rejects_paired_removal_of_the_signed_tail_segment_and_checkpoint() {
        let dir = tempdir().unwrap();
        let key = ProjectKey::generate();
        let signer = DeviceSigner::generate();
        let project = Uuid::new_v4();
        {
            let mut store = EvidenceStore::open(dir.path(), key.clone(), signer.clone()).unwrap();
            store.append(draft(project, "one")).unwrap();
            store.append(draft(project, "two")).unwrap();
        }
        fs::remove_file(dir.path().join("segments/00000000000000000002.segment")).unwrap();
        fs::remove_file(
            dir.path()
                .join("checkpoints/00000000000000000002.checkpoint"),
        )
        .unwrap();

        let error = open_error(dir.path(), key, signer);
        assert!(error
            .to_string()
            .contains("signed evidence tail was truncated"));
        assert!(error
            .to_string()
            .contains("SQLite high-water 2 exceeds signed checkpoint high-water 1"));
    }

    #[test]
    fn sync_copies_encrypted_segments_and_content_objects() {
        let dir = tempdir().unwrap();
        let sync = tempdir().unwrap();
        let mut store =
            EvidenceStore::open(dir.path(), ProjectKey::generate(), DeviceSigner::generate())
                .unwrap();
        store.append(draft(Uuid::new_v4(), "one")).unwrap();
        let hash = store.add_artifact(b"snapshot").unwrap();
        assert_eq!(store.sync_segments(sync.path()).unwrap(), 3);
        assert_eq!(store.sync_segments(sync.path()).unwrap(), 0);
        assert!(sync
            .path()
            .join("encrypted-evidence/segments/00000000000000000001.segment")
            .exists());
        assert!(sync
            .path()
            .join("encrypted-evidence/objects")
            .join(hash)
            .exists());
        assert!(sync
            .path()
            .join("encrypted-evidence/checkpoints/00000000000000000001.checkpoint")
            .exists());
    }

    #[test]
    fn sync_refuses_to_overwrite_a_conflicting_immutable_copy() {
        let dir = tempdir().unwrap();
        let sync = tempdir().unwrap();
        let mut store =
            EvidenceStore::open(dir.path(), ProjectKey::generate(), DeviceSigner::generate())
                .unwrap();
        store.append(draft(Uuid::new_v4(), "one")).unwrap();
        store.sync_segments(sync.path()).unwrap();
        let target = sync
            .path()
            .join("encrypted-evidence/segments/00000000000000000001.segment");
        fs::write(&target, b"conflicting bytes").unwrap();

        let error = store.sync_segments(sync.path()).unwrap_err();
        assert!(error.to_string().contains("immutable sync conflict"));
        assert_eq!(fs::read(target).unwrap(), b"conflicting bytes");
    }
}
