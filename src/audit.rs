//! Structured, durable, hash-chained audit log.
//!
//! Every audit-worthy occurrence is a typed [`AuditEvent`]. One emission path
//! ([`emit`]) projects the event two ways:
//!
//! - a human/grep-facing `[AUDIT] <KIND> key=value ...` line on stderr via
//!   `tracing` (target `guard::audit`), with control characters escaped by
//!   [`crate::redact::audit_escape`] so one logical record is always exactly
//!   one physical line; and
//! - an append-only JSONL record in the daemon state directory, where field
//!   content is JSON-encoded and therefore can never forge a physical record.
//!
//! The JSONL file is the authoritative record. Each [`AuditRecord`] carries a
//! sequence number and the SHA-256 of the previous serialized record (a fixed
//! genesis constant for the first), so any truncation, edit, or reorder breaks
//! the chain and `guard audit verify` reports the first broken sequence.

use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::fs::{File, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::{Path, PathBuf};
use std::sync::Mutex;

use crate::redact::audit_escape;

/// Audit record schema version.
pub const AUDIT_SCHEMA_VERSION: u32 = 1;

/// Chain seed hashed into the first record's `prev_hash`.
const GENESIS_SEED: &[u8] = b"guard-audit-log-genesis-v1";

/// `prev_hash` of the first record in a chain.
pub fn genesis_hash() -> String {
    hex_digest(GENESIS_SEED)
}

fn hex_digest(bytes: &[u8]) -> String {
    let digest = Sha256::digest(bytes);
    digest.iter().map(|byte| format!("{byte:02x}")).collect()
}

/// Every audit event kind the daemon, proxy, and CLI emit. The serialized
/// names match the historical `[AUDIT] <KIND>` stderr prefixes so existing
/// grep patterns keep working against both projections.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "SCREAMING_SNAKE_CASE")]
pub enum AuditKind {
    // Policy decisions on command execution requests.
    Allowed,
    Denied,
    ExecFailed,
    // Consequence gating lifecycle.
    Held,
    HoldOrphaned,
    Provisional,
    ProvisionalInterrupted,
    ProvisionalAutoConfirmed,
    ProvisionalCheckFailed,
    Confirm,
    Revert,
    RevertDeferred,
    RevertFailed,
    // Operator approvals.
    Approved,
    ApprovedExecuted,
    ApproveVoided,
    ApproveExecFailed,
    ApprovalExpired,
    ApprovalNote,
    DeniedHold,
    // Session administration.
    SessionGrant,
    SessionRevoke,
    SessionAppeal,
    SessionShowRejected,
    AdminRejected,
    // Secrets and issued credentials.
    SecretSet,
    SecretDelete,
    KubeconfigIssued,
    // Verb catalog and evaluator-generated coverage.
    VerbCreated,
    ApiVerbCoverageHit,
    ApiVerbCoverageEscalate,
    ApiVerbCoverageCleared,
    // Secret values injected into a spawned child's environment.
    SecretExposed,
    // Filesystem read grants.
    ReadGrantIssued,
    ReadGrantAuto,
    ReadGrantRevoked,
    ReadGrantRevokeFailed,
    // Learning: auto-learned deny shapes and auto-promoted verbs.
    DenyShapeLearned,
    VerbAutoPromoted,
    ApiVerbCoverageActivated,
    // Denial escalation surfaced to the operator.
    OperatorNotification,
    // API proxy decisions and safety refusals.
    Evaluate,
    ApiRevertFileUnsafe,
    ApiRevertDirUnsafe,
    // Daemon lifecycle and admission telemetry.
    ApiPromotionCorrupt,
    StartupRecovery,
    CommandAdmission,
    ApiJudgeSpend,
    // Client-side usage failures (no daemon sink; stderr projection only).
    CliUsageError,
}

impl AuditKind {
    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Allowed => "ALLOWED",
            Self::Denied => "DENIED",
            Self::ExecFailed => "EXEC_FAILED",
            Self::Held => "HELD",
            Self::HoldOrphaned => "HOLD_ORPHANED",
            Self::Provisional => "PROVISIONAL",
            Self::ProvisionalInterrupted => "PROVISIONAL_INTERRUPTED",
            Self::ProvisionalAutoConfirmed => "PROVISIONAL_AUTO_CONFIRMED",
            Self::ProvisionalCheckFailed => "PROVISIONAL_CHECK_FAILED",
            Self::Confirm => "CONFIRM",
            Self::Revert => "REVERT",
            Self::RevertDeferred => "REVERT_DEFERRED",
            Self::RevertFailed => "REVERT_FAILED",
            Self::Approved => "APPROVED",
            Self::ApprovedExecuted => "APPROVED_EXECUTED",
            Self::ApproveVoided => "APPROVE_VOIDED",
            Self::ApproveExecFailed => "APPROVE_EXEC_FAILED",
            Self::ApprovalExpired => "APPROVAL_EXPIRED",
            Self::ApprovalNote => "APPROVAL_NOTE",
            Self::DeniedHold => "DENIED_HOLD",
            Self::SessionGrant => "SESSION_GRANT",
            Self::SessionRevoke => "SESSION_REVOKE",
            Self::SessionAppeal => "SESSION_APPEAL",
            Self::SessionShowRejected => "SESSION_SHOW_REJECTED",
            Self::AdminRejected => "ADMIN_REJECTED",
            Self::SecretSet => "SECRET_SET",
            Self::SecretDelete => "SECRET_DELETE",
            Self::KubeconfigIssued => "KUBECONFIG_ISSUED",
            Self::VerbCreated => "VERB_CREATED",
            Self::ApiVerbCoverageHit => "API_VERB_COVERAGE_HIT",
            Self::ApiVerbCoverageEscalate => "API_VERB_COVERAGE_ESCALATE",
            Self::ApiVerbCoverageCleared => "API_VERB_COVERAGE_CLEARED",
            Self::SecretExposed => "SECRET_EXPOSED",
            Self::ReadGrantIssued => "READ_GRANT_ISSUED",
            Self::ReadGrantAuto => "READ_GRANT_AUTO",
            Self::ReadGrantRevoked => "READ_GRANT_REVOKED",
            Self::ReadGrantRevokeFailed => "READ_GRANT_REVOKE_FAILED",
            Self::DenyShapeLearned => "DENY_SHAPE_LEARNED",
            Self::VerbAutoPromoted => "VERB_AUTO_PROMOTED",
            Self::ApiVerbCoverageActivated => "API_VERB_COVERAGE_ACTIVATED",
            Self::OperatorNotification => "OPERATOR_NOTIFICATION",
            Self::Evaluate => "EVALUATE",
            Self::ApiRevertFileUnsafe => "API_REVERT_FILE_UNSAFE",
            Self::ApiRevertDirUnsafe => "API_REVERT_DIR_UNSAFE",
            Self::ApiPromotionCorrupt => "API_PROMOTION_CORRUPT",
            Self::StartupRecovery => "STARTUP_RECOVERY",
            Self::CommandAdmission => "COMMAND_ADMISSION",
            Self::ApiJudgeSpend => "API_JUDGE_SPEND",
            Self::CliUsageError => "CLI_USAGE_ERROR",
        }
    }
}

impl std::fmt::Display for AuditKind {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(self.as_str())
    }
}

/// One typed audit event: the single source of truth both projections render
/// from. Common fields are named; kind-specific detail goes into `fields`,
/// which preserves insertion order for the stderr projection.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditEvent {
    pub kind: AuditKind,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub handle: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub caller: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub session_fingerprint: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cwd: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub cmd: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub reason: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decision_source: Option<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub fields: Vec<(String, String)>,
}

impl AuditEvent {
    pub fn new(kind: AuditKind) -> Self {
        Self {
            kind,
            handle: None,
            caller: None,
            session_fingerprint: None,
            cwd: None,
            cmd: None,
            reason: None,
            decision_source: None,
            fields: Vec::new(),
        }
    }

    pub fn handle(mut self, handle: impl Into<String>) -> Self {
        self.handle = Some(handle.into());
        self
    }

    pub fn caller(mut self, caller: impl ToString) -> Self {
        self.caller = Some(caller.to_string());
        self
    }

    pub fn session_fingerprint(mut self, fingerprint: impl Into<String>) -> Self {
        self.session_fingerprint = Some(fingerprint.into());
        self
    }

    pub fn cwd(mut self, cwd: impl Into<String>) -> Self {
        self.cwd = Some(cwd.into());
        self
    }

    pub fn cmd(mut self, cmd: impl Into<String>) -> Self {
        self.cmd = Some(cmd.into());
        self
    }

    pub fn reason(mut self, reason: impl Into<String>) -> Self {
        self.reason = Some(reason.into());
        self
    }

    pub fn decision_source(mut self, source: impl Into<String>) -> Self {
        self.decision_source = Some(source.into());
        self
    }

    /// Append a kind-specific field. Order is preserved in both projections.
    pub fn field(mut self, key: impl Into<String>, value: impl ToString) -> Self {
        self.fields.push((key.into(), value.to_string()));
        self
    }

    /// The stderr projection of this event, without the `[AUDIT] ` prefix.
    /// Free-text values (command, reason, paths, extras) are escaped so one
    /// logical record renders as exactly one physical line; identifier-shaped
    /// fields (handle, fingerprints, decision source) never need it. The
    /// `caller` field renders unquoted (`caller=uid=1000`) to match the
    /// historical format.
    pub fn render_line(&self) -> String {
        let mut line = self.kind.as_str().to_string();
        if let Some(handle) = &self.handle {
            push_field(&mut line, "handle", handle, false);
        }
        if let Some(caller) = &self.caller {
            push_field(&mut line, "caller", caller, false);
        }
        if let Some(fingerprint) = &self.session_fingerprint {
            push_field(&mut line, "session_fingerprint", fingerprint, false);
        }
        if let Some(cwd) = &self.cwd {
            push_field(&mut line, "cwd", cwd, true);
        }
        if let Some(cmd) = &self.cmd {
            push_field(&mut line, "cmd", cmd, true);
        }
        if let Some(reason) = &self.reason {
            push_field(&mut line, "reason", reason, true);
        }
        if let Some(source) = &self.decision_source {
            push_field(&mut line, "decision_source", source, false);
        }
        for (key, value) in &self.fields {
            push_field(&mut line, key, value, value_needs_quoting(value));
        }
        line
    }
}

fn push_field(line: &mut String, key: &str, value: &str, quoted: bool) {
    use std::fmt::Write;
    let escaped = audit_escape(value);
    if quoted {
        let _ = write!(line, " {key}=\"{escaped}\"");
    } else {
        let _ = write!(line, " {key}={escaped}");
    }
}

fn value_needs_quoting(value: &str) -> bool {
    value.is_empty() || value.contains([' ', '"', '='])
}

/// One line of the JSONL audit file: the typed event plus the chain header.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct AuditRecord {
    /// Schema version of this record.
    pub v: u32,
    /// 1-based sequence number; equals the line number while the file is intact.
    pub seq: u64,
    /// Unix seconds when the record was appended.
    pub ts: u64,
    /// Hex SHA-256 of the previous serialized record line ([`genesis_hash`]
    /// for the first record).
    pub prev_hash: String,
    #[serde(flatten)]
    pub event: AuditEvent,
}

struct AuditLogState {
    file: File,
    next_seq: u64,
    prev_hash: String,
}

/// Append-only, hash-chained JSONL sink. One instance per daemon; appends are
/// serialized by an internal lock so seq/prev_hash stay consistent.
pub struct AuditLog {
    path: PathBuf,
    state: Mutex<AuditLogState>,
    fail_appends: std::sync::atomic::AtomicBool,
}

impl AuditLog {
    /// Open (creating if absent) the audit log at `path` and position the
    /// chain to continue from the existing tail. The file is owner-only
    /// (0600 on Unix; the daemon applies its ACL hardening on Windows). If
    /// the existing chain is not intact the log continues from the physical
    /// tail and a warning is emitted; `guard audit verify` reports the break.
    pub fn open(path: impl Into<PathBuf>) -> std::io::Result<Self> {
        let path = path.into();
        let meta = std::fs::symlink_metadata(&path);
        match meta {
            Ok(meta) if meta.file_type().is_symlink() || !meta.is_file() => {
                return Err(std::io::Error::other(format!(
                    "audit log path {} exists and is not a regular file",
                    path.display()
                )));
            }
            _ => {}
        }

        let (next_seq, prev_hash, existing) = recover_chain_position(&path)?;
        if existing > 0 {
            match verify_chain(&path)? {
                verification if verification.intact => {
                    tracing::info!(
                        "audit log {}: continuing intact chain at seq {}",
                        path.display(),
                        next_seq
                    );
                }
                verification => {
                    tracing::warn!(
                        "audit log {}: existing chain is NOT intact (first break at seq {:?}: {}); \
                         continuing from the physical tail so evidence is preserved. \
                         `guard audit verify` will keep reporting the break.",
                        path.display(),
                        verification.broken_at_seq,
                        verification.detail.as_deref().unwrap_or("unknown"),
                    );
                }
            }
        }

        let file = open_append_owner_only(&path)?;
        #[cfg(unix)]
        enforce_owner_only(&path)?;

        Ok(Self {
            path,
            state: Mutex::new(AuditLogState {
                file,
                next_seq,
                prev_hash,
            }),
            fail_appends: std::sync::atomic::AtomicBool::new(false),
        })
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Append one event as the next chained record. Returns the assigned
    /// sequence number. Any error means the record is NOT durable; callers
    /// gating auditable actions must fail closed on `Err`.
    pub fn append(&self, event: &AuditEvent) -> std::io::Result<u64> {
        let mut state = self.state.lock().unwrap_or_else(|e| e.into_inner());
        if self.fail_appends.load(std::sync::atomic::Ordering::Relaxed) {
            return Err(std::io::Error::other("audit append failure injected"));
        }
        let record = AuditRecord {
            v: AUDIT_SCHEMA_VERSION,
            seq: state.next_seq,
            ts: crate::env::now_unix(),
            prev_hash: state.prev_hash.clone(),
            event: event.clone(),
        };
        let line = serde_json::to_string(&record).map_err(std::io::Error::other)?;
        state.file.write_all(line.as_bytes())?;
        state.file.write_all(b"\n")?;
        state.file.flush()?;
        state.prev_hash = hex_digest(line.as_bytes());
        let seq = state.next_seq;
        state.next_seq += 1;
        Ok(seq)
    }

    /// Force every subsequent append to fail, simulating an unwritable sink
    /// (disk full, revoked permission). Test hook only.
    #[doc(hidden)]
    pub fn fail_appends_for_tests(&self, fail: bool) {
        self.fail_appends
            .store(fail, std::sync::atomic::Ordering::Relaxed);
    }
}

fn open_append_owner_only(path: &Path) -> std::io::Result<File> {
    let mut options = OpenOptions::new();
    options.append(true).create(true);
    #[cfg(unix)]
    {
        use std::os::unix::fs::OpenOptionsExt;
        options.mode(0o600).custom_flags(libc::O_NOFOLLOW);
    }
    options.open(path)
}

/// `OpenOptions::mode` applies only at creation; tighten a pre-existing file.
#[cfg(unix)]
fn enforce_owner_only(path: &Path) -> std::io::Result<()> {
    use std::os::unix::fs::PermissionsExt;
    let meta = std::fs::metadata(path)?;
    let mode = meta.permissions().mode();
    if mode & 0o077 != 0 {
        std::fs::set_permissions(path, std::fs::Permissions::from_mode(0o600))?;
    }
    Ok(())
}

/// Where a reopened log continues: `(next_seq, prev_hash, existing_lines)`.
/// The chain always continues over the physical tail bytes, so a record
/// appended after an intact history extends the chain seamlessly and one
/// appended after tampering is still anchored to what is actually on disk.
fn recover_chain_position(path: &Path) -> std::io::Result<(u64, String, u64)> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok((1, genesis_hash(), 0));
        }
        Err(e) => return Err(e),
    };
    let reader = BufReader::new(file);
    let mut last_line: Option<String> = None;
    let mut line_count: u64 = 0;
    for line in reader.lines() {
        let line = line?;
        line_count += 1;
        last_line = Some(line);
    }
    let Some(last_line) = last_line else {
        return Ok((1, genesis_hash(), 0));
    };
    let next_seq = match serde_json::from_str::<AuditRecord>(&last_line) {
        Ok(record) => record.seq + 1,
        Err(_) => line_count + 1,
    };
    Ok((next_seq, hex_digest(last_line.as_bytes()), line_count))
}

/// Result of walking an audit chain.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ChainVerification {
    /// True when every line parses, sequence numbers are contiguous from 1,
    /// and every `prev_hash` matches the previous line.
    pub intact: bool,
    /// Records validated before the first break (all of them when intact).
    pub records: u64,
    /// Sequence position (line number) of the first anomaly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub broken_at_seq: Option<u64>,
    /// Human description of the first anomaly.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub detail: Option<String>,
}

/// Walk the chain at `path` from genesis and report the first break, if any.
/// A missing file verifies as an intact empty chain.
pub fn verify_chain(path: &Path) -> std::io::Result<ChainVerification> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Ok(ChainVerification {
                intact: true,
                records: 0,
                broken_at_seq: None,
                detail: None,
            });
        }
        Err(e) => return Err(e),
    };
    let reader = BufReader::new(file);
    let mut expected_prev = genesis_hash();
    let mut validated: u64 = 0;
    for (expected_seq, line) in (1u64..).zip(reader.lines()) {
        let line = line?;
        let broken = |detail: String| {
            Ok(ChainVerification {
                intact: false,
                records: validated,
                broken_at_seq: Some(expected_seq),
                detail: Some(detail),
            })
        };
        let record: AuditRecord = match serde_json::from_str(&line) {
            Ok(record) => record,
            Err(e) => return broken(format!("record does not parse: {e}")),
        };
        if record.seq != expected_seq {
            return broken(format!(
                "sequence discontinuity: expected {expected_seq}, found {}",
                record.seq
            ));
        }
        if record.prev_hash != expected_prev {
            return broken(format!(
                "hash chain break: prev_hash does not match the preceding record (expected {expected_prev}, found {})",
                record.prev_hash
            ));
        }
        expected_prev = hex_digest(line.as_bytes());
        validated += 1;
    }
    Ok(ChainVerification {
        intact: true,
        records: validated,
        broken_at_seq: None,
        detail: None,
    })
}

/// Read the last `limit` records (in file order). A line that does not parse
/// is surfaced as `{"seq": null, "raw": "<line>"}` rather than hidden, so a
/// tampered tail stays visible in reads too.
pub fn tail_records(path: &Path, limit: usize) -> std::io::Result<Vec<serde_json::Value>> {
    let file = match File::open(path) {
        Ok(file) => file,
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(Vec::new()),
        Err(e) => return Err(e),
    };
    let reader = BufReader::new(file);
    let mut window: std::collections::VecDeque<String> =
        std::collections::VecDeque::with_capacity(limit + 1);
    for line in reader.lines() {
        let line = line?;
        window.push_back(line);
        if window.len() > limit {
            window.pop_front();
        }
    }
    Ok(window
        .into_iter()
        .map(|line| {
            serde_json::from_str::<serde_json::Value>(&line)
                .ok()
                .filter(|value| value.is_object())
                .unwrap_or_else(|| serde_json::json!({ "seq": null, "raw": line }))
        })
        .collect())
}

/// A process-wide observer of every emitted event's kind. The daemon installs
/// one so read-only metrics counters and the audit log share a single source of
/// truth: an event is counted at exactly the point it is audited. The observer
/// receives only the typed [`AuditKind`], never any free-text field, so it
/// cannot carry command text, secret names, or reasons into a metrics surface.
pub trait EventObserver: Send + Sync {
    fn observe(&self, kind: AuditKind);
}

/// Process-global event observer. First install wins (one daemon per process),
/// matching [`install_global_sink`].
static EVENT_OBSERVER: std::sync::OnceLock<std::sync::Arc<dyn EventObserver>> =
    std::sync::OnceLock::new();

/// Install the process-global event observer. First install wins; later calls
/// are ignored. Processes that never install one (the CLI) simply do not count.
pub fn install_event_observer(observer: std::sync::Arc<dyn EventObserver>) {
    let _ = EVENT_OBSERVER.set(observer);
}

/// The single emission path for audit events.
///
/// Always renders the stderr `[AUDIT]` projection; when a durable sink is
/// present, also appends the JSONL record. Returns true when the event is as
/// durable as the deployment allows: appended to the sink, or no sink is
/// configured (stderr/journald capture only, the pre-sink behavior). Returns
/// false only when a configured sink failed to append; callers gating
/// auditable actions must then fail closed.
pub fn emit(sink: Option<&AuditLog>, event: &AuditEvent) -> bool {
    // Count the event at the same choke point that renders and durably records
    // it. This is a single relaxed atomic increment inside the observer; it
    // never blocks and never sees any free-text field.
    if let Some(observer) = EVENT_OBSERVER.get() {
        observer.observe(event.kind);
    }
    tracing::info!(target: "guard::audit", "[AUDIT] {}", event.render_line());
    match sink {
        None => true,
        Some(log) => match log.append(event) {
            Ok(_) => true,
            Err(error) => {
                tracing::error!(
                    "audit sink append failed ({}): {error}; auditable actions fail closed",
                    log.path().display()
                );
                false
            }
        },
    }
}

/// Process-global sink for emitters that have no daemon context handle (the
/// API proxy inside the daemon, admission/spend telemetry). The daemon
/// installs the same `AuditLog` it threads through its own state, so both
/// routes append to one chain. Processes that never install it (the CLI)
/// keep the stderr projection only.
static GLOBAL_SINK: std::sync::OnceLock<std::sync::Arc<AuditLog>> = std::sync::OnceLock::new();

/// Install the process-global sink. First install wins; later calls are
/// ignored (one daemon per process).
pub fn install_global_sink(log: std::sync::Arc<AuditLog>) {
    let _ = GLOBAL_SINK.set(log);
}

/// Emit through the process-global sink (stderr-only when none is installed).
pub fn emit_global(event: &AuditEvent) -> bool {
    emit(GLOBAL_SINK.get().map(|log| log.as_ref()), event)
}

#[cfg(test)]
mod tests {
    use super::*;

    fn event(n: u32) -> AuditEvent {
        AuditEvent::new(AuditKind::Allowed)
            .caller(format!("uid={n}"))
            .session_fingerprint("none")
            .cmd(format!("echo {n}"))
            .reason("test allow")
    }

    #[test]
    fn chain_round_trip_verifies_intact() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let log = AuditLog::open(&path).unwrap();
        for n in 0..10 {
            log.append(&event(n)).unwrap();
        }
        let verification = verify_chain(&path).unwrap();
        assert!(verification.intact, "{verification:?}");
        assert_eq!(verification.records, 10);
        assert_eq!(verification.broken_at_seq, None);
    }

    #[test]
    fn tampered_middle_record_breaks_chain_at_seq() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let log = AuditLog::open(&path).unwrap();
        for n in 0..5 {
            log.append(&event(n)).unwrap();
        }
        let content = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(str::to_string).collect();
        lines[2] = lines[2].replace("echo 2", "echo doctored");
        std::fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();

        let verification = verify_chain(&path).unwrap();
        assert!(!verification.intact);
        // The edited line itself still parses and chains from line 2, so the
        // break surfaces at the NEXT record, whose prev_hash no longer matches
        // the doctored bytes.
        assert_eq!(verification.broken_at_seq, Some(4));
        assert_eq!(verification.records, 3);
    }

    #[test]
    fn deleted_record_breaks_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let log = AuditLog::open(&path).unwrap();
        for n in 0..5 {
            log.append(&event(n)).unwrap();
        }
        let content = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(str::to_string).collect();
        lines.remove(2);
        std::fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();

        let verification = verify_chain(&path).unwrap();
        assert!(!verification.intact);
        assert_eq!(verification.broken_at_seq, Some(3));
    }

    #[test]
    fn truncated_tail_breaks_reordered_chain() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let log = AuditLog::open(&path).unwrap();
        for n in 0..4 {
            log.append(&event(n)).unwrap();
        }
        let content = std::fs::read_to_string(&path).unwrap();
        let mut lines: Vec<String> = content.lines().map(str::to_string).collect();
        lines.swap(1, 2);
        std::fs::write(&path, format!("{}\n", lines.join("\n"))).unwrap();
        let verification = verify_chain(&path).unwrap();
        assert!(!verification.intact);
        assert_eq!(verification.broken_at_seq, Some(2));
    }

    #[test]
    fn reopen_continues_chain_across_restart() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        {
            let log = AuditLog::open(&path).unwrap();
            for n in 0..3 {
                log.append(&event(n)).unwrap();
            }
        }
        {
            let log = AuditLog::open(&path).unwrap();
            for n in 3..6 {
                log.append(&event(n)).unwrap();
            }
        }
        let verification = verify_chain(&path).unwrap();
        assert!(verification.intact, "{verification:?}");
        assert_eq!(verification.records, 6);
    }

    #[test]
    fn injected_append_failure_reports_not_durable() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let log = AuditLog::open(&path).unwrap();
        assert!(emit(Some(&log), &event(0)));
        log.fail_appends_for_tests(true);
        assert!(!emit(Some(&log), &event(1)));
        log.fail_appends_for_tests(false);
        assert!(emit(Some(&log), &event(2)));
        // Only the durable records are on disk and the chain is intact.
        let verification = verify_chain(&path).unwrap();
        assert!(verification.intact);
        assert_eq!(verification.records, 2);
    }

    #[test]
    fn multiline_field_content_is_one_json_record_and_not_a_forged_line() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let log = AuditLog::open(&path).unwrap();
        let forged = "payload\n{\"v\":1,\"seq\":9,\"kind\":\"ALLOWED\"}";
        log.append(&AuditEvent::new(AuditKind::Denied).cmd(forged).reason("x"))
            .unwrap();
        let content = std::fs::read_to_string(&path).unwrap();
        assert_eq!(content.lines().count(), 1, "one record, one line");
        let records = tail_records(&path, 10).unwrap();
        assert_eq!(records.len(), 1);
        assert_eq!(records[0]["cmd"], forged, "raw content is a JSON field");
    }

    #[test]
    fn tail_returns_last_records_and_surfaces_garbage() {
        let dir = tempfile::tempdir().unwrap();
        let path = dir.path().join("audit.jsonl");
        let log = AuditLog::open(&path).unwrap();
        for n in 0..5 {
            log.append(&event(n)).unwrap();
        }
        use std::io::Write;
        let mut file = std::fs::OpenOptions::new()
            .append(true)
            .open(&path)
            .unwrap();
        writeln!(file, "not json").unwrap();
        let records = tail_records(&path, 3).unwrap();
        assert_eq!(records.len(), 3);
        assert_eq!(records[0]["seq"], 4);
        assert_eq!(records[1]["seq"], 5);
        assert_eq!(records[2]["raw"], "not json");
    }

    #[test]
    fn render_line_matches_historical_policy_format() {
        let line = AuditEvent::new(AuditKind::Allowed)
            .caller("uid=1000")
            .session_fingerprint("none")
            .cmd("echo hi")
            .reason("static allow")
            .render_line();
        assert_eq!(
            line,
            "ALLOWED caller=uid=1000 session_fingerprint=none cmd=\"echo hi\" reason=\"static allow\""
        );
    }

    #[test]
    fn render_line_escapes_control_characters() {
        let line = AuditEvent::new(AuditKind::Denied)
            .cmd("x\n[AUDIT] ALLOWED forged")
            .reason("r")
            .render_line();
        assert!(!line.contains('\n'));
        assert!(line.contains("x\\n[AUDIT] ALLOWED forged"));
    }
}
