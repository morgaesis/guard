//! Candidate detection for repeated low-risk LLM approvals.
//!
//! This module tracks commands the LLM evaluator has approved more than once
//! at low risk and, once a pattern crosses `min_approvals`, returns a
//! `LearningOutcome` the caller (`server::learning::learning_notice`) turns into an
//! operator-facing notice.
//!
//! It deliberately does NOT grant a bypass itself. An agent's own repeated
//! behavior is not a trustworthy signal to grant that same agent a
//! permanent, LLM-skipping allow -- that would let an agent promote itself
//! past the evaluator by simply repeating a borderline-but-approved command,
//! via a second glob matcher with the same "can't parse shell quoting"
//! weakness `PolicyEngine` documents for its own deny-only fast path. Every
//! other deterministic-allow mechanism in this codebase (`guard verb`) is
//! operator-authored or operator-invoked; this one is too. The candidate
//! becomes a real, LLM-skipping rule only when the operator runs `guard verb
//! create --prompt` (the notice text gives the exact command), which goes
//! through the same synthesis safety gate as any other verb.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::collections::BTreeMap;
use std::io::Write;
use std::path::{Path, PathBuf};

use crate::env::now_unix;
use crate::redact::{
    command_contains_sensitive_literals, flattened_command_contains_sensitive_literals,
    redact_output_text,
};

#[cfg(unix)]
pub(crate) fn write_learning_file_atomically(path: &Path, content: &str) -> Result<()> {
    write_learning_file_atomically_with_sync(path, content, sync_parent_directory)
}

#[cfg(windows)]
pub(crate) fn write_learning_file_atomically(path: &Path, content: &str) -> Result<()> {
    write_learning_file_atomically_windows(path, content)
}

#[cfg(not(any(unix, windows)))]
pub(crate) fn write_learning_file_atomically(_path: &Path, _content: &str) -> Result<()> {
    anyhow::bail!("atomic learning-file durability is unsupported on this platform")
}

#[cfg(any(unix, test))]
fn write_learning_file_atomically_with_sync<F>(
    path: &Path,
    content: &str,
    sync_parent: F,
) -> Result<()>
where
    F: FnOnce(&Path) -> Result<()>,
{
    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("failed to create {}", parent.display()))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("failed to create temporary file in {}", parent.display()))?;
    if let Ok(metadata) = std::fs::metadata(path) {
        temporary
            .as_file()
            .set_permissions(metadata.permissions())
            .with_context(|| format!("failed to preserve permissions for {}", path.display()))?;
    }
    temporary
        .write_all(content.as_bytes())
        .with_context(|| format!("failed to write temporary file for {}", path.display()))?;
    temporary
        .as_file()
        .sync_all()
        .with_context(|| format!("failed to sync temporary file for {}", path.display()))?;
    let source = temporary
        .into_temp_path()
        .keep()
        .map_err(|error| error.error)
        .with_context(|| format!("failed to finalize temporary file for {}", path.display()))?;
    replace_finalized_learning_file(source, path, |source, destination| {
        std::fs::rename(source, destination)
    })?;
    sync_parent(parent)
        .with_context(|| format!("failed to sync parent directory {}", parent.display()))?;
    Ok(())
}

#[cfg(any(unix, windows, test))]
fn replace_finalized_learning_file<F>(source: PathBuf, destination: &Path, replace: F) -> Result<()>
where
    F: FnOnce(&Path, &Path) -> std::io::Result<()>,
{
    match replace(&source, destination) {
        Ok(()) => Ok(()),
        Err(replace_error) => match std::fs::remove_file(&source) {
            Ok(()) => Err(replace_error)
                .with_context(|| format!("failed to replace {}", destination.display())),
            Err(cleanup_error) if cleanup_error.kind() == std::io::ErrorKind::NotFound => {
                Err(replace_error)
                    .with_context(|| format!("failed to replace {}", destination.display()))
            }
            Err(cleanup_error) => anyhow::bail!(
                "failed to replace {}; temporary file {} remains after cleanup failed: {} (replacement error: {})",
                destination.display(),
                source.display(),
                cleanup_error,
                replace_error
            ),
        },
    }
}

#[cfg(unix)]
fn sync_parent_directory(parent: &Path) -> Result<()> {
    std::fs::File::open(parent)?.sync_all()?;
    Ok(())
}

#[cfg(windows)]
fn write_learning_file_atomically_windows(path: &Path, content: &str) -> Result<()> {
    use std::os::windows::ffi::OsStrExt;
    use windows_sys::Win32::Storage::FileSystem::{
        MoveFileExW, ReplaceFileW, MOVEFILE_WRITE_THROUGH,
    };

    let parent = path.parent().unwrap_or_else(|| Path::new("."));
    std::fs::create_dir_all(parent)
        .with_context(|| format!("failed to create {}", parent.display()))?;
    let mut temporary = tempfile::NamedTempFile::new_in(parent)
        .with_context(|| format!("failed to create temporary file in {}", parent.display()))?;
    temporary
        .write_all(content.as_bytes())
        .with_context(|| format!("failed to write temporary file for {}", path.display()))?;
    temporary
        .as_file()
        .sync_all()
        .with_context(|| format!("failed to sync temporary file for {}", path.display()))?;

    let source = temporary
        .into_temp_path()
        .keep()
        .map_err(|error| error.error)
        .with_context(|| format!("failed to finalize temporary file for {}", path.display()))?;
    let destination_exists = path.exists();
    replace_finalized_learning_file(source, path, |source, destination| {
        let source = source
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let destination = destination
            .as_os_str()
            .encode_wide()
            .chain(std::iter::once(0))
            .collect::<Vec<_>>();
        let replaced = unsafe {
            if destination_exists {
                // ReplaceFileW merges the destination's ACLs, security
                // attributes, streams, encryption, and compression into the
                // replacement. No ignore flags are used, so a metadata merge
                // failure aborts instead of widening access.
                ReplaceFileW(
                    destination.as_ptr(),
                    source.as_ptr(),
                    std::ptr::null(),
                    0,
                    std::ptr::null_mut(),
                    std::ptr::null_mut(),
                )
            } else {
                MoveFileExW(
                    source.as_ptr(),
                    destination.as_ptr(),
                    MOVEFILE_WRITE_THROUGH,
                )
            }
        };
        if replaced == 0 {
            Err(std::io::Error::last_os_error())
        } else {
            Ok(())
        }
    })?;
    // ReplaceFileW's write-through flag is unsupported. Flushing a newly
    // opened destination handle is the strongest standard file-level flush
    // available here; Windows does not expose a portable directory fsync.
    std::fs::OpenOptions::new()
        .write(true)
        .open(path)
        .with_context(|| format!("failed to reopen replaced file {}", path.display()))?
        .sync_all()
        .with_context(|| format!("failed to flush replaced file {}", path.display()))?;
    Ok(())
}

pub(crate) fn sanitize_learning_text(value: &str) -> String {
    redact_output_text(value)
}

#[derive(Debug, Clone)]
pub struct LearningConfig {
    pub path: PathBuf,
    pub min_approvals: u32,
    pub max_risk: i32,
    pub auto_shim: AutoShimMode,
}

impl LearningConfig {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            min_approvals: 2,
            max_risk: 2,
            auto_shim: AutoShimMode::Suggest,
        }
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum AutoShimMode {
    Off,
    Suggest,
    Create,
}

impl AutoShimMode {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "off" | "false" | "0" | "none" => Some(Self::Off),
            "suggest" | "hint" | "true" | "1" => Some(Self::Suggest),
            "create" | "auto" => Some(Self::Create),
            _ => None,
        }
    }

    pub fn as_str(self) -> &'static str {
        match self {
            Self::Off => "off",
            Self::Suggest => "suggest",
            Self::Create => "create",
        }
    }
}

#[derive(Debug, Clone)]
pub struct LearningOutcome {
    pub service: String,
    pub pattern: String,
    pub approvals: u32,
    pub required_approvals: u32,
    /// True once `approvals >= required_approvals`. This means the pattern is
    /// ready for operator review, NOT that it can now skip the LLM -- nothing
    /// in this module grants a bypass. See the module docs.
    pub is_candidate: bool,
    pub shim: Option<LearnedShim>,
    pub skipped_reason: Option<String>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct LearnedRulesFile {
    #[serde(default = "default_version")]
    pub version: u32,
    #[serde(default)]
    pub observations: BTreeMap<String, LearnedObservation>,
    #[serde(default)]
    pub rules: Vec<LearnedRule>,
}

fn default_version() -> u32 {
    1
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearnedObservation {
    pub service: String,
    pub pattern: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub equivalent_patterns: Vec<String>,
    pub approvals: u32,
    pub max_risk_seen: i32,
    pub first_seen_unix: u64,
    pub last_seen_unix: u64,
    pub last_command: String,
    pub last_reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shim: Option<LearnedShim>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LearnedRule {
    pub service: String,
    pub pattern: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub equivalent_patterns: Vec<String>,
    pub approvals: u32,
    pub max_risk_seen: i32,
    pub promoted_at_unix: u64,
    pub updated_at_unix: u64,
    pub last_reason: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub shim: Option<LearnedShim>,
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct LearnedShim {
    pub name: String,
    pub target_binary: String,
    pub target_args: Vec<String>,
    pub description: String,
}

impl LearnedShim {
    pub fn render_command(&self) -> String {
        let mut parts = Vec::with_capacity(self.target_args.len() + 1);
        parts.push(self.target_binary.clone());
        parts.extend(self.target_args.clone());
        parts.join(" ")
    }
}

#[derive(Debug, Clone)]
pub struct LearnedRuleStore {
    config: LearningConfig,
    data: LearnedRulesFile,
}

impl LearnedRuleStore {
    pub fn load(config: LearningConfig) -> Result<Self> {
        let mut data = if config.path.exists() {
            let content = std::fs::read_to_string(&config.path)
                .with_context(|| format!("failed to read {}", config.path.display()))?;
            if content.trim().is_empty() {
                LearnedRulesFile::default()
            } else {
                serde_yaml_ng::from_str(&content)
                    .with_context(|| format!("failed to parse {}", config.path.display()))?
            }
        } else {
            LearnedRulesFile::default()
        };

        let original_observations = data.observations.len();
        let original_rules = data.rules.len();
        data.observations
            .retain(|_, observation| !learned_observation_contains_sensitive_literals(observation));
        data.rules
            .retain(|rule| !learned_rule_contains_sensitive_literals(rule));
        let mut changed =
            original_observations != data.observations.len() || original_rules != data.rules.len();
        changed |= sanitize_learned_rules_prose(&mut data);
        let store = Self { config, data };
        if changed {
            store.save()?;
        }
        Ok(store)
    }

    pub fn path(&self) -> &Path {
        &self.config.path
    }

    pub fn min_approvals(&self) -> u32 {
        self.config.min_approvals
    }

    pub fn max_risk(&self) -> i32 {
        self.config.max_risk
    }

    pub fn auto_shim(&self) -> AutoShimMode {
        self.config.auto_shim
    }

    pub fn rule_count(&self) -> usize {
        self.data.rules.len()
    }

    pub fn record_approval(
        &mut self,
        binary: &str,
        args: &[String],
        command: &str,
        risk: Option<i32>,
        reason: &str,
    ) -> Result<Option<LearningOutcome>> {
        if command_contains_sensitive_literals(binary, args) {
            return Ok(None);
        }
        let risk = risk.unwrap_or(5);
        if risk > self.config.max_risk {
            return Ok(Some(LearningOutcome {
                service: binary.to_string(),
                pattern: command.to_string(),
                approvals: 0,
                required_approvals: self.config.min_approvals,
                is_candidate: false,
                shim: None,
                skipped_reason: Some(format!(
                    "risk {risk} exceeds max learned-rule risk {}",
                    self.config.max_risk
                )),
            }));
        }
        if looks_dangerous_for_learned_allow(command) {
            return Ok(Some(LearningOutcome {
                service: binary.to_string(),
                pattern: command.to_string(),
                approvals: 0,
                required_approvals: self.config.min_approvals,
                is_candidate: false,
                shim: None,
                skipped_reason: Some("command contains shell-control or destructive tokens".into()),
            }));
        }

        let candidate = RuleCandidate::from_command(binary, args, command);
        let reason = sanitize_learning_text(reason);
        let now = now_unix();
        let key = candidate.key();
        let observation = self
            .data
            .observations
            .entry(key)
            .or_insert_with(|| LearnedObservation {
                service: candidate.service.clone(),
                pattern: candidate.pattern.clone(),
                equivalent_patterns: candidate.equivalent_patterns.clone(),
                approvals: 0,
                max_risk_seen: risk,
                first_seen_unix: now,
                last_seen_unix: now,
                last_command: command.to_string(),
                last_reason: reason.clone(),
                shim: candidate.shim.clone(),
            });

        observation.approvals = observation.approvals.saturating_add(1);
        observation.max_risk_seen = observation.max_risk_seen.max(risk);
        observation.last_seen_unix = now;
        observation.last_command = command.to_string();
        observation.last_reason = reason.clone();
        observation.shim = candidate.shim.clone();
        observation.equivalent_patterns = candidate.equivalent_patterns.clone();

        let approvals = observation.approvals;
        let is_candidate = approvals >= self.config.min_approvals;
        if is_candidate {
            if let Some(rule) = self
                .data
                .rules
                .iter_mut()
                .find(|rule| rule.pattern == candidate.pattern)
            {
                rule.approvals = approvals;
                rule.equivalent_patterns = candidate.equivalent_patterns.clone();
                rule.max_risk_seen = observation.max_risk_seen;
                rule.updated_at_unix = now;
                rule.last_reason = reason.clone();
                rule.shim = candidate.shim.clone();
            } else {
                self.data.rules.push(LearnedRule {
                    service: candidate.service.clone(),
                    pattern: candidate.pattern.clone(),
                    equivalent_patterns: candidate.equivalent_patterns.clone(),
                    approvals,
                    max_risk_seen: observation.max_risk_seen,
                    promoted_at_unix: now,
                    updated_at_unix: now,
                    last_reason: reason.clone(),
                    shim: candidate.shim.clone(),
                });
            }
        }

        self.save()?;
        Ok(Some(LearningOutcome {
            service: candidate.service,
            pattern: candidate.pattern,
            approvals,
            required_approvals: self.config.min_approvals,
            is_candidate,
            shim: candidate.shim,
            skipped_reason: None,
        }))
    }

    fn save(&self) -> Result<()> {
        let mut data = self.data.clone();
        sanitize_learned_rules_prose(&mut data);
        let content = serde_yaml_ng::to_string(&data)?;
        write_learning_file_atomically(&self.config.path, &content)
    }
}

fn sanitize_learned_rules_prose(data: &mut LearnedRulesFile) -> bool {
    fn sanitize(value: &mut String) -> bool {
        let sanitized = sanitize_learning_text(value);
        if sanitized == *value {
            return false;
        }
        *value = sanitized;
        true
    }

    let mut changed = false;
    for observation in data.observations.values_mut() {
        changed |= sanitize(&mut observation.last_reason);
        if let Some(shim) = observation.shim.as_mut() {
            changed |= sanitize(&mut shim.description);
        }
    }
    for rule in &mut data.rules {
        changed |= sanitize(&mut rule.last_reason);
        if let Some(shim) = rule.shim.as_mut() {
            changed |= sanitize(&mut shim.description);
        }
    }
    changed
}

fn learned_shim_contains_sensitive_literals(shim: &LearnedShim) -> bool {
    command_contains_sensitive_literals(&shim.target_binary, &shim.target_args)
}

fn learned_observation_contains_sensitive_literals(observation: &LearnedObservation) -> bool {
    flattened_command_contains_sensitive_literals(&observation.pattern)
        || observation
            .equivalent_patterns
            .iter()
            .any(|pattern| flattened_command_contains_sensitive_literals(pattern))
        || flattened_command_contains_sensitive_literals(&observation.last_command)
        || observation
            .shim
            .as_ref()
            .is_some_and(learned_shim_contains_sensitive_literals)
}

fn learned_rule_contains_sensitive_literals(rule: &LearnedRule) -> bool {
    flattened_command_contains_sensitive_literals(&rule.pattern)
        || rule
            .equivalent_patterns
            .iter()
            .any(|pattern| flattened_command_contains_sensitive_literals(pattern))
        || rule
            .shim
            .as_ref()
            .is_some_and(learned_shim_contains_sensitive_literals)
}

#[derive(Debug, Clone)]
struct RuleCandidate {
    service: String,
    pattern: String,
    equivalent_patterns: Vec<String>,
    shim: Option<LearnedShim>,
}

impl RuleCandidate {
    fn from_command(binary: &str, args: &[String], command: &str) -> Self {
        if binary.eq_ignore_ascii_case("ssh") {
            if let Some(ssh) = parse_ssh_command(args) {
                let service = infer_ssh_service(&ssh.host, &ssh.remote_args);
                let pattern = command.to_string();
                let shim = ssh.remote_args.first().and_then(|remote_tool| {
                    let name = infer_shim_name(&service, remote_tool);
                    if name == binary || !is_valid_shim_name(&name) {
                        return None;
                    }
                    let mut target_args = ssh.prefix_args.clone();
                    target_args.push(remote_tool.clone());
                    Some(LearnedShim {
                        name,
                        target_binary: binary.to_string(),
                        target_args,
                        description: sanitize_learning_text(&format!(
                            "learned wrapper for {service} via ssh host {}",
                            ssh.host
                        )),
                    })
                });
                let equivalent_patterns = shim
                    .as_ref()
                    .map(|shim| {
                        let remote_tail = ssh.remote_args.get(1..).unwrap_or_default();
                        let mut parts = Vec::with_capacity(remote_tail.len() + 1);
                        parts.push(shim.name.clone());
                        parts.extend(remote_tail.iter().cloned());
                        vec![parts.join(" ")]
                    })
                    .unwrap_or_default();
                return Self {
                    service,
                    pattern,
                    equivalent_patterns,
                    shim,
                };
            }
        }

        let service = infer_service_from_binary(binary);
        let pattern = command.to_string();
        Self {
            service,
            pattern,
            equivalent_patterns: Vec::new(),
            shim: None,
        }
    }

    fn key(&self) -> String {
        format!("{}|{}", self.service, self.pattern)
    }
}

#[derive(Debug, Clone)]
struct SshCommandParts {
    host: String,
    prefix_args: Vec<String>,
    remote_args: Vec<String>,
}

fn parse_ssh_command(args: &[String]) -> Option<SshCommandParts> {
    let mut idx = 0usize;
    let mut host_idx = None;
    while idx < args.len() {
        let arg = &args[idx];
        if arg == "--" {
            host_idx = idx.checked_add(1);
            break;
        }
        if arg == "-" {
            return None;
        }
        if !arg.starts_with('-') {
            host_idx = Some(idx);
            break;
        }
        if ssh_option_takes_value(arg) && !ssh_option_has_inline_value(arg) {
            idx = idx.saturating_add(2);
        } else {
            idx = idx.saturating_add(1);
        }
    }

    let host_idx = host_idx?;
    let host = args.get(host_idx)?.clone();
    let prefix_args = args[..=host_idx].to_vec();
    let remote_args = args.get(host_idx + 1..).unwrap_or_default().to_vec();
    Some(SshCommandParts {
        host,
        prefix_args,
        remote_args,
    })
}

fn ssh_option_takes_value(arg: &str) -> bool {
    matches!(
        arg,
        "-b" | "-c"
            | "-D"
            | "-E"
            | "-e"
            | "-F"
            | "-I"
            | "-i"
            | "-J"
            | "-L"
            | "-l"
            | "-m"
            | "-O"
            | "-o"
            | "-p"
            | "-Q"
            | "-R"
            | "-S"
            | "-W"
            | "-w"
    ) || arg.starts_with("-o")
        || arg.starts_with("-i")
        || arg.starts_with("-p")
        || arg.starts_with("-l")
        || arg.starts_with("-J")
}

fn ssh_option_has_inline_value(arg: &str) -> bool {
    arg.len() > 2
}

fn infer_ssh_service(host: &str, remote_args: &[String]) -> String {
    let haystack = format!(
        "{} {}",
        host.to_ascii_lowercase(),
        remote_args.join(" ").to_ascii_lowercase()
    );
    if haystack.contains("opnsense") || haystack.contains("configctl") || haystack.contains("/api/")
    {
        return "opnsense-api".to_string();
    }

    let base = host
        .split('@')
        .next_back()
        .unwrap_or(host)
        .split('.')
        .next()
        .unwrap_or(host);
    sanitize_name(base, "service")
}

/// Also used by `gating::deny_shape` so both the allow-candidate and the
/// auto-deny bucketing key commands to the same "service" the same way.
pub(crate) fn infer_service_from_binary(binary: &str) -> String {
    sanitize_name(binary.trim_end_matches(".exe"), "service")
}

fn infer_shim_name(service: &str, remote_tool: &str) -> String {
    if service == "opnsense-api" {
        return "opnsense-api".to_string();
    }
    let tool = sanitize_name(remote_tool.trim_end_matches(".exe"), "tool");
    sanitize_name(&format!("{service}-{tool}"), "service-shim")
}

fn sanitize_name(value: &str, fallback: &str) -> String {
    let mut out = String::new();
    let mut previous_dash = false;
    for ch in value.chars() {
        let next = if ch.is_ascii_alphanumeric() {
            previous_dash = false;
            Some(ch.to_ascii_lowercase())
        } else if ch == '-' || ch == '_' || ch == '.' {
            if previous_dash {
                None
            } else {
                previous_dash = true;
                Some('-')
            }
        } else {
            None
        };
        if let Some(ch) = next {
            out.push(ch);
        }
    }
    let out = out.trim_matches('-').to_string();
    if out.is_empty() {
        fallback.to_string()
    } else {
        out
    }
}

fn is_valid_shim_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|ch| ch.is_ascii_alphanumeric() || ch == '-' || ch == '_')
}

/// Also used by `gating::allow_promotion`: both modules trust a repeated LLM
/// approval only up to the same floor of "obviously not something to ever
/// auto-trust regardless of how many times it was approved."
pub(crate) fn looks_dangerous_for_learned_allow(command: &str) -> bool {
    let lower = command.to_ascii_lowercase();
    let first_token = lower.split_whitespace().next().unwrap_or_default();
    if matches!(first_token, "sudo" | "su" | "reboot" | "shutdown" | "halt") {
        return true;
    }
    let dangerous_substrings = [
        " rm -rf /",
        "rm -rf /",
        "mkfs.",
        " dd if=",
        "dd if=",
        " shutdown",
        " reboot",
        " halt",
        " sudo ",
        " su ",
        "/etc/shadow",
        "/etc/sudoers",
    ];
    if lower.contains('|')
        || lower.contains('>')
        || lower.contains('<')
        || lower.contains(';')
        || lower.contains(">>")
        || lower.contains("&&")
        || lower.contains("||")
        || lower.contains(" $(")
        || lower.contains("$(")
        || lower.contains('`')
    {
        return true;
    }
    dangerous_substrings
        .iter()
        .any(|needle| lower.contains(needle))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn atomic_writer_propagates_parent_sync_failure_after_replace() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("learned.yaml");
        std::fs::write(&path, "old").unwrap();
        let error = write_learning_file_atomically_with_sync(&path, "new", |_| {
            anyhow::bail!("simulated directory sync failure")
        })
        .unwrap_err();
        assert!(error
            .to_string()
            .contains("failed to sync parent directory"));
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
    }

    #[test]
    fn failed_finalized_move_removes_the_temporary_file_and_preserves_destination() {
        let temp = tempfile::tempdir().unwrap();
        let source = temp.path().join("finalized.tmp");
        let destination = temp.path().join("learned.yaml");
        std::fs::write(&source, "new").unwrap();
        std::fs::write(&destination, "old").unwrap();
        let error = replace_finalized_learning_file(source.clone(), &destination, |_, _| {
            Err(std::io::Error::other("simulated replacement failure"))
        })
        .unwrap_err();
        assert!(error.to_string().contains("failed to replace"));
        assert!(!source.exists());
        assert_eq!(std::fs::read_to_string(destination).unwrap(), "old");
    }

    #[cfg(windows)]
    #[test]
    fn windows_atomic_writer_preserves_restricted_security_and_attributes() {
        use std::os::windows::ffi::OsStrExt;
        use windows_sys::Win32::Foundation::LocalFree;
        use windows_sys::Win32::Security::Authorization::{
            ConvertStringSecurityDescriptorToSecurityDescriptorW, SDDL_REVISION_1,
        };
        use windows_sys::Win32::Security::{
            GetFileSecurityW, SetFileSecurityW, DACL_SECURITY_INFORMATION,
            GROUP_SECURITY_INFORMATION, OWNER_SECURITY_INFORMATION,
            PROTECTED_DACL_SECURITY_INFORMATION,
        };
        use windows_sys::Win32::Storage::FileSystem::{
            GetFileAttributesW, SetFileAttributesW, FILE_ATTRIBUTE_HIDDEN, FILE_ATTRIBUTE_NORMAL,
        };

        fn wide(value: &std::ffi::OsStr) -> Vec<u16> {
            value.encode_wide().chain(std::iter::once(0)).collect()
        }
        fn security(path: &Path) -> Vec<u8> {
            let path = wide(path.as_os_str());
            let information =
                OWNER_SECURITY_INFORMATION | GROUP_SECURITY_INFORMATION | DACL_SECURITY_INFORMATION;
            let mut needed = 0;
            unsafe {
                GetFileSecurityW(
                    path.as_ptr(),
                    information,
                    std::ptr::null_mut(),
                    0,
                    &mut needed,
                );
            }
            let mut descriptor = vec![0u8; needed as usize];
            let loaded = unsafe {
                GetFileSecurityW(
                    path.as_ptr(),
                    information,
                    descriptor.as_mut_ptr().cast(),
                    needed,
                    &mut needed,
                )
            };
            assert_ne!(loaded, 0);
            descriptor
        }

        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("learned.yaml");
        std::fs::write(&path, "old").unwrap();
        let path_wide = wide(path.as_os_str());
        let sddl = wide(std::ffi::OsStr::new("D:P(A;;FA;;;OW)"));
        let mut descriptor = std::ptr::null_mut();
        let converted = unsafe {
            ConvertStringSecurityDescriptorToSecurityDescriptorW(
                sddl.as_ptr(),
                SDDL_REVISION_1,
                &mut descriptor,
                std::ptr::null_mut(),
            )
        };
        assert_ne!(converted, 0);
        let secured = unsafe {
            SetFileSecurityW(
                path_wide.as_ptr(),
                DACL_SECURITY_INFORMATION | PROTECTED_DACL_SECURITY_INFORMATION,
                descriptor,
            )
        };
        unsafe {
            LocalFree(descriptor);
        }
        assert_ne!(secured, 0);
        assert_ne!(
            unsafe { SetFileAttributesW(path_wide.as_ptr(), FILE_ATTRIBUTE_HIDDEN) },
            0
        );
        let before_security = security(&path);
        let before_attributes = unsafe { GetFileAttributesW(path_wide.as_ptr()) };

        write_learning_file_atomically(&path, "new").unwrap();
        assert_eq!(std::fs::read_to_string(&path).unwrap(), "new");
        assert_eq!(security(&path), before_security);
        assert_eq!(
            unsafe { GetFileAttributesW(path_wide.as_ptr()) },
            before_attributes
        );
        assert_ne!(
            unsafe { SetFileAttributesW(path_wide.as_ptr(), FILE_ATTRIBUTE_NORMAL) },
            0
        );
    }

    #[test]
    fn ssh_parser_keeps_prefix_through_host() {
        let args = vec![
            "-i".to_string(),
            "key.pem".to_string(),
            "-o".to_string(),
            "StrictHostKeyChecking=no".to_string(),
            "fw.example".to_string(),
            "configctl".to_string(),
            "system".to_string(),
            "status".to_string(),
        ];
        let parsed = parse_ssh_command(&args).expect("ssh parts");
        assert_eq!(parsed.host, "fw.example");
        assert_eq!(parsed.remote_args[0], "configctl");
        assert_eq!(
            parsed.prefix_args,
            vec![
                "-i".to_string(),
                "key.pem".to_string(),
                "-o".to_string(),
                "StrictHostKeyChecking=no".to_string(),
                "fw.example".to_string()
            ]
        );
    }

    #[test]
    fn opnsense_ssh_candidate_promotes_service_shim() {
        let args = vec![
            "firewall".to_string(),
            "configctl".to_string(),
            "system".to_string(),
            "status".to_string(),
        ];
        let candidate =
            RuleCandidate::from_command("ssh", &args, "ssh firewall configctl system status");
        assert_eq!(candidate.service, "opnsense-api");
        assert_eq!(candidate.pattern, "ssh firewall configctl system status");
        assert_eq!(
            candidate.equivalent_patterns,
            vec!["opnsense-api system status".to_string()]
        );
        assert_eq!(
            candidate.shim.as_ref().map(|shim| shim.name.as_str()),
            Some("opnsense-api")
        );
    }

    #[test]
    fn repeated_low_risk_approval_becomes_a_candidate_not_a_bypass() {
        let temp = tempfile::tempdir().unwrap();
        let config = LearningConfig {
            path: temp.path().join("learned.yaml"),
            min_approvals: 2,
            max_risk: 2,
            auto_shim: AutoShimMode::Suggest,
        };
        let mut store = LearnedRuleStore::load(config).unwrap();
        let args = vec!["status".to_string()];
        let first = store
            .record_approval("opnsense-api", &args, "opnsense-api status", Some(1), "ok")
            .unwrap()
            .unwrap();
        assert!(!first.is_candidate);
        assert_eq!(store.rule_count(), 0);

        let second = store
            .record_approval("opnsense-api", &args, "opnsense-api status", Some(1), "ok")
            .unwrap()
            .unwrap();
        assert!(second.is_candidate);
        // Crossing the threshold persists a reviewable candidate record, but
        // grants nothing: this module has no lookup that can return an allow.
        assert_eq!(store.rule_count(), 1);
    }

    #[test]
    fn sensitive_learning_records_are_rejected_and_purged_idempotently() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("learned.yaml");
        let config = LearningConfig {
            path: path.clone(),
            min_approvals: 1,
            max_risk: 2,
            auto_shim: AutoShimMode::Suggest,
        };
        let mut store = LearnedRuleStore::load(config.clone()).unwrap();
        let safe_args = vec!["status".to_string()];
        store
            .record_approval("fixturectl", &safe_args, "fixturectl status", Some(1), "ok")
            .unwrap();
        let safe_bytes = std::fs::read(&path).unwrap();
        let value = ["q", "7"].concat();
        assert!(store
            .record_approval(
                "curl",
                &["-u".to_string(), value.clone()],
                &format!("curl -u {value}"),
                Some(1),
                "ignored"
            )
            .unwrap()
            .is_none());
        assert_eq!(std::fs::read(&path).unwrap(), safe_bytes);

        let mut contaminated = store.data.clone();
        let mut observation = contaminated.observations.values().next().unwrap().clone();
        observation.pattern = format!("curl -u {value}");
        observation.last_command = observation.pattern.clone();
        contaminated
            .observations
            .insert("sensitive".to_string(), observation);
        let mut rule = contaminated.rules[0].clone();
        rule.pattern = format!("curl --user={value}");
        contaminated.rules.push(rule);
        write_learning_file_atomically(&path, &serde_yaml_ng::to_string(&contaminated).unwrap())
            .unwrap();

        let loaded = LearnedRuleStore::load(config.clone()).unwrap();
        assert_eq!(loaded.data.observations.len(), 1);
        assert_eq!(loaded.data.rules.len(), 1);
        let sanitized = std::fs::read(&path).unwrap();
        assert!(!sanitized
            .windows(value.len())
            .any(|window| window == value.as_bytes()));
        LearnedRuleStore::load(config).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), sanitized);
    }

    #[test]
    fn learned_rule_prose_is_sanitized_without_changing_safe_authority() {
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("learned.yaml");
        let config = LearningConfig {
            path: path.clone(),
            min_approvals: 1,
            max_risk: 2,
            auto_shim: AutoShimMode::Suggest,
        };
        let value = ["q", "7"].concat();
        let reason = format!("password={value}");
        let mut store = LearnedRuleStore::load(config.clone()).unwrap();
        store
            .record_approval(
                "fixturectl",
                &["status".to_string()],
                "fixturectl status",
                Some(1),
                &reason,
            )
            .unwrap();
        let expected_pattern = store.data.rules[0].pattern.clone();
        assert!(!std::fs::read(&path)
            .unwrap()
            .windows(value.len())
            .any(|window| window == value.as_bytes()));

        let mut contaminated = store.data.clone();
        contaminated
            .observations
            .values_mut()
            .for_each(|observation| observation.last_reason = reason.clone());
        contaminated.rules[0].last_reason = reason.clone();
        contaminated.rules[0].shim = Some(LearnedShim {
            name: "fixture-wrapper".to_string(),
            target_binary: "fixturectl".to_string(),
            target_args: vec!["status".to_string()],
            description: reason,
        });
        write_learning_file_atomically(&path, &serde_yaml_ng::to_string(&contaminated).unwrap())
            .unwrap();

        let loaded = LearnedRuleStore::load(config.clone()).unwrap();
        assert_eq!(loaded.data.rules.len(), 1);
        assert_eq!(loaded.data.rules[0].pattern, expected_pattern);
        let sanitized = std::fs::read(&path).unwrap();
        assert!(!sanitized
            .windows(value.len())
            .any(|window| window == value.as_bytes()));
        LearnedRuleStore::load(config).unwrap();
        assert_eq!(std::fs::read(&path).unwrap(), sanitized);
    }

    #[test]
    fn high_risk_approval_is_not_learned() {
        let temp = tempfile::tempdir().unwrap();
        let config = LearningConfig {
            path: temp.path().join("learned.yaml"),
            min_approvals: 1,
            max_risk: 2,
            auto_shim: AutoShimMode::Suggest,
        };
        let mut store = LearnedRuleStore::load(config).unwrap();
        let result = store
            .record_approval(
                "rm",
                &["-rf".into(), "/".into()],
                "rm -rf /",
                Some(9),
                "bad",
            )
            .unwrap()
            .unwrap();
        assert!(result.skipped_reason.is_some());
        assert_eq!(store.rule_count(), 0);
    }

    #[test]
    fn shell_control_without_spaces_is_not_learned() {
        let temp = tempfile::tempdir().unwrap();
        let config = LearningConfig {
            path: temp.path().join("learned.yaml"),
            min_approvals: 1,
            max_risk: 2,
            auto_shim: AutoShimMode::Suggest,
        };
        let mut store = LearnedRuleStore::load(config).unwrap();
        let result = store
            .record_approval(
                "ssh",
                &[
                    "firewall".into(),
                    "configctl".into(),
                    "status;reboot".into(),
                ],
                "ssh firewall configctl status;reboot",
                Some(1),
                "ok",
            )
            .unwrap()
            .unwrap();
        assert!(result.skipped_reason.is_some());
        assert_eq!(store.rule_count(), 0);
    }

    #[test]
    fn leading_privileged_command_is_not_learned() {
        assert!(looks_dangerous_for_learned_allow("sudo configctl status"));
        assert!(looks_dangerous_for_learned_allow("reboot"));
        assert!(looks_dangerous_for_learned_allow("shutdown /s"));
        assert!(looks_dangerous_for_learned_allow("halt"));
        assert!(looks_dangerous_for_learned_allow("su root"));
    }
}
