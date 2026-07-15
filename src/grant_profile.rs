//! Saved grant definitions and compatibility migration for legacy profiles.
//!
//! A saved grant is the reusable authorization object. It selects typed verbs,
//! carries secret-name entitlements and evaluator context, declares a default
//! lifetime and evaluation mode, and records generated coverage with evidence.
//! Issuing a saved grant creates a bounded live session grant.

use anyhow::{bail, Context, Result};
use guard::env::now_unix;
use guard::gating::verb::{
    CoverageAction, CoverageProbe, CoverageProvenance, ValueConstraint, Verb, VerbCoverageCell,
};
use guard::gating::Reversibility;
use serde::{Deserialize, Serialize};
use sha2::{Digest, Sha256};
use std::collections::BTreeMap;
use std::fmt;
use std::path::Path;
use std::str::FromStr;

#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, PartialOrd, Ord, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum EvaluationMode {
    #[default]
    Evaluator,
    PolicyOnly,
    ReadOnly,
}

impl fmt::Display for EvaluationMode {
    fn fmt(&self, formatter: &mut fmt::Formatter<'_>) -> fmt::Result {
        formatter.write_str(match self {
            Self::Evaluator => "evaluator",
            Self::PolicyOnly => "policy_only",
            Self::ReadOnly => "read_only",
        })
    }
}

impl FromStr for EvaluationMode {
    type Err = anyhow::Error;

    fn from_str(value: &str) -> Result<Self> {
        match value.replace('-', "_").as_str() {
            "evaluator" | "llm" => Ok(Self::Evaluator),
            "policy_only" | "no_llm" | "static_only" => Ok(Self::PolicyOnly),
            "read_only" | "readonly" => Ok(Self::ReadOnly),
            _ => bail!(
                "unknown evaluation mode '{}': expected evaluator, policy-only, or read-only",
                value
            ),
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct GrantCeiling {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub verbs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secret_names: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub max_ttl_secs: Option<u64>,
    #[serde(default)]
    pub allow_prompt_append: bool,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub evaluation_modes: Vec<EvaluationMode>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SavedGrant {
    pub name: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub label: Option<String>,
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub description: String,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub activated_verbs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub override_markers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secret_names: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_append: Option<String>,
    #[serde(default)]
    pub evaluation_mode: EvaluationMode,
    #[serde(default)]
    pub auto_approve_requests: bool,
    #[serde(default)]
    pub ceiling: GrantCeiling,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub generated_verbs: Vec<Verb>,
    #[serde(default)]
    pub revision: u64,
    #[serde(default)]
    pub created_unix: u64,
    #[serde(default)]
    pub updated_unix: u64,
}

impl SavedGrant {
    pub fn normalize(mut self) -> Result<Self> {
        validate_name(&self.name)?;
        normalize_strings(&mut self.activated_verbs);
        normalize_strings(&mut self.override_markers);
        normalize_strings(&mut self.secret_names);
        normalize_strings(&mut self.ceiling.verbs);
        normalize_strings(&mut self.ceiling.secret_names);
        self.ceiling.evaluation_modes.sort();
        self.ceiling.evaluation_modes.dedup();
        if self.revision == 0 {
            self.revision = 1;
        }
        let now = now_unix();
        if self.created_unix == 0 {
            self.created_unix = now;
        }
        self.updated_unix = now;
        if self.ceiling.verbs.is_empty() {
            self.ceiling.verbs = self.activated_verbs.clone();
        }
        if self.ceiling.secret_names.is_empty() {
            self.ceiling.secret_names = self.secret_names.clone();
        }
        if self.ceiling.max_ttl_secs.is_none() {
            self.ceiling.max_ttl_secs = self.ttl_secs;
        }
        if self.ceiling.evaluation_modes.is_empty() {
            self.ceiling.evaluation_modes.push(self.evaluation_mode);
        }
        validate_saved_grant(&self)?;
        Ok(self)
    }

    pub fn generated_verb_names(&self) -> Vec<String> {
        self.generated_verbs
            .iter()
            .map(|verb| verb.name.clone())
            .collect()
    }

    pub fn all_activated_verbs(&self) -> Vec<String> {
        let mut names = self.activated_verbs.clone();
        names.extend(self.generated_verb_names());
        normalize_strings(&mut names);
        names
    }

    pub fn contains_delta(&self, delta: &GrantRequestDelta) -> bool {
        delta.override_markers.is_empty()
            && delta
                .activated_verbs
                .iter()
                .all(|name| self.ceiling.verbs.contains(name))
            && delta.secret_names.iter().all(|name| {
                self.ceiling
                    .secret_names
                    .iter()
                    .any(|selector| selector_matches(selector, name))
            })
            && delta.ttl_secs.is_none_or(|ttl| {
                self.ceiling
                    .max_ttl_secs
                    .is_some_and(|maximum| ttl <= maximum)
            })
            && delta
                .prompt_append
                .as_ref()
                .is_none_or(|_| self.ceiling.allow_prompt_append)
            && delta
                .evaluation_mode
                .is_none_or(|mode| self.ceiling.evaluation_modes.contains(&mode))
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize, Default)]
pub struct GrantRequestDelta {
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub activated_verbs: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub override_markers: Vec<String>,
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub secret_names: Vec<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub ttl_secs: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub prompt_append: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub evaluation_mode: Option<EvaluationMode>,
}

impl GrantRequestDelta {
    pub fn is_empty(&self) -> bool {
        self.activated_verbs.is_empty()
            && self.override_markers.is_empty()
            && self.secret_names.is_empty()
            && self.ttl_secs.is_none()
            && self.prompt_append.is_none()
            && self.evaluation_mode.is_none()
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "snake_case")]
pub enum GrantRequestStatus {
    Pending,
    Approved,
    Denied,
    Withdrawn,
}

impl GrantRequestStatus {
    pub fn as_str(self) -> &'static str {
        match self {
            Self::Pending => "pending",
            Self::Approved => "approved",
            Self::Denied => "denied",
            Self::Withdrawn => "withdrawn",
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct GrantRequest {
    pub handle: String,
    pub session_token: String,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub saved_grant: Option<String>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_saved_revision: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub issued_session_revision: Option<String>,
    pub delta: GrantRequestDelta,
    pub justification: String,
    pub status: GrantRequestStatus,
    pub created_unix: u64,
    /// Requests are capabilities with a bounded review window. A decision made
    /// after this instant is rejected and must be resubmitted.
    #[serde(default)]
    pub expires_unix: u64,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_unix: Option<u64>,
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub decided_reason: Option<String>,
    pub next_action: String,
}

impl GrantRequest {
    pub fn new(
        session_token: String,
        saved_grant: Option<String>,
        mut delta: GrantRequestDelta,
        justification: String,
    ) -> Result<Self> {
        normalize_strings(&mut delta.activated_verbs);
        normalize_strings(&mut delta.override_markers);
        normalize_strings(&mut delta.secret_names);
        if session_token.trim().is_empty() {
            bail!("grant request requires a session token");
        }
        if justification.trim().is_empty() {
            bail!("grant request requires a justification");
        }
        if delta.is_empty() {
            bail!("grant request has no requested change");
        }
        let handle = format!("gr-{:032x}", rand::random::<u128>());
        let created_unix = now_unix();
        Ok(Self {
            next_action: format!("guard grant request show {handle}"),
            handle,
            session_token,
            saved_grant,
            issued_saved_revision: None,
            issued_session_revision: None,
            delta,
            justification,
            status: GrantRequestStatus::Pending,
            created_unix,
            expires_unix: created_unix.saturating_add(86_400),
            decided_unix: None,
            decided_reason: None,
        })
    }
}

#[derive(Debug, Clone, Default)]
pub struct SavedGrantCatalog {
    grants: BTreeMap<String, SavedGrant>,
}

impl SavedGrantCatalog {
    pub fn empty() -> Self {
        Self::default()
    }

    /// Overlay already-normalized durable rows onto file-backed definitions.
    /// Durable edits win by name without incrementing their revision at load.
    pub fn overlay_rows(&mut self, rows: Vec<SavedGrant>) -> Result<()> {
        for grant in rows {
            validate_name(&grant.name)?;
            validate_saved_grant(&grant)?;
            self.grants.insert(grant.name.clone(), grant);
        }
        Ok(())
    }

    /// Apply durable deletions after file definitions and stored edits load.
    /// Saving the same name again removes its tombstone in the store.
    pub fn apply_tombstones(&mut self, names: &[String]) {
        for name in names {
            self.grants.remove(name);
        }
    }

    pub fn names(&self) -> Vec<String> {
        self.grants.keys().cloned().collect()
    }

    pub fn list(&self) -> Vec<SavedGrant> {
        self.grants.values().cloned().collect()
    }

    pub fn get(&self, name: &str) -> Option<&SavedGrant> {
        self.grants.get(name)
    }

    pub fn insert(&mut self, grant: SavedGrant) -> Result<SavedGrant> {
        let grant = grant.normalize()?;
        if self.grants.contains_key(&grant.name) {
            bail!(
                "saved grant '{}' already exists; use `guard grant edit`",
                grant.name
            );
        }
        self.grants.insert(grant.name.clone(), grant.clone());
        Ok(grant)
    }

    pub fn replace(&mut self, grant: SavedGrant) -> Result<SavedGrant> {
        let previous = self
            .grants
            .get(&grant.name)
            .ok_or_else(|| anyhow::anyhow!("unknown saved grant: '{}'", grant.name))?;
        let mut grant = grant;
        grant.created_unix = previous.created_unix;
        grant.revision = previous.revision.saturating_add(1);
        let grant = grant.normalize()?;
        self.grants.insert(grant.name.clone(), grant.clone());
        Ok(grant)
    }

    pub fn remove(&mut self, name: &str) -> Option<SavedGrant> {
        self.grants.remove(name)
    }

    /// Parse saved grants and migrate the legacy top-level `profiles` key.
    /// Legacy globs migrate only when they are exact argv prefixes. Ambiguous
    /// shell-style patterns fail with an actionable migration error.
    pub fn from_yaml(text: &str) -> Result<Self> {
        let file: GrantFile =
            serde_yaml_ng::from_str(text).context("failed to parse saved grant catalog")?;
        let mut catalog = Self::empty();
        for grant in file.grants {
            catalog.insert(grant)?;
        }
        for profile in file.profiles {
            let grant = migrate_profile(profile)?;
            if catalog.grants.contains_key(&grant.name) {
                bail!("duplicate saved grant name: '{}'", grant.name);
            }
            catalog.grants.insert(grant.name.clone(), grant);
        }
        Ok(catalog)
    }

    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path)
            .with_context(|| format!("failed to read saved grant catalog {}", path.display()))?;
        Self::from_yaml(&text)
    }
}

#[derive(Debug, Deserialize)]
struct GrantFile {
    #[serde(default)]
    grants: Vec<SavedGrant>,
    #[serde(default)]
    profiles: Vec<LegacyProfile>,
}

#[derive(Debug, Deserialize)]
struct LegacyProfile {
    name: String,
    #[serde(default)]
    description: String,
    #[serde(default)]
    allow: Vec<String>,
    #[serde(default)]
    deny: Vec<String>,
    #[serde(default)]
    activated_verbs: Vec<String>,
    #[serde(default)]
    override_markers: Vec<String>,
    #[serde(default)]
    ttl_secs: Option<u64>,
    #[serde(default)]
    prompt_append: Option<String>,
}

fn migrate_profile(profile: LegacyProfile) -> Result<SavedGrant> {
    validate_name(&profile.name)?;
    let mut generated_verbs = Vec::new();
    for (index, pattern) in profile.allow.iter().enumerate() {
        generated_verbs.push(migrate_legacy_pattern(
            &profile.name,
            index,
            pattern,
            CoverageAction::Preauthorized,
        )?);
    }
    let offset = generated_verbs.len();
    for (index, pattern) in profile.deny.iter().enumerate() {
        generated_verbs.push(migrate_legacy_pattern(
            &profile.name,
            offset + index,
            pattern,
            CoverageAction::Deny,
        )?);
    }
    SavedGrant {
        name: profile.name,
        label: None,
        description: profile.description,
        activated_verbs: profile.activated_verbs,
        override_markers: profile.override_markers,
        secret_names: Vec::new(),
        ttl_secs: profile.ttl_secs,
        prompt_append: profile.prompt_append,
        evaluation_mode: EvaluationMode::Evaluator,
        auto_approve_requests: false,
        ceiling: GrantCeiling::default(),
        generated_verbs,
        revision: 1,
        created_unix: now_unix(),
        updated_unix: now_unix(),
    }
    .normalize()
}

fn migrate_legacy_pattern(
    grant: &str,
    index: usize,
    pattern: &str,
    action: CoverageAction,
) -> Result<Verb> {
    if pattern.contains(['?', '[', ']', '\'', '"', '\\', '$', '`', ';', '|', '&'])
        || pattern.matches('*').count() > 1
        || pattern.contains('*') && !pattern.ends_with(" *")
    {
        bail!(
            "legacy grant pattern {:?} cannot migrate safely: use a typed verb coverage cell or an exact trailing ' *' argv suffix",
            pattern
        );
    }
    let prefix = pattern.strip_suffix(" *").unwrap_or(pattern).trim();
    let trailing_wildcard = pattern.ends_with(" *");
    let tokens = prefix.split_whitespace().collect::<Vec<_>>();
    if tokens.is_empty() {
        bail!("legacy grant pattern {:?} has no binary", pattern);
    }
    let binary = tokens[0].to_string();
    let options = tokens
        .iter()
        .skip(1)
        .enumerate()
        .map(|(position, value)| ValueConstraint {
            options: Vec::new(),
            position: Some(position),
            values: vec![(*value).to_string()],
            allow_dash: value.starts_with('-'),
            required: true,
            allow_multiple: false,
        })
        .collect::<Vec<_>>();
    let evidence_args = tokens
        .iter()
        .skip(1)
        .map(|token| (*token).to_string())
        .collect::<Vec<_>>();
    let mut boundary_args = evidence_args.clone();
    boundary_args.push("__outside_legacy_prefix__".to_string());
    let digest = Sha256::digest(pattern.as_bytes());
    let suffix = digest[..4]
        .iter()
        .map(|byte| format!("{byte:02x}"))
        .collect::<String>();
    let verb_name = format!("grant-{grant}-legacy-{index}-{suffix}");
    let cell = VerbCoverageCell {
        name: if action == CoverageAction::Deny {
            "explicit-deny".to_string()
        } else {
            "explicit-allow".to_string()
        },
        action,
        required_args: Vec::new(),
        forbidden_args: Vec::new(),
        min_args: Some(evidence_args.len()),
        max_args: (!trailing_wildcard).then_some(evidence_args.len()),
        options,
        target: None,
        inventory: None,
        namespace: None,
        fanout: None,
        environment: Vec::new(),
        override_marker: None,
        sticky: true,
        provenance: Some(CoverageProvenance {
            source: "legacy_profile_migration".to_string(),
            evidence: vec![pattern.to_string()],
            regime_stamp: "legacy-profile-v1".to_string(),
            prompt_stamp: "not-applicable".to_string(),
            model_stamp: "not-applicable".to_string(),
            generated_unix: now_unix(),
            probes: vec![
                CoverageProbe {
                    dimension: "evidence".to_string(),
                    args: evidence_args,
                    expected_match: true,
                    observed_match: true,
                },
                CoverageProbe {
                    dimension: "boundary".to_string(),
                    args: boundary_args,
                    expected_match: trailing_wildcard,
                    observed_match: trailing_wildcard,
                },
            ],
        }),
    };
    Ok(Verb {
        name: verb_name,
        description: format!("Migrated saved-grant coverage for {pattern}"),
        binary,
        args: Vec::new(),
        baseline: false,
        coverage: vec![cell],
        credential_plan: None,
        params: BTreeMap::new(),
        consequence: Reversibility::Irreversible,
        revert: None,
        trusted: action == CoverageAction::Preauthorized,
        prompt_context: None,
        source_prose: None,
        evidence: Some(pattern.to_string()),
        auto_promoted: false,
        promotion_stamp: None,
    })
}

fn validate_saved_grant(grant: &SavedGrant) -> Result<()> {
    if grant.activated_verbs.is_empty()
        && grant.generated_verbs.is_empty()
        && grant.secret_names.is_empty()
        && grant.prompt_append.is_none()
    {
        bail!(
            "saved grant '{}' grants nothing: select a verb, entitlement, or evaluator prompt",
            grant.name
        );
    }
    if grant
        .secret_names
        .iter()
        .any(|selector| selector.trim().is_empty() || selector.contains(char::is_whitespace))
    {
        bail!(
            "saved grant '{}' has an invalid secret-name selector",
            grant.name
        );
    }
    for verb in &grant.generated_verbs {
        let expected = format!("grant-{}-", grant.name);
        if !verb.name.starts_with(&expected) {
            bail!(
                "generated verb '{}' must begin with '{}'",
                verb.name,
                expected
            );
        }
        for cell in &verb.coverage {
            let provenance = cell.provenance.as_ref().ok_or_else(|| {
                anyhow::anyhow!(
                    "generated verb '{}' coverage '{}' is missing provenance",
                    verb.name,
                    cell.name
                )
            })?;
            if provenance.probes.is_empty()
                || provenance
                    .probes
                    .iter()
                    .any(|probe| probe.expected_match != probe.observed_match)
            {
                bail!(
                    "generated verb '{}' coverage '{}' has incomplete or failing probes",
                    verb.name,
                    cell.name
                );
            }
        }
    }
    Ok(())
}

fn validate_name(name: &str) -> Result<()> {
    let valid = !name.is_empty()
        && name.bytes().enumerate().all(|(index, byte)| {
            byte.is_ascii_lowercase() || byte.is_ascii_digit() || (index > 0 && byte == b'-')
        });
    if !valid {
        bail!("saved grant name '{}' must be lowercase kebab-case", name);
    }
    Ok(())
}

fn normalize_strings(values: &mut Vec<String>) {
    values.retain(|value| !value.trim().is_empty());
    values.sort();
    values.dedup();
}

fn selector_matches(selector: &str, value: &str) -> bool {
    if let Some(prefix) = selector.strip_suffix('*') {
        value.starts_with(prefix)
    } else {
        selector == value
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_saved_grant_catalog() {
        let catalog = SavedGrantCatalog::from_yaml(
            "grants:\n  - name: deploy-host-a\n    activated_verbs: [session-apply]\n    secret_names: [ANSIBLE_*]\n    ttl_secs: 3600\n    evaluation_mode: evaluator\n",
        )
        .expect("valid catalog");
        let grant = catalog.get("deploy-host-a").expect("saved grant");
        assert_eq!(grant.activated_verbs, vec!["session-apply"]);
        assert_eq!(grant.secret_names, vec!["ANSIBLE_*"]);
        assert_eq!(grant.revision, 1);
    }

    #[test]
    fn reference_saved_grant_catalog_is_valid() {
        let catalog = SavedGrantCatalog::from_yaml(include_str!("../examples/saved-grants.yaml"))
            .expect("reference catalog");
        assert_eq!(
            catalog.names(),
            vec![
                "ansible-host-a-apply".to_string(),
                "cert-manager-rotation".to_string(),
                "kube-readonly".to_string()
            ]
        );
    }

    #[test]
    fn migrates_unambiguous_profile_without_complement_denies() {
        let catalog = SavedGrantCatalog::from_yaml(
            "profiles:\n  - name: legacy\n    allow: [\"kubectl get pods\", \"kubectl describe *\"]\n    deny: [\"kubectl delete pod\"]\n",
        )
        .expect("migrate profile");
        let grant = catalog.get("legacy").expect("saved grant");
        assert_eq!(grant.generated_verbs.len(), 3);
        assert_eq!(grant.generated_verbs[0].coverage.len(), 1);
        assert_eq!(
            grant.generated_verbs[0].coverage[0].action,
            CoverageAction::Preauthorized
        );
        assert!(grant.generated_verbs[0].trusted);
        assert!(grant.generated_verbs[0].coverage[0].sticky);
        assert_eq!(
            grant.generated_verbs[2].coverage[0].action,
            CoverageAction::Deny
        );

        let mut verbs = guard::gating::verb::VerbCatalog::empty();
        for verb in &grant.generated_verbs {
            verbs
                .upsert_saved_grant_verb(verb.clone())
                .expect("install migrated verb");
        }
        let actions = |args: &[&str]| {
            verbs
                .match_command_all(
                    "kubectl",
                    &args
                        .iter()
                        .map(|value| (*value).to_string())
                        .collect::<Vec<_>>(),
                )
                .into_iter()
                .map(|matched| matched.action)
                .collect::<Vec<_>>()
        };

        assert_eq!(
            actions(&["get", "pods"]),
            vec![CoverageAction::Preauthorized]
        );
        assert!(
            actions(&["get"]).is_empty(),
            "missing exact argv must not match"
        );
        assert!(
            actions(&["get", "pods", "-A"]).is_empty(),
            "extra exact argv must not match"
        );
        assert_eq!(
            actions(&["describe"]),
            vec![CoverageAction::Preauthorized],
            "a trailing wildcard may match an empty suffix"
        );
        assert_eq!(
            actions(&["describe", "pod", "web"]),
            vec![CoverageAction::Preauthorized],
            "a trailing wildcard widens only the suffix after its fixed prefix"
        );
        assert!(
            actions(&[]).is_empty(),
            "missing wildcard prefix must not match"
        );
        assert_eq!(actions(&["delete", "pod"]), vec![CoverageAction::Deny]);
        assert!(
            actions(&["delete", "pod", "--force"]).is_empty(),
            "exact deny cardinality must be preserved"
        );
    }

    #[test]
    fn rejects_ambiguous_legacy_glob() {
        let error = SavedGrantCatalog::from_yaml(
            "profiles:\n  - name: legacy\n    allow: [\"kubectl get secret*\"]\n",
        )
        .expect_err("ambiguous glob");
        assert!(error.to_string().contains("cannot migrate safely"));
    }

    #[test]
    fn request_auto_approval_stays_inside_ceiling() {
        let grant = SavedGrant {
            name: "deploy".to_string(),
            label: None,
            description: String::new(),
            activated_verbs: vec!["deploy-a".to_string()],
            override_markers: Vec::new(),
            secret_names: vec!["DEPLOY_KEY".to_string()],
            ttl_secs: Some(300),
            prompt_append: None,
            evaluation_mode: EvaluationMode::Evaluator,
            auto_approve_requests: true,
            ceiling: GrantCeiling::default(),
            generated_verbs: Vec::new(),
            revision: 1,
            created_unix: 1,
            updated_unix: 1,
        }
        .normalize()
        .unwrap();
        assert!(grant.contains_delta(&GrantRequestDelta {
            activated_verbs: vec!["deploy-a".to_string()],
            secret_names: vec!["DEPLOY_KEY".to_string()],
            ttl_secs: Some(120),
            ..GrantRequestDelta::default()
        }));
        assert!(!grant.contains_delta(&GrantRequestDelta {
            activated_verbs: vec!["deploy-b".to_string()],
            ..GrantRequestDelta::default()
        }));
        assert!(!grant.contains_delta(&GrantRequestDelta {
            override_markers: vec!["operator:apply".to_string()],
            ..GrantRequestDelta::default()
        }));
    }

    #[test]
    fn durable_rows_overlay_file_catalog_without_dropping_other_grants() {
        let mut catalog = SavedGrantCatalog::from_yaml(
            "grants:\n  - name: file-only\n    prompt_append: file\n  - name: shared\n    prompt_append: file revision\n",
        )
        .unwrap();
        let durable = SavedGrantCatalog::from_yaml(
            "grants:\n  - name: shared\n    prompt_append: durable revision\n",
        )
        .unwrap()
        .get("shared")
        .unwrap()
        .clone();
        catalog.overlay_rows(vec![durable]).unwrap();
        assert!(catalog.get("file-only").is_some());
        assert_eq!(
            catalog.get("shared").unwrap().prompt_append.as_deref(),
            Some("durable revision")
        );
    }
}
