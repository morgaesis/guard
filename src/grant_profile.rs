//! Saved grant definitions and compatibility migration for legacy profiles.
//!
//! A saved grant is the reusable authorization object. It selects typed verbs,
//! carries secret-name entitlements and evaluator context, declares a default
//! lifetime and evaluation mode, and records generated coverage with evidence.
//! Issuing a saved grant creates a bounded live session grant.

use anyhow::{bail, Context, Result};
use guard::env::now_unix;
use guard::gating::verb::{
    canonicalize_generated_authority_envelope, generated_access_matcher_shape,
    normalize_generated_access_verb, parse_normalized_generated_access_verb, CoverageAction,
    CoverageObservationReplay, CoverageProvenance, ValueConstraint, Verb, VerbCoverageCell,
};
use guard::gating::Reversibility;
use guard::principal::PrincipalKey;
use guard::redact::{
    command_contains_sensitive_literals, command_metadata, json_contains_exact_secrets,
    redact_output_text, text_contains_sensitive_literals,
};
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
#[serde(deny_unknown_fields)]
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
    pub fn validate_canonical(&self) -> Result<()> {
        validate_saved_grant(self)
    }

    pub fn canonicalized_for_migration(mut self) -> Result<Self> {
        canonicalize_saved_grant_envelope(&mut self)?;
        validate_saved_grant(&self)?;
        Ok(self)
    }

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
        canonicalize_saved_grant_envelope(&mut self)?;
        validate_saved_grant(&self)?;
        Ok(self)
    }

    #[cfg(test)]
    pub fn generated_verb_names(&self) -> Vec<String> {
        self.generated_verbs
            .iter()
            .map(|verb| verb.name.clone())
            .collect()
    }

    #[cfg(test)]
    pub fn all_activated_verbs(&self) -> Vec<String> {
        let mut names = self.activated_verbs.clone();
        names.extend(self.generated_verb_names());
        normalize_strings(&mut names);
        names
    }

    #[cfg(test)]
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
    /// Internal bearer target for compatibility session amendments. Access
    /// projections always replace this value with a stable fingerprint.
    #[serde(default)]
    pub session_token: String,
    /// Daemon-authenticated requester. Access requests always populate this
    /// from the local peer and never accept it from the wire.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requester: Option<PrincipalKey>,
    /// Stable session fingerprint or agent label used by the public access
    /// workflow. This is safe to display and is never accepted as authority.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub target: Option<String>,
    /// Canonical digest used to converge equivalent retries.
    #[serde(default, skip_serializing_if = "String::is_empty")]
    pub request_key: String,
    /// Declarative bounded-use policy carried by proactive extension. Ordinary
    /// agent requests leave this unset and the operator chooses at approval.
    #[serde(default, skip_serializing_if = "Option::is_none")]
    pub requested_uses: Option<u64>,
    /// Complete typed scope covered by this access request. `delta` contains
    /// only authority missing from the target session.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub authority_verbs: Vec<String>,
    /// Exact synthesized coverage proposed by this request. It remains inert
    /// until operator approval commits it to the catalog.
    #[serde(default, skip_serializing_if = "Vec::is_empty")]
    pub proposed_verbs: Vec<serde_json::Value>,
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
            next_action: format!("guard access show {handle}"),
            handle,
            session_token,
            requester: None,
            target: None,
            request_key: String::new(),
            requested_uses: None,
            authority_verbs: Vec::new(),
            proposed_verbs: Vec::new(),
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

    pub fn new_access(
        requester: PrincipalKey,
        session_token: Option<String>,
        target: String,
        delta: GrantRequestDelta,
        intent: String,
    ) -> Result<Self> {
        Self::new_access_with_uses(requester, session_token, target, delta, intent, None)
    }

    pub fn new_access_with_uses(
        requester: PrincipalKey,
        session_token: Option<String>,
        target: String,
        mut delta: GrantRequestDelta,
        intent: String,
        requested_uses: Option<u64>,
    ) -> Result<Self> {
        normalize_strings(&mut delta.activated_verbs);
        normalize_strings(&mut delta.override_markers);
        normalize_strings(&mut delta.secret_names);
        if intent.trim().is_empty() {
            bail!("access request requires an intent");
        }
        if delta.is_empty() && requested_uses.is_none() {
            bail!("access request has no requested change");
        }
        let handle = format!("gr-{:032x}", rand::random::<u128>());
        let created_unix = now_unix();
        let mut request = Self {
            next_action: format!("guard access show {handle}"),
            handle,
            session_token: session_token.unwrap_or_default(),
            requester: Some(requester),
            target: Some(target),
            request_key: String::new(),
            requested_uses,
            authority_verbs: Vec::new(),
            proposed_verbs: Vec::new(),
            saved_grant: None,
            issued_saved_revision: None,
            issued_session_revision: None,
            delta,
            justification: intent,
            status: GrantRequestStatus::Pending,
            created_unix,
            expires_unix: created_unix.saturating_add(86_400),
            decided_unix: None,
            decided_reason: None,
        };
        request.request_key = request.canonical_access_key()?;
        Ok(request)
    }

    pub fn canonical_access_key(&self) -> Result<String> {
        let requester = self
            .requester
            .as_ref()
            .context("access request requires an authenticated requester")?;
        // The convergence key is a digest of matcher authority, not a
        // persistence validator. Use normalized authority when available and
        // retain the raw matcher shape for a request that must be rejected by
        // the durable validator, so callers can still submit it for a
        // fail-closed rejection rather than failing while constructing its
        // diagnostic key.
        let proposed_authority = self
            .proposed_verbs
            .iter()
            .map(|value| {
                let verb = serde_json::from_value::<Verb>(value.clone())
                    .context("decode proposed access coverage for request key")?;
                let authority = normalize_generated_access_verb(verb.clone()).unwrap_or(verb);
                Ok(generated_access_matcher_shape(&authority))
            })
            .collect::<Result<Vec<_>>>()?;
        let encoded = serde_json::to_vec(&(
            requester,
            &self.session_token,
            &self.delta,
            self.requested_uses,
            &self.authority_verbs,
            proposed_authority,
            &self.issued_session_revision,
        ))?;
        let digest = Sha256::digest(encoded);
        Ok(format!(
            "ar-{}",
            digest[..16]
                .iter()
                .map(|byte| format!("{byte:02x}"))
                .collect::<String>()
        ))
    }

    /// Decode durable generated-access proposals through the single canonical
    /// proposal gate. This does not consult the live catalog.
    pub fn validated_generated_access_proposals(&self) -> Result<Vec<Verb>> {
        self.proposed_verbs
            .iter()
            .map(parse_normalized_generated_access_verb)
            .collect()
    }

    /// Whether this row carries any access-specific projection. Requester
    /// presence is intentionally not part of detection: pure shape validation
    /// requires it, so stripping the principal cannot turn an access row into
    /// a legacy grant request.
    pub fn has_access_projection(&self) -> bool {
        self.target.is_some()
            || !self.request_key.is_empty()
            || !self.authority_verbs.is_empty()
            || !self.proposed_verbs.is_empty()
            || self.requested_uses.is_some()
    }

    /// Validate the pure shape of a principal-bound access request. Catalog
    /// existence and operator-authored verb properties are checked separately
    /// by the server because they depend on live state.
    pub fn validate_principal_access_shape(&self) -> Result<Vec<Verb>> {
        if self.requester.is_none()
            || self.target.as_deref().is_none_or(str::is_empty)
            || self.request_key.is_empty()
        {
            bail!("request is not a canonical principal-bound access request");
        }
        if self.saved_grant.is_some()
            || self.issued_saved_revision.is_some()
            || !self.delta.override_markers.is_empty()
            || !self.delta.secret_names.is_empty()
            || self.delta.ttl_secs.is_some()
            || self.delta.prompt_append.is_some()
            || self.delta.evaluation_mode.is_some()
        {
            bail!("access request contains authority outside its displayed verb scope");
        }
        if self.authority_verbs.is_empty()
            || self
                .delta
                .activated_verbs
                .iter()
                .any(|verb| !self.authority_verbs.contains(verb))
        {
            bail!("access request verb scope is incomplete or inconsistent");
        }

        let proposed = self.validated_generated_access_proposals()?;
        let mut proposal_names = std::collections::BTreeSet::new();
        for verb in &proposed {
            if !proposal_names.insert(verb.name.clone()) {
                bail!("access request contains duplicate proposed coverage");
            }
            if !self.authority_verbs.contains(&verb.name)
                || !self.delta.activated_verbs.contains(&verb.name)
            {
                bail!("access request contains unreferenced proposed coverage");
            }
        }
        if self.status == GrantRequestStatus::Pending {
            let expected = self
                .canonical_access_key()
                .context("invalid access request convergence key")?;
            if expected != self.request_key {
                bail!("access request convergence key does not match its displayed scope");
            }
        }
        Ok(proposed)
    }
}

pub fn normalize_access_intent(value: &str) -> String {
    value
        .split_whitespace()
        .collect::<Vec<_>>()
        .join(" ")
        .to_ascii_lowercase()
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
                "saved grant '{}' already exists; use `guard access request <intent>` for missing authority",
                grant.name
            );
        }
        self.grants.insert(grant.name.clone(), grant.clone());
        Ok(grant)
    }

    #[cfg(test)]
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
            "legacy grant pattern cannot migrate safely: use a typed verb coverage cell or an exact trailing ' *' argv suffix"
        );
    }
    let prefix = pattern.strip_suffix(" *").unwrap_or(pattern).trim();
    let trailing_wildcard = pattern.ends_with(" *");
    let tokens = prefix.split_whitespace().collect::<Vec<_>>();
    if tokens.is_empty() {
        bail!("legacy grant pattern has no binary");
    }
    let binary = tokens[0].to_string();
    let evidence_args = tokens
        .iter()
        .skip(1)
        .map(|token| (*token).to_string())
        .collect::<Vec<_>>();
    if command_contains_sensitive_literals(&binary, &evidence_args) {
        bail!(
            "legacy grant pattern cannot migrate safely because it contains credential-bearing command authority"
        );
    }
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
    let evidence_metadata = command_metadata(&binary, &evidence_args);
    let evidence_arg_count = evidence_args.len();
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
        cwd: None,
        environment: Vec::new(),
        override_marker: None,
        sticky: true,
        provenance: Some(CoverageProvenance {
            source: "legacy_profile_migration".to_string(),
            evidence: vec![evidence_metadata.clone()],
            regime_stamp: "legacy-profile-v1".to_string(),
            prompt_stamp: "not-applicable".to_string(),
            model_stamp: "not-applicable".to_string(),
            generated_unix: now_unix(),
            probes: Vec::new(),
            // Replayed from the migrated legacy pattern; no probe was
            // executed against the generated cell.
            observation_replays: vec![
                CoverageObservationReplay {
                    dimension: "evidence".to_string(),
                    args: evidence_args,
                    template_match: true,
                },
                CoverageObservationReplay {
                    dimension: "boundary".to_string(),
                    args: boundary_args,
                    template_match: trailing_wildcard,
                },
            ],
        }),
    };
    Ok(Verb {
        name: verb_name,
        description: format!(
            "Runs {binary} with {} pinned argument(s) from saved-grant coverage.",
            evidence_arg_count
        ),
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
        evidence: Some(evidence_metadata),
        auto_promoted: false,
        promotion_stamp: None,
    })
}

fn validate_saved_grant(grant: &SavedGrant) -> Result<()> {
    let mut canonical = grant.clone();
    canonicalize_saved_grant_envelope(&mut canonical)?;
    if serde_json::to_value(&canonical)? != serde_json::to_value(grant)? {
        bail!("saved grant metadata is not in canonical sanitized form");
    }
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
            if provenance
                .probes
                .iter()
                .any(|probe| probe.expected_match != probe.observed_match)
            {
                bail!(
                    "generated verb '{}' coverage '{}' has failing probes",
                    verb.name,
                    cell.name
                );
            }
            // Provenance must carry at least one record of where the cell
            // came from: either probes a generator actually executed or
            // observation replays of the evidence it was derived from.
            if provenance.probes.is_empty() && provenance.observation_replays.is_empty() {
                bail!(
                    "generated verb '{}' coverage '{}' has no probe or observation-replay provenance",
                    verb.name,
                    cell.name
                );
            }
        }
    }
    Ok(())
}

fn canonicalize_saved_grant_envelope(grant: &mut SavedGrant) -> Result<()> {
    grant.label = grant.label.take().map(|value| redact_output_text(&value));
    grant.description = redact_output_text(&grant.description);
    if grant
        .prompt_append
        .as_deref()
        .is_some_and(text_contains_sensitive_literals)
    {
        bail!("saved grant evaluator context contains a sensitive literal");
    }
    for verb in &mut grant.generated_verbs {
        *verb = canonicalize_generated_authority_envelope(verb.clone())?;
    }
    let serialized = serde_json::to_value(&*grant)?;
    if json_contains_exact_secrets(&serialized, &[]) {
        bail!("saved grant contains a trusted exact credential literal");
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

#[cfg(test)]
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
    use guard::gating::verb::{generated_access_verb_name, CoverageProbe, ParamSpec};

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
        assert!(grant.generated_verbs.iter().all(|verb| {
            verb.evidence
                .as_deref()
                .is_some_and(|evidence| evidence.starts_with("[argv-sha256:"))
                && verb.coverage[0]
                    .provenance
                    .as_ref()
                    .is_some_and(|provenance| {
                        provenance
                            .evidence
                            .iter()
                            .all(|evidence| evidence.starts_with("[argv-sha256:"))
                    })
        }));
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
    fn rejects_credential_bearing_legacy_authority_without_retaining_source_metadata() {
        let value = ["legacy", "-fixture-value"].concat();
        let yaml = format!(
            "profiles:\n  - name: legacy\n    allow: [\"fixturectl --api-token={value} inspect\"]\n"
        );
        let error = SavedGrantCatalog::from_yaml(&yaml).expect_err("credential authority");
        assert!(error.to_string().contains("credential-bearing"));
        assert!(!error.to_string().contains(&value));
    }

    #[test]
    fn saved_grant_canonicalizes_exact_literals_in_explanatory_metadata() {
        let value = ["grant", "-metadata-fixture"].concat();
        let _scope =
            guard::redact::register_trusted_exact_secrets(std::slice::from_ref(&value)).unwrap();
        let grant = SavedGrant {
            name: "fixture".to_string(),
            label: Some(format!("label {value}")),
            description: format!("description {value}"),
            activated_verbs: vec!["fixture-verb".to_string()],
            override_markers: Vec::new(),
            secret_names: Vec::new(),
            ttl_secs: None,
            prompt_append: None,
            evaluation_mode: EvaluationMode::ReadOnly,
            auto_approve_requests: false,
            ceiling: GrantCeiling::default(),
            generated_verbs: Vec::new(),
            revision: 1,
            created_unix: 1,
            updated_unix: 1,
        }
        .normalize()
        .unwrap();
        assert_eq!(grant.label.as_deref(), Some("label [REDACTED]"));
        assert_eq!(grant.description, "description [REDACTED]");
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
    fn ceiling_round_trip_and_request_fields_preserve_authority_boundaries() {
        let catalog = SavedGrantCatalog::from_yaml(
            "grants:\n  - name: bounded\n    activated_verbs: [inspect]\n    override_markers: [operator:apply]\n    secret_names: [service/readonly/*]\n    ttl_secs: 120\n    prompt_append: baseline context\n    evaluation_mode: evaluator\n    auto_approve_requests: true\n    ceiling:\n      verbs: [inspect, restart-one]\n      secret_names: [service/readonly/*]\n      max_ttl_secs: 300\n      allow_prompt_append: true\n      evaluation_modes: [evaluator, policy_only]\n",
        )
        .unwrap();
        let saved = catalog.get("bounded").unwrap();
        let encoded = serde_json::to_string(saved).unwrap();
        let decoded: SavedGrant = serde_json::from_str(&encoded).unwrap();
        assert_eq!(decoded.ceiling, saved.ceiling);
        assert_eq!(decoded.override_markers, vec!["operator:apply"]);

        let delta = GrantRequestDelta {
            activated_verbs: vec!["restart-one".to_string()],
            prompt_append: Some("evaluate only the named service".to_string()),
            ..Default::default()
        };
        assert!(saved.contains_delta(&delta));
        let request = GrantRequest::new(
            "session-token".to_string(),
            Some("bounded".to_string()),
            delta.clone(),
            "pager alert requires one bounded restart".to_string(),
        )
        .unwrap();
        assert_eq!(
            request.justification,
            "pager alert requires one bounded restart"
        );
        assert_eq!(request.delta.prompt_append, delta.prompt_append);
        assert!(!request.justification.contains("evaluate only"));
        assert!(!saved.contains_delta(&GrantRequestDelta {
            override_markers: vec!["operator:apply".to_string()],
            ..Default::default()
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

    #[test]
    fn access_request_keys_coalesce_equivalent_authority_but_isolate_principals() {
        let delta = GrantRequestDelta {
            activated_verbs: vec!["inspect".to_string()],
            ..GrantRequestDelta::default()
        };
        let one = GrantRequest::new_access(
            PrincipalKey::from_uid(1001),
            None,
            "agent:1001".to_string(),
            delta.clone(),
            "Inspect   the fixture".to_string(),
        )
        .unwrap();
        let retry = GrantRequest::new_access(
            PrincipalKey::from_uid(1001),
            None,
            "agent:1001".to_string(),
            delta.clone(),
            " inspect the fixture ".to_string(),
        )
        .unwrap();
        let other = GrantRequest::new_access(
            PrincipalKey::from_uid(1002),
            None,
            "agent:1002".to_string(),
            delta,
            "inspect the fixture".to_string(),
        )
        .unwrap();
        assert_eq!(one.request_key, retry.request_key);
        assert_ne!(one.request_key, other.request_key);
        assert_eq!(one.requester, Some(PrincipalKey::from_uid(1001)));
        assert!(one.session_token.is_empty());
    }

    #[test]
    fn access_request_keys_ignore_prose_and_display_target_for_one_session_revision() {
        let delta = GrantRequestDelta {
            activated_verbs: vec!["access-command-run".to_string()],
            ..GrantRequestDelta::default()
        };
        let mut execution = GrantRequest::new_access(
            PrincipalKey::from_uid(1001),
            Some("session-token".to_string()),
            "session:fixture".to_string(),
            delta.clone(),
            "access-command-run".to_string(),
        )
        .unwrap();
        execution.authority_verbs = vec!["access-command-run".to_string()];
        execution.issued_session_revision = Some("revision-4".to_string());
        execution.request_key = execution.canonical_access_key().unwrap();

        let mut prose = GrantRequest::new_access(
            PrincipalKey::from_uid(1001),
            Some("session-token".to_string()),
            "agent:1001".to_string(),
            delta,
            "Run the bounded command".to_string(),
        )
        .unwrap();
        prose.authority_verbs = vec!["access-command-run".to_string()];
        prose.issued_session_revision = Some("revision-4".to_string());
        prose.request_key = prose.canonical_access_key().unwrap();

        assert_eq!(execution.request_key, prose.request_key);
        prose.session_token = "another-session".to_string();
        assert_ne!(execution.request_key, prose.canonical_access_key().unwrap());
    }

    #[test]
    fn access_request_keys_ignore_every_generated_provenance_field() {
        fn proposal(seed: &str, generated_unix: u64) -> serde_json::Value {
            let mut verb = Verb {
                name: "access-generated-fixture".to_string(),
                description: String::new(),
                binary: "fixturectl".to_string(),
                args: vec!["inspect".to_string(), "{item}".to_string()],
                baseline: false,
                coverage: vec![VerbCoverageCell {
                    name: "item".to_string(),
                    action: CoverageAction::Evaluate,
                    required_args: Vec::new(),
                    forbidden_args: Vec::new(),
                    min_args: None,
                    max_args: None,
                    options: Vec::new(),
                    target: None,
                    inventory: None,
                    namespace: None,
                    fanout: None,
                    cwd: None,
                    environment: Vec::new(),
                    override_marker: None,
                    sticky: false,
                    provenance: Some(CoverageProvenance {
                        source: format!("source-{seed}"),
                        evidence: vec![format!("evidence-{seed}")],
                        regime_stamp: format!("regime-{seed}"),
                        prompt_stamp: format!("prompt-{seed}"),
                        model_stamp: format!("model-{seed}"),
                        generated_unix,
                        probes: vec![CoverageProbe {
                            dimension: format!("dimension-{seed}"),
                            args: vec!["inspect".to_string(), "item".to_string()],
                            expected_match: true,
                            observed_match: true,
                        }],
                        observation_replays: Vec::new(),
                    }),
                }],
                credential_plan: None,
                params: BTreeMap::from([(
                    "item".to_string(),
                    ParamSpec {
                        pattern: "^[a-z]+$".to_string(),
                        required: true,
                        default: None,
                        allow_dash: false,
                    },
                )]),
                consequence: Reversibility::Irreversible,
                revert: None,
                trusted: false,
                prompt_context: None,
                source_prose: None,
                evidence: None,
                auto_promoted: false,
                promotion_stamp: None,
            };
            verb = guard::gating::verb::normalize_generated_access_verb(verb).unwrap();
            verb.name = generated_access_verb_name(&verb);
            serde_json::to_value(verb).unwrap()
        }

        let first_proposal = proposal("one", 1);
        let name = serde_json::from_value::<Verb>(first_proposal.clone())
            .unwrap()
            .name;
        let delta = GrantRequestDelta {
            activated_verbs: vec![name.to_string()],
            ..GrantRequestDelta::default()
        };
        let mut first = GrantRequest::new_access(
            PrincipalKey::from_uid(1001),
            None,
            "agent:1001".to_string(),
            delta.clone(),
            "inspect bounded fixture".to_string(),
        )
        .unwrap();
        first.authority_verbs = vec![name.to_string()];
        first.proposed_verbs = vec![first_proposal];
        first.request_key = first.canonical_access_key().unwrap();

        let mut second = first.clone();
        second.proposed_verbs = vec![proposal("two", 2)];
        second.request_key = second.canonical_access_key().unwrap();
        assert_eq!(first.request_key, second.request_key);
    }
}
