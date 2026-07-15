//! Operator-authored session-grant profiles.
//!
//! A profile is a named bundle of the same fields an operator would otherwise
//! type into `guard session new`: a ttl, legacy allow/deny globs, activated
//! verbs, exact override markers, and evaluator prompt context. `guard session
//! new --profile <name>` mints a session token from the
//! bundle in one round trip, so a recurring, bounded "box" of access (e.g.
//! cert-manager certificate rotation) does not have to be re-authored per
//! session or per operator round-trip.
//!
//! A profile is only a convenience for authoring a grant ahead of time. The
//! grant it mints takes the identical install and validation path as a
//! hand-authored `guard session new`, so a profile is no new trust boundary --
//! it cannot express anything an operator could not type directly.
//!
//! The catalog mirrors the verb catalog's shape (a `profiles:` list of named
//! entries in operator-controlled YAML) and, like `--allow-bin`, is read once at
//! daemon startup rather than hot-reloaded: profiles are consulted only at the
//! rare grant-mint action, so a change takes effect on the next daemon start.

use anyhow::{bail, Context, Result};
use serde::Deserialize;
use std::collections::BTreeMap;
use std::path::Path;

/// One named profile: a pre-authored session grant.
#[derive(Debug, Clone, Deserialize)]
pub struct GrantProfile {
    pub name: String,
    /// Operator-facing note describing what the profile is for. Metadata only:
    /// part of the operator YAML schema, never read by the daemon.
    #[serde(default)]
    #[allow(dead_code)]
    pub description: String,
    #[serde(default)]
    pub allow: Vec<String>,
    #[serde(default)]
    pub deny: Vec<String>,
    #[serde(default)]
    pub activated_verbs: Vec<String>,
    #[serde(default)]
    pub override_markers: Vec<String>,
    /// Grant lifetime in seconds; omit for no expiry.
    #[serde(default)]
    pub ttl_secs: Option<u64>,
    /// Evaluator context appended to the LLM system prompt for calls made under
    /// a session minted from this profile.
    #[serde(default)]
    pub prompt_append: Option<String>,
}

#[derive(Debug, Deserialize)]
struct ProfileFile {
    #[serde(default)]
    profiles: Vec<GrantProfile>,
}

/// A parsed, validated set of named profiles keyed by name.
#[derive(Debug, Clone, Default)]
pub struct ProfileCatalog {
    profiles: BTreeMap<String, GrantProfile>,
}

impl ProfileCatalog {
    pub fn empty() -> Self {
        Self::default()
    }

    pub fn names(&self) -> Vec<String> {
        self.profiles.keys().cloned().collect()
    }

    pub fn get(&self, name: &str) -> Option<&GrantProfile> {
        self.profiles.get(name)
    }

    /// Parse and validate a catalog from YAML text. Rejects duplicate names and
    /// profiles that would grant nothing, so an authoring mistake fails at load
    /// rather than silently minting an empty (unrestricted) grant later.
    pub fn from_yaml(text: &str) -> Result<Self> {
        let file: ProfileFile =
            serde_yaml_ng::from_str(text).context("failed to parse session profile catalog")?;
        let mut profiles = BTreeMap::new();
        for profile in file.profiles {
            validate_profile(&profile)?;
            if profiles
                .insert(profile.name.clone(), profile.clone())
                .is_some()
            {
                bail!("duplicate session profile name: '{}'", profile.name);
            }
        }
        Ok(Self { profiles })
    }

    /// Load a catalog from a file.
    pub fn load(path: &Path) -> Result<Self> {
        let text = std::fs::read_to_string(path).with_context(|| {
            format!("failed to read session profile catalog {}", path.display())
        })?;
        Self::from_yaml(&text)
    }
}

fn validate_profile(profile: &GrantProfile) -> Result<()> {
    if profile.name.trim().is_empty() {
        bail!("session profile name must not be empty");
    }
    if profile.allow.is_empty()
        && profile.deny.is_empty()
        && profile.activated_verbs.is_empty()
        && profile.prompt_append.is_none()
    {
        bail!(
            "session profile '{}' grants nothing: set allow, deny, activated_verbs, or prompt_append",
            profile.name
        );
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_named_profiles() {
        let catalog = ProfileCatalog::from_yaml(
            "profiles:\n  - name: cert-manager-rotation\n    description: rotate cert-manager certs\n    ttl_secs: 3600\n    allow:\n      - \"kubectl get certificate*\"\n      - \"kubectl delete secret*\"\n    deny:\n      - \"kubectl delete namespace*\"\n    activated_verbs: [session-apply]\n    override_markers: [operator:apply]\n    prompt_append: \"restoring cert-manager certificates\"\n",
        )
        .expect("valid catalog");
        let profile = catalog
            .get("cert-manager-rotation")
            .expect("profile present");
        assert_eq!(profile.ttl_secs, Some(3600));
        assert_eq!(
            profile.allow,
            vec![
                "kubectl get certificate*".to_string(),
                "kubectl delete secret*".to_string()
            ]
        );
        assert_eq!(profile.deny, vec!["kubectl delete namespace*".to_string()]);
        assert_eq!(profile.activated_verbs, vec!["session-apply"]);
        assert_eq!(profile.override_markers, vec!["operator:apply"]);
        assert_eq!(
            profile.prompt_append.as_deref(),
            Some("restoring cert-manager certificates")
        );
        assert!(catalog.get("nope").is_none());
    }

    #[test]
    fn rejects_duplicate_names() {
        let err = ProfileCatalog::from_yaml(
            "profiles:\n  - name: dup\n    allow: [\"echo*\"]\n  - name: dup\n    allow: [\"ls*\"]\n",
        )
        .expect_err("duplicates must fail");
        assert!(err.to_string().contains("duplicate session profile name"));
    }

    #[test]
    fn rejects_empty_profile() {
        let err = ProfileCatalog::from_yaml("profiles:\n  - name: hollow\n")
            .expect_err("an empty profile must fail");
        assert!(err.to_string().contains("grants nothing"));
    }

    #[test]
    fn empty_catalog_has_no_names() {
        assert!(ProfileCatalog::from_yaml("profiles: []\n")
            .expect("valid")
            .names()
            .is_empty());
    }

    #[test]
    fn shipped_profile_catalog_parses() {
        let path = Path::new(env!("CARGO_MANIFEST_DIR")).join("examples/session-profiles.yaml");
        let catalog = ProfileCatalog::load(&path).expect("shipped profiles load");
        let typed = catalog
            .get("ansible-host-a-apply")
            .expect("typed profile is present");
        assert_eq!(typed.activated_verbs, vec!["ansible-host-a-apply"]);
        assert_eq!(typed.override_markers, vec!["operator:ansible-apply"]);
    }
}
