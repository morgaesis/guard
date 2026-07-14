//! Cross-platform caller/daemon identity key.
//!
//! Every consequence-gating authorization decision — who is the operator, who
//! owns a provisional or approval row, which secret namespace a caller sees —
//! is expressed in terms of a [`PrincipalKey`] rather than a Unix uid, so a
//! Windows named-pipe caller identified by SID is a first-class principal with
//! exact parity to a Unix uid caller. The only platform-specific code is how
//! the key is produced (a uid string on Unix, a SID string on Windows); every
//! comparison and scoping decision downstream is shared.

use serde::{Deserialize, Deserializer, Serialize};

/// A caller's identity, as the string produced by `CallerIdentity::user_key()`:
/// a decimal uid on Unix, a SID (`S-1-5-...`) on Windows, or a token for TCP
/// callers. An unauthenticated caller has no key (`None`); two missing keys
/// must never compare equal — see [`scope_eq`].
#[derive(Debug, Clone, PartialEq, Eq, PartialOrd, Ord, Hash, Serialize, Deserialize)]
pub struct PrincipalKey(String);

impl PrincipalKey {
    /// Wrap a raw identity string (uid/SID/token) verbatim.
    pub fn from_raw(s: impl Into<String>) -> Self {
        Self(s.into())
    }

    /// A Unix uid principal (the decimal uid as a string).
    pub fn from_uid(uid: u32) -> Self {
        Self(uid.to_string())
    }

    /// A Windows SID principal.
    pub fn from_sid(sid: impl Into<String>) -> Self {
        Self(sid.into())
    }

    pub fn as_str(&self) -> &str {
        &self.0
    }

    pub fn into_string(self) -> String {
        self.0
    }

    /// Case-insensitive identity equality. Windows SIDs are case-insensitive;
    /// Unix uid strings are decimal digits and so unaffected. Used for every
    /// operator/owner comparison so a SID that differs only in case still
    /// matches the same principal.
    pub fn eq_ci(&self, other: &PrincipalKey) -> bool {
        self.0.eq_ignore_ascii_case(&other.0)
    }

    /// A filesystem- and env-var-safe namespace segment for per-principal
    /// secret storage. A pure-decimal key (a Unix uid) maps to `u<uid>`, which
    /// preserves the existing on-disk `pass guard/u<uid>/...` and `secrets.yaml`
    /// layout (no secret-store migration on upgrade). Any other key (a SID such
    /// as `S-1-5-21-a-b-c-rid`) has every non-alphanumeric character replaced
    /// with `_`, which is injective for SIDs and valid as both a `pass` path
    /// segment and an environment-variable name fragment.
    pub fn segment(&self) -> String {
        if !self.0.is_empty() && self.0.bytes().all(|b| b.is_ascii_digit()) {
            format!("u{}", self.0)
        } else {
            self.0
                .chars()
                .map(|c| if c.is_ascii_alphanumeric() { c } else { '_' })
                .collect()
        }
    }
}

impl std::fmt::Display for PrincipalKey {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.write_str(&self.0)
    }
}

/// Read-scoping equality that treats absence as never-equal: true iff both
/// sides are present and the same principal. Two unauthenticated callers
/// (`None`) never match, which closes the cross-caller visibility hole where a
/// `None == None` comparison would make every gated row owned-by-everyone.
pub fn scope_eq(a: &Option<PrincipalKey>, b: &Option<PrincipalKey>) -> bool {
    matches!((a, b), (Some(x), Some(y)) if x.eq_ci(y))
}

/// Deserialize a row owner from either the current string form (a
/// [`PrincipalKey`]) or the legacy numeric `caller_uid` form, so
/// provisional/approval rows written by an older (uid-only) daemon are
/// preserved across an upgrade rather than dropped. `null`/absent → `None`.
pub fn principal_from_legacy<'de, D>(d: D) -> Result<Option<PrincipalKey>, D::Error>
where
    D: Deserializer<'de>,
{
    use serde::de::Error;
    match Option::<serde_json::Value>::deserialize(d)? {
        None | Some(serde_json::Value::Null) => Ok(None),
        Some(serde_json::Value::Number(n)) => Ok(Some(PrincipalKey(n.to_string()))),
        Some(serde_json::Value::String(s)) => Ok(Some(PrincipalKey(s))),
        Some(other) => Err(D::Error::custom(format!(
            "invalid principal value: {other}"
        ))),
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn scope_eq_treats_absence_as_never_equal() {
        let a = Some(PrincipalKey::from_raw("1000"));
        let b = Some(PrincipalKey::from_raw("1001"));
        assert!(scope_eq(&a, &a));
        assert!(!scope_eq(&a, &b));
        assert!(!scope_eq(&None, &None));
        assert!(!scope_eq(&a, &None));
        assert!(!scope_eq(&None, &a));
    }

    #[test]
    fn sid_is_case_insensitive() {
        let upper = PrincipalKey::from_sid("S-1-5-21-1-2-3-1001");
        let lower = PrincipalKey::from_sid("s-1-5-21-1-2-3-1001");
        assert!(upper.eq_ci(&lower));
        assert!(scope_eq(&Some(upper), &Some(lower)));
    }

    #[test]
    fn uid_segment_preserves_legacy_layout() {
        assert_eq!(PrincipalKey::from_uid(1000).segment(), "u1000");
    }

    #[test]
    fn sid_segment_is_safe_and_injective() {
        let a = PrincipalKey::from_sid("S-1-5-21-1-2-3-1001").segment();
        let b = PrincipalKey::from_sid("S-1-5-21-1-2-3-1002").segment();
        assert_eq!(a, "S_1_5_21_1_2_3_1001");
        assert_ne!(a, b);
        assert!(a.chars().all(|c| c.is_ascii_alphanumeric() || c == '_'));
    }

    #[test]
    fn legacy_numeric_caller_uid_deserializes() {
        #[derive(serde::Deserialize)]
        struct Row {
            #[serde(
                default,
                alias = "caller_uid",
                deserialize_with = "principal_from_legacy"
            )]
            principal: Option<PrincipalKey>,
        }
        let old: Row = serde_json::from_str(r#"{"caller_uid": 1000}"#).unwrap();
        assert_eq!(old.principal, Some(PrincipalKey::from_raw("1000")));
        let new: Row = serde_json::from_str(r#"{"principal": "S-1-5-21-1-2-3-1001"}"#).unwrap();
        assert_eq!(
            new.principal,
            Some(PrincipalKey::from_raw("S-1-5-21-1-2-3-1001"))
        );
        let none: Row = serde_json::from_str(r#"{}"#).unwrap();
        assert_eq!(none.principal, None);
        let null: Row = serde_json::from_str(r#"{"caller_uid": null}"#).unwrap();
        assert_eq!(null.principal, None);
    }
}
