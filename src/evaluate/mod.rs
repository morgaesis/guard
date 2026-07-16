//! Command evaluation: static-policy fast paths, cached decisions, and LLM-backed judgment.

mod cache;
mod client;
mod config;
mod parse;
mod prompt;
mod redact;
mod result;
mod synthesis;
mod verb_confirm;

/// Fuzzing-only surface for the provider-response parser. Hidden from docs;
/// not a stable API. The `parse` module itself stays private.
#[doc(hidden)]
pub mod fuzzing {
    pub use super::parse::{
        parse_decision_response, provider_error_summary, response_shape_summary,
    };
}

pub use cache::{EvalCache, DEFAULT_CACHE_CAPACITY, DEFAULT_CACHE_TTL_SECS};
pub use config::{EvalConfig, LlmConfig};
pub use redact::redact_for_llm;
pub use result::{EvalResult, EvalSource, LlmResponse};

use cache::CachedResult;
use prompt::{
    SYSTEM_PROMPT_GATING, SYSTEM_PROMPT_PARANOID, SYSTEM_PROMPT_READONLY, SYSTEM_PROMPT_SAFE,
};
use verb_confirm::SYSTEM_PROMPT_CONFIRM_VERB_PROMOTION;

use crate::gating::allow_promotion::AllowPromotionStore;
use crate::gating::deny_shape::{split_command_line, DenyShapeStore};
use crate::gating::GateMode;
use crate::learned_rules::{AutoShimMode, LearnedRuleStore, LearningOutcome};
use crate::policy::{PolicyEngine, PolicyMode};
use anyhow::{bail, Context, Result};
use reqwest::Client;
use std::collections::hash_map::DefaultHasher;
use std::hash::{Hash, Hasher};
use std::sync::Arc;
use tokio::sync::RwLock;

pub struct Evaluator {
    policy_engine: Option<PolicyEngine>,
    llm_config: LlmConfig,
    http_client: Client,
    system_prompt: String,
    cache: Option<RwLock<EvalCache>>,
    mode: Option<PolicyMode>,
    gate_mode: GateMode,
    learned_rules: Option<Arc<RwLock<LearnedRuleStore>>>,
    deny_shapes: Option<Arc<RwLock<DenyShapeStore>>>,
    allow_promotion: Option<Arc<RwLock<AllowPromotionStore>>>,
    /// Hash of the model + prompts that back verb-promotion decisions (the
    /// base evaluation prompt, which drives the reversibility votes
    /// promotion relies on, and the evidence-synthesis prompt). Stamped onto
    /// every auto-promoted verb; if either changes, a fresh `Evaluator` gets
    /// a fresh stamp and `server::execute_command_inner` stops trusting
    /// verbs promoted under the old one. See `gating::allow_promotion`.
    verb_promotion_stamp: String,
}

impl Evaluator {
    pub fn new(config: EvalConfig) -> Result<Self> {
        let policy_engine = if let Some(ref path) = config.policy_path {
            if !path.exists() {
                bail!("policy file does not exist: {}", path.display());
            }
            Some(PolicyEngine::load_file(path).context("failed to load policy file")?)
        } else {
            config.mode.map(PolicyEngine::from_mode)
        };

        if config.llm.enabled {
            if let Some(ref engine) = policy_engine {
                if !engine.allow_list().is_empty() {
                    tracing::warn!(
                        "static policy has {} allow pattern(s) configured, but they do not skip \
                         the LLM evaluator while it is enabled (glob patterns over a flat command \
                         string cannot be trusted for that); use `guard verb` for a deterministic, \
                         LLM-skipping allow instead. Static allow patterns are only authoritative \
                         when the LLM is disabled (--no-llm).",
                        engine.allow_list().len()
                    );
                }
            }
        }

        // Load system prompt. Priority:
        // 1. code-supplied literal prompt for specialized daemon evaluators
        // 2. --system-prompt <path> (explicit override)
        // 3. ~/.config/guard/system-prompt.txt (user customization)
        // 4. Mode-specific compiled prompt (readonly/safe/paranoid)
        let system_prompt = if let Some(ref prompt) = config.system_prompt_literal {
            prompt.clone()
        } else if let Some(ref path) = config.system_prompt_path {
            std::fs::read_to_string(path)
                .with_context(|| format!("failed to read system prompt from {}", path.display()))?
        } else {
            let default_path =
                dirs::config_dir().map(|d| d.join("guard").join("system-prompt.txt"));
            match default_path {
                Some(p) if p.exists() => {
                    tracing::info!("Loading system prompt from {}", p.display());
                    std::fs::read_to_string(&p).with_context(|| {
                        format!("failed to read system prompt from {}", p.display())
                    })?
                }
                _ => {
                    // Select compiled prompt based on mode
                    match config.mode {
                        Some(PolicyMode::Safe) => {
                            tracing::info!("Using SAFE mode system prompt");
                            SYSTEM_PROMPT_SAFE.to_string()
                        }
                        Some(PolicyMode::Paranoid) => {
                            tracing::info!("Using PARANOID mode system prompt");
                            SYSTEM_PROMPT_PARANOID.to_string()
                        }
                        Some(PolicyMode::Readonly) | None => {
                            tracing::info!("Using READONLY mode system prompt");
                            SYSTEM_PROMPT_READONLY.to_string()
                        }
                    }
                }
            }
        };

        // Append additive prompt if configured
        let system_prompt = if let Some(ref append_path) = config.system_prompt_append_path {
            let append_text = std::fs::read_to_string(append_path).with_context(|| {
                format!(
                    "failed to read additive prompt from {}",
                    append_path.display()
                )
            })?;
            tracing::info!("Appending additive prompt from {}", append_path.display());
            format!("{}\n\n{}", system_prompt, append_text)
        } else {
            system_prompt
        };

        // When consequence-gating is enabled, append the classification appendix.
        // It is additive: it asks the model to classify the reversibility of
        // commands it already approves and never alters the approve/deny boundary
        // the base prompt encodes. With gating off, the prompt is byte-identical
        // to the pre-gating build.
        let system_prompt = if config.gate_mode.is_on() {
            tracing::info!("Consequence gating enabled: appending classification appendix");
            format!("{}\n\n{}", system_prompt, SYSTEM_PROMPT_GATING)
        } else {
            system_prompt
        };

        let http_client = Client::builder()
            .timeout(config.llm.timeout())
            .build()
            .context("failed to create HTTP client")?;

        let cache = if config.cache_enabled {
            tracing::info!(
                "LLM decision cache enabled: capacity={} ttl={}s",
                config.cache_capacity,
                config.cache_ttl.as_secs()
            );
            Some(RwLock::new(EvalCache::new(
                config.cache_capacity,
                config.cache_ttl,
            )))
        } else {
            None
        };

        // Stamp verb promotion to the model + prompts that justify it: the
        // base evaluation prompt (drives the reversibility votes a
        // promotion relies on) and the evidence-synthesis prompt used to
        // confirm one. Either changing invalidates prior promotions -- see
        // `gating::allow_promotion` and `server::execute_command_inner`.
        let verb_promotion_stamp = {
            let mut hasher = DefaultHasher::new();
            config.llm.model().hash(&mut hasher);
            system_prompt.hash(&mut hasher);
            SYSTEM_PROMPT_CONFIRM_VERB_PROMOTION.hash(&mut hasher);
            format!("{:x}", hasher.finish())
        };

        Ok(Self {
            policy_engine,
            llm_config: config.llm,
            http_client,
            system_prompt,
            cache,
            mode: config.mode,
            gate_mode: config.gate_mode,
            learned_rules: config.learned_rules,
            deny_shapes: config.deny_shapes,
            allow_promotion: config.allow_promotion,
            verb_promotion_stamp,
        })
    }

    pub fn mode(&self) -> Option<PolicyMode> {
        self.mode
    }

    pub fn gate_mode(&self) -> GateMode {
        self.gate_mode
    }

    pub fn llm_enabled(&self) -> bool {
        self.llm_config.enabled
    }

    pub fn llm_model_chain(&self) -> Vec<String> {
        self.llm_config.model_chain()
    }

    pub fn cache_enabled(&self) -> bool {
        self.cache.is_some()
    }

    pub async fn cache_size(&self) -> usize {
        match &self.cache {
            Some(c) => c.read().await.len(),
            None => 0,
        }
    }

    pub fn learning_enabled(&self) -> bool {
        self.learned_rules.is_some()
    }

    pub async fn learned_rule_count(&self) -> usize {
        match &self.learned_rules {
            Some(store) => store.read().await.rule_count(),
            None => 0,
        }
    }

    pub async fn learned_auto_shim_mode(&self) -> Option<AutoShimMode> {
        match &self.learned_rules {
            Some(store) => Some(store.read().await.auto_shim()),
            None => None,
        }
    }

    pub async fn record_learned_approval(
        &self,
        binary: &str,
        args: &[String],
        command: &str,
        risk: Option<i32>,
        reason: &str,
    ) -> Result<Option<LearningOutcome>> {
        let Some(store) = &self.learned_rules else {
            return Ok(None);
        };
        let mut guard = store.write().await;
        guard.record_approval(binary, args, command, risk, reason)
    }

    /// Hash of the model + prompts backing verb-promotion decisions. See the
    /// `verb_promotion_stamp` field doc.
    pub fn verb_promotion_stamp(&self) -> &str {
        &self.verb_promotion_stamp
    }

    pub fn has_static_policy(&self) -> bool {
        if let Some(ref engine) = self.policy_engine {
            !engine.allow_list().is_empty() || !engine.deny_list().is_empty()
        } else {
            false
        }
    }

    pub async fn validate(&self) -> Result<()> {
        if let Some(ref engine) = self.policy_engine {
            if !engine.allow_list().is_empty() || !engine.deny_list().is_empty() {
                tracing::debug!("static policy has explicit rules");
            }
        }

        if self.llm_config.enabled {
            if self.llm_config.api_key.is_none() {
                bail!("llm_enabled but llm_api_key not provided");
            }

            if let Err(e) = self.ping_llm().await {
                bail!("LLM connectivity check failed: {}", e);
            }
        }

        Ok(())
    }

    pub async fn evaluate(&self, command: &str) -> EvalResult {
        self.evaluate_with_context(command, None).await
    }

    /// Evaluate `command`. If `prompt_append` is provided, append it to the
    /// system prompt for this single LLM call so the evaluator has the
    /// session-specific context. The decision cache is bypassed when a
    /// session prompt is in play, because cached decisions were made under
    /// the base prompt and may not hold under the extended context.
    ///
    /// Equivalent to `evaluate_with_reevaluate(command, prompt_append, false)`:
    /// the auto-learned deny-shape fast path (`gating::deny_shape`) is
    /// consulted. Operator-authored `PolicyEngine` deny rules are always
    /// consulted regardless; only the auto-learned store can be skipped, and
    /// only via the `reevaluate` flag.
    pub async fn evaluate_with_context(
        &self,
        command: &str,
        prompt_append: Option<&str>,
    ) -> EvalResult {
        self.evaluate_with_reevaluate(command, prompt_append, false)
            .await
    }

    /// Same as `evaluate_with_context`, with an explicit `reevaluate` flag.
    /// `reevaluate = true` skips only the auto-learned deny-shape fast path
    /// and forces a fresh LLM call -- it never skips operator-authored
    /// `PolicyEngine` deny rules, which stay absolute. Safe to expose to
    /// callers broadly: its only effect is "ask the LLM again," never a
    /// grant, since the auto-learned store can only ever hold deny shapes.
    pub async fn evaluate_with_reevaluate(
        &self,
        command: &str,
        prompt_append: Option<&str>,
        reevaluate: bool,
    ) -> EvalResult {
        self.evaluate_with_reevaluate_inner(command, prompt_append, reevaluate, false)
            .await
    }

    /// Same as `evaluate_with_reevaluate`, but a non-empty prompt can still be
    /// cached under a prompt-qualified key. This is for daemon-supplied
    /// execution metadata such as cwd, not caller/session authorization prose.
    pub async fn evaluate_with_cacheable_context(
        &self,
        command: &str,
        prompt_append: Option<&str>,
        reevaluate: bool,
    ) -> EvalResult {
        self.evaluate_with_reevaluate_inner(command, prompt_append, reevaluate, true)
            .await
    }

    async fn evaluate_with_reevaluate_inner(
        &self,
        command: &str,
        prompt_append: Option<&str>,
        reevaluate: bool,
        cache_prompt_context: bool,
    ) -> EvalResult {
        let session_prompt_active = prompt_append.map(|s| !s.trim().is_empty()).unwrap_or(false);
        let cache_blocked_by_prompt = session_prompt_active && !cache_prompt_context;
        let cache_key = if session_prompt_active && cache_prompt_context {
            format!(
                "{}\n\n[GUARD EVALUATION CONTEXT]\n{}",
                command,
                prompt_append.unwrap_or_default()
            )
        } else {
            command.to_string()
        };

        // Pre-LLM fast-reject: an explicit deny pattern (or deny-decision
        // group rule) rejects without an LLM call. A command that matches
        // nothing here -- including under a deny-only policy with no other
        // rules, or under an allow-only policy whose allow list doesn't
        // cover it -- falls through to the LLM, exactly as if no policy
        // were loaded. Allow patterns never skip the LLM: `guard verb`
        // (`trusted = true`) is the supported mechanism for a deterministic,
        // LLM-skipping allow. See `PolicyEngine::check_deny_fast_path`.
        // This check is never skipped by `reevaluate`.
        if let Some(ref engine) = self.policy_engine {
            if let Some(reason) = engine.check_deny_fast_path(command) {
                tracing::debug!("static policy denied: {}", reason);
                return EvalResult::Deny {
                    reason,
                    source: EvalSource::StaticPolicy,
                    risk: None,
                };
            }
        }

        // Auto-learned deny fast path: shapes the daemon synthesized itself
        // from repeated LLM denials (`gating::deny_shape`). Unlike the
        // operator PolicyEngine check above, `reevaluate` skips this one --
        // its only effect is forcing a fresh LLM call, never a grant, since
        // this store can only ever hold shapes the LLM already denied.
        if !reevaluate {
            if let Some(ref store) = self.deny_shapes {
                let (binary, args_joined) = split_command_line(command);
                let hit = {
                    let guard = store.read().await;
                    guard
                        .matches(binary, args_joined)
                        .map(|shape| shape.last_reason.clone())
                };
                if let Some(reason) = hit {
                    tracing::debug!("auto-learned deny shape matched: {}", reason);
                    return EvalResult::Deny {
                        reason: format!(
                            "{reason} (re-run with --reevaluate to force a fresh evaluator check)"
                        ),
                        source: EvalSource::LearnedDeny,
                        risk: None,
                    };
                }
            }
        }

        if self.llm_config.enabled {
            // Cache lookup happens on the LLM path only, and only when no
            // session-specific prompt is in play. Session prompts change
            // the decision surface, so they bypass the cache to avoid
            // returning a verdict made under the base prompt.
            if !cache_blocked_by_prompt {
                if let Some(ref cache) = self.cache {
                    let hit = {
                        let guard = cache.read().await;
                        guard.get(&cache_key)
                    };
                    if let Some(result) = hit {
                        tracing::debug!("cache hit for command");
                        return result;
                    }
                }
            }

            let result = self.evaluate_llm(command, prompt_append).await;

            // Only insert into cache when the verdict was made under the
            // base prompt. Decisions reached with a session-specific prompt
            // are not portable to other sessions.
            if !cache_blocked_by_prompt {
                if let Some(ref cache) = self.cache {
                    match &result {
                        EvalResult::Allow { reason, .. } => {
                            let mut guard = cache.write().await;
                            guard.insert(
                                cache_key.clone(),
                                CachedResult::Allow {
                                    reason: reason.clone(),
                                    risk: result.risk(),
                                    reversibility: result.reversibility(),
                                },
                            );
                        }
                        EvalResult::Deny { reason, .. } => {
                            let mut guard = cache.write().await;
                            guard.insert(
                                cache_key.clone(),
                                CachedResult::Deny {
                                    reason: reason.clone(),
                                    risk: result.risk(),
                                },
                            );
                        }
                        EvalResult::Error(_) => {
                            // Don't cache transient errors.
                        }
                    }
                }
            }

            return result;
        }

        // LLM disabled: PolicyEngine is the sole, authoritative decision-maker,
        // so its full allow/deny/default-deny semantics apply here (unlike the
        // pre-LLM fast path above, which only ever fast-rejects).
        if let Some(ref engine) = self.policy_engine {
            let static_result = engine.check(command);
            return if static_result.is_allowed() {
                EvalResult::Allow {
                    reason: static_result.reason,
                    source: EvalSource::StaticPolicy,
                    risk: None,
                    reversibility: None,
                }
            } else {
                EvalResult::Deny {
                    reason: static_result.reason,
                    source: EvalSource::StaticPolicy,
                    risk: None,
                }
            };
        }

        EvalResult::Deny {
            reason: "no policy and LLM disabled: default-deny".to_string(),
            source: EvalSource::StaticPolicy,
            risk: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::{EvalConfig, EvalResult, EvalSource, Evaluator};
    use crate::gating::deny_shape::DenyShapeStore;
    use crate::learned_rules::{AutoShimMode, LearnedRuleStore};
    use std::sync::Arc;
    use tokio::sync::RwLock;

    #[tokio::test]
    async fn evaluate_with_context_session_prompt_does_not_seed_cache() {
        // LLM disabled and no static rules: every call falls through to
        // the default-deny branch without ever touching the LLM cache
        // path. We exercise the API and assert the cache remains empty.
        let evaluator =
            Evaluator::new(EvalConfig::default().llm_enabled(false)).expect("build evaluator");

        let _ = evaluator
            .evaluate_with_context("ls -la", Some("session is restoring backups"))
            .await;

        let cache = evaluator.cache.as_ref().expect("cache enabled by default");
        assert!(
            cache.read().await.is_empty(),
            "session-prompted call must not seed the cache"
        );
    }

    #[tokio::test]
    async fn deny_only_policy_falls_through_to_llm_on_no_match() {
        // Regression test: a deny-only policy (the documented
        // "fast-reject known-bad, LLM decides the rest" use case, e.g.
        // examples/deny-policy.yaml) must NOT hard-deny a command that
        // matches nothing. Proven here by reaching the LLM stage (which
        // errors for lack of an API key) rather than short-circuiting to a
        // StaticPolicy deny on bare default-deny fallthrough.
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("deny-only.yaml");
        std::fs::write(
            &path,
            "policy:\n  commands:\n    deny:\n      - \"rm -rf /*\"\n",
        )
        .unwrap();

        let evaluator = Evaluator::new(EvalConfig::default().policy_path(path)).unwrap();

        match evaluator.evaluate("ls -la").await {
            EvalResult::Error(msg) => assert!(msg.contains("API key")),
            other => {
                panic!("expected fallthrough to the LLM (and an API-key error), got {other:?}")
            }
        }

        match evaluator.evaluate("rm -rf /*").await {
            EvalResult::Deny { source, reason, .. } => {
                assert_eq!(source, EvalSource::StaticPolicy);
                assert!(reason.contains("deny pattern"));
            }
            other => panic!("expected an explicit deny match to fast-reject, got {other:?}"),
        }
    }

    #[tokio::test]
    async fn allow_only_policy_falls_through_to_llm_on_no_match() {
        // Regression test: an allow-only policy must not deny everything
        // outside the allow list; non-matching commands fall through to the
        // LLM, and allow matches do not skip the LLM either (no LLM-skip
        // glob mechanism is supported while the LLM is enabled -- use
        // `guard verb` for that; see examples/verbs-readonly.yaml).
        let temp = tempfile::tempdir().unwrap();
        let path = temp.path().join("allow-only.yaml");
        std::fs::write(&path, "policy:\n  commands:\n    allow:\n      - \"id\"\n").unwrap();

        let evaluator = Evaluator::new(EvalConfig::default().policy_path(path)).unwrap();

        match evaluator.evaluate("ls -la").await {
            EvalResult::Error(msg) => assert!(msg.contains("API key")),
            other => panic!("expected fallthrough to the LLM, got {other:?}"),
        }
        match evaluator.evaluate("id").await {
            EvalResult::Error(msg) => assert!(msg.contains("API key")),
            other => {
                panic!("allow patterns must not skip the LLM while it is enabled, got {other:?}")
            }
        }
    }

    #[tokio::test]
    async fn learned_rule_observation_does_not_bypass_llm() {
        // A learned-rule observation that crossed the promotion threshold must
        // NOT grant itself an LLM-skipping allow: only the operator, via
        // `guard verb create`, can grant that. With no LLM key configured the
        // call must still reach (and fail in) the LLM path, not short-circuit
        // to an allow from the learned-rule store.
        let temp = tempfile::tempdir().unwrap();
        let mut store = LearnedRuleStore::load(crate::learned_rules::LearningConfig {
            path: temp.path().join("learned.yaml"),
            min_approvals: 1,
            max_risk: 2,
            auto_shim: AutoShimMode::Suggest,
        })
        .unwrap();
        let outcome = store
            .record_approval(
                "opnsense-api",
                &["status".to_string()],
                "opnsense-api status",
                Some(1),
                "safe status lookup",
            )
            .unwrap()
            .unwrap();
        assert!(
            outcome.is_candidate,
            "single approval should cross min_approvals=1"
        );

        let evaluator =
            Evaluator::new(EvalConfig::default().learned_rules(Arc::new(RwLock::new(store))))
                .unwrap();

        let result = evaluator.evaluate("opnsense-api status").await;
        match result {
            EvalResult::Error(msg) => assert!(msg.contains("API key")),
            other => panic!("expected an LLM error (no bypass), got {other:?}"),
        }
    }

    #[tokio::test]
    async fn learned_deny_shape_fast_rejects_without_llm() {
        // A promoted deny shape must fast-reject a matching command without
        // ever reaching the LLM stage. Promote the shape directly (the
        // synthesis LLM call itself is a separate, mocked-free unit boundary
        // covered in gating::deny_shape) and prove the wiring in
        // evaluate_with_context consults it before the LLM path.
        let temp = tempfile::tempdir().unwrap();
        let mut store = DenyShapeStore::load(crate::gating::deny_shape::DenyLearningConfig::new(
            temp.path().join("deny.yaml"),
        ))
        .unwrap();
        store
            .promote_shape(
                "kubectl",
                "kubectl",
                r"^delete namespace \S+$",
                &["delete namespace prod".to_string()],
                "namespace deletion is destructive",
                3,
            )
            .unwrap();

        let evaluator =
            Evaluator::new(EvalConfig::default().deny_shapes(Arc::new(RwLock::new(store))))
                .unwrap();

        match evaluator.evaluate("kubectl delete namespace prod").await {
            EvalResult::Deny { source, reason, .. } => {
                assert_eq!(source, EvalSource::LearnedDeny);
                assert!(reason.contains("namespace deletion is destructive"));
                for forbidden in ["promoted", "learned", "fast path"] {
                    assert!(
                        !reason.to_ascii_lowercase().contains(forbidden),
                        "client-facing deny reason exposed {forbidden}: {reason}"
                    );
                }
            }
            other => panic!("expected a fast-rejected deny with no LLM call, got {other:?}"),
        }

        // A non-matching command for the same binary must not be affected.
        match evaluator.evaluate("kubectl get pods").await {
            EvalResult::Error(msg) => assert!(msg.contains("API key")),
            other => {
                panic!("expected fallthrough to the LLM for a non-matching shape, got {other:?}")
            }
        }
    }

    #[tokio::test]
    async fn reevaluate_flag_skips_only_the_learned_deny_store() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = DenyShapeStore::load(crate::gating::deny_shape::DenyLearningConfig::new(
            temp.path().join("deny.yaml"),
        ))
        .unwrap();
        store
            .promote_shape(
                "kubectl",
                "kubectl",
                r"^delete namespace \S+$",
                &["delete namespace prod".to_string()],
                "namespace deletion is destructive",
                3,
            )
            .unwrap();

        let evaluator = Evaluator::new(
            EvalConfig::default()
                .llm_enabled(false)
                .deny_shapes(Arc::new(RwLock::new(store))),
        )
        .unwrap();

        match evaluator
            .evaluate_with_reevaluate("kubectl delete namespace prod", None, false)
            .await
        {
            EvalResult::Deny { source, .. } => assert_eq!(source, EvalSource::LearnedDeny),
            other => panic!("expected the learned-deny fast path, got {other:?}"),
        }

        // reevaluate=true must skip the auto-learned store; with the LLM
        // disabled and no policy engine, the fallback is a bare default-deny
        // (StaticPolicy), proving the learned-deny check was bypassed.
        match evaluator
            .evaluate_with_reevaluate("kubectl delete namespace prod", None, true)
            .await
        {
            EvalResult::Deny { source, reason, .. } => {
                assert_eq!(source, EvalSource::StaticPolicy);
                assert!(reason.contains("default-deny"));
            }
            other => panic!("expected reevaluate to skip the learned-deny store, got {other:?}"),
        }
    }
}
