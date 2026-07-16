//! Evaluator configuration: LLM connection settings and the builder-style EvalConfig.

use super::cache::{DEFAULT_CACHE_CAPACITY, DEFAULT_CACHE_TTL_SECS};
use crate::gating::allow_promotion::AllowPromotionStore;
use crate::gating::deny_shape::DenyShapeStore;
use crate::gating::GateMode;
use crate::learned_rules::LearnedRuleStore;
use crate::policy::PolicyMode;
use std::path::PathBuf;
use std::sync::Arc;
use std::time::Duration;
use tokio::sync::RwLock;

/// Default model used when no `--llm-model` or `--llm-models` is supplied.
///
/// The user's stated preference is a single call to this model, no fallback, no
/// static policy. Changing this default will change the out-of-the-box behaviour
/// of every daemon, so update deliberately.
const DEFAULT_MODEL: &str = "openai/gpt-5.4-mini";
/// Generous enough for a slow provider cold-start plus a reasoning model's
/// hidden thinking tokens; 10s produced spurious transport timeouts in
/// production.
const DEFAULT_TIMEOUT: u64 = 30;
pub(super) const DEFAULT_API_URL: &str = "https://openrouter.ai/api/v1/chat/completions";
const DEFAULT_RETRIES: u32 = 2;

#[derive(Debug, Clone)]
pub struct LlmConfig {
    pub enabled: bool,
    pub api_key: Option<String>,
    pub api_url: Option<String>,
    /// Primary model slug. Used if `models` is empty.
    pub model: Option<String>,
    /// Optional ordered fallback chain. If non-empty, overrides `model` and is
    /// tried in order. Each model gets its own retry budget (`retries`).
    pub models: Vec<String>,
    pub timeout_secs: u64,
    /// Retries PER model (total attempts = retries + 1, capped at 3).
    pub retries: u32,
}

impl Default for LlmConfig {
    fn default() -> Self {
        Self {
            enabled: true,
            api_key: None,
            api_url: None,
            model: None,
            models: Vec::new(),
            timeout_secs: DEFAULT_TIMEOUT,
            retries: DEFAULT_RETRIES,
        }
    }
}

impl LlmConfig {
    pub fn api_url(&self) -> String {
        self.api_url
            .clone()
            .unwrap_or_else(|| DEFAULT_API_URL.to_string())
    }

    pub fn model(&self) -> String {
        self.model
            .clone()
            .unwrap_or_else(|| DEFAULT_MODEL.to_string())
    }

    /// Returns the ordered chain of models to try. Always contains at least one
    /// entry: if no `models` chain and no `model` is set, falls back to `DEFAULT_MODEL`.
    pub fn model_chain(&self) -> Vec<String> {
        if !self.models.is_empty() {
            self.models.clone()
        } else {
            vec![self.model()]
        }
    }

    pub fn timeout(&self) -> Duration {
        Duration::from_secs(self.timeout_secs)
    }

    /// Retry budget capped at 2 (so total attempts per model <= 3).
    pub fn effective_retries(&self) -> u32 {
        self.retries.min(2)
    }
}

#[derive(Debug, Clone)]
pub struct EvalConfig {
    pub policy_path: Option<PathBuf>,
    pub mode: Option<PolicyMode>,
    pub llm: LlmConfig,
    /// Path to a custom system prompt file. If set, overrides the compiled-in prompt.
    pub system_prompt_path: Option<PathBuf>,
    /// Literal system prompt supplied by code. Used for daemon-owned evaluator
    /// specializations that are not command-line command judges.
    pub system_prompt_literal: Option<String>,
    /// Path to an additive prompt file. Contents are appended to the base prompt
    /// (whether compiled-in or custom), letting operators add environment-specific
    /// instructions without replacing the built-in prompts.
    pub system_prompt_append_path: Option<PathBuf>,
    /// Cache LLM decisions in-memory. Keyed on command line; TTL-bounded.
    /// Disable to force fresh evaluation on every request.
    pub cache_enabled: bool,
    pub cache_capacity: usize,
    pub cache_ttl: Duration,
    /// Consequence-gating mode. When `Consequence`, the evaluator appends the
    /// classification appendix to the system prompt and asks the model for a
    /// reversibility class on every approval. Fixed for the evaluator's
    /// lifetime (the daemon recreates the evaluator if the prompt changes).
    pub gate_mode: GateMode,
    /// Optional learned static allow overlay. Misses fall through to LLM.
    pub learned_rules: Option<Arc<RwLock<LearnedRuleStore>>>,
    /// Optional auto-learned deny-shape store. Unlike `learned_rules`, a hit
    /// here IS an authoritative deny fast path -- see `gating::deny_shape`.
    pub deny_shapes: Option<Arc<RwLock<DenyShapeStore>>>,
    /// Optional auto-verb-promotion observation store -- see
    /// `gating::allow_promotion`. Bookkeeping only; the verb catalog itself
    /// (where a promoted verb actually lands) lives in `server::ServerState`,
    /// not here.
    pub allow_promotion: Option<Arc<RwLock<AllowPromotionStore>>>,
}

impl Default for EvalConfig {
    fn default() -> Self {
        Self {
            policy_path: None,
            mode: None,
            llm: LlmConfig::default(),
            system_prompt_path: None,
            system_prompt_literal: None,
            system_prompt_append_path: None,
            cache_enabled: true,
            cache_capacity: DEFAULT_CACHE_CAPACITY,
            cache_ttl: Duration::from_secs(DEFAULT_CACHE_TTL_SECS),
            gate_mode: GateMode::Off,
            learned_rules: None,
            deny_shapes: None,
            allow_promotion: None,
        }
    }
}

impl EvalConfig {
    pub fn policy_path(mut self, path: PathBuf) -> Self {
        self.policy_path = Some(path);
        self
    }

    pub fn llm_enabled(mut self, enabled: bool) -> Self {
        self.llm.enabled = enabled;
        self
    }

    pub fn mode(mut self, mode: PolicyMode) -> Self {
        self.mode = Some(mode);
        self
    }

    pub fn llm_api_key(mut self, key: String) -> Self {
        self.llm.api_key = Some(key);
        self
    }

    pub fn llm_api_url(mut self, url: String) -> Self {
        self.llm.api_url = Some(url);
        self
    }

    pub fn llm_model(mut self, model: String) -> Self {
        self.llm.model = Some(model);
        self
    }

    pub fn llm_models(mut self, models: Vec<String>) -> Self {
        self.llm.models = models;
        self
    }

    pub fn llm_timeout_secs(mut self, secs: u64) -> Self {
        self.llm.timeout_secs = secs;
        self
    }

    pub fn llm_retries(mut self, retries: u32) -> Self {
        self.llm.retries = retries;
        self
    }

    pub fn system_prompt_path(mut self, path: PathBuf) -> Self {
        self.system_prompt_path = Some(path);
        self.system_prompt_literal = None;
        self
    }

    pub fn system_prompt_literal(mut self, prompt: String) -> Self {
        self.system_prompt_literal = Some(prompt);
        self.system_prompt_path = None;
        self
    }

    pub fn system_prompt_append_path(mut self, path: PathBuf) -> Self {
        self.system_prompt_append_path = Some(path);
        self
    }

    pub fn cache_enabled(mut self, enabled: bool) -> Self {
        self.cache_enabled = enabled;
        self
    }

    pub fn cache_capacity(mut self, capacity: usize) -> Self {
        self.cache_capacity = capacity.max(1);
        self
    }

    pub fn cache_ttl(mut self, ttl: Duration) -> Self {
        self.cache_ttl = ttl;
        self
    }

    pub fn gate_mode(mut self, mode: GateMode) -> Self {
        self.gate_mode = mode;
        self
    }

    pub fn learned_rules(mut self, store: Arc<RwLock<LearnedRuleStore>>) -> Self {
        self.learned_rules = Some(store);
        self
    }

    pub fn allow_promotion(mut self, store: Arc<RwLock<AllowPromotionStore>>) -> Self {
        self.allow_promotion = Some(store);
        self
    }

    pub fn deny_shapes(mut self, store: Arc<RwLock<DenyShapeStore>>) -> Self {
        self.deny_shapes = Some(store);
        self
    }
}

#[cfg(test)]
mod tests {
    use super::{
        EvalConfig, LlmConfig, DEFAULT_API_URL, DEFAULT_MODEL, DEFAULT_RETRIES, DEFAULT_TIMEOUT,
    };
    use std::path::PathBuf;

    #[test]
    fn test_llm_config_defaults() {
        let config = LlmConfig::default();
        assert!(config.enabled);
        assert!(config.api_url.is_none());
        assert!(config.model.is_none());
        assert!(config.models.is_empty());
        assert_eq!(config.timeout_secs, DEFAULT_TIMEOUT);
        assert_eq!(config.model(), DEFAULT_MODEL);
        assert_eq!(config.model(), "openai/gpt-5.4-mini");
        assert_eq!(config.api_url(), DEFAULT_API_URL);
        assert_eq!(config.retries, DEFAULT_RETRIES);
    }

    #[test]
    fn test_llm_config_model_chain_default_single() {
        let config = LlmConfig::default();
        let chain = config.model_chain();
        assert_eq!(chain, vec!["openai/gpt-5.4-mini".to_string()]);
    }

    #[test]
    fn test_llm_config_model_chain_uses_models_when_set() {
        let config = LlmConfig {
            models: vec!["a".into(), "b".into(), "c".into()],
            ..Default::default()
        };
        let chain = config.model_chain();
        assert_eq!(
            chain,
            vec!["a".to_string(), "b".to_string(), "c".to_string()]
        );
    }

    #[test]
    fn test_llm_config_effective_retries_capped() {
        let config = LlmConfig {
            retries: 99,
            ..Default::default()
        };
        assert_eq!(config.effective_retries(), 2);
    }

    #[test]
    fn test_llm_config_builder() {
        let config = LlmConfig {
            enabled: false,
            api_key: Some("test-key".to_string()),
            model: Some("test-model".to_string()),
            ..Default::default()
        };

        assert!(!config.enabled);
        assert_eq!(config.api_key.as_deref(), Some("test-key"));
        assert_eq!(config.model(), "test-model");
    }

    #[test]
    fn test_eval_config_builder() {
        let config = EvalConfig::default()
            .policy_path(PathBuf::from("/test/policy.yaml"))
            .llm_enabled(false)
            .llm_api_key("key".to_string())
            .llm_timeout_secs(30)
            .llm_retries(1)
            .llm_models(vec!["m1".into(), "m2".into()]);

        assert_eq!(
            config.policy_path.as_ref().unwrap().to_str(),
            Some("/test/policy.yaml")
        );
        assert!(!config.llm.enabled);
        assert_eq!(config.llm.api_key.as_deref(), Some("key"));
        assert_eq!(config.llm.timeout_secs, 30);
        assert_eq!(config.llm.retries, 1);
        assert_eq!(config.llm.models.len(), 2);
    }
}
