use crate::learned_rules::{AutoShimMode, LearnedRuleStore, LearningOutcome};
use crate::policy::{PolicyEngine, PolicyMode};
use anyhow::{bail, Context, Result};
use regex::Regex;
use reqwest::Client;
use serde::{Deserialize, Serialize};
use std::collections::HashMap;
use std::path::PathBuf;
use std::sync::{Arc, OnceLock};
use std::time::{Duration, Instant};
use tokio::sync::RwLock;

/// Readonly mode system prompt (read-only-biased evaluation), compiled from
/// config/system-prompt-readonly.md. Override at runtime with
/// `--system-prompt <path>` or `~/.config/guard/system-prompt.txt`.
const SYSTEM_PROMPT_READONLY: &str = include_str!("../config/system-prompt-readonly.md");

/// SAFE mode prompt: allow almost everything, rely on env_clear + output redaction.
const SYSTEM_PROMPT_SAFE: &str = include_str!("../config/system-prompt-safe.md");

/// PARANOID mode prompt: block everything except basic read-only inspection.
const SYSTEM_PROMPT_PARANOID: &str = include_str!("../config/system-prompt-paranoid.md");

/// Default model used when no `--llm-model` or `--llm-models` is supplied.
///
/// The user's stated preference is a single call to this model, no fallback, no
/// static policy. Changing this default will change the out-of-the-box behaviour
/// of every daemon, so update deliberately.
const DEFAULT_MODEL: &str = "openai/gpt-5.4-nano";
const DEFAULT_TIMEOUT: u64 = 10;
const DEFAULT_API_URL: &str = "https://openrouter.ai/api/v1/chat/completions";
const DEFAULT_RETRIES: u32 = 2;

pub const DEFAULT_CACHE_CAPACITY: usize = 1024;
pub const DEFAULT_CACHE_TTL_SECS: u64 = 3600;

/// In-memory cache of evaluator decisions for the stateless per-command path.
///
/// Key: the exact command line that gets evaluated. The cache is owned by a
/// single Evaluator instance; the Evaluator's prompt and mode are fixed for
/// its lifetime, so the command line alone is a sufficient key. Changing
/// the prompt requires recreating the Evaluator, which gets a fresh cache.
///
/// Eviction is FIFO on insertion time — a small LRU would be nicer but the
/// cache is size-bounded and turnover is low, so the extra complexity is
/// not worth it here.
pub struct EvalCache {
    entries: HashMap<String, CacheEntry>,
    capacity: usize,
    ttl: Duration,
}

struct CacheEntry {
    result: CachedResult,
    inserted_at: Instant,
}

#[derive(Clone)]
enum CachedResult {
    Allow { reason: String, risk: Option<i32> },
    Deny { reason: String, risk: Option<i32> },
}

impl CachedResult {
    fn into_eval(self) -> EvalResult {
        match self {
            CachedResult::Allow { reason, risk } => EvalResult::Allow {
                reason,
                source: EvalSource::Cache,
                risk,
            },
            CachedResult::Deny { reason, risk } => EvalResult::Deny {
                reason,
                source: EvalSource::Cache,
                risk,
            },
        }
    }
}

impl EvalCache {
    pub fn new(capacity: usize, ttl: Duration) -> Self {
        Self {
            entries: HashMap::new(),
            capacity: capacity.max(1),
            ttl,
        }
    }

    fn get(&self, key: &str) -> Option<EvalResult> {
        let entry = self.entries.get(key)?;
        if entry.inserted_at.elapsed() >= self.ttl {
            return None;
        }
        Some(entry.result.clone().into_eval())
    }

    fn insert(&mut self, key: String, result: CachedResult) {
        if !self.entries.contains_key(&key) && self.entries.len() >= self.capacity {
            let oldest_key = self
                .entries
                .iter()
                .min_by_key(|(_, e)| e.inserted_at)
                .map(|(k, _)| k.clone());
            if let Some(k) = oldest_key {
                self.entries.remove(&k);
            }
        }
        self.entries.insert(
            key,
            CacheEntry {
                result,
                inserted_at: Instant::now(),
            },
        );
    }

    pub fn len(&self) -> usize {
        self.entries.len()
    }

    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
}

/// Per-attempt backoff schedule (seconds). Index = attempt number (0 = first retry).
/// The initial attempt is not delayed.
const BACKOFF_SECONDS: [f64; 3] = [0.5, 1.5, 4.5];

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
    /// Path to an additive prompt file. Contents are appended to the base prompt
    /// (whether compiled-in or custom), letting operators add environment-specific
    /// instructions without replacing the built-in prompts.
    pub system_prompt_append_path: Option<PathBuf>,
    /// Cache LLM decisions in-memory. Keyed on command line; TTL-bounded.
    /// Disable to force fresh evaluation on every request.
    pub cache_enabled: bool,
    pub cache_capacity: usize,
    pub cache_ttl: Duration,
    /// Optional learned static allow overlay. Misses fall through to LLM.
    pub learned_rules: Option<Arc<RwLock<LearnedRuleStore>>>,
}

impl Default for EvalConfig {
    fn default() -> Self {
        Self {
            policy_path: None,
            mode: None,
            llm: LlmConfig::default(),
            system_prompt_path: None,
            system_prompt_append_path: None,
            cache_enabled: true,
            cache_capacity: DEFAULT_CACHE_CAPACITY,
            cache_ttl: Duration::from_secs(DEFAULT_CACHE_TTL_SECS),
            learned_rules: None,
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

    pub fn learned_rules(mut self, store: Arc<RwLock<LearnedRuleStore>>) -> Self {
        self.learned_rules = Some(store);
        self
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct LlmResponse {
    pub decision: String,
    pub reason: String,
    pub risk: i32,
}

#[derive(Debug, Clone)]
pub enum EvalResult {
    Allow {
        reason: String,
        source: EvalSource,
        risk: Option<i32>,
    },
    Deny {
        reason: String,
        source: EvalSource,
        risk: Option<i32>,
    },
    Error(String),
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum EvalSource {
    StaticPolicy,
    LearnedRule,
    Cache,
    Llm,
}

impl std::fmt::Display for EvalResult {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            EvalResult::Allow { reason, source, .. } => {
                write!(f, "Allow ({:?}): {}", source, reason)
            }
            EvalResult::Deny { reason, source, .. } => {
                write!(f, "Deny ({:?}): {}", source, reason)
            }
            EvalResult::Error(e) => {
                write!(f, "Error: {}", e)
            }
        }
    }
}

impl EvalResult {
    pub fn is_allow(&self) -> bool {
        matches!(self, EvalResult::Allow { .. })
    }

    pub fn is_deny(&self) -> bool {
        matches!(self, EvalResult::Deny { .. })
    }

    pub fn is_error(&self) -> bool {
        matches!(self, EvalResult::Error(_))
    }

    pub fn reason(&self) -> String {
        match self {
            EvalResult::Allow { reason, .. } => reason.clone(),
            EvalResult::Deny { reason, .. } => reason.clone(),
            EvalResult::Error(e) => format!("LLM unavailable: {}", e),
        }
    }

    pub fn risk(&self) -> Option<i32> {
        match self {
            EvalResult::Allow { risk, .. } | EvalResult::Deny { risk, .. } => *risk,
            EvalResult::Error(_) => None,
        }
    }
}

/// Classifies why a single LLM attempt failed, so the retry loop can decide
/// whether to retry at all and whether to downgrade from function-calling to
/// JSON-response-format prompting.
#[derive(Debug)]
enum AttemptError {
    /// 429 from the provider. Carries an optional Retry-After seconds value.
    RateLimited { retry_after: Option<u64> },
    /// Any 5xx from the provider.
    ServerError(String),
    /// Transport-level failure (DNS, TLS, connection reset, timeout).
    Transport(String),
    /// Response parsed but no usable content/tool-call was found, OR a
    /// tool-call's arguments JSON did not match our schema.
    ParseError(String),
    /// 4xx other than 429 (bad request, auth, model-not-found). Not retried.
    ClientError(String),
}

impl std::fmt::Display for AttemptError {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            Self::RateLimited { retry_after } => {
                write!(f, "rate_limited (retry_after={:?})", retry_after)
            }
            Self::ServerError(s) => write!(f, "server_error: {}", s),
            Self::Transport(s) => write!(f, "transport_error: {}", s),
            Self::ParseError(s) => write!(f, "parse_error: {}", s),
            Self::ClientError(s) => write!(f, "client_error: {}", s),
        }
    }
}

impl AttemptError {
    /// Retriable means "try again within the per-model budget". Client errors
    /// (401/403/404) are NOT retriable because retrying with the same key/model
    /// won't help.
    fn is_retriable(&self) -> bool {
        matches!(
            self,
            Self::RateLimited { .. }
                | Self::ServerError(_)
                | Self::Transport(_)
                | Self::ParseError(_)
        )
    }

    fn status_tag(&self) -> &'static str {
        match self {
            Self::RateLimited { .. } => "rate_limited",
            Self::ServerError(_) => "server_error",
            Self::Transport(_) => "transport_error",
            Self::ParseError(_) => "parse_error",
            Self::ClientError(_) => "client_error",
        }
    }
}

pub struct Evaluator {
    policy_engine: Option<PolicyEngine>,
    llm_config: LlmConfig,
    http_client: Client,
    system_prompt: String,
    cache: Option<RwLock<EvalCache>>,
    mode: Option<PolicyMode>,
    learned_rules: Option<Arc<RwLock<LearnedRuleStore>>>,
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

        // Load system prompt. Priority:
        // 1. --system-prompt <path> (explicit override)
        // 2. ~/.config/guard/system-prompt.txt (user customization)
        // 3. Mode-specific compiled prompt (readonly/safe/paranoid)
        let system_prompt = if let Some(ref path) = config.system_prompt_path {
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

        Ok(Self {
            policy_engine,
            llm_config: config.llm,
            http_client,
            system_prompt,
            cache,
            mode: config.mode,
            learned_rules: config.learned_rules,
        })
    }

    pub fn mode(&self) -> Option<PolicyMode> {
        self.mode
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

    async fn ping_llm(&self) -> Result<()> {
        let api_key = self
            .llm_config
            .api_key
            .as_ref()
            .context("API key required")?;

        let url = format!(
            "{}/models",
            self.llm_config
                .api_url
                .as_ref()
                .map(|u| u.trim_end_matches('/').to_string())
                .unwrap_or_else(|| DEFAULT_API_URL
                    .split('/')
                    .take(3)
                    .collect::<Vec<_>>()
                    .join("/"))
        );

        let response = self
            .http_client
            .get(&url)
            .header("Authorization", format!("Bearer {}", api_key))
            .timeout(Duration::from_secs(5))
            .send()
            .await;

        match response {
            Ok(resp) if resp.status().is_success() => {
                tracing::debug!("LLM connectivity check passed");
                Ok(())
            }
            Ok(resp) => {
                let status = resp.status();
                let body = resp.text().await.unwrap_or_default();
                tracing::warn!("LLM API returned {}: {}", status, body);
                Ok(())
            }
            Err(e) => {
                tracing::warn!("LLM connectivity check failed: {}", e);
                Err(e.into())
            }
        }
    }

    pub async fn evaluate(&self, command: &str) -> EvalResult {
        self.evaluate_with_context(command, None).await
    }

    /// Evaluate `command`. If `prompt_append` is provided, append it to the
    /// system prompt for this single LLM call so the evaluator has the
    /// session-specific context. The decision cache is bypassed when a
    /// session prompt is in play, because cached decisions were made under
    /// the base prompt and may not hold under the extended context.
    pub async fn evaluate_with_context(
        &self,
        command: &str,
        prompt_append: Option<&str>,
    ) -> EvalResult {
        let session_prompt_active = prompt_append.map(|s| !s.trim().is_empty()).unwrap_or(false);

        // Only apply static policy if the engine has explicit rules.
        // Empty engines (from modes without a policy file) should not block anything
        // since they'd just default-deny everything before the LLM gets a chance.
        if let Some(ref engine) = self.policy_engine {
            if !engine.deny_list().is_empty() || !engine.allow_list().is_empty() {
                let static_result = engine.check(command);
                if static_result.is_denied() {
                    tracing::debug!("static policy denied: {}", static_result.reason);
                    return EvalResult::Deny {
                        reason: static_result.reason,
                        source: EvalSource::StaticPolicy,
                        risk: None,
                    };
                }
            }
        }

        if !session_prompt_active {
            if let Some(ref learned_rules) = self.learned_rules {
                let hit = {
                    let guard = learned_rules.read().await;
                    guard.check(command)
                };
                if let Some(hit) = hit {
                    let mut reason = format!(
                        "learned static rule: matched `{}` for service `{}`",
                        hit.matched_pattern, hit.service
                    );
                    if let Some(shim) = hit.shim {
                        reason.push_str(&format!(
                            "; prefer shim `{}` for shorter future calls",
                            shim.name
                        ));
                    }
                    return EvalResult::Allow {
                        reason,
                        source: EvalSource::LearnedRule,
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
            if !session_prompt_active {
                if let Some(ref cache) = self.cache {
                    let hit = {
                        let guard = cache.read().await;
                        guard.get(command)
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
            if !session_prompt_active {
                if let Some(ref cache) = self.cache {
                    match &result {
                        EvalResult::Allow { reason, .. } => {
                            let mut guard = cache.write().await;
                            guard.insert(
                                command.to_string(),
                                CachedResult::Allow {
                                    reason: reason.clone(),
                                    risk: result.risk(),
                                },
                            );
                        }
                        EvalResult::Deny { reason, .. } => {
                            let mut guard = cache.write().await;
                            guard.insert(
                                command.to_string(),
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

        if let Some(ref engine) = self.policy_engine {
            let static_result = engine.check(command);
            if static_result.is_allowed() {
                return EvalResult::Allow {
                    reason: static_result.reason,
                    source: EvalSource::StaticPolicy,
                    risk: None,
                };
            }
        }

        EvalResult::Deny {
            reason: "no policy and LLM disabled: default-deny".to_string(),
            source: EvalSource::StaticPolicy,
            risk: None,
        }
    }

    /// Top-level LLM evaluation: walks the model-fallback chain and, per model,
    /// runs the retry loop. The LLM NEVER sees the unredacted command; only the
    /// caller's audit log does.
    #[tracing::instrument(skip(self, command, prompt_append), fields(command_len = command.len()))]
    async fn evaluate_llm(&self, command: &str, prompt_append: Option<&str>) -> EvalResult {
        let api_key = match &self.llm_config.api_key {
            Some(k) => k.clone(),
            None => {
                return EvalResult::Error("LLM API key not configured".to_string());
            }
        };

        // Redact secret-shaped substrings BEFORE the command text enters any LLM
        // payload. The audit log, on the other hand, sees the original — that
        // happens in the caller's layer, not here.
        let redacted_command = redact_for_llm(command);
        if redacted_command != command {
            tracing::info!("redacted secret-shaped content from LLM prompt");
        }

        let api_url = self.llm_config.api_url();
        let chain = self.llm_config.model_chain();

        // Build the per-call system prompt. Session-supplied context is
        // appended after the base prompt so the static guardrails still
        // anchor the evaluator.
        let system_prompt = match prompt_append {
            Some(extra) if !extra.trim().is_empty() => {
                format!("{}\n\nSession context:\n{}", self.system_prompt, extra)
            }
            _ => self.system_prompt.clone(),
        };

        let mut last_error: Option<String> = None;
        for model in &chain {
            match self
                .evaluate_model(&api_key, &api_url, model, &redacted_command, &system_prompt)
                .await
            {
                Ok(decision) => {
                    if decision.decision.eq_ignore_ascii_case("APPROVE") {
                        return EvalResult::Allow {
                            reason: decision.reason,
                            source: EvalSource::Llm,
                            risk: Some(decision.risk),
                        };
                    } else {
                        return EvalResult::Deny {
                            reason: decision.reason,
                            source: EvalSource::Llm,
                            risk: Some(decision.risk),
                        };
                    }
                }
                Err(e) => {
                    tracing::warn!(
                        "model {} exhausted retry budget: {} — trying next in chain",
                        model,
                        e
                    );
                    last_error = Some(format!("{}: {}", model, e));
                }
            }
        }

        EvalResult::Error(
            last_error.unwrap_or_else(|| "LLM chain exhausted without result".to_string()),
        )
    }

    /// Runs one model through the full retry budget. Returns Ok(decision) on the
    /// first successful attempt, or Err once the budget is exhausted.
    #[tracing::instrument(skip(self, api_key, command, system_prompt), fields(model = %model))]
    async fn evaluate_model(
        &self,
        api_key: &str,
        api_url: &str,
        model: &str,
        command: &str,
        system_prompt: &str,
    ) -> Result<LlmResponse, AttemptError> {
        let max_retries = self.llm_config.effective_retries();
        // total attempts = 1 initial + max_retries
        let total_attempts = max_retries + 1;

        let mut last_err: Option<AttemptError> = None;
        for attempt in 0..total_attempts {
            // Decide mode: initial attempt uses function-calling; once a parse-error
            // retry happens we switch that model to JSON-response-format mode.
            let use_function_calling =
                attempt == 0 || !matches!(last_err, Some(AttemptError::ParseError(_)));

            // Backoff before retries (not before the first attempt).
            if attempt > 0 {
                // If the previous error was a 429 with Retry-After, prefer that.
                let delay = if let Some(AttemptError::RateLimited {
                    retry_after: Some(s),
                }) = &last_err
                {
                    Duration::from_secs(*s)
                } else {
                    let idx = ((attempt - 1) as usize).min(BACKOFF_SECONDS.len() - 1);
                    let base = BACKOFF_SECONDS[idx];
                    // Jitter: +/- 20%. rand::random() returns f64 in [0,1).
                    let r: f64 = rand::random();
                    let jitter = (r - 0.5) * 0.4;
                    Duration::from_secs_f64(base * (1.0 + jitter))
                };
                tokio::time::sleep(delay).await;
            }

            let attempt_num = attempt + 1;
            tracing::info!(
                model = %model,
                attempt = attempt_num,
                mode = if use_function_calling { "function_calling" } else { "json_format" },
                "LLM attempt start",
            );

            let result = self
                .one_attempt(
                    api_key,
                    api_url,
                    model,
                    command,
                    system_prompt,
                    use_function_calling,
                )
                .await;

            match result {
                Ok((decision, usage)) => {
                    log_usage(model, attempt_num, &usage, "ok");
                    tracing::info!(
                        model = %model,
                        attempt = attempt_num,
                        "LLM attempt succeeded"
                    );
                    return Ok(decision);
                }
                Err(e) => {
                    let status_tag = e.status_tag();
                    // Log failed attempt usage (zero tokens we know of; still visible in audit).
                    log_usage(model, attempt_num, &TokenUsage::default(), status_tag);
                    tracing::info!(
                        model = %model,
                        attempt = attempt_num,
                        "LLM attempt failed: {}",
                        e
                    );

                    if !e.is_retriable() || attempt_num == total_attempts {
                        return Err(e);
                    }
                    last_err = Some(e);
                }
            }
        }

        Err(last_err.unwrap_or_else(|| AttemptError::Transport("unknown failure".to_string())))
    }

    /// One HTTP round-trip to the provider. Returns the parsed decision on success,
    /// or a classified AttemptError.
    async fn one_attempt(
        &self,
        api_key: &str,
        api_url: &str,
        model: &str,
        command: &str,
        system_prompt: &str,
        use_function_calling: bool,
    ) -> Result<(LlmResponse, TokenUsage), AttemptError> {
        let body = if use_function_calling {
            build_function_call_body(model, system_prompt, command)
        } else {
            build_json_response_body(model, system_prompt, command)
        };

        tracing::debug!("LLM POST {}: model={}", api_url, model);

        let response = self
            .http_client
            .post(api_url)
            .header("Authorization", format!("Bearer {}", api_key))
            .header("Content-Type", "application/json")
            .json(&body)
            .send()
            .await
            .map_err(|e| AttemptError::Transport(e.to_string()))?;

        let status = response.status();

        // Extract Retry-After before consuming the body
        let retry_after = response
            .headers()
            .get(reqwest::header::RETRY_AFTER)
            .and_then(|v| v.to_str().ok())
            .and_then(|s| s.parse::<u64>().ok());

        let response_text = response
            .text()
            .await
            .map_err(|e| AttemptError::Transport(e.to_string()))?;

        if status.as_u16() == 429 {
            return Err(AttemptError::RateLimited { retry_after });
        }
        if status.is_server_error() {
            return Err(AttemptError::ServerError(format!(
                "{}: {}",
                status,
                truncate(&response_text, 200)
            )));
        }
        if status.is_client_error() {
            return Err(AttemptError::ClientError(format!(
                "{}: {}",
                status,
                truncate(&response_text, 200)
            )));
        }
        if !status.is_success() {
            return Err(AttemptError::Transport(format!(
                "unexpected status {}: {}",
                status,
                truncate(&response_text, 200)
            )));
        }

        let parsed: serde_json::Value = serde_json::from_str(&response_text)
            .map_err(|e| AttemptError::ParseError(format!("non-JSON response: {}", e)))?;

        let usage = extract_usage(&parsed);

        let decision = if use_function_calling {
            parse_tool_call(&parsed)
        } else {
            parse_json_content(&parsed)
        }
        .map_err(|e| AttemptError::ParseError(e.to_string()))?;

        Ok((decision, usage))
    }
}

/// Token usage metrics from the provider response.
#[derive(Debug, Clone, Copy, Default)]
struct TokenUsage {
    prompt: u64,
    completion: u64,
    total: u64,
}

fn extract_usage(parsed: &serde_json::Value) -> TokenUsage {
    let Some(usage) = parsed.get("usage") else {
        return TokenUsage::default();
    };
    TokenUsage {
        prompt: usage
            .get("prompt_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        completion: usage
            .get("completion_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
        total: usage
            .get("total_tokens")
            .and_then(|v| v.as_u64())
            .unwrap_or(0),
    }
}

fn log_usage(model: &str, attempt: u32, usage: &TokenUsage, status: &str) {
    tracing::info!(
        "[LLM_USAGE] model={} attempt={} prompt_tokens={} completion_tokens={} total_tokens={} status={}",
        model,
        attempt,
        usage.prompt,
        usage.completion,
        usage.total,
        status,
    );
}

fn truncate(s: &str, max: usize) -> String {
    if s.len() <= max {
        s.to_string()
    } else {
        format!("{}...", &s[..max])
    }
}

/// Build the OpenAI-compatible body for a function-calling request. The evaluator
/// defines exactly one tool, `decide`, with a strict schema, and forces the model
/// to call it via `tool_choice`.
fn build_function_call_body(model: &str, system_prompt: &str, command: &str) -> serde_json::Value {
    let user_message = format!("Command: {}", command);
    serde_json::json!({
        "model": model,
        "max_tokens": 512,
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message}
        ],
        "tools": [{
            "type": "function",
            "function": {
                "name": "decide",
                "description": "Record the authorization decision for the command",
                "parameters": {
                    "type": "object",
                    "properties": {
                        "decision": {
                            "type": "string",
                            "enum": ["APPROVE", "DENY"],
                            "description": "APPROVE if the command is allowed under the active mode policy, DENY if the active mode policy blocks it"
                        },
                        "reason": {
                            "type": "string",
                            "description": "Brief explanation of the decision (one sentence)"
                        },
                        "risk": {
                            "type": "integer",
                            "minimum": 0,
                            "maximum": 10,
                            "description": "Risk score from 0 (completely safe) to 10 (catastrophic)"
                        }
                    },
                    "required": ["decision", "reason", "risk"],
                    "additionalProperties": false
                }
            }
        }],
        "tool_choice": {"type": "function", "function": {"name": "decide"}}
    })
}

/// Build the request body for the fallback path: tell the model to emit a bare
/// JSON object and parse it tolerantly. Used after a parse-error retry or when
/// the provider does not support function calling.
fn build_json_response_body(model: &str, system_prompt: &str, command: &str) -> serde_json::Value {
    let user_message = format!(
        "Command: {}\n\nRespond with ONLY a JSON object matching this schema (no prose, no markdown):\n{{\"decision\": \"APPROVE\" or \"DENY\", \"reason\": \"brief\", \"risk\": 0-10}}",
        command
    );
    serde_json::json!({
        "model": model,
        "max_tokens": 512,
        "response_format": {"type": "json_object"},
        "messages": [
            {"role": "system", "content": system_prompt},
            {"role": "user", "content": user_message}
        ]
    })
}

/// Parse a function-calling response: `choices[0].message.tool_calls[0].function.arguments`
/// is a JSON string that must match the `decide` schema.
fn parse_tool_call(parsed: &serde_json::Value) -> Result<LlmResponse> {
    let tool_calls = parsed
        .pointer("/choices/0/message/tool_calls")
        .and_then(|v| v.as_array())
        .ok_or_else(|| anyhow::anyhow!("no tool_calls in response"))?;

    let tool_call = tool_calls
        .first()
        .ok_or_else(|| anyhow::anyhow!("empty tool_calls array"))?;

    let fn_name = tool_call
        .pointer("/function/name")
        .and_then(|v| v.as_str())
        .unwrap_or("");

    if fn_name != "decide" {
        bail!("unexpected tool call: {}", fn_name);
    }

    let args_str = tool_call
        .pointer("/function/arguments")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("no arguments in tool call"))?;

    // Tool-call arguments are always a JSON string in the OpenAI protocol; parse
    // strictly first, fall back to lax for small model deviations.
    let value: serde_json::Value = match serde_json::from_str(args_str) {
        Ok(v) => v,
        Err(_) => {
            let relaxed = lax_extract_json(args_str)?;
            serde_json::from_str(&relaxed)
                .with_context(|| format!("failed to parse tool arguments: {}", args_str))?
        }
    };

    decision_from_value(&value)
}

/// Parse a JSON-response-format message: `choices[0].message.content` should be
/// a JSON object, but small models often wrap it in markdown fences or prose.
fn parse_json_content(parsed: &serde_json::Value) -> Result<LlmResponse> {
    let content = parsed
        .pointer("/choices/0/message/content")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("no content in response"))?;

    if content.trim().is_empty() {
        bail!("empty content in response");
    }

    let extracted = lax_extract_json(content)?;
    let value: serde_json::Value = serde_json::from_str(&extracted)
        .with_context(|| format!("failed to parse extracted JSON: {}", extracted))?;
    decision_from_value(&value)
}

/// Build an LlmResponse from a parsed JSON value, accepting decision values
/// case-insensitively (APPROVE/approve/Approve → APPROVE) and coercing a
/// missing/invalid risk to 5.
fn decision_from_value(value: &serde_json::Value) -> Result<LlmResponse> {
    let decision_raw = value
        .get("decision")
        .and_then(|v| v.as_str())
        .ok_or_else(|| anyhow::anyhow!("missing 'decision' field"))?;
    let decision = match decision_raw.trim().to_ascii_uppercase().as_str() {
        "APPROVE" => "APPROVE".to_string(),
        "DENY" => "DENY".to_string(),
        other => bail!("invalid decision value: '{}'", other),
    };

    let reason = value
        .get("reason")
        .and_then(|v| v.as_str())
        .unwrap_or("")
        .to_string();

    let risk = value.get("risk").and_then(|v| v.as_i64()).unwrap_or(5) as i32;

    Ok(LlmResponse {
        decision,
        reason,
        risk,
    })
}

/// Lax JSON extractor: strips markdown fences, finds the first balanced `{...}`
/// substring, and patches common small-model mistakes (trailing commas, unquoted
/// keys) before attempting a permissive parse.
///
/// Returns a stringified JSON object that `serde_json::from_str` will accept, or
/// an error if no plausible object can be recovered.
fn lax_extract_json(text: &str) -> Result<String> {
    // 1. Strip markdown code fences.
    let stripped = strip_markdown_fences(text);

    // 2. Strict parse first.
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&stripped) {
        return serde_json::to_string(&v).map_err(|e| anyhow::anyhow!(e));
    }

    // 3. Find the first balanced {...} substring.
    let Some(candidate) = find_balanced_object(&stripped) else {
        bail!("no JSON object found in: {}", truncate(&stripped, 120));
    };

    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&candidate) {
        return serde_json::to_string(&v).map_err(|e| anyhow::anyhow!(e));
    }

    // 4. Permissive patches: strip trailing commas, quote bare keys.
    let patched = permissive_patch(&candidate);
    if let Ok(v) = serde_json::from_str::<serde_json::Value>(&patched) {
        return serde_json::to_string(&v).map_err(|e| anyhow::anyhow!(e));
    }

    bail!("could not recover JSON from: {}", truncate(&candidate, 120))
}

fn strip_markdown_fences(text: &str) -> String {
    let t = text.trim();
    if let Some(rest) = t.strip_prefix("```json") {
        return rest.trim_end_matches("```").trim().to_string();
    }
    if let Some(rest) = t.strip_prefix("```JSON") {
        return rest.trim_end_matches("```").trim().to_string();
    }
    if let Some(rest) = t.strip_prefix("```") {
        return rest.trim_end_matches("```").trim().to_string();
    }
    t.to_string()
}

/// Find the first `{` and walk forward matching braces (respecting string
/// boundaries) until the outermost brace is closed. Returns the inclusive slice.
fn find_balanced_object(text: &str) -> Option<String> {
    let bytes = text.as_bytes();
    let start = bytes.iter().position(|&b| b == b'{')?;
    let mut depth = 0i32;
    let mut in_string = false;
    let mut escape = false;
    for (i, &b) in bytes.iter().enumerate().skip(start) {
        if in_string {
            if escape {
                escape = false;
            } else if b == b'\\' {
                escape = true;
            } else if b == b'"' {
                in_string = false;
            }
            continue;
        }
        match b {
            b'"' => in_string = true,
            b'{' => depth += 1,
            b'}' => {
                depth -= 1;
                if depth == 0 {
                    return Some(text[start..=i].to_string());
                }
            }
            _ => {}
        }
    }
    None
}

/// Patch common small-model JSON mistakes so serde_json can parse:
/// - Strip trailing commas before `}` or `]`
/// - Quote unquoted keys like `{decision: "APPROVE"}` → `{"decision": "APPROVE"}`
fn permissive_patch(text: &str) -> String {
    let (trailing_comma, unquoted_key) = permissive_patterns();
    let step1 = trailing_comma.replace_all(text, "$1");
    let step2 = unquoted_key.replace_all(&step1, r#"$1"$2":"#);
    step2.into_owned()
}

fn permissive_patterns() -> &'static (Regex, Regex) {
    static P: OnceLock<(Regex, Regex)> = OnceLock::new();
    P.get_or_init(|| {
        (
            Regex::new(r",(\s*[}\]])").expect("valid regex"),
            Regex::new(r"([\{,]\s*)([A-Za-z_][A-Za-z0-9_]*)\s*:").expect("valid regex"),
        )
    })
}

/// Credential/secret patterns redacted from command text BEFORE it is sent to
/// the LLM. The audit log still sees the original command — redaction is a
/// pre-LLM transform, not an output transform.
///
/// Any match is replaced with `[REDACTED]`. Patterns are conservative: the AWS
/// secret-key pattern in particular only fires when paired with a `secret`
/// context word nearby, because bare 40-char base64 is common in totally benign
/// commands.
fn llm_redaction_patterns() -> &'static Vec<(Regex, &'static str)> {
    static P: OnceLock<Vec<(Regex, &str)>> = OnceLock::new();
    P.get_or_init(|| {
        vec![
            // PEM blocks (any type). Dotall via (?s).
            (
                Regex::new(r"(?s)-----BEGIN [A-Z ]+-----.*?-----END [A-Z ]+-----")
                    .expect("valid regex"),
                "[REDACTED]",
            ),
            // OpenRouter-style key (more specific prefix than OpenAI, so match first).
            (
                Regex::new(r"sk-or-[A-Za-z0-9_-]{30,}").expect("valid regex"),
                "[REDACTED]",
            ),
            // Anthropic-style key.
            (
                Regex::new(r"sk-ant-[A-Za-z0-9_-]{30,}").expect("valid regex"),
                "[REDACTED]",
            ),
            // OpenAI-style key (generic sk- prefix).
            (
                Regex::new(r"sk-[A-Za-z0-9_-]{30,}").expect("valid regex"),
                "[REDACTED]",
            ),
            // AWS Access Key ID.
            (
                Regex::new(r"AKIA[0-9A-Z]{16}").expect("valid regex"),
                "[REDACTED]",
            ),
            // Generic JWT (3-segment, eyJ header).
            (
                Regex::new(r"eyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+")
                    .expect("valid regex"),
                "[REDACTED]",
            ),
            // Bearer tokens.
            (
                Regex::new(r"Bearer\s+[A-Za-z0-9._~+/-]{20,}").expect("valid regex"),
                "Bearer [REDACTED]",
            ),
            // AWS secret access key: only when paired with a `secret` context.
            // Matches `aws_secret_access_key=<40 base64/+/ chars>` or similar.
            (
                Regex::new(r"(?i)(secret[_a-z]*\s*[=:]\s*['\x22]?)([A-Za-z0-9/+]{40})")
                    .expect("valid regex"),
                "${1}[REDACTED]",
            ),
        ]
    })
}

/// Apply pre-LLM redaction to a command string.
pub fn redact_for_llm(command: &str) -> String {
    let mut result = command.to_string();
    for (pattern, replacement) in llm_redaction_patterns() {
        result = pattern.replace_all(&result, *replacement).to_string();
    }
    result
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn cache_hit_returns_cached_allow() {
        let mut cache = EvalCache::new(4, Duration::from_secs(60));
        cache.insert(
            "ls -la".to_string(),
            CachedResult::Allow {
                reason: "inspection".to_string(),
                risk: Some(1),
            },
        );
        match cache.get("ls -la") {
            Some(EvalResult::Allow { reason, .. }) => assert_eq!(reason, "inspection"),
            other => panic!("expected cached Allow, got {:?}", other),
        }
    }

    #[test]
    fn cache_miss_returns_none() {
        let cache = EvalCache::new(4, Duration::from_secs(60));
        assert!(cache.get("ls -la").is_none());
    }

    #[test]
    fn cache_ttl_expires_entry() {
        let mut cache = EvalCache::new(4, Duration::from_millis(10));
        cache.insert(
            "ls".to_string(),
            CachedResult::Allow {
                reason: "ok".to_string(),
                risk: Some(1),
            },
        );
        std::thread::sleep(Duration::from_millis(20));
        assert!(cache.get("ls").is_none(), "entry should have expired");
    }

    #[test]
    fn cache_evicts_oldest_when_full() {
        let mut cache = EvalCache::new(2, Duration::from_secs(60));
        cache.insert(
            "a".into(),
            CachedResult::Allow {
                reason: "a".into(),
                risk: Some(1),
            },
        );
        std::thread::sleep(Duration::from_millis(2));
        cache.insert(
            "b".into(),
            CachedResult::Allow {
                reason: "b".into(),
                risk: Some(1),
            },
        );
        std::thread::sleep(Duration::from_millis(2));
        cache.insert(
            "c".into(),
            CachedResult::Allow {
                reason: "c".into(),
                risk: Some(1),
            },
        );

        assert!(cache.get("a").is_none(), "oldest should have been evicted");
        assert!(cache.get("b").is_some());
        assert!(cache.get("c").is_some());
        assert_eq!(cache.len(), 2);
    }

    #[test]
    fn cache_caches_both_allow_and_deny() {
        let mut cache = EvalCache::new(4, Duration::from_secs(60));
        cache.insert(
            "ok".into(),
            CachedResult::Allow {
                reason: "ok".into(),
                risk: Some(1),
            },
        );
        cache.insert(
            "bad".into(),
            CachedResult::Deny {
                reason: "bad".into(),
                risk: Some(9),
            },
        );
        assert!(matches!(cache.get("ok"), Some(EvalResult::Allow { .. })));
        assert!(matches!(cache.get("bad"), Some(EvalResult::Deny { .. })));
    }

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
    async fn learned_rule_allow_bypasses_missing_llm_key() {
        let temp = tempfile::tempdir().unwrap();
        let mut store = LearnedRuleStore::load(crate::learned_rules::LearningConfig {
            path: temp.path().join("learned.yaml"),
            min_approvals: 1,
            max_risk: 2,
            auto_shim: AutoShimMode::Suggest,
        })
        .unwrap();
        store
            .record_approval(
                "opnsense-api",
                &["status".to_string()],
                "opnsense-api status",
                Some(1),
                "safe status lookup",
            )
            .unwrap();

        let evaluator =
            Evaluator::new(EvalConfig::default().learned_rules(Arc::new(RwLock::new(store))))
                .unwrap();

        let result = evaluator.evaluate("opnsense-api status").await;
        match result {
            EvalResult::Allow { source, reason, .. } => {
                assert_eq!(source, EvalSource::LearnedRule);
                assert!(reason.contains("learned static rule"));
            }
            other => panic!("expected learned allow, got {other:?}"),
        }
    }

    #[test]
    fn test_eval_result_display() {
        let allow = EvalResult::Allow {
            reason: "test".to_string(),
            source: EvalSource::Llm,
            risk: Some(1),
        };
        assert!(allow.to_string().contains("Allow"));
        assert!(allow.to_string().contains("Llm"));

        let deny = EvalResult::Deny {
            reason: "test".to_string(),
            source: EvalSource::StaticPolicy,
            risk: None,
        };
        assert!(deny.to_string().contains("Deny"));
        assert!(deny.to_string().contains("StaticPolicy"));

        let err = EvalResult::Error("test error".to_string());
        assert!(err.to_string().contains("Error"));
        assert!(err.to_string().contains("test error"));
    }

    #[test]
    fn test_eval_result_helpers() {
        let allow = EvalResult::Allow {
            reason: "test".to_string(),
            source: EvalSource::Llm,
            risk: Some(1),
        };
        assert!(allow.is_allow());
        assert!(!allow.is_deny());
        assert!(!allow.is_error());

        let deny = EvalResult::Deny {
            reason: "test".to_string(),
            source: EvalSource::StaticPolicy,
            risk: None,
        };
        assert!(!deny.is_allow());
        assert!(deny.is_deny());
        assert!(!deny.is_error());

        let err = EvalResult::Error("test".to_string());
        assert!(!err.is_allow());
        assert!(!err.is_deny());
        assert!(err.is_error());
    }

    #[test]
    fn test_llm_config_defaults() {
        let config = LlmConfig::default();
        assert!(config.enabled);
        assert!(config.api_url.is_none());
        assert!(config.model.is_none());
        assert!(config.models.is_empty());
        assert_eq!(config.timeout_secs, DEFAULT_TIMEOUT);
        assert_eq!(config.model(), DEFAULT_MODEL);
        assert_eq!(config.model(), "openai/gpt-5.4-nano");
        assert_eq!(config.api_url(), DEFAULT_API_URL);
        assert_eq!(config.retries, DEFAULT_RETRIES);
    }

    #[test]
    fn test_llm_config_model_chain_default_single() {
        let config = LlmConfig::default();
        let chain = config.model_chain();
        assert_eq!(chain, vec!["openai/gpt-5.4-nano".to_string()]);
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

    // --- Lax parser tests ---

    #[test]
    fn test_lax_extract_json_direct() {
        let s = r#"{"decision":"APPROVE","reason":"safe","risk":1}"#;
        let out = lax_extract_json(s).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["decision"], "APPROVE");
    }

    #[test]
    fn test_lax_extract_json_markdown_wrapped() {
        let s = "```json\n{\"decision\": \"DENY\", \"reason\": \"nope\", \"risk\": 9}\n```";
        let out = lax_extract_json(s).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["decision"], "DENY");
        assert_eq!(v["risk"], 9);
    }

    #[test]
    fn test_lax_extract_json_plain_fence() {
        let s = "```\n{\"decision\": \"APPROVE\", \"reason\": \"ok\", \"risk\": 2}\n```";
        let out = lax_extract_json(s).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["decision"], "APPROVE");
    }

    #[test]
    fn test_lax_extract_json_with_prose() {
        let s = r#"Sure! Here is the answer: {"decision": "DENY", "reason": "bad", "risk": 8} — hope that helps."#;
        let out = lax_extract_json(s).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["decision"], "DENY");
    }

    #[test]
    fn test_lax_extract_json_trailing_comma() {
        let s = r#"{"decision": "APPROVE", "reason": "ok", "risk": 1,}"#;
        let out = lax_extract_json(s).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["decision"], "APPROVE");
    }

    #[test]
    fn test_lax_extract_json_unquoted_keys() {
        let s = r#"{decision: "DENY", reason: "dangerous", risk: 10}"#;
        let out = lax_extract_json(s).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["decision"], "DENY");
        assert_eq!(v["risk"], 10);
    }

    #[test]
    fn test_lax_extract_json_nested_object_balanced() {
        // The outer braces contain a nested object; extractor must capture the
        // outermost balanced pair, not stop at the first `}`.
        let s = r#"{"decision": "APPROVE", "reason": "ok", "risk": 1, "meta": {"k": "v"}}"#;
        let out = lax_extract_json(s).unwrap();
        let v: serde_json::Value = serde_json::from_str(&out).unwrap();
        assert_eq!(v["decision"], "APPROVE");
    }

    #[test]
    fn test_lax_extract_json_invalid_errors() {
        assert!(lax_extract_json("not json at all, no braces").is_err());
    }

    #[test]
    fn test_decision_from_value_case_insensitive() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"decision":"approve","reason":"ok","risk":1}"#).unwrap();
        let d = decision_from_value(&v).unwrap();
        assert_eq!(d.decision, "APPROVE");

        let v: serde_json::Value =
            serde_json::from_str(r#"{"decision":"Deny","reason":"no","risk":9}"#).unwrap();
        let d = decision_from_value(&v).unwrap();
        assert_eq!(d.decision, "DENY");
    }

    #[test]
    fn test_decision_from_value_missing_risk() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"decision":"APPROVE","reason":"ok"}"#).unwrap();
        let d = decision_from_value(&v).unwrap();
        assert_eq!(d.risk, 5);
    }

    #[test]
    fn test_decision_from_value_rejects_garbage() {
        let v: serde_json::Value =
            serde_json::from_str(r#"{"decision":"MAYBE","reason":"hm","risk":3}"#).unwrap();
        assert!(decision_from_value(&v).is_err());
    }

    // --- Tool-call parser tests ---

    #[test]
    fn test_parse_tool_call_success() {
        let resp: serde_json::Value = serde_json::from_str(
            r#"{
                "choices": [{
                    "message": {
                        "tool_calls": [{
                            "id": "call_abc",
                            "type": "function",
                            "function": {
                                "name": "decide",
                                "arguments": "{\"decision\":\"APPROVE\",\"reason\":\"safe\",\"risk\":1}"
                            }
                        }]
                    }
                }]
            }"#,
        )
        .unwrap();
        let d = parse_tool_call(&resp).unwrap();
        assert_eq!(d.decision, "APPROVE");
        assert_eq!(d.risk, 1);
    }

    #[test]
    fn test_parse_tool_call_no_tool_calls() {
        let resp: serde_json::Value =
            serde_json::from_str(r#"{"choices":[{"message":{"content":"something"}}]}"#).unwrap();
        assert!(parse_tool_call(&resp).is_err());
    }

    #[test]
    fn test_parse_tool_call_wrong_function_name() {
        let resp: serde_json::Value = serde_json::from_str(
            r#"{
                "choices": [{
                    "message": {
                        "tool_calls": [{
                            "function": {"name": "other", "arguments": "{}"}
                        }]
                    }
                }]
            }"#,
        )
        .unwrap();
        assert!(parse_tool_call(&resp).is_err());
    }

    #[test]
    fn test_parse_json_content_success() {
        let resp: serde_json::Value = serde_json::from_str(
            r#"{"choices":[{"message":{"content":"{\"decision\":\"DENY\",\"reason\":\"bad\",\"risk\":9}"}}]}"#,
        )
        .unwrap();
        let d = parse_json_content(&resp).unwrap();
        assert_eq!(d.decision, "DENY");
    }

    #[test]
    fn test_parse_json_content_markdown_wrapped() {
        let resp: serde_json::Value = serde_json::from_str(
            r#"{"choices":[{"message":{"content":"```json\n{\"decision\":\"APPROVE\",\"reason\":\"ok\",\"risk\":2}\n```"}}]}"#,
        )
        .unwrap();
        let d = parse_json_content(&resp).unwrap();
        assert_eq!(d.decision, "APPROVE");
    }

    #[test]
    fn test_parse_json_content_empty() {
        let resp: serde_json::Value =
            serde_json::from_str(r#"{"choices":[{"message":{"content":""}}]}"#).unwrap();
        assert!(parse_json_content(&resp).is_err());
    }

    // --- Redaction tests ---

    #[test]
    fn test_redact_for_llm_openai_key() {
        let s = "curl -H 'Authorization: Bearer sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEF'";
        let r = redact_for_llm(s);
        assert!(!r.contains("sk-abcdef"), "got: {r}");
        assert!(r.contains("[REDACTED]"));
    }

    #[test]
    fn test_redact_for_llm_openrouter_key() {
        let s = "echo sk-or-v1-abcdefghijklmnopqrstuvwxyz0123456789ABCDEF0123456789";
        let r = redact_for_llm(s);
        assert!(!r.contains("sk-or-v1-abcdef"));
        assert!(r.contains("[REDACTED]"));
    }

    #[test]
    fn test_redact_for_llm_anthropic_key() {
        let s = "export KEY=sk-ant-api03-abcdefghijklmnopqrstuvwxyz0123456789ABCDEF";
        let r = redact_for_llm(s);
        assert!(!r.contains("sk-ant-api03"));
        assert!(r.contains("[REDACTED]"));
    }

    #[test]
    fn test_redact_for_llm_aws_access_key_id() {
        let s = "aws configure set aws_access_key_id AKIAIOSFODNN7EXAMPLE";
        let r = redact_for_llm(s);
        assert!(!r.contains("AKIAIOSFODNN7EXAMPLE"));
        assert!(r.contains("[REDACTED]"));
    }

    #[test]
    fn test_redact_for_llm_aws_secret_with_context() {
        // Only redact the 40-char base64 when paired with a `secret` context
        let s = "aws_secret_access_key=wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY";
        let r = redact_for_llm(s);
        assert!(!r.contains("wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY"));
        assert!(r.contains("[REDACTED]"));
    }

    #[test]
    fn test_redact_for_llm_jwt() {
        let s = "curl -H 'Authorization: Bearer eyJhbGciOiJIUzI1NiJ9.eyJzdWIiOiIxMjM0NTY3ODkwIn0.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c'";
        let r = redact_for_llm(s);
        assert!(!r.contains("eyJhbGciOi"));
        assert!(r.contains("[REDACTED]"));
    }

    #[test]
    fn test_redact_for_llm_pem_block() {
        let s = "echo '-----BEGIN RSA PRIVATE KEY-----\nMIIEpAIBAAKC...\n-----END RSA PRIVATE KEY-----' > /tmp/k";
        let r = redact_for_llm(s);
        assert!(!r.contains("MIIEpAIBAAKC"));
        assert!(r.contains("[REDACTED]"));
    }

    #[test]
    fn test_redact_for_llm_bearer_standalone() {
        let s = "Authorization: Bearer ghp_abcdefghijklmnopqrstuvwxyz012345";
        let r = redact_for_llm(s);
        assert!(!r.contains("ghp_abcdefghij"));
        assert!(r.contains("[REDACTED]"));
    }

    #[test]
    fn test_redact_for_llm_leaves_benign_text_alone() {
        let s = "ls -la /etc/passwd && cat /etc/hostname";
        let r = redact_for_llm(s);
        assert_eq!(r, s);
    }

    #[test]
    fn test_redact_for_llm_idempotent() {
        let s = "curl -H 'Authorization: Bearer sk-abcdefghijklmnopqrstuvwxyz0123456789ABCDEF'";
        let r1 = redact_for_llm(s);
        let r2 = redact_for_llm(&r1);
        assert_eq!(r1, r2);
    }

    // --- Retry loop tests using a mock HTTP server ---

    async fn mock_server_evaluator(port: u16, retries: u32, models: Vec<String>) -> Evaluator {
        let mut config = EvalConfig::default()
            .llm_api_key("test-key".to_string())
            .llm_api_url(format!("http://127.0.0.1:{}", port))
            .llm_timeout_secs(5)
            .llm_retries(retries);
        if !models.is_empty() {
            config = config.llm_models(models);
        }
        Evaluator::new(config).expect("evaluator")
    }

    /// A one-shot tokio-based HTTP mock. Serves a sequence of (status, body,
    /// content-type) tuples and then closes.
    async fn run_mock(
        listener: tokio::net::TcpListener,
        responses: Vec<(u16, String, Option<String>)>,
    ) {
        use tokio::io::{AsyncReadExt, AsyncWriteExt};
        let mut idx = 0;
        while idx < responses.len() {
            let (mut stream, _) = match listener.accept().await {
                Ok(s) => s,
                Err(_) => return,
            };
            // Read request headers until CRLF CRLF, plus any content-length body.
            let mut buf = Vec::with_capacity(4096);
            let mut tmp = [0u8; 2048];
            while let Ok(n) = stream.read(&mut tmp).await {
                if n == 0 {
                    break;
                }
                buf.extend_from_slice(&tmp[..n]);
                if let Some(pos) = find_subslice(&buf, b"\r\n\r\n") {
                    let headers = String::from_utf8_lossy(&buf[..pos]);
                    let mut content_length = 0usize;
                    for line in headers.split("\r\n") {
                        if let Some(v) = line.strip_prefix("Content-Length: ") {
                            content_length = v.trim().parse().unwrap_or(0);
                        } else if let Some(v) = line.strip_prefix("content-length: ") {
                            content_length = v.trim().parse().unwrap_or(0);
                        }
                    }
                    let body_so_far = buf.len() - pos - 4;
                    if body_so_far >= content_length {
                        break;
                    }
                }
            }

            let (status, body, retry_after) = &responses[idx];
            idx += 1;
            let status_text = match status {
                200 => "OK",
                429 => "Too Many Requests",
                500 => "Internal Server Error",
                _ => "Status",
            };
            let mut resp = format!(
                "HTTP/1.1 {} {}\r\nContent-Type: application/json\r\nContent-Length: {}\r\n",
                status,
                status_text,
                body.len()
            );
            if let Some(ra) = retry_after {
                resp.push_str(&format!("Retry-After: {}\r\n", ra));
            }
            resp.push_str("Connection: close\r\n\r\n");
            resp.push_str(body);
            let _ = stream.write_all(resp.as_bytes()).await;
            let _ = stream.shutdown().await;
        }
    }

    fn find_subslice(haystack: &[u8], needle: &[u8]) -> Option<usize> {
        haystack.windows(needle.len()).position(|w| w == needle)
    }

    fn tool_call_body(decision: &str) -> String {
        format!(
            r#"{{
                "choices": [{{
                    "message": {{
                        "tool_calls": [{{
                            "id": "c1",
                            "type": "function",
                            "function": {{
                                "name": "decide",
                                "arguments": "{{\"decision\":\"{}\",\"reason\":\"test\",\"risk\":1}}"
                            }}
                        }}]
                    }}
                }}],
                "usage": {{"prompt_tokens": 10, "completion_tokens": 5, "total_tokens": 15}}
            }}"#,
            decision
        )
    }

    #[tokio::test]
    async fn test_retry_on_429_then_success() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let responses = vec![
            (
                429,
                r#"{"error":"rate limited"}"#.to_string(),
                Some("1".to_string()),
            ),
            (200, tool_call_body("APPROVE"), None),
        ];
        let mock = tokio::spawn(run_mock(listener, responses));

        let evaluator = mock_server_evaluator(port, 2, vec![]).await;
        let result = evaluator.evaluate_llm("id", None).await;
        assert!(result.is_allow(), "got: {}", result);
        let _ = mock.await;
    }

    #[tokio::test]
    async fn test_retry_on_500_then_success() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let responses = vec![
            (500, r#"{"error":"boom"}"#.to_string(), None),
            (200, tool_call_body("DENY"), None),
        ];
        let mock = tokio::spawn(run_mock(listener, responses));

        let evaluator = mock_server_evaluator(port, 2, vec![]).await;
        let result = evaluator.evaluate_llm("rm -rf /", None).await;
        assert!(result.is_deny(), "got: {}", result);
        let _ = mock.await;
    }

    #[tokio::test]
    async fn test_retry_exhausted_returns_error() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        let responses = vec![
            (
                429,
                r#"{"error":"rate limited"}"#.to_string(),
                Some("1".to_string()),
            ),
            (
                429,
                r#"{"error":"rate limited"}"#.to_string(),
                Some("1".to_string()),
            ),
            (
                429,
                r#"{"error":"rate limited"}"#.to_string(),
                Some("1".to_string()),
            ),
        ];
        let mock = tokio::spawn(run_mock(listener, responses));

        let evaluator = mock_server_evaluator(port, 2, vec![]).await;
        let result = evaluator.evaluate_llm("id", None).await;
        assert!(result.is_error());
        assert!(
            result.reason().contains("rate_limited"),
            "got: {}",
            result.reason()
        );
        let _ = mock.await;
    }

    #[tokio::test]
    async fn test_fallback_chain_primary_fails_secondary_succeeds() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // Primary fails all 3 attempts (500s), secondary succeeds on first attempt.
        let responses = vec![
            (500, r#"{"error":"boom"}"#.to_string(), None),
            (500, r#"{"error":"boom"}"#.to_string(), None),
            (500, r#"{"error":"boom"}"#.to_string(), None),
            (200, tool_call_body("APPROVE"), None),
        ];
        let mock = tokio::spawn(run_mock(listener, responses));

        let evaluator =
            mock_server_evaluator(port, 2, vec!["primary/m1".into(), "secondary/m2".into()]).await;
        let result = evaluator.evaluate_llm("id", None).await;
        assert!(result.is_allow(), "got: {}", result);
        let _ = mock.await;
    }

    #[tokio::test]
    async fn test_parse_error_switches_to_json_format_and_succeeds() {
        let listener = tokio::net::TcpListener::bind("127.0.0.1:0").await.unwrap();
        let port = listener.local_addr().unwrap().port();
        // First response: 200 but no tool_calls → ParseError.
        // Second response: 200 with content containing JSON.
        let bad_body = r#"{"choices":[{"message":{"content":"I cannot comply"}}]}"#.to_string();
        let good_body = r#"{"choices":[{"message":{"content":"{\"decision\":\"APPROVE\",\"reason\":\"ok\",\"risk\":1}"}}]}"#.to_string();
        let responses = vec![(200, bad_body, None), (200, good_body, None)];
        let mock = tokio::spawn(run_mock(listener, responses));

        let evaluator = mock_server_evaluator(port, 2, vec![]).await;
        let result = evaluator.evaluate_llm("id", None).await;
        assert!(result.is_allow(), "got: {}", result);
        let _ = mock.await;
    }
}
