//! Policy engine for command authorization.
//!
//! Provides a declarative, rule-based policy system with default-deny semantics.
//! Policies can be loaded from YAML configuration or built programmatically.

use anyhow::{Context, Result};
use serde::{Deserialize, Serialize};
use std::path::Path;

/// Built-in operating modes for the policy engine.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum PolicyMode {
    Readonly,
    Paranoid,
    Safe,
}

impl PolicyMode {
    pub fn parse(value: &str) -> Option<Self> {
        match value.trim().to_ascii_lowercase().as_str() {
            "readonly" => Some(Self::Readonly),
            "default" => {
                tracing::warn!("GUARD_MODE=\"default\" is deprecated, use \"readonly\" instead");
                Some(Self::Readonly)
            }
            "paranoid" => Some(Self::Paranoid),
            "safe" => Some(Self::Safe),
            _ => None,
        }
    }

    pub fn as_str(&self) -> &'static str {
        match self {
            Self::Readonly => "readonly",
            Self::Paranoid => "paranoid",
            Self::Safe => "safe",
        }
    }
}

/// The authorization decision for a command.
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize)]
#[serde(rename_all = "lowercase")]
pub enum Decision {
    Allow,
    Deny,
}

/// The result of a policy check.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyResult {
    pub decision: Decision,
    pub reason: String,
}

impl PolicyResult {
    /// Create an allow result with a reason.
    pub fn allow(reason: impl Into<String>) -> Self {
        Self {
            decision: Decision::Allow,
            reason: reason.into(),
        }
    }

    /// Create a deny result with a reason.
    pub fn deny(reason: impl Into<String>) -> Self {
        Self {
            decision: Decision::Deny,
            reason: reason.into(),
        }
    }

    /// Returns true if the command is allowed.
    pub fn is_allowed(&self) -> bool {
        self.decision == Decision::Allow
    }

    /// Returns true if the command is denied.
    pub fn is_denied(&self) -> bool {
        self.decision == Decision::Deny
    }
}

/// A single policy rule matching commands by glob pattern.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyRule {
    /// Glob patterns that match this rule (e.g., "ssh*", "kubectl*").
    pub patterns: Vec<String>,
    /// The decision to apply when this rule matches.
    #[serde(rename = "action", alias = "decision")]
    pub decision: Decision,
    /// Human-readable description of this rule.
    #[serde(default)]
    pub description: Option<String>,
}

impl PolicyRule {
    /// Check if a command matches any of this rule's patterns.
    pub fn matches(&self, cmd: &str) -> bool {
        self.patterns.iter().any(|p| match_glob(p, cmd))
    }
}

/// A named group of policy rules with optional priority.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyGroup {
    pub name: String,
    pub rules: Vec<PolicyRule>,
    #[serde(default)]
    pub priority: i32,
}

/// The complete policy configuration.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PolicyConfig {
    #[serde(default)]
    pub policy: PolicyDefinitions,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct PolicyDefinitions {
    /// Command-level allow/deny lists (simple glob patterns as strings).
    #[serde(default)]
    pub commands: CommandPolicy,

    /// Named policy groups for structured rules.
    #[serde(default)]
    pub groups: Vec<PolicyGroup>,
}

#[derive(Debug, Clone, Default, Serialize, Deserialize)]
pub struct CommandPolicy {
    #[serde(default)]
    pub allow: Vec<String>,

    #[serde(default)]
    pub deny: Vec<String>,
}

/// The policy engine that evaluates commands against configured rules.
#[derive(Debug, Clone)]
pub struct PolicyEngine {
    allow_patterns: Vec<String>,
    deny_patterns: Vec<String>,
    groups: Vec<PolicyGroup>,
    rules: Vec<PolicyRule>,
}

impl Default for PolicyEngine {
    fn default() -> Self {
        Self::new()
    }
}

impl PolicyEngine {
    /// Create a new policy engine with default-deny behavior.
    pub fn new() -> Self {
        Self {
            allow_patterns: Vec::new(),
            deny_patterns: Vec::new(),
            groups: Vec::new(),
            rules: Vec::new(),
        }
    }

    /// Add an allow pattern (glob syntax).
    pub fn add_allow(mut self, pattern: impl Into<String>) -> Self {
        self.allow_patterns.push(pattern.into());
        self
    }

    /// Add a deny pattern (glob syntax).
    pub fn add_deny(mut self, pattern: impl Into<String>) -> Self {
        self.deny_patterns.push(pattern.into());
        self
    }

    /// Add a policy group.
    pub fn add_group(mut self, group: PolicyGroup) -> Self {
        self.groups.push(group);
        self
    }

    /// Add a policy rule.
    pub fn add_rule(mut self, rule: PolicyRule) -> Self {
        self.rules.push(rule);
        self
    }

    /// Load configuration from a YAML file.
    pub fn load_file<P: AsRef<Path>>(path: P) -> Result<Self> {
        let content = std::fs::read_to_string(path.as_ref())
            .with_context(|| format!("failed to read policy file: {}", path.as_ref().display()))?;
        Self::load_yaml(&content)
    }

    /// Load configuration from a YAML string.
    pub fn load_yaml(yaml: &str) -> Result<Self> {
        let config: PolicyConfig = serde_yaml::from_str(yaml)?;
        Self::from_config(&config.policy)
    }

    /// Load the default policy from ~/.config/guard/policy.yaml
    /// Falls back to a permissive default if no config exists.
    pub fn load_default() -> Result<Self> {
        if let Some(config_dir) = dirs::config_dir() {
            let policy_path = config_dir.join("guard").join("policy.yaml");
            if policy_path.exists() {
                return Self::load_file(&policy_path);
            }
        }

        // Return a permissive default policy
        tracing::info!("No policy file found, using permissive default");
        Ok(Self::new())
    }

    /// Build a policy engine for the given mode.
    ///
    /// Returns an empty engine. All patterns must be loaded from config files.
    /// Use `load_file()` or `load_yaml()` with a policy YAML to add rules.
    ///
    /// ## Why no built-in patterns
    ///
    /// Static glob patterns match against flat command strings. They cannot:
    /// - Parse shell operators: `ls; rm -rf /` is seen as command "ls;" with args,
    ///   not two separate commands. The `rm -rf /` part is invisible to deny patterns.
    /// - Understand quoting/escaping: `bash -c "rm -rf /"` is caught by `bash -c *`,
    ///   but `bas''h -c "rm -rf /"` is not.
    /// - Evaluate semantics: `find / -name shadow` is benign, `find / -exec cat {} \;`
    ///   is not. Both start with `find`.
    /// - Handle broad allow patterns safely: `head*` allows `head -1 /etc/shadow`,
    ///   `ls*` allows `ls; rm -rf /` when chained.
    ///
    /// The LLM evaluator handles all these cases. If you need static policies,
    /// load them from a config file and use DENY rules only.
    /// See `examples/deny-policy.yaml` for a reference deny-list.
    pub fn from_mode(_mode: PolicyMode) -> Self {
        Self::new()
    }

    /// Build a PolicyEngine from a PolicyDefinitions struct.
    pub fn from_config(config: &PolicyDefinitions) -> Result<Self> {
        let mut engine = Self::new();

        // Convert simple string patterns to rules
        for pattern in &config.commands.allow {
            engine.allow_patterns.push(pattern.clone());
        }

        for pattern in &config.commands.deny {
            engine.deny_patterns.push(pattern.clone());
        }

        // Add named groups
        for group in &config.groups {
            engine = engine.add_group(group.clone());
        }

        // Convert command lists to explicit rules for internal matching
        for pattern in &config.commands.allow {
            engine.rules.push(PolicyRule {
                patterns: vec![pattern.clone()],
                decision: Decision::Allow,
                description: Some(format!("allow: {}", pattern)),
            });
        }

        for pattern in &config.commands.deny {
            engine.rules.push(PolicyRule {
                patterns: vec![pattern.clone()],
                decision: Decision::Deny,
                description: Some(format!("deny: {}", pattern)),
            });
        }

        Ok(engine)
    }

    /// Check if a command is allowed, returning the policy result.
    ///
    /// Evaluation order:
    /// 1. Explicit deny patterns (highest priority)
    /// 2. Explicit allow patterns
    /// 3. Policy group rules (in priority order)
    /// 4. Default-deny
    pub fn check_command(&self, cmd: &str, args: &[String]) -> PolicyResult {
        // Build full command string for pattern matching
        let full_cmd = if args.is_empty() {
            cmd.to_string()
        } else {
            format!("{} {}", cmd, args.join(" "))
        };

        let cmd_only = cmd.to_string();
        let cmd_with_first_arg = if !args.is_empty() {
            format!("{} {}", cmd, args[0])
        } else {
            cmd_only.clone()
        };

        // 1. Check explicit deny patterns (highest priority)
        for pattern in &self.deny_patterns {
            if pattern_matches(pattern, &full_cmd, &cmd_with_first_arg, &cmd_only) {
                return PolicyResult::deny(format!("matched deny pattern: {}", pattern));
            }
        }

        // 2. Check explicit allow patterns
        for pattern in &self.allow_patterns {
            if pattern_matches(pattern, &full_cmd, &cmd_with_first_arg, &cmd_only) {
                return PolicyResult::allow(format!("matched allow pattern: {}", pattern));
            }
        }

        // 3. Check policy group rules (sorted by priority, highest first)
        let mut sorted_groups = self.groups.clone();
        sorted_groups.sort_by_key(|g| std::cmp::Reverse(g.priority));

        for group in &sorted_groups {
            for rule in &group.rules {
                if rule.matches(&full_cmd) || rule.matches(&cmd_with_first_arg) {
                    let reason = if let Some(ref desc) = rule.description {
                        format!("[{}] {}", group.name, desc)
                    } else {
                        format!(
                            "[{}] matched rule with patterns: {}",
                            group.name,
                            rule.patterns.join(", ")
                        )
                    };

                    return match rule.decision {
                        Decision::Allow => PolicyResult::allow(reason),
                        Decision::Deny => PolicyResult::deny(reason),
                    };
                }
            }
        }

        // 4. Default-deny: anything not explicitly allowed is denied
        PolicyResult::deny("default-deny: no matching allow rule".to_string())
    }

    /// Check a command string (auto-parsed into cmd + args).
    pub fn check(&self, command: &str) -> PolicyResult {
        let parts = parse_command(command);
        let cmd = parts[0].as_str();
        let args = &parts[1..];
        self.check_command(cmd, args)
    }

    /// Returns a list of all configured allow patterns.
    pub fn allow_list(&self) -> &[String] {
        &self.allow_patterns
    }

    /// Returns a list of all configured deny patterns.
    pub fn deny_list(&self) -> &[String] {
        &self.deny_patterns
    }

    /// Returns the number of policy groups.
    pub fn group_count(&self) -> usize {
        self.groups.len()
    }
}

/// Match a glob pattern against a string.
///
/// Supports:
/// - `*` matches any sequence of characters
/// - `?` matches any single character
/// - `[abc]` matches any character in the set
/// - `[!abc]` matches any character not in the set
fn match_glob(pattern: &str, text: &str) -> bool {
    // Exact match is always valid
    if pattern == text {
        return true;
    }

    // Handle patterns with wildcards
    if !pattern.contains('*') && !pattern.contains('?') && !pattern.contains('[') {
        // No wildcards, must be exact match (already handled above)
        return false;
    }

    let pattern_chars: Vec<char> = pattern.chars().collect();
    let text_chars: Vec<char> = text.chars().collect();

    match_glob_recursive(&pattern_chars, &text_chars)
}

/// Recursive glob matching with backtracking.
fn match_glob_recursive(pattern: &[char], text: &[char]) -> bool {
    let mut p_idx = 0usize;
    let mut t_idx = 0usize;
    let mut star_pos: Option<usize> = None;
    let mut t_at_star: Option<usize> = None;

    loop {
        if p_idx < pattern.len() {
            match pattern[p_idx] {
                '*' => {
                    // Save position before *, and current text position
                    star_pos = Some(p_idx);
                    t_at_star = Some(t_idx);
                    p_idx += 1;
                }
                '?' => {
                    if t_idx < text.len() {
                        p_idx += 1;
                        t_idx += 1;
                    } else if let (Some(sp), Some(_)) = (star_pos, t_at_star) {
                        // Backtrack to previous *
                        p_idx = sp + 1;
                        t_idx = t_at_star.unwrap() + 1;
                        t_at_star = Some(t_idx);
                    } else {
                        return false;
                    }
                }
                '[' => {
                    // Find closing ]
                    if let Some(end) = pattern[p_idx..].iter().position(|&c| c == ']') {
                        let class_end = p_idx + end;
                        let class = &pattern[p_idx + 1..class_end];

                        let negated = class.first() == Some(&'!');
                        let class_content = if negated { &class[1..] } else { class };

                        if t_idx < text.len() {
                            let ch = text[t_idx];
                            let matches = class_content.contains(&ch)
                                || (class_content.len() == 3
                                    && class_content[1] == '-'
                                    && ch >= class_content[0]
                                    && ch <= class_content[2]);

                            if matches != negated {
                                p_idx = class_end + 1;
                                t_idx += 1;
                            } else if let (Some(sp), Some(_)) = (star_pos, t_at_star) {
                                p_idx = sp + 1;
                                t_idx = t_at_star.unwrap() + 1;
                                t_at_star = Some(t_idx);
                            } else {
                                return false;
                            }
                        } else if let (Some(sp), Some(_)) = (star_pos, t_at_star) {
                            p_idx = sp + 1;
                            t_idx = t_at_star.unwrap() + 1;
                            t_at_star = Some(t_idx);
                        } else {
                            return false;
                        }
                    } else {
                        // No closing ], treat [ as literal
                        if t_idx < text.len() && pattern[p_idx] == text[t_idx] {
                            p_idx += 1;
                            t_idx += 1;
                        } else if let (Some(sp), Some(_)) = (star_pos, t_at_star) {
                            p_idx = sp + 1;
                            t_idx = t_at_star.unwrap() + 1;
                            t_at_star = Some(t_idx);
                        } else {
                            return false;
                        }
                    }
                }
                c => {
                    if t_idx < text.len() && c == text[t_idx] {
                        p_idx += 1;
                        t_idx += 1;
                    } else if let (Some(sp), Some(_)) = (star_pos, t_at_star) {
                        // Backtrack: try matching * with more characters
                        p_idx = sp + 1;
                        t_idx = t_at_star.unwrap() + 1;
                        t_at_star = Some(t_idx);
                        // If we've consumed all text after backtracking and still have pattern,
                        // fail immediately to avoid infinite loop
                        if t_idx >= text.len() && p_idx < pattern.len() {
                            return false;
                        }
                    } else {
                        return false;
                    }
                }
            }
        } else if t_idx < text.len() {
            // Pattern exhausted but text remains - only valid if we can match remaining with *
            if let (Some(sp), Some(_)) = (star_pos, t_at_star) {
                // Try matching * with more characters
                p_idx = sp + 1;
                t_idx = t_at_star.unwrap() + 1;
                t_at_star = Some(t_idx);
            } else {
                return false;
            }
        } else {
            // Both exhausted - match success
            return true;
        }
    }
}

/// Check if a pattern matches any of the given command variants.
///
/// This handles the common case where a simple pattern like "ssh" should match
/// both "ssh" and "ssh user@host" (command with arguments).
fn pattern_matches(
    pattern: &str,
    full_cmd: &str,
    cmd_with_first_arg: &str,
    cmd_only: &str,
) -> bool {
    // If the pattern has no wildcards, it should match as a prefix of the command
    if !pattern.contains('*') && !pattern.contains('?') && !pattern.contains('[') {
        // Match as prefix with boundary: "ssh" matches "ssh" or "ssh user@host"
        // but NOT "ssh-agent" or "github" (different commands)
        let matches_prefix = |s: &str| -> bool {
            s == pattern || (s.starts_with(pattern) && s[pattern.len()..].starts_with(' '))
        };
        return matches_prefix(full_cmd)
            || matches_prefix(cmd_with_first_arg)
            || matches_prefix(cmd_only)
            || match_glob(pattern, full_cmd)
            || match_glob(pattern, cmd_with_first_arg)
            || match_glob(pattern, cmd_only);
    }
    // For patterns with wildcards, use glob matching
    match_glob(pattern, full_cmd) || match_glob(pattern, cmd_with_first_arg)
}

/// Parse a command string into parts, respecting quoting.
fn parse_command(cmd: &str) -> Vec<String> {
    let mut parts = Vec::new();
    let mut current = String::new();
    let mut in_single_quote = false;
    let mut in_double_quote = false;
    let mut escape_next = false;

    for ch in cmd.chars() {
        if escape_next {
            current.push(ch);
            escape_next = false;
            continue;
        }

        match ch {
            '\\' if !in_single_quote => {
                escape_next = true;
            }
            '\'' if !in_double_quote => {
                in_single_quote = !in_single_quote;
            }
            '"' if !in_single_quote => {
                in_double_quote = !in_double_quote;
            }
            ' ' | '\t' | '\n' | '\r' if !in_single_quote && !in_double_quote => {
                if !current.is_empty() {
                    parts.push(current.clone());
                    current.clear();
                }
            }
            _ => {
                current.push(ch);
            }
        }
    }

    if !current.is_empty() {
        parts.push(current);
    }

    if parts.is_empty() {
        parts.push(String::new());
    }

    parts
}

#[cfg(test)]
mod tests {
    use super::*;

    // === Glob matching tests ===

    #[test]
    fn test_glob_exact_match() {
        assert!(match_glob("ssh", "ssh"));
        assert!(!match_glob("ssh", "ssh-agent"));
    }

    #[test]
    fn test_glob_star_prefix() {
        assert!(match_glob("ssh*", "ssh"));
        assert!(match_glob("ssh*", "ssh-agent"));
        assert!(match_glob("ssh*", "ssh -V"));
        assert!(!match_glob("ssh*", "kssh"));
    }

    #[test]
    fn test_glob_star_suffix() {
        assert!(match_glob("*ssh", "ssh"));
        assert!(match_glob("*ssh", "kssh"));
        assert!(!match_glob("*ssh", "ssh-agent"));
    }

    #[test]
    fn test_glob_star_both() {
        assert!(match_glob("*ssh*", "ssh"));
        assert!(match_glob("*ssh*", "ksshk"));
        assert!(match_glob("*ssh*", "ssh-agent"));
        assert!(match_glob("*ssh*", "kssh-agent"));
    }

    #[test]
    fn test_glob_question_mark() {
        assert!(match_glob("ssh?", "sshx"));
        assert!(match_glob("ssh?", "ssh1"));
        assert!(!match_glob("ssh?", "ssh"));
        assert!(!match_glob("ssh?", "sshab"));
    }

    #[test]
    fn test_glob_character_class() {
        assert!(match_glob("ssh[abc]", "ssha"));
        assert!(match_glob("ssh[abc]", "sshb"));
        assert!(!match_glob("ssh[abc]", "sshd"));
        assert!(!match_glob("ssh[abc]", "ssh"));
    }

    #[test]
    fn test_glob_complex_patterns() {
        // Real-world patterns
        assert!(match_glob("kubectl*", "kubectl"));
        assert!(match_glob("kubectl*", "kubectl get pods"));
        assert!(match_glob("kubectl*", "kubectl exec -it nginx -- /bin/sh"));
        assert!(!match_glob("kubectl*", "dockubectl"));

        assert!(match_glob("docker*", "docker"));
        assert!(match_glob("docker*", "docker ps"));
        assert!(match_glob("docker*", "docker-compose up -d"));
    }

    // === Command parsing tests ===

    #[test]
    fn test_parse_command_simple() {
        let parts = parse_command("ssh user@host");
        assert_eq!(parts, vec!["ssh", "user@host"]);
    }

    #[test]
    fn test_parse_command_multiple_args() {
        let parts = parse_command("kubectl get pods -n default");
        assert_eq!(parts, vec!["kubectl", "get", "pods", "-n", "default"]);
    }

    #[test]
    fn test_parse_command_with_quotes() {
        let parts = parse_command(r#"echo "hello world""#);
        assert_eq!(parts, vec!["echo", "hello world"]);
    }

    #[test]
    fn test_parse_command_with_single_quotes() {
        let parts = parse_command("echo 'hello world'");
        assert_eq!(parts, vec!["echo", "hello world"]);
    }

    #[test]
    fn test_parse_command_with_escaped() {
        let parts = parse_command(r#"echo "hello\"world""#);
        assert_eq!(parts, vec!["echo", "hello\"world"]);
    }

    #[test]
    fn test_parse_command_empty() {
        let parts = parse_command("");
        assert_eq!(parts, vec![""]);
    }

    #[test]
    fn test_parse_command_destructive() {
        let parts = parse_command("rm -rf /");
        assert_eq!(parts, vec!["rm", "-rf", "/"]);
    }

    // === PolicyEngine tests ===

    #[test]
    fn test_default_deny() {
        let engine = PolicyEngine::new();
        let result = engine.check("anycommand");
        assert!(result.is_denied());
        assert!(result.reason.contains("default-deny"));
    }

    #[test]
    fn test_allow_pattern() {
        let engine = PolicyEngine::new().add_allow("ssh");
        assert!(engine.check("ssh").is_allowed());
        assert!(engine.check("ssh user@host").is_allowed());
        assert!(engine.check("kubectl get pods").is_denied());
    }

    #[test]
    fn test_allow_glob_pattern() {
        let engine = PolicyEngine::new()
            .add_allow("kubectl*")
            .add_allow("docker*");

        assert!(engine.check("kubectl").is_allowed());
        assert!(engine.check("kubectl get pods").is_allowed());
        assert!(engine.check("docker ps").is_allowed());
        assert!(engine.check("docker-compose up").is_allowed());
        assert!(engine.check("ssh").is_denied());
    }

    #[test]
    fn test_deny_pattern() {
        let engine = PolicyEngine::new().add_allow("*").add_deny("rm -rf /*");

        assert!(engine.check("ssh user@host").is_allowed());
        assert!(engine.check("ls -la").is_allowed());
        assert!(engine.check("rm -rf /").is_denied());
    }

    #[test]
    fn test_deny_before_allow() {
        // Even with allow *, deny should take precedence
        let engine = PolicyEngine::new().add_allow("*").add_deny("rm -rf /*");

        let result = engine.check("rm -rf /*");
        assert!(result.is_denied());
        assert!(result.reason.contains("deny pattern"));
    }

    #[test]
    fn test_yaml_loading() {
        let yaml = r#"
policy:
  commands:
    allow:
      - ssh
      - kubectl
      - docker
    deny:
      - "rm -rf /*"
      - "dd if=*"
"#;
        let engine = PolicyEngine::load_yaml(yaml).unwrap();

        assert!(engine.check("ssh").is_allowed());
        assert!(engine.check("kubectl get pods").is_allowed());
        assert!(engine.check("docker ps").is_allowed());
        assert!(engine.check("rm -rf /").is_denied());
        assert!(engine.check("dd if=/dev/zero").is_denied());
        assert!(engine.check("ls").is_denied()); // default-deny
    }

    #[test]
    fn test_yaml_with_groups() {
        let yaml = r#"
policy:
  groups:
    - name: admin
      priority: 10
      rules:
        - patterns:
            - "sudo*"
            - "systemctl*"
          action: allow
          description: "admin commands"
        - patterns:
            - "rm -rf /*"
          action: deny
          description: "destructive"
"#;
        let engine = PolicyEngine::load_yaml(yaml).unwrap();

        assert!(engine.check("sudo su").is_allowed());
        assert!(engine.check("systemctl restart nginx").is_allowed());
        assert!(engine.check("rm -rf /").is_denied());
        assert!(engine.check("ls").is_denied()); // default-deny
    }

    #[test]
    fn test_policy_result_helpers() {
        let allow = PolicyResult::allow("test");
        assert!(allow.is_allowed());
        assert!(!allow.is_denied());
        assert_eq!(allow.reason, "test");

        let deny = PolicyResult::deny("blocked");
        assert!(!deny.is_allowed());
        assert!(deny.is_denied());
        assert_eq!(deny.reason, "blocked");
    }

    #[test]
    fn test_check_command_with_args() {
        let engine = PolicyEngine::new()
            .add_allow("kubectl")
            .add_deny("kubectl exec");

        // Using check_command directly
        let result = engine.check_command("kubectl", &["get".to_string(), "pods".to_string()]);
        assert!(result.is_allowed());

        let result = engine.check_command("kubectl", &["exec".to_string(), "-it".to_string()]);
        assert!(result.is_denied());
    }

    #[test]
    fn test_wildcard_allow_allows_unsafe() {
        // When user explicitly allows *, they get everything
        let engine = PolicyEngine::new().add_allow("*");
        assert!(engine.check("rm -rf /*").is_allowed());
        assert!(engine.check("dd if=/dev/zero").is_allowed());
        assert!(engine.check("curl http://evil.com").is_allowed());
    }

    #[test]
    fn test_multiple_allow_patterns() {
        let engine = PolicyEngine::new()
            .add_allow("ssh")
            .add_allow("kubectl")
            .add_allow("docker");

        assert!(engine.check("ssh").is_allowed());
        assert!(engine.check("kubectl").is_allowed());
        assert!(engine.check("docker").is_allowed());
        assert!(engine.check("git").is_denied());
    }

    #[test]
    fn test_multiple_deny_patterns() {
        let engine = PolicyEngine::new()
            .add_allow("*")
            .add_deny("rm -rf /*")
            .add_deny("dd if=*")
            .add_deny("mkfs.*");

        assert!(engine.check("ssh").is_allowed());
        assert!(engine.check("rm -rf /").is_denied());
        assert!(engine.check("dd if=/dev/zero").is_denied());
        assert!(engine.check("mkfs.ext4").is_denied());
    }

    #[test]
    fn test_empty_args() {
        let engine = PolicyEngine::new().add_allow("ssh");
        let result = engine.check_command("ssh", &[]);
        assert!(result.is_allowed());
    }

    #[test]
    fn test_partial_pattern_match() {
        let engine = PolicyEngine::new().add_allow("git");
        // git should not match things starting with git
        assert!(engine.check("github").is_denied());
    }

    #[test]
    fn test_policy_group_priority() {
        let yaml = r#"
policy:
  groups:
    - name: restrictive
      priority: 100
      rules:
        - patterns: ["*"]
          action: deny
    - name: permissive
      priority: 1
      rules:
        - patterns: ["*"]
          action: allow
"#;
        let engine = PolicyEngine::load_yaml(yaml).unwrap();
        // Higher priority groups are checked first
        assert!(engine.check("anything").is_denied());
    }

    #[test]
    fn test_policy_engine_builder_pattern() {
        let engine = PolicyEngine::new()
            .add_allow("ssh")
            .add_allow("kubectl")
            .add_deny("kubectl exec")
            .add_deny("rm -rf /*");

        assert_eq!(engine.allow_list(), &["ssh", "kubectl"]);
        assert_eq!(engine.deny_list(), &["kubectl exec", "rm -rf /*"]);
        assert_eq!(engine.group_count(), 0);
    }

    #[test]
    fn test_policy_mode_parse() {
        assert_eq!(PolicyMode::parse("readonly"), Some(PolicyMode::Readonly));
        assert_eq!(PolicyMode::parse("Paranoid"), Some(PolicyMode::Paranoid));
        assert_eq!(PolicyMode::parse("SAFE"), Some(PolicyMode::Safe));
        assert_eq!(PolicyMode::parse("invalid"), None);
        // "default" is a deprecated alias for Readonly
        assert_eq!(PolicyMode::parse("default"), Some(PolicyMode::Readonly));
        assert_eq!(PolicyMode::parse("Default"), Some(PolicyMode::Readonly));
    }

    #[test]
    fn test_builtin_modes_are_empty() {
        // Modes return empty engines. All patterns come from config files.
        for mode in [PolicyMode::Paranoid, PolicyMode::Readonly, PolicyMode::Safe] {
            let engine = PolicyEngine::from_mode(mode);
            assert!(
                engine.allow_list().is_empty(),
                "{:?} should have no allows",
                mode
            );
            assert!(
                engine.deny_list().is_empty(),
                "{:?} should have no denies",
                mode
            );
            // Everything goes to default-deny without config
            assert!(engine.check("ls -la /").is_denied());
        }
    }

    #[test]
    fn test_real_world_scenarios() {
        let yaml = r#"
policy:
  commands:
    allow:
      - git
      - ls
      - cd
      - pwd
      - cat
      - grep
      - curl
      - wget
    deny:
      - "rm -rf /*"
      - "rm -rf /"
      - "dd if=*"
      - "mkfs.*"
      - ":(){:|:&};:"
"#;
        let engine = PolicyEngine::load_yaml(yaml).unwrap();

        // Safe commands
        assert!(engine.check("git status").is_allowed());
        assert!(engine.check("ls -la").is_allowed());
        assert!(engine.check("cat /etc/hosts").is_allowed());
        assert!(engine.check("curl https://example.com").is_allowed());

        // Dangerous commands (denied)
        assert!(engine.check("rm -rf /").is_denied());
        assert!(engine.check("rm -rf /*").is_denied());
        assert!(engine.check("dd if=/dev/zero of=/dev/sda").is_denied());
        assert!(engine.check("mkfs.ext4 /dev/sda").is_denied());
        assert!(engine.check(":(){:|:&};:").is_denied());

        // Default deny for unspecified commands
        assert!(engine.check("ssh user@host").is_denied());
        assert!(engine.check("python script.py").is_denied());
    }

    #[test]
    fn test_yaml_syntax_error() {
        let yaml = "invalid: yaml: content: [";
        assert!(PolicyEngine::load_yaml(yaml).is_err());
    }

    #[test]
    fn test_policy_result_serialization() {
        let result = PolicyResult::allow("test reason");
        let json = serde_json::to_string(&result).unwrap();
        assert!(json.contains("allow"));
        assert!(json.contains("test reason"));

        let result: PolicyResult = serde_json::from_str(&json).unwrap();
        assert!(result.is_allowed());
    }

    #[test]
    fn test_decision_serialization() {
        let allow = Decision::Allow;
        let deny = Decision::Deny;

        let allow_json = serde_json::to_string(&allow).unwrap();
        let deny_json = serde_json::to_string(&deny).unwrap();

        assert_eq!(allow_json, "\"allow\"");
        assert_eq!(deny_json, "\"deny\"");
    }
}
