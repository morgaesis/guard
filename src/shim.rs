//! Shim generator for wrapping system tools with guard approval.
//!
//! This module generates shell scripts ("shims") that intercept calls to
//! sensitive tools and route them through guard for approval.
//!
//! # Overview
//!
//! Shim scripts are tiny shell wrappers placed in a dedicated directory.
//! When that directory is prepended to PATH, the shims intercept tool calls,
//! invoke guard for approval, and only proceed if approved.
//!
//! # Example
//!
//! ```rust,no_run
//! use guard::shim::ShimGenerator;
//!
//! let gen = ShimGenerator::new("/usr/local/bin/guard", "/home/user/.guard/shims");
//! gen.generate_all()?;
//! println!("{}", gen.path_instruction());
//! ```

use anyhow::{bail, Context, Result};
use std::fs::{self, File};
use std::io::Write;
#[cfg(unix)]
use std::os::unix::fs::PermissionsExt;
use std::path::{Path, PathBuf};

/// Default tools that get shims generated for them.
pub const DEFAULT_TOOLS: &[(&str, &str)] = &[
    // SSH and file transfer
    ("ssh", "Secure Shell client"),
    ("scp", "Secure copy over SSH"),
    ("sftp", "Secure file transfer over SSH"),
    // Network tools
    ("curl", "URL transfer tool"),
    ("wget", "Network downloader"),
    // Cloud and container tools
    ("aws", "AWS CLI"),
    ("kubectl", "Kubernetes CLI"),
    ("docker", "Docker CLI"),
    // VCS
    ("git", "Git version control (for add/commit scanning)"),
];

/// The set of tools managed by shims.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct ShimTool {
    /// The tool name (e.g., "ssh", "curl")
    pub name: &'static str,
    /// Human-readable description
    pub description: &'static str,
}

impl ShimTool {
    /// Create a new tool entry.
    pub const fn new(name: &'static str, description: &'static str) -> Self {
        Self { name, description }
    }
}

/// Shim generator for creating tool wrapper scripts.
///
/// Generates executable shell scripts that intercept calls to specified tools
/// and route them through guard for approval before execution.
///
/// # Shell escaping
///
/// The generated shims use proper shell quoting to handle arguments safely.
/// Arguments are passed through `"$@"` which preserves spaces and special
/// characters correctly.
#[derive(Debug, Clone)]
pub struct ShimGenerator {
    /// Path to the guard binary.
    guard_binary: PathBuf,
    /// Directory where shim scripts are written.
    shim_dir: PathBuf,
}

impl ShimGenerator {
    /// Create a new ShimGenerator.
    ///
    /// # Arguments
    ///
    /// * `guard_binary` - Path to the guard executable
    /// * `shim_dir` - Directory where shims will be generated
    ///
    /// # Example
    ///
    /// ```
    /// use guard::shim::ShimGenerator;
    ///
    /// let gen = ShimGenerator::new(
    ///     "/usr/local/bin/guard",
    ///     "/home/user/.guard/shims"
    /// );
    /// ```
    pub fn new(guard_binary: impl Into<PathBuf>, shim_dir: impl Into<PathBuf>) -> Self {
        Self {
            guard_binary: guard_binary.into(),
            shim_dir: shim_dir.into(),
        }
    }

    /// Create a new ShimGenerator with default paths.
    ///
    /// Uses `guard` from PATH and `~/.guard/shims` for the shim directory.
    pub fn with_defaults() -> Result<Self> {
        let guard_binary = find_guard_binary()?;
        let shim_dir = default_shim_dir()?;

        Ok(Self::new(guard_binary, shim_dir))
    }

    /// Return the shim directory path.
    pub fn path(&self) -> PathBuf {
        self.shim_dir.clone()
    }

    /// Return a shell command to prepend the shim directory to PATH.
    ///
    /// # Example output
    ///
    /// ```text
    /// export PATH=/home/user/.guard/shims:$PATH
    /// ```
    pub fn path_instruction(&self) -> String {
        format!(
            "export PATH={}:$PATH",
            escape_path_for_shell(&self.shim_dir)
        )
    }

    /// Generate a shim for a specific tool.
    ///
    /// Writes an executable shell script to `{shim_dir}/{tool}` that
    /// calls `guard exec {tool} "$@"`.
    pub fn generate_tool(&self, tool: &str) -> Result<PathBuf> {
        // Validate tool name - must be alphanumeric plus hyphens/underscores
        if !is_valid_tool_name(tool) {
            bail!("invalid tool name: '{}'", tool);
        }

        let shim_path = self.shim_dir.join(tool);
        let shim_content = self.render_shim(tool);

        // Create shim directory if needed
        if !self.shim_dir.exists() {
            fs::create_dir_all(&self.shim_dir).context(format!(
                "failed to create shim directory: {}",
                self.shim_dir.display()
            ))?;
        }

        // Write the shim script
        let mut file = File::create(&shim_path)
            .context(format!("failed to create shim: {}", shim_path.display()))?;

        file.write_all(shim_content.as_bytes())
            .context(format!("failed to write shim: {}", shim_path.display()))?;

        // Make executable (Unix mode bit; on Windows executability is by
        // extension and the shim is not chmod'd).
        #[cfg(unix)]
        {
            let metadata = fs::metadata(&shim_path)?;
            let mut permissions = metadata.permissions();
            permissions.set_mode(0o755);
            fs::set_permissions(&shim_path, permissions).context(format!(
                "failed to set permissions on: {}",
                shim_path.display()
            ))?;
        }

        tracing::debug!("generated shim: {}", shim_path.display());
        Ok(shim_path)
    }

    /// Generate shims for the specified tools.
    ///
    /// # Arguments
    ///
    /// * `tools` - Slice of tool names to generate shims for
    ///
    /// # Example
    ///
    /// ```
    /// use guard::shim::ShimGenerator;
    ///
    /// let gen = ShimGenerator::with_defaults().unwrap();
    /// gen.generate(&["ssh", "scp", "curl"])?;
    /// ```
    pub fn generate(&self, tools: &[&str]) -> Result<Vec<PathBuf>> {
        let mut paths = Vec::with_capacity(tools.len());

        for tool in tools {
            let path = self.generate_tool(tool)?;
            paths.push(path);
        }

        tracing::info!(
            "generated {} shims in {}",
            paths.len(),
            self.shim_dir.display()
        );
        Ok(paths)
    }

    /// Generate shims for all default tools.
    ///
    /// See [`DEFAULT_TOOLS`] for the list of tools.
    pub fn generate_all(&self) -> Result<Vec<PathBuf>> {
        let tools: Vec<&str> = DEFAULT_TOOLS.iter().map(|(name, _)| *name).collect();
        self.generate(&tools)
    }

    /// Remove the shim for a specific tool.
    pub fn remove_tool(&self, tool: &str) -> Result<()> {
        if !is_valid_tool_name(tool) {
            bail!("invalid tool name: '{}'", tool);
        }

        let shim_path = self.shim_dir.join(tool);

        if !shim_path.exists() {
            tracing::debug!(
                "shim does not exist, nothing to remove: {}",
                shim_path.display()
            );
            return Ok(());
        }

        fs::remove_file(&shim_path)
            .context(format!("failed to remove shim: {}", shim_path.display()))?;

        tracing::debug!("removed shim: {}", shim_path.display());
        Ok(())
    }

    /// Remove shims for the specified tools.
    ///
    /// # Arguments
    ///
    /// * `tools` - Slice of tool names to remove shims for
    pub fn remove(&self, tools: &[&str]) -> Result<()> {
        for tool in tools {
            self.remove_tool(tool)?;
        }

        tracing::info!(
            "removed {} shims from {}",
            tools.len(),
            self.shim_dir.display()
        );
        Ok(())
    }

    /// Remove all shims from the shim directory.
    ///
    /// This removes all files in the shim directory that correspond to known tools.
    pub fn remove_all(&self) -> Result<()> {
        let tools: Vec<&str> = DEFAULT_TOOLS.iter().map(|(name, _)| *name).collect();
        self.remove(&tools)
    }

    /// List all currently installed shims.
    ///
    /// Returns tool names that have shims in the shim directory.
    pub fn list_installed(&self) -> Result<Vec<String>> {
        if !self.shim_dir.exists() {
            return Ok(Vec::new());
        }

        let entries = fs::read_dir(&self.shim_dir).context(format!(
            "failed to read shim directory: {}",
            self.shim_dir.display()
        ))?;

        let mut installed = Vec::new();
        for entry in entries {
            let entry = entry?;
            let path = entry.path();

            // Skip directories
            if path.is_dir() {
                continue;
            }

            // Get the filename as a tool name
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                // Only include files that are valid tool names
                if is_valid_tool_name(name) {
                    installed.push(name.to_string());
                }
            }
        }

        installed.sort();
        Ok(installed)
    }

    /// Get information about all available tools.
    ///
    /// Returns a slice of tool descriptors for all tools that can have shims.
    pub fn available_tools() -> Vec<ShimTool> {
        DEFAULT_TOOLS
            .iter()
            .map(|(name, desc)| ShimTool::new(name, desc))
            .collect()
    }

    /// Render the shim script content for a tool.
    fn render_shim(&self, tool: &str) -> String {
        // The guard binary path needs shell-safe quoting
        let guard_bin = escape_for_shell(self.guard_binary.to_string_lossy().as_ref());

        // Use exec to replace the shell process, preserving all arguments via "$@"
        // The single quotes around $@ prevent any additional shell expansion
        format!(
            "#!/bin/sh\n\
             # Shim generated by guard for '{tool}'\n\
             # Do not edit manually - regenerate with: guard shim generate\n\
             exec {guard_bin} exec '{tool}' \"$@\"\n",
            tool = tool,
            guard_bin = guard_bin
        )
    }
}

/// Find the guard binary in PATH.
fn find_guard_binary() -> Result<PathBuf> {
    // First check if there's a configured path
    if let Some(path) = std::env::var("GUARD_BIN")
        .ok()
        .or_else(|| std::env::var("SSH_GUARD_BIN").ok())
    {
        let path = PathBuf::from(&path);
        if path.exists() {
            return Ok(path);
        }
    }

    // Try to find 'guard' in PATH
    if let Ok(path) = std::env::var("PATH") {
        for dir in path.split(':') {
            let candidate = PathBuf::from(dir).join("guard");
            if candidate.exists() {
                return Ok(candidate);
            }
        }
    }

    bail!("could not find 'guard' binary in PATH. Set SSH_GUARD_BIN or ensure guard is in PATH.")
}

/// Get the default shim directory path.
fn default_shim_dir() -> Result<PathBuf> {
    let home = dirs::home_dir().context("could not determine home directory")?;

    Ok(home.join(".guard").join("shims"))
}

/// Check if a tool name is valid (alphanumeric plus hyphens/underscores).
fn is_valid_tool_name(name: &str) -> bool {
    !name.is_empty()
        && name.len() <= 64
        && name
            .chars()
            .all(|c| c.is_alphanumeric() || c == '-' || c == '_')
}

/// Escape a path for safe use in a shell script.
///
/// Wraps the path in single quotes, escaping any single quotes within.
fn escape_for_shell(s: &str) -> String {
    // Replace ' with '\'' (end quote, escaped quote, start new quote)
    // Then wrap in single quotes
    let escaped = s.replace('\'', "'\\''");
    format!("'{}'", escaped)
}

/// Escape a path for use in double-quoted shell strings.
///
/// For use in contexts like: export PATH="...":$PATH
fn escape_path_for_shell(path: &Path) -> String {
    escape_for_shell(path.to_string_lossy().as_ref())
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::sync::Mutex;

    // -------------------------------------------------------------------------
    // Tests for utility functions
    // -------------------------------------------------------------------------

    #[test]
    fn test_is_valid_tool_name() {
        // Valid names
        assert!(is_valid_tool_name("ssh"));
        assert!(is_valid_tool_name("kubectl"));
        assert!(is_valid_tool_name("git-commit"));
        assert!(is_valid_tool_name("docker-container"));
        assert!(is_valid_tool_name("aws_cli_v2"));

        // Invalid names
        assert!(!is_valid_tool_name(""));
        assert!(!is_valid_tool_name("ssh scp")); // space
        assert!(!is_valid_tool_name("ssh;rm")); // semicolon
        assert!(!is_valid_tool_name("$(whoami)")); // command substitution
        assert!(!is_valid_tool_name("../../../etc/passwd")); // path traversal
    }

    #[test]
    fn test_escape_for_shell() {
        // Simple case - no escaping needed
        assert_eq!(escape_for_shell("/usr/local/bin"), "'/usr/local/bin'");

        // Single quote inside
        assert_eq!(escape_for_shell("O'Brien"), "'O'\\''Brien'");

        // Empty string
        assert_eq!(escape_for_shell(""), "''");

        // Path with spaces
        assert_eq!(escape_for_shell("/path/with spaces"), "'/path/with spaces'");

        // Path with special chars
        assert_eq!(
            escape_for_shell("/path/with'dquote"),
            "'/path/with'\\''dquote'"
        );
    }

    #[test]
    fn test_escape_path_for_shell() {
        let path = PathBuf::from("/home/user/.guard/shims");
        assert_eq!(escape_path_for_shell(&path), "'/home/user/.guard/shims'");
    }

    // -------------------------------------------------------------------------
    // Tests for ShimGenerator
    // -------------------------------------------------------------------------

    fn temp_shim_dir() -> (Mutex<PathBuf>, ShimGenerator) {
        let temp_dir = tempfile::tempdir().expect("failed to create temp dir");
        #[allow(deprecated)]
        let temp_path = temp_dir.into_path();
        let guard_binary = "/usr/local/bin/guard".to_string();

        let gen = ShimGenerator::new(&guard_binary, &temp_path);

        // Keep temp_path alive by returning it wrapped in Mutex
        // The ShimGenerator holds the path, so we just need to ensure
        // the directory exists for the lifetime of the test
        (Mutex::new(temp_path), gen)
    }

    #[test]
    fn test_shim_generator_new() {
        let gen = ShimGenerator::new("/usr/bin/guard", "/home/user/shims");
        assert_eq!(gen.path(), PathBuf::from("/home/user/shims"));
    }

    #[test]
    fn test_shim_generator_path_instruction() {
        let gen = ShimGenerator::new("/usr/bin/guard", "/home/user/.guard/shims");
        let instruction = gen.path_instruction();
        assert!(instruction.starts_with("export PATH="));
        assert!(instruction.contains("/home/user/.guard/shims"));
        assert!(instruction.ends_with(":$PATH"));
    }

    #[test]
    fn test_generate_single_shim() -> Result<()> {
        let (_temp, gen) = temp_shim_dir();

        let path = gen.generate_tool("ssh")?;
        assert!(path.exists());

        // Verify content
        let content = fs::read_to_string(&path)?;
        assert!(content.contains("#!/bin/sh"));
        assert!(content.contains("exec"));
        assert!(content.contains("guard"));
        assert!(content.contains("ssh"));

        // Verify it's executable (Unix mode bit only; no equivalent on Windows).
        #[cfg(unix)]
        {
            use std::os::unix::fs::PermissionsExt;
            let metadata = fs::metadata(&path)?;
            let mode = metadata.permissions().mode() & 0o777;
            assert_eq!(mode, 0o755);
        }

        Ok(())
    }

    #[test]
    fn test_generate_creates_directory() -> Result<()> {
        let temp_base = tempfile::tempdir()?;
        let shim_dir = temp_base.path().join("deeply/nested/shims");
        let gen = ShimGenerator::new("/usr/bin/guard", &shim_dir);

        gen.generate_tool("curl")?;
        assert!(shim_dir.exists());
        assert!(shim_dir.join("curl").exists());

        Ok(())
    }

    #[test]
    fn test_generate_multiple_tools() -> Result<()> {
        let (_temp, gen) = temp_shim_dir();

        let tools = ["ssh", "scp", "curl"];
        let paths = gen.generate(&tools)?;

        assert_eq!(paths.len(), 3);
        for tool in &tools {
            assert!(gen.path().join(tool).exists());
        }

        Ok(())
    }

    #[test]
    fn test_generate_all_tools() -> Result<()> {
        let (_temp, gen) = temp_shim_dir();

        let paths = gen.generate_all()?;
        assert_eq!(paths.len(), DEFAULT_TOOLS.len());

        for (name, _) in DEFAULT_TOOLS {
            assert!(gen.path().join(name).exists(), "missing shim for {}", name);
        }

        Ok(())
    }

    #[test]
    fn test_generate_invalid_tool_name() {
        let (_temp, gen) = temp_shim_dir();

        let result = gen.generate_tool("ssh;rm");
        assert!(result.is_err());
        assert!(result
            .unwrap_err()
            .to_string()
            .contains("invalid tool name"));
    }

    #[test]
    fn test_remove_single_shim() -> Result<()> {
        let (_temp, gen) = temp_shim_dir();

        // First generate
        gen.generate_tool("ssh")?;
        assert!(gen.path().join("ssh").exists());

        // Then remove
        gen.remove_tool("ssh")?;
        assert!(!gen.path().join("ssh").exists());

        Ok(())
    }

    #[test]
    fn test_remove_nonexistent_shim() -> Result<()> {
        let (_temp, gen) = temp_shim_dir();

        // Should not error when removing non-existent shim
        gen.remove_tool("nonexistent")?;
        assert!(!gen.path().join("nonexistent").exists());

        Ok(())
    }

    #[test]
    fn test_remove_multiple_tools() -> Result<()> {
        let (_temp, gen) = temp_shim_dir();

        let tools = ["ssh", "scp", "curl"];
        gen.generate(&tools)?;

        gen.remove(&tools)?;

        for tool in &tools {
            assert!(!gen.path().join(tool).exists());
        }

        Ok(())
    }

    #[test]
    fn test_remove_all() -> Result<()> {
        let (_temp, gen) = temp_shim_dir();

        gen.generate_all()?;
        gen.remove_all()?;

        for (name, _) in DEFAULT_TOOLS {
            assert!(
                !gen.path().join(name).exists(),
                "shim {} still exists",
                name
            );
        }

        Ok(())
    }

    #[test]
    fn test_list_installed_empty() -> Result<()> {
        let (_temp, gen) = temp_shim_dir();

        let installed = gen.list_installed()?;
        assert!(installed.is_empty());

        Ok(())
    }

    #[test]
    fn test_list_installed() -> Result<()> {
        let (_temp, gen) = temp_shim_dir();

        gen.generate(&["ssh", "scp", "curl"])?;

        let installed = gen.list_installed()?;
        assert_eq!(installed.len(), 3);
        assert!(installed.contains(&"ssh".to_string()));
        assert!(installed.contains(&"scp".to_string()));
        assert!(installed.contains(&"curl".to_string()));

        Ok(())
    }

    #[test]
    fn test_list_installed_ignores_non_tools() -> Result<()> {
        let (_temp, gen) = temp_shim_dir();

        gen.generate_tool("ssh")?;

        // Add a non-tool file
        let other_file = gen.path().join("README.txt");
        fs::write(&other_file, "not a shim")?;

        let installed = gen.list_installed()?;
        assert_eq!(installed.len(), 1);
        assert_eq!(installed[0], "ssh");

        Ok(())
    }

    #[test]
    fn test_render_shim_content() {
        let gen = ShimGenerator::new("/usr/bin/guard", "/home/user/shims");
        let content = gen.render_shim("ssh");

        // Check shebang
        assert!(content.starts_with("#!/bin/sh\n"));

        // Check tool name comment
        assert!(content.contains("# Shim generated by guard for 'ssh'"));

        // Check exec line
        assert!(content.contains("exec '/usr/bin/guard' exec 'ssh' \"$@\""));
    }

    #[test]
    fn test_shim_tool_new() {
        let tool = ShimTool::new("ssh", "Secure Shell");
        assert_eq!(tool.name, "ssh");
        assert_eq!(tool.description, "Secure Shell");
    }

    #[test]
    fn test_available_tools() {
        let tools = ShimGenerator::available_tools();

        // Should have all default tools
        assert!(!tools.is_empty());
        assert_eq!(tools.len(), DEFAULT_TOOLS.len());

        // Check that expected tools are present
        let tool_names: Vec<_> = tools.iter().map(|t| t.name).collect();
        assert!(tool_names.contains(&"ssh"));
        assert!(tool_names.contains(&"curl"));
        assert!(tool_names.contains(&"git"));
    }

    // -------------------------------------------------------------------------
    // Tests for shell escaping edge cases
    // -------------------------------------------------------------------------

    #[test]
    fn test_shim_content_with_single_quote_in_path() {
        let gen = ShimGenerator::new("/path/with'quote/guard", "/home/user/shims");
        let content = gen.render_shim("ssh");

        // Should escape the single quote properly
        assert!(content.contains("exec '/path/with'\\''quote/guard'"));
    }

    #[test]
    fn test_path_instruction_escapes_path() {
        let gen = ShimGenerator::new("/usr/bin/guard", "/path/with' spaces/shims");
        let instruction = gen.path_instruction();

        // Should properly escape the path with spaces
        assert!(instruction.contains("'"));
        assert!(instruction.contains("export PATH="));
    }
}
