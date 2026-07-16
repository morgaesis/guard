//! Deterministic pre-LLM classification of ssh invocations as read-only-safe.
//! These parsers decide whether a guarded ssh command can take the
//! deterministic allow fast path without evaluator review, so a parsing
//! divergence here skips evaluation entirely. They are pure functions on the
//! untrusted argv, kept in the library crate so they can be fuzzed.

/// Allow-list (deny-by-default) check on the ssh options in an invocation.
/// Returns true only when every option is on a small set known to be safe for
/// a read-only diagnostic: no command execution, no agent / X11 / port /
/// socket forwarding, no proxy or jump host, no tunnel, no external config or
/// identity/library file, and no control socket. Any unrecognized option
/// forfeits the fast path to the evaluator.
///
/// The scan covers the whole "option zone", not just the options before the
/// destination. ssh honors options that appear *between* the destination and
/// the remote command (e.g. `ssh host -o ProxyCommand=... id`), so scanning
/// stops only at the command itself - the second positional (non-option)
/// token. Everything from there on is the remote command's own arguments,
/// which ssh does not re-parse as options. (Verified against ssh's own
/// `-G` dry run: an `-o` before the command token is applied; one after it is
/// not.)
///
/// This is intentionally stricter than enumerating dangerous options: an
/// option we have not vetted (including future ssh additions, `-F` external
/// configs, `-I` PKCS#11 modules, `-E`/`-i`/`-S` file paths, and `-o`
/// directives outside the vetted keyword set) never takes the fast path.
/// Combined short flags such as `-Cq` are treated as unrecognized rather than
/// decomposed, again forfeiting to the evaluator.
pub fn ssh_options_all_readonly_safe(args: &[String]) -> bool {
    // 0 = before the destination, 1 = between destination and remote command.
    let mut positionals_seen = 0;
    let mut i = 0;
    while i < args.len() {
        let arg = args[i].as_str();

        // A non-option token is either the destination (first) or the start
        // of the remote command (second). Once the command starts, the rest
        // are command arguments that ssh does not treat as options.
        if !arg.starts_with('-') {
            positionals_seen += 1;
            if positionals_seen >= 2 {
                return true;
            }
            i += 1;
            continue;
        }
        // A bare "-" is not a valid ssh option; be conservative.
        if arg == "-" {
            return false;
        }

        // `-o directive` (separate value): only a vetted keyword is allowed.
        if arg == "-o" {
            match args.get(i + 1) {
                Some(value) if ssh_o_directive_readonly_safe(value) => {
                    i += 2;
                    continue;
                }
                _ => return false,
            }
        }
        // `-oDirective` (concatenated value).
        if let Some(value) = arg.strip_prefix("-o") {
            if ssh_o_directive_readonly_safe(value) {
                i += 1;
                continue;
            }
            return false;
        }

        // `-p port` / `-l login`: the value is an inert port or username.
        // Consume the value token so it is not mistaken for a positional.
        if arg == "-p" || arg == "-l" {
            if args.get(i + 1).is_none() {
                return false;
            }
            i += 2;
            continue;
        }
        // `-p2222` / `-lroot` (concatenated value).
        if arg.starts_with("-p") || arg.starts_with("-l") {
            i += 1;
            continue;
        }

        // Bare boolean flags known safe for a read-only diagnostic.
        if is_safe_ssh_flag(arg) {
            i += 1;
            continue;
        }

        // Anything else (forwarding, proxy, jump, tunnel, external config or
        // key/library file, control socket, X11, unknown option) forfeits.
        return false;
    }
    true
}

/// Boolean ssh flags that cannot turn a read-only diagnostic into code
/// execution, forwarding, or file indirection: address-family selection,
/// compression, quiet/verbose logging, no-tty, and the *restrictive* toggles
/// that disable agent / X11 / GSSAPI forwarding.
fn is_safe_ssh_flag(arg: &str) -> bool {
    if matches!(arg, "-4" | "-6" | "-C" | "-q" | "-T" | "-a" | "-x" | "-k") {
        return true;
    }
    // Verbosity: `-v`, `-vv`, `-vvv`, ...
    arg.len() >= 2 && arg[1..].bytes().all(|b| b == b'v')
}

/// True only for an `-o keyword[=value]` directive whose keyword is on a small
/// vetted set (batch/non-interactive behavior, connection timeouts, keepalive,
/// and host-key handling). Everything else - ProxyCommand, ProxyJump,
/// LocalCommand, RemoteCommand, *Forward, Tunnel, Include, IdentityFile,
/// ControlPath, and any unknown keyword - is rejected. A value containing a
/// newline is rejected outright so a second directive cannot be introduced on
/// a later line past the first-keyword check.
pub fn ssh_o_directive_readonly_safe(value: &str) -> bool {
    if value.contains('\n') || value.contains('\r') {
        return false;
    }
    let lower = value.trim_start().to_ascii_lowercase();
    let mut parts = lower
        .split(|ch: char| ch == '=' || ch.is_whitespace())
        .filter(|part| !part.is_empty());
    let key = parts.next().unwrap_or("");
    let directive_value = parts.next().unwrap_or("");
    match key {
        "batchmode"
        | "connecttimeout"
        | "connectionattempts"
        | "serveraliveinterval"
        | "serveralivecountmax"
        | "updatehostkeys"
        | "checkhostip" => true,
        // Host-key checking is permitted only in its security-preserving
        // forms. Disabling it (`no`/`off`) or deferring to an interactive
        // prompt (`ask`) would let an interposed relay alter the
        // diagnostic's output, so those forfeit to the evaluator rather than
        // taking the deterministic fast path. An empty value falls back to
        // ssh's strict default, which is safe.
        "stricthostkeychecking" => matches!(directive_value, "yes" | "accept-new" | ""),
        _ => false,
    }
}

/// True only for an exact, whole read-only diagnostic command (no shell
/// control, no arguments beyond a fixed safe flag). Anything else returns
/// false and falls back to the model.
pub fn is_fixed_readonly_diagnostic(command: &str) -> bool {
    if contains_shell_control(command) {
        return false;
    }
    let lower = command.trim().to_ascii_lowercase();
    let tokens = command_tokens(&lower);
    if tokens.is_empty() {
        return false;
    }

    matches!(
        tokens.as_slice(),
        [cmd] if matches!(cmd.as_str(), "id" | "whoami" | "hostname" | "uptime")
    ) || matches!(
        tokens.as_slice(),
        [cmd, flag] if cmd == "uname" && matches!(flag.as_str(), "-a" | "-r" | "-sr")
    ) || matches!(
        tokens.as_slice(),
        [cmd, flag] if cmd == "df" && matches!(flag.as_str(), "-h" | "-hi")
    )
}

pub fn contains_shell_control(command: &str) -> bool {
    command.contains(';')
        || command.contains("&&")
        || command.contains("||")
        || command.contains('|')
        || command.contains('>')
        || command.contains('<')
        || command.contains('`')
        || command.contains("$(")
        || command.contains('\n')
}

pub fn command_tokens(command: &str) -> Vec<String> {
    command
        .split(|c: char| {
            !(c.is_ascii_alphanumeric()
                || matches!(c, '-' | '_' | '.' | '/' | '~' | '*' | '?' | ':'))
        })
        .filter(|part| !part.is_empty())
        .map(str::to_string)
        .collect()
}
