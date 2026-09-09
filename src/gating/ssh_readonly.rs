//! Legacy SSH argv parsing retained for request validation, credential-path
//! preflight, and wire compatibility. SSH has no executable authority profile,
//! so these pure parsers cannot authorize process start.

/// SSH options that consume the following argument as their value.
///
/// This mirrors the option forms listed in OpenSSH's usage synopsis. Keeping
/// it with [`ssh_argument_boundaries`] makes all consumers agree on which
/// tokens are destination/command positionals rather than option values.
const SSH_OPTIONS_WITH_ARGUMENT: &[&str] = &[
    "-B", "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O", "-o", "-P",
    "-p", "-Q", "-R", "-S", "-W", "-w",
];

/// Indexes that split an SSH argv into its option zone, destination, and
/// remote command. SSH accepts options before the destination and between the
/// destination and the first remote-command token. Once that command token is
/// reached, every remaining token belongs to the remote command, including
/// dash-prefixed arguments.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct SshArgumentBoundaries {
    pub destination: Option<usize>,
    pub command_start: Option<usize>,
}

/// Find the destination and first remote-command token using OpenSSH's two
/// option prefixes. OpenSSH parses options once before the destination and,
/// unless `--` ended option parsing, once more immediately after it. The first
/// token after those prefixes starts the remote command; its entire suffix is
/// left untouched.
pub fn ssh_argument_boundaries(args: &[String]) -> SshArgumentBoundaries {
    let leading_options = ssh_option_prefix(args, 0);
    let destination = (leading_options.end < args.len()).then_some(leading_options.end);
    let Some(destination) = destination else {
        return SshArgumentBoundaries {
            destination: None,
            command_start: None,
        };
    };

    let after_destination = destination + 1;
    let command_start = if leading_options.terminated {
        (after_destination < args.len()).then_some(after_destination)
    } else {
        let trailing_options = ssh_option_prefix(args, after_destination);
        (trailing_options.end < args.len()).then_some(trailing_options.end)
    };

    SshArgumentBoundaries {
        destination: Some(destination),
        command_start,
    }
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
struct SshOptionPrefix {
    end: usize,
    terminated: bool,
}

/// Consume only a local SSH-option prefix. Returning at the first positional
/// token is what prevents dash-prefixed arguments after the remote command
/// starts from being reconsidered as SSH options.
fn ssh_option_prefix(args: &[String], start: usize) -> SshOptionPrefix {
    let mut index = start;
    while index < args.len() {
        let arg = args[index].as_str();
        if arg == "--" {
            return SshOptionPrefix {
                end: index + 1,
                terminated: true,
            };
        }
        if !arg.starts_with('-') {
            break;
        }

        let width = 1 + usize::from(ssh_option_takes_separate_argument(arg));
        index = index.saturating_add(width).min(args.len());
    }

    SshOptionPrefix {
        end: index,
        terminated: false,
    }
}

fn ssh_option_takes_separate_argument(arg: &str) -> bool {
    SSH_OPTIONS_WITH_ARGUMENT.contains(&arg)
}

/// Allow-list (deny-by-default) check on the ssh options in an invocation.
/// Returns true only when every option is on a small set known to be safe for
/// a read-only diagnostic: no command execution, no agent / X11 / port /
/// socket forwarding, no proxy or jump host, no tunnel, no external config or
/// identity/library file, and no control socket. Any unrecognized option
/// fails this legacy compatibility classification.
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
/// directives outside the vetted keyword set) fail this classification.
/// Combined short flags such as `-Cq` are treated as unrecognized rather than
/// decomposed and therefore fail this classification.
pub fn ssh_options_all_readonly_safe(args: &[String]) -> bool {
    let boundaries = ssh_argument_boundaries(args);
    let option_zone_end = boundaries.command_start.unwrap_or(args.len());
    let mut i = 0;
    while i < option_zone_end {
        let arg = args[i].as_str();

        // The destination remains positional even when `--` permits a name
        // beginning with a dash. The shared boundary parser has already
        // excluded the remote command and every one of its arguments.
        if boundaries.destination == Some(i) {
            i += 1;
            continue;
        }
        // The option terminator is syntax, not a local behavior switch.
        if arg == "--" {
            i += 1;
            continue;
        }
        if !arg.starts_with('-') {
            i += 1;
            continue;
        }
        // A bare "-" is not a valid ssh option; be conservative.
        if arg == "-" {
            return false;
        }

        // `-o directive` (separate value): only a vetted keyword is allowed.
        if arg == "-o" {
            match args.get(i + 1).filter(|_| i + 1 < option_zone_end) {
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
            if i + 1 >= option_zone_end {
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
        // key/library file, control socket, X11, unknown option) fails.
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
        // diagnostic's output, so those fail the compatibility classifier. An
        // empty value falls back to
        // ssh's strict default, which is safe.
        "stricthostkeychecking" => matches!(directive_value, "yes" | "accept-new" | ""),
        _ => false,
    }
}

/// True only for an exact, whole read-only diagnostic command (no shell
/// control, no arguments beyond a fixed safe flag). Anything else returns
/// false. This classifier does not grant executable authority.
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
