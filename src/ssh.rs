/// SSH options that take a separate argument value.
const OPTS_WITH_ARG: &[&str] = &[
    "-b", "-c", "-D", "-E", "-e", "-F", "-I", "-i", "-J", "-L", "-l", "-m", "-O", "-o", "-p", "-Q",
    "-R", "-S", "-W", "-w",
];

/// Extract the remote command from SSH arguments.
/// SSH syntax: ssh [options] destination [command [argument ...]]
pub fn extract_command(args: &[String]) -> String {
    let mut skip_next = false;
    let mut found_destination = false;
    let mut cmd_parts: Vec<&str> = Vec::new();

    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }

        let mut is_opt_with_arg = false;
        for opt in OPTS_WITH_ARG {
            if arg == *opt {
                is_opt_with_arg = true;
                skip_next = true;
                break;
            }
            // Handle -oValue (option+value concatenated)
            if arg.starts_with(opt) && arg.len() > 2 {
                is_opt_with_arg = true;
                break;
            }
        }
        if is_opt_with_arg {
            continue;
        }

        // Skip standalone flags
        if arg.starts_with('-') {
            continue;
        }

        // First non-option is destination, rest is the command
        if !found_destination {
            found_destination = true;
            continue;
        }

        cmd_parts.push(arg);
    }

    cmd_parts.join(" ")
}

/// Extract the destination host from SSH arguments.
pub fn extract_destination(args: &[String]) -> Option<String> {
    let mut skip_next = false;

    for arg in args {
        if skip_next {
            skip_next = false;
            continue;
        }

        let mut is_opt_with_arg = false;
        for opt in OPTS_WITH_ARG {
            if arg == *opt {
                is_opt_with_arg = true;
                skip_next = true;
                break;
            }
            if arg.starts_with(opt) && arg.len() > 2 {
                is_opt_with_arg = true;
                break;
            }
        }
        if is_opt_with_arg {
            continue;
        }

        if arg.starts_with('-') {
            continue;
        }

        return Some(arg.clone());
    }

    None
}

#[cfg(test)]
mod tests {
    use super::*;

    fn args(s: &[&str]) -> Vec<String> {
        s.iter().map(|x| x.to_string()).collect()
    }

    #[test]
    fn test_extract_command_simple() {
        // When command is a single quoted string (typical usage)
        assert_eq!(extract_command(&args(&["user@host", "ls -la"])), "ls -la");
    }

    #[test]
    fn test_extract_command_separate_args() {
        // Separate args: -la looks like a flag and gets skipped (matches bash behavior)
        assert_eq!(extract_command(&args(&["user@host", "ls", "-la"])), "ls");
    }

    #[test]
    fn test_extract_command_with_options() {
        assert_eq!(
            extract_command(&args(&["-p", "2222", "user@host", "uptime"])),
            "uptime"
        );
    }

    #[test]
    fn test_extract_command_with_concatenated_option() {
        assert_eq!(
            extract_command(&args(&["-p2222", "user@host", "df -h"])),
            "df -h"
        );
    }

    #[test]
    fn test_extract_command_no_command() {
        assert_eq!(extract_command(&args(&["user@host"])), "");
    }

    #[test]
    fn test_extract_command_with_flags() {
        assert_eq!(
            extract_command(&args(&["-v", "-A", "user@host", "cat", "/etc/hosts"])),
            "cat /etc/hosts"
        );
    }

    #[test]
    fn test_extract_command_with_identity_file() {
        assert_eq!(
            extract_command(&args(&["-i", "/path/to/key", "host", "whoami"])),
            "whoami"
        );
    }

    #[test]
    fn test_extract_destination_simple() {
        assert_eq!(
            extract_destination(&args(&["user@host", "ls"])),
            Some("user@host".to_string())
        );
    }

    #[test]
    fn test_extract_destination_with_options() {
        assert_eq!(
            extract_destination(&args(&["-p", "22", "-i", "key", "myhost"])),
            Some("myhost".to_string())
        );
    }

    #[test]
    fn test_extract_destination_none() {
        assert_eq!(extract_destination(&args(&["-v", "-A"])), None);
    }
}
