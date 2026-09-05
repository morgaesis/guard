use guard::gating::ssh_readonly::ssh_argument_boundaries;

/// Extract the remote command from SSH arguments.
/// SSH syntax: ssh [options] destination [command [argument ...]]
pub fn extract_command(args: &[String]) -> String {
    ssh_argument_boundaries(args)
        .command_start
        .map(|index| args[index..].join(" "))
        .unwrap_or_default()
}

/// Extract the destination host from SSH arguments.
pub fn extract_destination(args: &[String]) -> Option<String> {
    ssh_argument_boundaries(args)
        .destination
        .map(|index| args[index].clone())
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
        assert_eq!(
            extract_command(&args(&["user@host", "ls", "-la"])),
            "ls -la"
        );
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
    fn test_extract_command_preserves_post_command_dash_arguments() {
        assert_eq!(
            extract_command(&args(&["user@host", "id", "-u", "--format=verbose"])),
            "id -u --format=verbose"
        );
    }

    #[test]
    fn test_extract_command_honors_option_terminator_after_destination() {
        assert_eq!(
            extract_command(&args(&["user@host", "--", "-remote-tool", "--flag"])),
            "-remote-tool --flag"
        );
    }

    #[test]
    fn test_extract_command_honors_option_terminator_before_destination() {
        let invocation = args(&["--", "-named-host", "id", "-u"]);
        assert_eq!(extract_destination(&invocation), Some("-named-host".into()));
        assert_eq!(extract_command(&invocation), "id -u");
    }

    #[test]
    fn test_extract_command_skips_safe_post_destination_option() {
        assert_eq!(
            extract_command(&args(&["user@host", "-o", "ConnectTimeout=5", "id"])),
            "id"
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
