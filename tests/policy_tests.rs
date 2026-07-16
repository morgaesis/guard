use guard::policy::PolicyEngine;
use serde::Deserialize;

#[derive(Debug, Deserialize)]
struct TestCase {
    command: String,
    expect: String,
    desc: String,
}

fn load_tests() -> Vec<TestCase> {
    let yaml = include_str!("guard_tests.yaml");
    let tests: Vec<TestCase> =
        serde_yaml_ng::from_str(yaml).expect("failed to parse guard_tests.yaml");
    tests
}

#[derive(Debug, Deserialize)]
struct CtfScenario {
    command: String,
    category: String,
    desc: String,
    expect: String,
}

fn load_ctf_scenarios() -> Vec<CtfScenario> {
    let yaml = include_str!("ctf_scenarios.yaml");
    serde_yaml_ng::from_str(yaml).expect("failed to parse ctf_scenarios.yaml")
}

/// Load the example deny policy from examples/deny-policy.yaml.
fn load_deny_policy() -> PolicyEngine {
    let yaml = include_str!("../examples/deny-policy.yaml");
    PolicyEngine::load_yaml(yaml).expect("failed to parse deny-policy.yaml")
}

fn create_test_policy() -> PolicyEngine {
    PolicyEngine::new()
        .add_allow("whoami")
        .add_allow("hostname")
        .add_allow("pwd")
        .add_allow("id")
        .add_allow("uname")
        .add_allow("date")
        .add_allow("echo")
        .add_allow("cat /etc/hosts")
        .add_allow("cat /etc/passwd")
        .add_allow("ls")
        .add_allow("ps")
        .add_allow("free")
        .add_allow("df")
        .add_allow("du")
        .add_allow("uptime")
        .add_allow("netstat")
        .add_allow("iptables -L")
        .add_allow("docker")
        .add_allow("git")
        .add_deny("sudo su")
        .add_deny("sudo -i")
        .add_deny("su root")
        .add_deny("rm -rf /")
        .add_deny("rm -rf /*")
        .add_deny("dd if=*")
        .add_deny("dd of=*")
        .add_deny("mkfs.*")
        .add_deny("iptables -F")
        .add_deny("systemctl stop")
        .add_deny("curl * | bash")
        .add_deny("wget * | sh")
        .add_deny(":(){:|:&};:")
        .add_deny("cat /etc/shadow")
        .add_deny("cat /etc/sudoers")
}

/// Every guard_tests.yaml case is evaluated against the static test policy,
/// the same way the CTF scenarios are evaluated against the example deny
/// policy. Expectations in the file reflect static glob semantics, including
/// its documented limitations (shell operators are invisible to glob
/// patterns; the LLM evaluator layer covers those).
#[test]
fn test_guard_yaml_suite_against_static_policy() {
    let engine = create_test_policy();
    let tests = load_tests();
    assert!(!tests.is_empty(), "guard_tests.yaml should have test cases");

    let allow_count = tests.iter().filter(|t| t.expect == "ALLOW").count();
    let deny_count = tests.iter().filter(|t| t.expect == "DENY").count();
    assert!(allow_count > 10, "should have ALLOW test cases");
    assert!(deny_count > 5, "should have DENY test cases");

    let mut failures = Vec::new();
    for case in &tests {
        let result = engine.check(&case.command);
        let met = match case.expect.as_str() {
            "ALLOW" => result.is_allowed(),
            "DENY" => result.is_denied(),
            other => {
                failures.push(format!(
                    "  {}: unknown expect value: {other}\n    command: {}",
                    case.desc, case.command
                ));
                continue;
            }
        };
        if !met {
            failures.push(format!(
                "  {}: expected {}, got {:?}\n    command: {}",
                case.desc, case.expect, result, case.command
            ));
        }
    }

    assert!(
        failures.is_empty(),
        "\nguard_tests.yaml failures ({}/{}):\n{}",
        failures.len(),
        tests.len(),
        failures.join("\n")
    );
}

// === CTF scenario tests against example deny policy ===

#[test]
fn test_ctf_deny_policy() {
    let engine = load_deny_policy();
    let scenarios = load_ctf_scenarios();
    let mut failures = Vec::new();

    for scenario in &scenarios {
        let result = engine.check(&scenario.command);
        // "matched deny pattern: X" = explicit deny pattern match
        // "default-deny: ..." = no pattern matched at all
        let caught_by_deny = result.reason.contains("matched deny pattern");

        match scenario.expect.as_str() {
            "DENY" => {
                if !caught_by_deny {
                    failures.push(format!(
                        "  [{}] {}: expected DENY (pattern match), got: {}\n    command: {}",
                        scenario.category, scenario.desc, result.reason, scenario.command,
                    ));
                }
            }
            "PASS" => {
                if caught_by_deny {
                    failures.push(format!(
                        "  [{}] {}: expected PASS (no deny match), but caught: {}\n    command: {}",
                        scenario.category, scenario.desc, result.reason, scenario.command,
                    ));
                }
            }
            other => {
                failures.push(format!(
                    "  [{}] {}: unknown expect value: {}",
                    scenario.category, scenario.desc, other,
                ));
            }
        }
    }

    assert!(
        failures.is_empty(),
        "\nDeny policy test failures ({}/{}):\n{}",
        failures.len(),
        scenarios.len(),
        failures.join("\n")
    );
}

#[test]
fn test_ctf_scenarios_parsable() {
    let scenarios = load_ctf_scenarios();
    assert!(
        scenarios.len() >= 55,
        "should have at least 55 CTF scenarios, got {}",
        scenarios.len()
    );

    let categories: std::collections::HashSet<_> =
        scenarios.iter().map(|s| s.category.as_str()).collect();
    assert!(
        categories.len() >= 10,
        "should have at least 10 categories, got {}",
        categories.len()
    );

    for scenario in &scenarios {
        assert!(
            scenario.expect == "DENY" || scenario.expect == "PASS",
            "scenario '{}' has invalid expect: {} (must be DENY or PASS)",
            scenario.desc,
            scenario.expect
        );
    }
}

#[test]
fn test_empty_mode_engines_have_no_patterns() {
    use guard::policy::PolicyMode;

    for mode in [PolicyMode::Readonly, PolicyMode::Safe, PolicyMode::Paranoid] {
        let engine = PolicyEngine::from_mode(mode);
        assert!(
            engine.allow_list().is_empty(),
            "{:?} mode should have no allow patterns",
            mode
        );
        assert!(
            engine.deny_list().is_empty(),
            "{:?} mode should have no deny patterns",
            mode
        );
    }
}
