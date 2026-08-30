use serde_json::json;
use serde_yaml_ng::{Mapping, Value};
use std::collections::BTreeSet;
use std::process::{Command, Output};

const DEPENDABOT_CONFIG: &str = include_str!("../.github/dependabot.yml");
const REVIEW_WORKFLOW: &str = include_str!("../.github/workflows/dependabot-automerge.yml");
const PRIVILEGED_WORKFLOW: &str =
    include_str!("../.github/workflows/dependabot-enable-automerge.yml");

fn parse_yaml(source: &str) -> Value {
    serde_yaml_ng::from_str(source).expect("workflow YAML must parse")
}

fn field<'a>(value: &'a Value, key: &str) -> &'a Value {
    value
        .as_mapping()
        .and_then(|mapping| mapping.get(Value::String(key.to_owned())))
        .unwrap_or_else(|| panic!("missing YAML field {key}"))
}

fn mapping(value: &Value) -> &Mapping {
    value.as_mapping().expect("expected YAML mapping")
}

fn string(value: &Value) -> &str {
    value.as_str().expect("expected YAML string")
}

fn strings(value: &Value) -> Vec<&str> {
    value
        .as_sequence()
        .expect("expected YAML sequence")
        .iter()
        .map(string)
        .collect()
}

fn job<'a>(workflow: &'a Value, name: &str) -> &'a Value {
    field(field(workflow, "jobs"), name)
}

fn steps(job: &Value) -> &[Value] {
    field(job, "steps")
        .as_sequence()
        .expect("job steps must be a sequence")
}

fn named_step<'a>(job: &'a Value, name: &str) -> &'a Value {
    steps(job)
        .iter()
        .find(|step| field(step, "name").as_str() == Some(name))
        .unwrap_or_else(|| panic!("missing workflow step {name}"))
}

fn run_script<'a>(job: &'a Value, name: &str) -> &'a str {
    string(field(named_step(job, name), "run"))
}

#[test]
fn dependabot_batches_each_ecosystem_by_semver_risk() {
    let config = parse_yaml(DEPENDABOT_CONFIG);
    assert!(mapping(&config).get("multi-ecosystem-groups").is_none());

    let updates = field(&config, "updates")
        .as_sequence()
        .expect("updates must be a sequence");
    assert_eq!(updates.len(), 4);

    let expected = [
        ("cargo", "/", "root-cargo-patch-minor", "root-cargo-major"),
        (
            "github-actions",
            "/",
            "github-actions-patch-minor",
            "github-actions-major",
        ),
        (
            "cargo",
            "/fuzz",
            "fuzz-cargo-patch-minor",
            "fuzz-cargo-major",
        ),
        (
            "docker",
            "/.clusterfuzzlite",
            "docker-patch-minor",
            "docker-major",
        ),
    ];

    for (ecosystem, directory, non_major_group, major_group) in expected {
        let update = updates
            .iter()
            .find(|entry| {
                field(entry, "package-ecosystem").as_str() == Some(ecosystem)
                    && field(entry, "directory").as_str() == Some(directory)
            })
            .unwrap_or_else(|| panic!("missing {ecosystem} update entry for {directory}"));
        assert!(mapping(update).get("cooldown").is_none());

        let groups = field(update, "groups");
        assert_eq!(mapping(groups).len(), 2);

        let non_major = field(groups, non_major_group);
        assert_eq!(strings(field(non_major, "patterns")), ["*"]);
        assert_eq!(
            strings(field(non_major, "update-types"))
                .into_iter()
                .collect::<BTreeSet<_>>(),
            BTreeSet::from(["minor", "patch"])
        );

        let major = field(groups, major_group);
        assert_eq!(strings(field(major, "patterns")), ["*"]);
        assert_eq!(strings(field(major, "update-types")), ["major"]);
    }
}

#[test]
fn review_gate_is_read_only_and_has_no_metadata_fallbacks() {
    let workflow = parse_yaml(REVIEW_WORKFLOW);
    let triggers = mapping(field(&workflow, "on"));
    assert_eq!(triggers.len(), 1);
    let pull_request = field(field(&workflow, "on"), "pull_request");
    assert_eq!(strings(field(pull_request, "branches")), ["main"]);
    assert_eq!(
        strings(field(pull_request, "types")),
        ["opened", "reopened", "synchronize"]
    );
    assert!(mapping(field(&workflow, "permissions")).is_empty());

    let review_job = job(&workflow, "review-gate");
    let permissions = mapping(field(review_job, "permissions"));
    assert_eq!(permissions.len(), 2);
    assert_eq!(field(field(review_job, "permissions"), "contents"), "read");
    assert_eq!(
        field(field(review_job, "permissions"), "pull-requests"),
        "read"
    );

    let source = run_script(review_job, "Validate pull request source");
    assert!(source.contains("$GITHUB_EVENT_PATH"));
    assert!(source.contains("dependabot[bot]"));
    assert!(source.contains("^[1-9][0-9]*$"));
    assert!(source.contains("^[0-9a-f]{40}$"));

    let metadata = named_step(review_job, "Resolve verified Dependabot metadata");
    assert_eq!(
        string(field(metadata, "uses")),
        "dependabot/fetch-metadata@25dd0e34f4fe68f24cc83900b1fe3fe149efef98"
    );

    let policy = run_script(review_job, "Enforce auto-merge policy");
    assert!(policy.contains("UPDATED_DEPENDENCIES_JSON"));
    assert!(policy.contains("version-update:semver-major"));
    assert!(policy.contains("packageEcosystem == $ecosystem"));
    assert!(policy.contains(".directory == $directory"));
    assert!(policy.contains(".targetBranch == $target"));

    for step in steps(review_job) {
        if let Some(run) = mapping(step).get("run").and_then(Value::as_str) {
            assert!(
                !run.contains("${{"),
                "run blocks must not expand expressions"
            );
            assert!(
                !run.contains(".body"),
                "PR bodies are not classifier inputs"
            );
            assert!(
                !run.contains("head_ref"),
                "branch names are not metadata inputs"
            );
        }
        if let Some(uses) = mapping(step).get("uses").and_then(Value::as_str) {
            assert!(uses.starts_with("dependabot/fetch-metadata@"));
        }
    }
}

fn privileged_policy_errors(source: &str) -> Vec<&'static str> {
    let Ok(workflow) = serde_yaml_ng::from_str::<Value>(source) else {
        return vec!["yaml"];
    };
    let mut errors = Vec::new();

    let Some(triggers) = mapping(&workflow).get("on").and_then(Value::as_mapping) else {
        return vec!["trigger"];
    };
    if triggers.len() != 1 || !triggers.contains_key("workflow_run") {
        errors.push("trigger");
    } else {
        let workflow_run = field(field(&workflow, "on"), "workflow_run");
        if strings(field(workflow_run, "workflows")) != ["Dependabot review gate"]
            || strings(field(workflow_run, "types")) != ["completed"]
        {
            errors.push("source-workflow");
        }
    }

    if !mapping(field(&workflow, "permissions")).is_empty() {
        errors.push("top-permissions");
    }

    let jobs = mapping(field(&workflow, "jobs"));
    if jobs.len() != 1 || !jobs.contains_key("enable-auto-merge") {
        errors.push("job-shape");
        return errors;
    }
    let merge_job = job(&workflow, "enable-auto-merge");
    let permissions = field(merge_job, "permissions");
    let permissions_valid = permissions.as_mapping().is_some_and(|permissions| {
        permissions.len() == 2
            && permissions.get("contents").and_then(Value::as_str) == Some("write")
            && permissions.get("pull-requests").and_then(Value::as_str) == Some("write")
    });
    if !permissions_valid {
        errors.push("job-permissions");
    }

    let job_steps = steps(merge_job);
    if job_steps.len() != 1 {
        errors.push("step-count");
    }
    if job_steps
        .iter()
        .any(|step| mapping(step).contains_key("uses"))
    {
        errors.push("uses-action");
    }

    let Some(run) = job_steps
        .iter()
        .find(|step| {
            mapping(step).get("name").and_then(Value::as_str)
                == Some("Validate source and enable auto-merge")
        })
        .and_then(|step| mapping(step).get("run"))
        .and_then(Value::as_str)
    else {
        errors.push("merge-step");
        return errors;
    };

    for forbidden in [
        "checkout",
        "artifact",
        "cache",
        ".body",
        "pull_request_target",
        "--admin",
        "bypass",
    ] {
        if run.to_ascii_lowercase().contains(forbidden) {
            errors.push("forbidden-input-or-bypass");
        }
    }
    if run.contains("${{") {
        errors.push("expression-in-run");
    }

    for required in [
        "$GITHUB_EVENT_PATH",
        ".workflow_run.event",
        ".workflow_run.actor.login",
        ".workflow_run.pull_requests | arrays | length",
        ".workflow_run.head_sha",
        ".workflow_run.repository.full_name",
        "[ \"$current_state\" != \"open\" ]",
        "[ \"$current_base_ref\" != \"main\" ]",
        "[ \"$current_head_sha\" != \"$source_head_sha\" ]",
        "--match-head-commit \"$source_head_sha\"",
        "--auto",
        "--squash",
    ] {
        if !run.contains(required) {
            errors.push("missing-validation-or-native-merge");
        }
    }

    errors
}

#[test]
fn privileged_workflow_has_one_validated_native_merge_step() {
    assert_eq!(
        privileged_policy_errors(PRIVILEGED_WORKFLOW),
        Vec::<&str>::new()
    );
}

#[test]
fn privileged_workflow_policy_rejects_negative_mutations() {
    let mutations = [
        (
            "checkout",
            PRIVILEGED_WORKFLOW.replace(
                "    steps:\n      - name:",
                "    steps:\n      - uses: actions/checkout@v4\n      - name:",
            ),
        ),
        (
            "artifact",
            PRIVILEGED_WORKFLOW.replace(
                "    steps:\n      - name:",
                "    steps:\n      - uses: actions/download-artifact@v4\n      - name:",
            ),
        ),
        (
            "cache",
            PRIVILEGED_WORKFLOW.replace(
                "    steps:\n      - name:",
                "    steps:\n      - uses: actions/cache@v4\n      - name:",
            ),
        ),
        (
            "pull request body",
            PRIVILEGED_WORKFLOW.replace(
                "head_repository: .head.repo.full_name",
                "head_repository: .head.repo.full_name, pull_body: .body",
            ),
        ),
        (
            "pull request target",
            PRIVILEGED_WORKFLOW.replace("  workflow_run:", "  pull_request_target:"),
        ),
        (
            "write all",
            PRIVILEGED_WORKFLOW.replace(
                "    permissions:\n      contents: write\n      pull-requests: write",
                "    permissions: write-all",
            ),
        ),
        (
            "admin bypass",
            PRIVILEGED_WORKFLOW.replace("            --auto \\\n", "            --auto \\\n            --admin \\\n"),
        ),
        (
            "stale head",
            PRIVILEGED_WORKFLOW.replace(
                " || [ \"$current_head_sha\" != \"$source_head_sha\" ]",
                "",
            ),
        ),
        (
            "untrusted interpolation",
            PRIVILEGED_WORKFLOW.replace(
                "          set -euo pipefail",
                "          set -euo pipefail\n          echo \"${{ github.event.workflow_run.head_sha }}\"",
            ),
        ),
    ];

    for (name, mutation) in mutations {
        assert_ne!(
            mutation, PRIVILEGED_WORKFLOW,
            "mutation {name} did not apply"
        );
        assert!(
            !privileged_policy_errors(&mutation).is_empty(),
            "mutation {name} escaped the privileged workflow policy"
        );
    }
}

#[cfg(unix)]
fn run_policy_script(
    script: &str,
    ecosystem: &str,
    directory: &str,
    update_type: &str,
    dependencies: serde_json::Value,
) -> Output {
    Command::new("bash")
        .args(["-c", script])
        .env("PACKAGE_ECOSYSTEM", ecosystem)
        .env("DIRECTORY", directory)
        .env("TARGET_BRANCH", "main")
        .env("UPDATE_TYPE", update_type)
        .env("UPDATED_DEPENDENCIES_JSON", dependencies.to_string())
        .output()
        .expect("classifier script must run")
}

#[cfg(unix)]
fn dependency(ecosystem: &str, directory: &str, update_type: &str) -> serde_json::Value {
    json!({
        "dependencyName": "example-package",
        "updateType": update_type,
        "packageEcosystem": ecosystem,
        "directory": directory,
        "targetBranch": "main"
    })
}

#[cfg(unix)]
#[test]
fn classifier_accepts_only_eligible_consistent_metadata() {
    let workflow = parse_yaml(REVIEW_WORKFLOW);
    let script = run_script(job(&workflow, "review-gate"), "Enforce auto-merge policy");

    let eligible = run_policy_script(
        script,
        "cargo",
        "/",
        "version-update:semver-minor",
        json!([
            dependency("cargo", "/", "version-update:semver-minor"),
            dependency("cargo", "/", "version-update:semver-patch")
        ]),
    );
    assert!(
        eligible.status.success(),
        "{}",
        String::from_utf8_lossy(&eligible.stderr)
    );

    let action_patch = run_policy_script(
        script,
        "github_actions",
        "/",
        "version-update:semver-patch",
        json!([dependency(
            "github_actions",
            "/",
            "version-update:semver-patch"
        )]),
    );
    assert!(action_patch.status.success());

    let rejected = [
        run_policy_script(
            script,
            "cargo",
            "/",
            "version-update:semver-major",
            json!([dependency("cargo", "/", "version-update:semver-major")]),
        ),
        run_policy_script(
            script,
            "docker",
            "/.clusterfuzzlite",
            "version-update:semver-patch",
            json!([dependency(
                "docker",
                "/.clusterfuzzlite",
                "version-update:semver-patch"
            )]),
        ),
        run_policy_script(
            script,
            "cargo",
            "/",
            "version-update:semver-minor",
            json!([
                dependency("cargo", "/", "version-update:semver-minor"),
                dependency("cargo", "/", "version-update:semver-major")
            ]),
        ),
        run_policy_script(
            script,
            "cargo",
            "/",
            "version-update:semver-patch",
            json!([dependency(
                "github_actions",
                "/",
                "version-update:semver-patch"
            )]),
        ),
        run_policy_script(
            script,
            "cargo",
            "/",
            "version-update:semver-patch",
            json!([]),
        ),
    ];
    assert!(rejected.iter().all(|output| !output.status.success()));
}

#[cfg(unix)]
fn privileged_event(repository: &str, head_sha: &str) -> serde_json::Value {
    json!({
        "action": "completed",
        "repository": { "full_name": repository },
        "workflow_run": {
            "name": "Dependabot review gate",
            "path": ".github/workflows/dependabot-automerge.yml",
            "event": "pull_request",
            "conclusion": "success",
            "actor": { "login": "dependabot[bot]" },
            "repository": { "full_name": repository },
            "pull_requests": [{ "number": 17 }],
            "head_sha": head_sha
        }
    })
}

#[cfg(unix)]
fn run_privileged_script(api_head_sha: &str) -> (Output, Option<String>) {
    use std::fs;
    use std::os::unix::fs::PermissionsExt;

    let workflow = parse_yaml(PRIVILEGED_WORKFLOW);
    let script = run_script(
        job(&workflow, "enable-auto-merge"),
        "Validate source and enable auto-merge",
    );
    let temp = tempfile::tempdir().expect("temporary test directory");
    let bin_dir = temp.path().join("bin");
    fs::create_dir(&bin_dir).expect("fake executable directory");
    let fake_gh = bin_dir.join("gh");
    fs::write(
        &fake_gh,
        r#"#!/bin/sh
set -eu
if [ "$1" = "api" ]; then
  printf '%s\n' "$FAKE_PR_METADATA"
  exit 0
fi
if [ "$1" = "pr" ] && [ "$2" = "merge" ]; then
  shift 2
  printf '%s\n' "$*" > "$FAKE_MERGE_LOG"
  exit 0
fi
exit 2
"#,
    )
    .expect("fake gh executable");
    fs::set_permissions(&fake_gh, fs::Permissions::from_mode(0o700)).expect("fake gh permissions");

    let repository = "owner/repository";
    let source_head_sha = "a".repeat(40);
    let event_path = temp.path().join("event.json");
    fs::write(
        &event_path,
        privileged_event(repository, &source_head_sha).to_string(),
    )
    .expect("workflow event fixture");
    let merge_log = temp.path().join("merge.log");
    let api_metadata = json!({
        "number": 17,
        "state": "open",
        "author": "dependabot[bot]",
        "base_ref": "main",
        "head_sha": api_head_sha,
        "head_repository": repository
    });
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = Command::new("bash")
        .args(["-c", script])
        .env("PATH", path)
        .env("GITHUB_EVENT_PATH", &event_path)
        .env("GITHUB_REPOSITORY", repository)
        .env("FAKE_PR_METADATA", api_metadata.to_string())
        .env("FAKE_MERGE_LOG", &merge_log)
        .output()
        .expect("privileged script must run");
    let merge_arguments = fs::read_to_string(merge_log).ok();
    (output, merge_arguments)
}

#[cfg(unix)]
#[test]
fn privileged_step_binds_native_auto_merge_to_the_tested_head() {
    let source_head_sha = "a".repeat(40);
    let (accepted, merge_arguments) = run_privileged_script(&source_head_sha);
    assert!(
        accepted.status.success(),
        "{}",
        String::from_utf8_lossy(&accepted.stderr)
    );
    let merge_arguments = merge_arguments.expect("eligible PR must reach native auto-merge");
    assert!(merge_arguments.contains("--auto"));
    assert!(merge_arguments.contains("--squash"));
    assert!(merge_arguments.contains(&format!("--match-head-commit {source_head_sha}")));
    assert!(!merge_arguments.contains("--admin"));

    let stale_head_sha = "b".repeat(40);
    let (rejected, merge_arguments) = run_privileged_script(&stale_head_sha);
    assert!(!rejected.status.success());
    assert!(merge_arguments.is_none());
}
