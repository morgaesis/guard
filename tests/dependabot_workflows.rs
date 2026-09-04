#[cfg(unix)]
use serde_json::json;
use serde_yaml_ng::{Mapping, Value};
use std::collections::BTreeSet;
#[cfg(unix)]
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
fn review_workflow_separates_required_classification_from_eligibility() {
    let workflow = parse_yaml(REVIEW_WORKFLOW);
    let triggers = mapping(field(&workflow, "on"));
    assert_eq!(triggers.len(), 2);
    let push = field(field(&workflow, "on"), "push");
    assert_eq!(strings(field(push, "branches")), ["main"]);
    let pull_request = field(field(&workflow, "on"), "pull_request");
    assert_eq!(strings(field(pull_request, "branches")), ["main"]);
    assert_eq!(
        strings(field(pull_request, "types")),
        ["opened", "reopened", "synchronize"]
    );
    assert!(mapping(field(&workflow, "permissions")).is_empty());

    let jobs = mapping(field(&workflow, "jobs"));
    assert_eq!(
        jobs.keys().map(string).collect::<BTreeSet<_>>(),
        BTreeSet::from(["eligibility", "review-gate"])
    );

    let review_job = job(&workflow, "review-gate");
    assert_eq!(field(review_job, "name"), "Classify dependency update");
    assert_eq!(
        field(
            named_step(review_job, "Record mainline classification"),
            "if"
        ),
        "github.event_name == 'push'"
    );
    assert_eq!(
        field(named_step(review_job, "Classify pull request source"), "if"),
        "github.event_name == 'pull_request'"
    );
    let permissions = mapping(field(review_job, "permissions"));
    assert_eq!(permissions.len(), 2);
    assert_eq!(field(field(review_job, "permissions"), "contents"), "read");
    assert_eq!(
        field(field(review_job, "permissions"), "pull-requests"),
        "read"
    );
    assert_eq!(
        field(field(review_job, "outputs"), "eligible"),
        "${{ steps.policy.outputs.eligible }}"
    );

    let source = run_script(review_job, "Classify pull request source");
    assert!(source.contains("$GITHUB_EVENT_PATH"));
    assert!(source.contains("dependabot[bot]"));
    assert!(source.contains("is_dependabot=false"));
    assert!(source.contains("is_dependabot=true"));
    assert!(source.contains("^[1-9][0-9]*$"));
    assert!(source.contains("^[0-9a-f]{40}$"));

    let metadata = named_step(review_job, "Resolve verified Dependabot metadata");
    assert_eq!(
        field(metadata, "if"),
        "steps.source.outputs.is_dependabot == 'true'"
    );
    assert_eq!(
        string(field(metadata, "uses")),
        "dependabot/fetch-metadata@25dd0e34f4fe68f24cc83900b1fe3fe149efef98"
    );

    let policy_step = named_step(review_job, "Classify auto-merge eligibility");
    assert_eq!(field(policy_step, "if"), "always()");
    let policy = string(field(policy_step, "run"));
    for required in [
        "eligible=false",
        "eligible=true",
        "METADATA_OUTCOME",
        "UPDATED_DEPENDENCIES_JSON",
        "version-update:semver-major",
        "packageEcosystem == $ecosystem",
        ".directory == $directory",
        ".targetBranch == $target",
    ] {
        assert!(
            policy.contains(required),
            "missing policy invariant {required}"
        );
    }

    let eligibility = job(&workflow, "eligibility");
    assert_eq!(field(eligibility, "name"), "Auto-merge eligible");
    assert_eq!(field(eligibility, "needs"), "review-gate");
    assert_eq!(
        field(eligibility, "if"),
        "github.event_name == 'pull_request' && needs.review-gate.outputs.eligible == 'true'"
    );
    assert!(mapping(field(eligibility, "permissions")).is_empty());

    for workflow_job in jobs.values() {
        for step in steps(workflow_job) {
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
    let job_condition = string(field(merge_job, "if"));
    for required in [
        "github.event.workflow_run.conclusion == 'success'",
        "github.event.workflow_run.event == 'pull_request'",
        "github.event.workflow_run.actor.login == 'dependabot[bot]'",
    ] {
        if !job_condition.contains(required) {
            errors.push("source-job-condition");
        }
    }
    let permissions = field(merge_job, "permissions");
    let permissions_valid = permissions.as_mapping().is_some_and(|permissions| {
        permissions.len() == 3
            && permissions.get("actions").and_then(Value::as_str) == Some("read")
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
        ".workflow_run.id",
        ".workflow_run.event",
        ".workflow_run.actor.login",
        ".workflow_run.pull_requests | arrays | length",
        ".workflow_run.head_sha",
        ".workflow_run.repository.full_name",
        "/actions/runs/${source_run_id}/jobs?filter=latest&per_page=100",
        ".name == \"Classify dependency update\"",
        ".name == \"Auto-merge eligible\"",
        ".conclusion == \"success\"",
        "contents/.github/workflows/dependabot-automerge.yml?ref=${source_head_sha}",
        "contents/.github/workflows/dependabot-automerge.yml?ref=main",
        "[ \"$source_blob_sha\" != \"$trusted_blob_sha\" ]",
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
                "    permissions:\n      actions: read\n      contents: write\n      pull-requests: write",
                "    permissions: write-all",
            ),
        ),
        (
            "missing actions read",
            PRIVILEGED_WORKFLOW.replace("      actions: read\n", ""),
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
            "workflow drift",
            PRIVILEGED_WORKFLOW.replace(
                "          if [ \"$source_blob_sha\" != \"$trusted_blob_sha\" ]; then",
                "          if false; then",
            ),
        ),
        (
            "job signals",
            PRIVILEGED_WORKFLOW.replace(
                ".name == \"Auto-merge eligible\"",
                ".name == \"Some other job\"",
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
fn pull_request_event(
    repository: &str,
    author: &str,
    head_repository: &str,
    base: &str,
    state: &str,
) -> serde_json::Value {
    json!({
        "repository": { "full_name": repository },
        "pull_request": {
            "number": 17,
            "user": { "login": author },
            "state": state,
            "base": { "ref": base },
            "head": {
                "sha": "a".repeat(40),
                "repo": { "full_name": head_repository }
            }
        }
    })
}

#[cfg(unix)]
fn run_source_script(event: serde_json::Value, repository: &str) -> (Output, String) {
    use std::fs;

    let workflow = parse_yaml(REVIEW_WORKFLOW);
    let script = run_script(
        job(&workflow, "review-gate"),
        "Classify pull request source",
    );
    let temp = tempfile::tempdir().expect("temporary test directory");
    let event_path = temp.path().join("event.json");
    let output_path = temp.path().join("output.txt");
    fs::write(&event_path, event.to_string()).expect("pull request event fixture");
    let output = Command::new("bash")
        .args(["-c", script])
        .env("GITHUB_EVENT_PATH", &event_path)
        .env("GITHUB_OUTPUT", &output_path)
        .env("GITHUB_REPOSITORY", repository)
        .output()
        .expect("source classifier script must run");
    let outputs = fs::read_to_string(output_path).unwrap_or_default();
    (output, outputs)
}

#[cfg(unix)]
#[test]
fn source_classifier_accepts_ordinary_prs_without_claiming_eligibility() {
    let repository = "owner/repository";
    let (ordinary, outputs) = run_source_script(
        pull_request_event(repository, "contributor", "fork/repository", "main", "open"),
        repository,
    );
    assert!(
        ordinary.status.success(),
        "{}",
        String::from_utf8_lossy(&ordinary.stderr)
    );
    assert_eq!(outputs, "is_dependabot=false\n");

    let (dependabot, outputs) = run_source_script(
        pull_request_event(repository, "dependabot[bot]", repository, "main", "open"),
        repository,
    );
    assert!(dependabot.status.success());
    assert_eq!(outputs, "is_dependabot=true\n");
}

#[cfg(unix)]
#[test]
fn source_classifier_fails_dependabot_authenticity_errors() {
    let repository = "owner/repository";
    let invalid_events = [
        pull_request_event(
            repository,
            "dependabot[bot]",
            "fork/repository",
            "main",
            "open",
        ),
        pull_request_event(
            "other/repository",
            "dependabot[bot]",
            repository,
            "main",
            "open",
        ),
        pull_request_event(repository, "dependabot[bot]", repository, "release", "open"),
        pull_request_event(repository, "dependabot[bot]", repository, "main", "closed"),
    ];

    for event in invalid_events {
        let (output, eligibility) = run_source_script(event, repository);
        assert!(!output.status.success());
        assert!(!eligibility.contains("is_dependabot=true"));
    }
}

#[cfg(unix)]
fn run_policy_script(
    is_dependabot: bool,
    metadata_outcome: &str,
    ecosystem: &str,
    directory: &str,
    target_branch: &str,
    update_type: &str,
    dependencies: serde_json::Value,
) -> (Output, String) {
    use std::fs;

    let workflow = parse_yaml(REVIEW_WORKFLOW);
    let script = run_script(
        job(&workflow, "review-gate"),
        "Classify auto-merge eligibility",
    );
    let temp = tempfile::tempdir().expect("temporary test directory");
    let output_path = temp.path().join("output.txt");
    let output = Command::new("bash")
        .args(["-c", script])
        .env("DIRECTORY", directory)
        .env("GITHUB_OUTPUT", &output_path)
        .env(
            "IS_DEPENDABOT",
            if is_dependabot { "true" } else { "false" },
        )
        .env("METADATA_OUTCOME", metadata_outcome)
        .env("PACKAGE_ECOSYSTEM", ecosystem)
        .env("TARGET_BRANCH", target_branch)
        .env("UPDATED_DEPENDENCIES_JSON", dependencies.to_string())
        .env("UPDATE_TYPE", update_type)
        .output()
        .expect("eligibility classifier script must run");
    let outputs = fs::read_to_string(output_path).unwrap_or_default();
    (output, outputs)
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
fn assert_ineligible(result: (Output, String)) {
    let (output, outputs) = result;
    assert!(
        output.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&output.stdout),
        String::from_utf8_lossy(&output.stderr)
    );
    assert_eq!(outputs, "eligible=false\n");
}

#[cfg(unix)]
#[test]
fn classifier_keeps_ordinary_and_manual_review_cases_successful_but_ineligible() {
    assert_ineligible(run_policy_script(
        false,
        "skipped",
        "",
        "",
        "",
        "",
        json!([]),
    ));
    assert_ineligible(run_policy_script(
        true,
        "success",
        "cargo",
        "/",
        "main",
        "version-update:semver-major",
        json!([dependency("cargo", "/", "version-update:semver-major")]),
    ));
    assert_ineligible(run_policy_script(
        true,
        "success",
        "docker",
        "/.clusterfuzzlite",
        "main",
        "version-update:semver-patch",
        json!([dependency(
            "docker",
            "/.clusterfuzzlite",
            "version-update:semver-patch"
        )]),
    ));
    assert_ineligible(run_policy_script(
        true,
        "success",
        "cargo",
        "/",
        "main",
        "version-update:semver-major",
        json!([
            dependency("cargo", "/", "version-update:semver-minor"),
            dependency("cargo", "/", "version-update:semver-major")
        ]),
    ));
    assert_ineligible(run_policy_script(
        true,
        "success",
        "cargo",
        "/",
        "main",
        "version-update:semver-patch",
        json!([
            dependency("cargo", "/", "version-update:semver-patch"),
            dependency("github_actions", "/", "version-update:semver-patch")
        ]),
    ));
    assert_ineligible(run_policy_script(
        true,
        "success",
        "cargo",
        "/",
        "release",
        "version-update:semver-patch",
        json!([dependency("cargo", "/", "version-update:semver-patch")]),
    ));
}

#[cfg(unix)]
#[test]
fn classifier_emits_eligibility_only_for_supported_patch_and_minor_updates() {
    let cases = [
        (
            "cargo",
            "/",
            "version-update:semver-minor",
            json!([
                dependency("cargo", "/", "version-update:semver-minor"),
                dependency("cargo", "/", "version-update:semver-patch")
            ]),
        ),
        (
            "cargo",
            "/fuzz",
            "version-update:semver-patch",
            json!([dependency("cargo", "/fuzz", "version-update:semver-patch")]),
        ),
        (
            "github_actions",
            "/",
            "version-update:semver-patch",
            json!([dependency(
                "github_actions",
                "/",
                "version-update:semver-patch"
            )]),
        ),
    ];

    for (ecosystem, directory, update_type, dependencies) in cases {
        let (output, outputs) = run_policy_script(
            true,
            "success",
            ecosystem,
            directory,
            "main",
            update_type,
            dependencies,
        );
        assert!(
            output.status.success(),
            "{}",
            String::from_utf8_lossy(&output.stderr)
        );
        assert_eq!(outputs, "eligible=false\neligible=true\n");
    }
}

#[cfg(unix)]
#[test]
fn classifier_fails_metadata_operational_errors() {
    let failures = [
        run_policy_script(
            true,
            "failure",
            "cargo",
            "/",
            "main",
            "version-update:semver-patch",
            json!([dependency("cargo", "/", "version-update:semver-patch")]),
        ),
        run_policy_script(
            true,
            "success",
            "",
            "",
            "",
            "version-update:semver-patch",
            json!([dependency("cargo", "/", "version-update:semver-patch")]),
        ),
        run_policy_script(
            true,
            "success",
            "cargo",
            "/",
            "main",
            "version-update:semver-patch",
            json!([]),
        ),
        run_policy_script(
            true,
            "success",
            "cargo",
            "/",
            "main",
            "unknown",
            json!([dependency("cargo", "/", "version-update:semver-patch")]),
        ),
    ];

    for (output, outputs) in failures {
        assert!(!output.status.success());
        assert_eq!(outputs, "eligible=false\n");
    }
}

#[cfg(unix)]
fn privileged_event(repository: &str, head_sha: &str) -> serde_json::Value {
    json!({
        "action": "completed",
        "repository": { "full_name": repository },
        "workflow_run": {
            "id": 4242,
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
fn source_job(run_id: u64, name: &str, conclusion: &str) -> serde_json::Value {
    json!({
        "run_id": run_id,
        "name": name,
        "status": "completed",
        "conclusion": conclusion
    })
}

#[cfg(unix)]
#[derive(Clone)]
struct PrivilegedFixture {
    event: serde_json::Value,
    jobs: serde_json::Value,
    repository: serde_json::Value,
    source_blob: serde_json::Value,
    trusted_blob: serde_json::Value,
    pull_request: serde_json::Value,
}

#[cfg(unix)]
impl PrivilegedFixture {
    fn eligible() -> Self {
        let repository = "owner/repository";
        let source_head_sha = "a".repeat(40);
        let workflow_blob_sha = "c".repeat(40);
        Self {
            event: privileged_event(repository, &source_head_sha),
            jobs: json!({
                "total_count": 2,
                "jobs": [
                    source_job(4242, "Classify dependency update", "success"),
                    source_job(4242, "Auto-merge eligible", "success")
                ]
            }),
            repository: json!({ "default_branch": "main" }),
            source_blob: json!({
                "type": "file",
                "path": ".github/workflows/dependabot-automerge.yml",
                "sha": workflow_blob_sha
            }),
            trusted_blob: json!({
                "type": "file",
                "path": ".github/workflows/dependabot-automerge.yml",
                "sha": workflow_blob_sha
            }),
            pull_request: json!({
                "number": 17,
                "state": "open",
                "author": "dependabot[bot]",
                "base_ref": "main",
                "head_sha": source_head_sha,
                "head_repository": repository
            }),
        }
    }
}

#[cfg(unix)]
fn run_privileged_script(fixture: &PrivilegedFixture) -> (Output, Option<String>) {
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
  request=""
  for argument in "$@"; do
    case "$argument" in
      repos/*) request="$argument" ;;
    esac
  done
  case "$request" in
    "repos/${GITHUB_REPOSITORY}/actions/runs/${FAKE_RUN_ID}/jobs?filter=latest&per_page=100")
      printf '%s\n' "$FAKE_RUN_JOBS"
      ;;
    "repos/${GITHUB_REPOSITORY}/contents/.github/workflows/dependabot-automerge.yml?ref=${FAKE_HEAD_SHA}")
      printf '%s\n' "$FAKE_SOURCE_BLOB"
      ;;
    "repos/${GITHUB_REPOSITORY}/contents/.github/workflows/dependabot-automerge.yml?ref=main")
      printf '%s\n' "$FAKE_TRUSTED_BLOB"
      ;;
    "repos/${GITHUB_REPOSITORY}/pulls/17")
      printf '%s\n' "$FAKE_PR_METADATA"
      ;;
    "repos/${GITHUB_REPOSITORY}")
      printf '%s\n' "$FAKE_REPOSITORY_METADATA"
      ;;
    *)
      exit 2
      ;;
  esac
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

    let event_path = temp.path().join("event.json");
    fs::write(&event_path, fixture.event.to_string()).expect("workflow event fixture");
    let merge_log = temp.path().join("merge.log");
    let path = format!(
        "{}:{}",
        bin_dir.display(),
        std::env::var("PATH").unwrap_or_default()
    );
    let output = Command::new("bash")
        .args(["-c", script])
        .env("PATH", path)
        .env("GITHUB_EVENT_PATH", &event_path)
        .env("GITHUB_REPOSITORY", "owner/repository")
        .env("FAKE_HEAD_SHA", "a".repeat(40))
        .env("FAKE_MERGE_LOG", &merge_log)
        .env("FAKE_PR_METADATA", fixture.pull_request.to_string())
        .env("FAKE_REPOSITORY_METADATA", fixture.repository.to_string())
        .env("FAKE_RUN_ID", "4242")
        .env("FAKE_RUN_JOBS", fixture.jobs.to_string())
        .env("FAKE_SOURCE_BLOB", fixture.source_blob.to_string())
        .env("FAKE_TRUSTED_BLOB", fixture.trusted_blob.to_string())
        .output()
        .expect("privileged script must run");
    let merge_arguments = fs::read_to_string(merge_log).ok();
    (output, merge_arguments)
}

#[cfg(unix)]
#[test]
fn privileged_step_binds_native_auto_merge_to_trusted_successful_signals() {
    let fixture = PrivilegedFixture::eligible();
    let source_head_sha = "a".repeat(40);
    let (accepted, merge_arguments) = run_privileged_script(&fixture);
    assert!(
        accepted.status.success(),
        "stdout: {}\nstderr: {}",
        String::from_utf8_lossy(&accepted.stdout),
        String::from_utf8_lossy(&accepted.stderr)
    );
    let merge_arguments = merge_arguments.expect("eligible PR must reach native auto-merge");
    assert!(merge_arguments.contains("--auto"));
    assert!(merge_arguments.contains("--squash"));
    assert!(merge_arguments.contains(&format!("--match-head-commit {source_head_sha}")));
    assert!(!merge_arguments.contains("--admin"));
}

#[cfg(unix)]
#[test]
fn privileged_step_rejects_missing_duplicate_or_failed_job_signals() {
    let mut missing_eligibility = PrivilegedFixture::eligible();
    missing_eligibility.jobs = json!({
        "total_count": 1,
        "jobs": [source_job(4242, "Classify dependency update", "success")]
    });

    let mut missing_classifier = PrivilegedFixture::eligible();
    missing_classifier.jobs = json!({
        "total_count": 1,
        "jobs": [source_job(4242, "Auto-merge eligible", "success")]
    });

    let mut duplicate_eligibility = PrivilegedFixture::eligible();
    duplicate_eligibility.jobs = json!({
        "total_count": 3,
        "jobs": [
            source_job(4242, "Classify dependency update", "success"),
            source_job(4242, "Auto-merge eligible", "success"),
            source_job(4242, "Auto-merge eligible", "success")
        ]
    });

    let mut duplicate_classifier = PrivilegedFixture::eligible();
    duplicate_classifier.jobs = json!({
        "total_count": 3,
        "jobs": [
            source_job(4242, "Classify dependency update", "success"),
            source_job(4242, "Classify dependency update", "success"),
            source_job(4242, "Auto-merge eligible", "success")
        ]
    });

    let mut skipped = PrivilegedFixture::eligible();
    skipped.jobs = json!({
        "total_count": 2,
        "jobs": [
            source_job(4242, "Classify dependency update", "success"),
            source_job(4242, "Auto-merge eligible", "skipped")
        ]
    });

    let mut wrong_run = PrivilegedFixture::eligible();
    wrong_run.jobs = json!({
        "total_count": 2,
        "jobs": [
            source_job(4242, "Classify dependency update", "success"),
            source_job(7, "Auto-merge eligible", "success")
        ]
    });

    for (name, fixture) in [
        ("missing eligibility", missing_eligibility),
        ("missing classifier", missing_classifier),
        ("duplicate eligibility", duplicate_eligibility),
        ("duplicate classifier", duplicate_classifier),
        ("skipped eligibility", skipped),
        ("wrong run", wrong_run),
    ] {
        let (output, merge_arguments) = run_privileged_script(&fixture);
        assert!(!output.status.success(), "{name} signal was accepted");
        assert!(merge_arguments.is_none(), "{name} signal reached merge");
    }
}

#[cfg(unix)]
#[test]
fn privileged_step_rejects_workflow_drift_and_stale_or_wrong_live_metadata() {
    let mut workflow_drift = PrivilegedFixture::eligible();
    workflow_drift.source_blob["sha"] = json!("d".repeat(40));

    let mut stale_head = PrivilegedFixture::eligible();
    stale_head.pull_request["head_sha"] = json!("b".repeat(40));

    let mut source_actor = PrivilegedFixture::eligible();
    source_actor.event["workflow_run"]["actor"]["login"] = json!("contributor");

    let mut live_actor = PrivilegedFixture::eligible();
    live_actor.pull_request["author"] = json!("contributor");

    let mut event_repository = PrivilegedFixture::eligible();
    event_repository.event["repository"]["full_name"] = json!("other/repository");

    let mut run_repository = PrivilegedFixture::eligible();
    run_repository.event["workflow_run"]["repository"]["full_name"] = json!("other/repository");

    let mut head_repository = PrivilegedFixture::eligible();
    head_repository.pull_request["head_repository"] = json!("fork/repository");

    let mut wrong_base = PrivilegedFixture::eligible();
    wrong_base.pull_request["base_ref"] = json!("release");

    let mut closed = PrivilegedFixture::eligible();
    closed.pull_request["state"] = json!("closed");

    for (name, fixture) in [
        ("workflow drift", workflow_drift),
        ("stale head", stale_head),
        ("source actor", source_actor),
        ("live actor", live_actor),
        ("event repository", event_repository),
        ("run repository", run_repository),
        ("head repository", head_repository),
        ("base branch", wrong_base),
        ("pull request state", closed),
    ] {
        let (output, merge_arguments) = run_privileged_script(&fixture);
        assert!(!output.status.success(), "{name} was accepted");
        assert!(merge_arguments.is_none(), "{name} reached merge");
    }
}
