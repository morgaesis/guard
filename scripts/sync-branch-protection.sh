#!/usr/bin/env bash
set -euo pipefail

# Synchronizes the required status checks in the branch ruleset with the
# declared list below. The list is the single source of truth: the CI drift
# guard (audit.yml, branch_protection_drift) runs this script with --check,
# and an administrator applies changes with --apply.
#
# Usage:
#   scripts/sync-branch-protection.sh            Print current vs intended diff.
#   scripts/sync-branch-protection.sh --check    Diff only; exit 1 on drift,
#                                                exit 2 when rules are unreadable.
#   scripts/sync-branch-protection.sh --apply    Print the diff, then apply the
#                                                intended list via the API.
#
# Environment:
#   REPO    owner/name (default: derived from the current directory's remote)
#   BRANCH  protected branch (default: main)
#
# --check works with any token that can read the repository, including the
# default Actions token with Metadata read permission. --apply requires
# repository administration permission.
#
# Every context in the list reports a conclusion (success, failure, or
# skipped) on every pull_request event: ci.yml, audit.yml, and
# dependabot-automerge.yml all trigger on pull_request without path filters.
# A job skipped by its `if:` condition (for example "Classify dependency
# update" on non-Dependabot PRs) satisfies its required context. Deliberately
# excluded contexts:
#   - Report Outdated Dependencies: fails on any upstream release, independent
#     of PR content.
#   - OSSF Scorecard: never runs on pull_request.
#   - Fuzz security boundaries: time-boxed fuzzing is nondeterministic across
#     runs.
#   - Prompt Regression Corpus: its workflow is path-filtered, so most PRs
#     would have no status and could never merge.

BRANCH="${BRANCH:-main}"
REPO="${REPO:-$(gh repo view --json nameWithOwner --jq .nameWithOwner)}"

# app_id 15368 is GitHub Actions; pinning it prevents other apps from
# satisfying these contexts.
APP_ID=15368

REQUIRED_CONTEXTS=(
  "Test & Lint"
  "Build (x86_64-unknown-linux-gnu)"
  "Build (aarch64-unknown-linux-gnu)"
  "Build (aarch64-apple-darwin)"
  "Build (x86_64-pc-windows-msvc)"
  "Classify dependency update"
  "Security Audit (CVEs)"
  "License & Dependency Policy"
  "Unused Dependencies"
  "Dependency Review"
  "CodeQL (actions)"
  "CodeQL (rust)"
  "GitHub Actions Security"
)

mode="diff"
case "${1:-}" in
  "") ;;
  --check) mode="check" ;;
  --apply) mode="apply" ;;
  *)
    echo "usage: $0 [--check|--apply]" >&2
    exit 64
    ;;
esac

current_contexts() {
  local rules rule
  rules=$(gh api "repos/${REPO}/rules/branches/${BRANCH}") || return 2
  rule=$(printf '%s\n' "$rules" \
    | jq -e 'map(select(.type == "required_status_checks")) | if length == 0 then empty else .[0] end') \
    || return 2
  printf '%s\n' "$rule" | jq -r '.parameters.required_status_checks[].context'
}

if ! current=$(current_contexts); then
  echo "error: branch rules are unreadable or no required_status_checks rule exists for ${REPO}@${BRANCH}" >&2
  exit 2
fi

intended=$(printf '%s\n' "${REQUIRED_CONTEXTS[@]}" | LC_ALL=C sort)
current=$(printf '%s\n' "$current" | LC_ALL=C sort)

echo "Repository: ${REPO}  Branch: ${BRANCH}"
if [ "$current" = "$intended" ]; then
  echo "Required status checks are in sync (${#REQUIRED_CONTEXTS[@]} contexts)."
  [ "$mode" = "apply" ] && echo "Nothing to apply."
  exit 0
fi

echo "Required status checks differ:"
echo "--- current"
echo "+++ intended"
LC_ALL=C comm -3 <(printf '%s\n' "$current") <(printf '%s\n' "$intended") \
  | while IFS= read -r line; do
      case "$line" in
        $'\t'*) echo "+ ${line#$'\t'}" ;;
        *) echo "- ${line}" ;;
      esac
    done

case "$mode" in
  diff)
    echo "Dry run; pass --apply to update."
    exit 0
    ;;
  check)
    exit 1
    ;;
  apply)
    rules=$(gh api "repos/${REPO}/rules/branches/${BRANCH}") || {
      echo "error: branch rules are unreadable for ${REPO}@${BRANCH}" >&2
      exit 2
    }
    ruleset_id=$(printf '%s\n' "$rules" \
      | jq -e -r 'map(select(.type == "required_status_checks")) | if length == 0 then empty else .[0].ruleset_id end') \
      || {
        echo "error: no required_status_checks rule exists for ${REPO}@${BRANCH}" >&2
        exit 2
      }
    required_checks=$(printf '%s\n' "${REQUIRED_CONTEXTS[@]}" \
      | jq -R . \
      | jq -s --argjson app_id "$APP_ID" 'map({context: ., integration_id: $app_id})')
    payload=$(gh api "repos/${REPO}/rulesets/${ruleset_id}" \
      | jq --argjson required_checks "$required_checks" '
          {
            name,
            target,
            enforcement,
            conditions,
            bypass_actors,
            rules: (
              .rules
              | map(
                  if .type == "required_status_checks" then
                    .parameters.required_status_checks = $required_checks
                  else
                    .
                  end
                )
            )
          }
          | with_entries(select(.value != null))
        ')
    printf '%s\n' "$payload" | gh api -X PUT \
      "repos/${REPO}/rulesets/${ruleset_id}" \
      --input - > /dev/null
    echo "Applied ${#REQUIRED_CONTEXTS[@]} required contexts to ruleset ${ruleset_id} for ${REPO}@${BRANCH}."
    ;;
esac
