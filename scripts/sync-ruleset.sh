#!/usr/bin/env bash
set -euo pipefail

# Synchronizes the required status checks in the active repository ruleset
# that protects the declared branch. The list is the single source of truth:
# the CI drift guard (audit.yml, ruleset_drift) runs this script with --check,
# and an administrator applies changes with --apply.
#
# Usage:
#   scripts/sync-ruleset.sh            Print current vs intended diff.
#   scripts/sync-ruleset.sh --check    Diff only; exit 1 on drift,
#                                      exit 2 when the ruleset is unreadable.
#   scripts/sync-ruleset.sh --apply    Print the diff, then update the ruleset.
#
# Environment:
#   REPO    owner/name (default: derived from the current directory's remote)
#   BRANCH  protected branch (default: main)
#   RULESET_NAME  active ruleset name (default: Protect main)
#
# Updating the ruleset requires a token with repository administration
# permission. The ruleset API is the only GitHub control plane this script
# uses.
#
# Every context in the list reports a conclusion (success, failure, or
# skipped) on every pull_request event: ci.yml, audit.yml, and
# dependabot-automerge.yml all trigger on pull_request without path filters.
# A job skipped by its `if:` condition (for example "Classify dependency
# update" on non-Dependabot PRs) satisfies its required context. Deliberately
# excluded contexts:
#   - Report Outdated Dependencies: reports available releases without
#     blocking a pull request.
#   - OSSF Scorecard: never runs on pull_request.
#   - Fuzz security boundaries: time-boxed fuzzing is nondeterministic across
#     runs.
#   - Prompt Regression Corpus: its workflow is path-filtered, so most PRs
#     would have no status and could never merge.

BRANCH="${BRANCH:-main}"
REPO="${REPO:-$(gh repo view --json nameWithOwner --jq .nameWithOwner)}"
RULESET_NAME="${RULESET_NAME:-Protect main}"

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

ruleset_id() {
  local ids
  if ! ids=$(gh api "repos/${REPO}/rulesets" 2>/dev/null \
      | jq -r --arg name "$RULESET_NAME" '
          .[]
          | select(
              .name == $name
              and .target == "branch"
              and .enforcement == "active"
            )
          | .id'); then
    return 2
  fi
  if [ "$(printf '%s\n' "$ids" | sed '/^$/d' | wc -l | tr -d ' ')" -ne 1 ]; then
    echo "error: expected one active ${RULESET_NAME@Q} ruleset" >&2
    return 2
  fi
  printf '%s\n' "$ids"
}

read_ruleset() {
  local id
  local ruleset
  if ! id=$(ruleset_id); then
    return 2
  fi
  if ! ruleset=$(gh api "repos/${REPO}/rulesets/${id}" 2>/dev/null); then
    return 2
  fi
  if ! gh api "repos/${REPO}/rules/branches/${BRANCH}" 2>/dev/null \
      | jq -e --argjson id "$id" 'any(.[]; .ruleset_id == $id)' > /dev/null; then
    echo "error: ${RULESET_NAME@Q} does not protect ${BRANCH}" >&2
    return 2
  fi
  printf '%s' "$ruleset"
}

current_contexts() {
  jq -r '
    [.rules[] | select(.type == "required_status_checks")]
    | if length == 1
      then .[0].parameters.required_status_checks[].context
      else error("expected one required_status_checks rule")
      end'
}

if ! ruleset=$(read_ruleset); then
  echo "error: cannot read the active ${RULESET_NAME@Q} ruleset for ${REPO}@${BRANCH}" >&2
  exit 2
fi

if ! current=$(printf '%s' "$ruleset" | current_contexts); then
  echo "error: cannot read required status checks from ${RULESET_NAME@Q}" >&2
  exit 2
fi

intended=$(printf '%s\n' "${REQUIRED_CONTEXTS[@]}" | LC_ALL=C sort)
current=$(printf '%s\n' "$current" | LC_ALL=C sort)

echo "Repository: ${REPO}  Branch: ${BRANCH}  Ruleset: ${RULESET_NAME}"
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
    intended_checks=$(printf '%s\n' "${REQUIRED_CONTEXTS[@]}" \
      | jq -R . \
      | jq -s --argjson app_id "$APP_ID" \
          'map({context: ., integration_id: $app_id})')
    payload=$(printf '%s' "$ruleset" | jq --argjson checks "$intended_checks" '
      {
        name,
        target,
        enforcement,
        bypass_actors,
        conditions,
        rules: [
          .rules[]
          | if .type == "required_status_checks"
            then .parameters.required_status_checks = $checks
            else .
            end
        ]
      }')
    id=$(ruleset_id)
    printf '%s\n' "$payload" | gh api -X PUT "repos/${REPO}/rulesets/${id}" \
      --input - > /dev/null
    echo "Applied ${#REQUIRED_CONTEXTS[@]} required contexts to ${RULESET_NAME@Q}."
    ;;
esac
