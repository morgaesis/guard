#!/usr/bin/env bash
set -euo pipefail

# Declares, verifies, and synchronizes the required GitHub Actions checks for
# the protected branch. The tuple list is the source of truth for branch-rule
# drift detection and release evidence validation.
#
# Usage:
#   scripts/sync-branch-protection.sh [--check|--apply|--validate]
#   scripts/sync-branch-protection.sh --required-checks-json
#   scripts/sync-branch-protection.sh --verify-commit <commit>
#
# --check exits 1 on drift and 2 when rules are unreadable. --apply requires
# repository administration permission. --validate checks the proposed tuple
# declaration without reading live repository state. --verify-commit exits
# nonzero unless every declared GitHub Actions check succeeded for the supplied
# commit.

BRANCH="${BRANCH:-main}"
REPO="${REPO:-}"

# GitHub Actions. Pinning the integration prevents another app from satisfying
# a required context with the same display name.
APP_ID=15368

REQUIRED_CONTEXTS=(
  "Test & Lint"
  "Secret Leak Scan"
  "Branch Protection Drift"
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

usage() {
  echo "usage: $0 [--check|--apply|--validate|--required-checks-json|--verify-commit <commit>]" >&2
  exit 64
}

resolve_repo() {
  if [ -z "$REPO" ]; then
    REPO=$(gh repo view --json nameWithOwner --jq .nameWithOwner)
  fi
  [[ "$REPO" == */* ]] || {
    echo "error: REPO must be owner/name" >&2
    exit 2
  }
}

validate_required_checks() {
  local context
  declare -A seen=()
  [ "${#REQUIRED_CONTEXTS[@]}" -gt 0 ] || {
    echo "error: no required status checks are declared" >&2
    return 2
  }
  for context in "${REQUIRED_CONTEXTS[@]}"; do
    if [[ -z "$context" || "$context" == [[:space:]]* || "$context" == *[[:space:]] || "$context" == *$'\n'* ]]; then
      echo "error: required status check names must be nonempty single-line values without surrounding whitespace" >&2
      return 2
    fi
    if [[ -n "${seen[$context]+present}" ]]; then
      echo "error: duplicate required status check: $context" >&2
      return 2
    fi
    seen["$context"]=1
  done
}

required_checks_json() {
  validate_required_checks || return 2
  printf '%s\n' "${REQUIRED_CONTEXTS[@]}" \
    | jq -R . \
    | jq -s --argjson integration_id "$APP_ID" \
        'map({context: ., integration_id: $integration_id}) | sort_by(.context, .integration_id)'
}

normalize_checks() {
  jq '
    map({
      context: (.context | tostring),
      integration_id: ((.integration_id // .app_id // .app.id // null) | if . == null then null else tonumber end)
    })
    | sort_by(.context, .integration_id)
  '
}

required_rule() {
  local rules
  rules=$(gh api "repos/${REPO}/rules/branches/${BRANCH}") || return 2
  printf '%s\n' "$rules" | jq -e '
    map(select(.type == "required_status_checks"))
    | if length == 1
      then .[0]
      else error("expected exactly one required_status_checks rule")
      end
  ' || return 2
}

current_checks_json() {
  local rule
  rule=$(required_rule) || return 2
  printf '%s\n' "$rule" \
    | jq -e '.parameters.required_status_checks' \
    | normalize_checks || return 2
}

print_diff() {
  local current intended
  current=$(current_checks_json) || return 2
  intended=$(required_checks_json)
  echo "Repository: ${REPO}  Branch: ${BRANCH}"
  if [ "$current" = "$intended" ]; then
    echo "Required status checks are in sync (${#REQUIRED_CONTEXTS[@]} tuples)."
    return 0
  fi
  echo "Required status check tuples differ:"
  diff -u <(jq -S . <<< "$current") <(jq -S . <<< "$intended") || true
  return 1
}

verify_commit() {
  local commit="$1" expected check_runs tuple context integration_id
  [[ "$commit" =~ ^[0-9a-f]{40}$ ]] || {
    echo "error: commit must be a full lowercase SHA-1" >&2
    exit 64
  }
  resolve_repo
  expected=$(required_checks_json)
  check_runs=$(gh api --paginate "repos/${REPO}/commits/${commit}/check-runs?filter=latest&per_page=100" \
    | jq -s '[.[].check_runs[]]') || {
      echo "error: check runs are unreadable for ${commit}" >&2
      exit 2
    }
  while IFS= read -r tuple; do
    context=$(jq -r '.context' <<< "$tuple")
    integration_id=$(jq -r '.integration_id' <<< "$tuple")
    if ! jq -e --arg commit "$commit" --arg context "$context" --argjson integration_id "$integration_id" '
        [ .[]
          | select(.head_sha == $commit and .name == $context and .app.id == $integration_id)
        ]
        | sort_by(.completed_at // .started_at // .created_at // "", .id)
        | last
        | .status == "completed" and .conclusion == "success"
      ' <<< "$check_runs" >/dev/null; then
      echo "error: required check did not succeed: ${context} (GitHub Actions ${integration_id})" >&2
      exit 1
    fi
  done < <(jq -c '.[]' <<< "$expected")
  echo "All ${#REQUIRED_CONTEXTS[@]} required check tuples succeeded for ${commit}."
}

mode="diff"
case "${1:-}" in
  "") ;;
  --check) mode="check" ;;
  --apply) mode="apply" ;;
  --validate)
    [ "$#" -eq 1 ] || usage
    validate_required_checks
    required_checks_json | jq -e \
      --argjson expected_count "${#REQUIRED_CONTEXTS[@]}" \
      --argjson expected_integration "$APP_ID" '
        length == $expected_count
        and all(.[].context; type == "string" and length > 0)
        and all(.[].integration_id; . == $expected_integration)
      ' >/dev/null
    echo "Validated ${#REQUIRED_CONTEXTS[@]} proposed required check tuples."
    exit 0
    ;;
  --required-checks-json)
    [ "$#" -eq 1 ] || usage
    required_checks_json
    exit 0
    ;;
  --verify-commit)
    [ "$#" -eq 2 ] || usage
    verify_commit "$2"
    exit 0
    ;;
  *) usage ;;
esac

resolve_repo
if print_diff; then
  [ "$mode" = "apply" ] && echo "Nothing to apply."
  exit 0
else
  status=$?
fi
if [ "$status" -eq 2 ]; then
  echo "error: required-check rules are unreadable or ambiguous for ${REPO}@${BRANCH}" >&2
  exit 2
fi

case "$mode" in
  diff)
    echo "Dry run; pass --apply to update."
    exit 0
    ;;
  check)
    exit 1
    ;;
  apply)
    intended=$(required_checks_json)
    if strict=$(gh api \
      "repos/${REPO}/branches/${BRANCH}/protection/required_status_checks" \
      --jq '.strict' 2>/dev/null); then
      checks=$(jq --argjson app_id "$APP_ID" \
        'map({context: .context, app_id: $app_id})' <<< "$intended")
      jq -n --argjson strict "$strict" --argjson checks "$checks" \
        '{strict: $strict, checks: $checks}' \
        | gh api -X PATCH "repos/${REPO}/branches/${BRANCH}/protection/required_status_checks" --input - > /dev/null
    else
      effective_rules=$(gh api "repos/${REPO}/rules/branches/${BRANCH}")
      mapfile -t ruleset_ids < <(
        jq -r '.[] | select(.type == "required_status_checks") | .ruleset_id' \
          <<< "$effective_rules" | LC_ALL=C sort -u
      )
      if [ "${#ruleset_ids[@]}" -ne 1 ]; then
        echo "error: expected exactly one ruleset with required status checks for ${BRANCH}" >&2
        exit 2
      fi
      ruleset_id=${ruleset_ids[0]}
      ruleset=$(gh api "repos/${REPO}/rulesets/${ruleset_id}")
      if [ "$(jq -r '.source_type' <<< "$ruleset")" != "Repository" ] || \
          [ "$(jq '[.rules[] | select(.type == "required_status_checks")] | length' <<< "$ruleset")" -ne 1 ]; then
        echo "error: required status checks must come from one repository ruleset" >&2
        exit 2
      fi
      payload=$(jq --argjson checks "$intended" '{
        name,
        target,
        enforcement,
        bypass_actors,
        conditions,
        rules: (.rules | map(
          if .type == "required_status_checks"
          then .parameters.required_status_checks = $checks
          else .
          end
        ))
      }' <<< "$ruleset")
      printf '%s\n' "$payload" | gh api -X PUT "repos/${REPO}/rulesets/${ruleset_id}" --input - > /dev/null
    fi
    if ! print_diff; then
      echo "error: branch-protection apply did not produce the declared tuples" >&2
      exit 2
    fi
    echo "Applied ${#REQUIRED_CONTEXTS[@]} required check tuples to ${REPO}@${BRANCH}."
    ;;
esac
