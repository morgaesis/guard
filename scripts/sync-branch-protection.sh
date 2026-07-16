#!/usr/bin/env bash
set -euo pipefail

# Synchronizes the required status checks on the protected branch with the
# declared list below. The list is the single source of truth: the CI drift
# guard (audit.yml, branch_protection_drift) runs this script with --check,
# and an administrator applies changes with --apply.
#
# Usage:
#   scripts/sync-branch-protection.sh            Print current vs intended diff.
#   scripts/sync-branch-protection.sh --check    Diff only; exit 1 on drift,
#                                                exit 2 when protection is unreadable.
#   scripts/sync-branch-protection.sh --apply    Print the diff, then apply the
#                                                intended list via the API.
#
# Environment:
#   REPO    owner/name (default: derived from the current directory's remote)
#   BRANCH  protected branch (default: main)
#
# Reading the protection endpoint and applying changes require a token with
# repository administration permission. --check additionally tries the public
# branch endpoint, which exposes required check contexts to lesser tokens on
# public repositories.
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
  local out
  if out=$(gh api "repos/${REPO}/branches/${BRANCH}/protection/required_status_checks" \
      --jq '.contexts[]' 2>/dev/null); then
    printf '%s\n' "$out"
    return 0
  fi
  # Fallback for tokens without administration permission: the branch
  # endpoint exposes the same contexts on public repositories.
  if out=$(gh api "repos/${REPO}/branches/${BRANCH}" \
      --jq '.protection.required_status_checks.contexts[]' 2>/dev/null); then
    printf '%s\n' "$out"
    return 0
  fi
  return 2
}

if ! current=$(current_contexts); then
  echo "error: cannot read required status checks for ${REPO}@${BRANCH}" >&2
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
    # Preserve the current strict setting; this script only manages contexts.
    strict=$(gh api "repos/${REPO}/branches/${BRANCH}/protection/required_status_checks" \
      --jq '.strict')
    payload=$(printf '%s\n' "${REQUIRED_CONTEXTS[@]}" \
      | jq -R . \
      | jq -s --argjson strict "$strict" --argjson app_id "$APP_ID" \
          '{strict: $strict, checks: map({context: ., app_id: $app_id})}')
    printf '%s\n' "$payload" | gh api -X PATCH \
      "repos/${REPO}/branches/${BRANCH}/protection/required_status_checks" \
      --input - > /dev/null
    echo "Applied ${#REQUIRED_CONTEXTS[@]} required contexts to ${REPO}@${BRANCH}."
    ;;
esac
