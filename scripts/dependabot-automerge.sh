#!/usr/bin/env bash
set -euo pipefail

# Classifies and merges Dependabot pull requests, and keeps mainline workflow
# evidence present for commits that the Actions token merged.
#
# Usage:
#   scripts/dependabot-automerge.sh classify <pull-request-number>
#   scripts/dependabot-automerge.sh reconcile
#   scripts/dependabot-automerge.sh ensure-mainline-runs
#
# Environment:
#   GITHUB_REPOSITORY  owner/name of the repository to act on.
#   GH_TOKEN           token for the gh CLI.
#
# Every decision is derived from GitHub API metadata. The script never checks
# out, builds, or executes pull request content, so it is safe to run from the
# default branch with a write token.
#
# classify prints one JSON object with a decision of "eligible" or "manual".
# A pull request is eligible only when all of the following hold:
#   - it is open, not a draft, authored by dependabot[bot], targets main, and
#     its head branch lives in this repository under dependabot/;
#   - it consists of exactly one commit, authored by dependabot[bot], committed
#     by GitHub, with a verified signature;
#   - every changed file is a modification inside one eligible manifest set
#     (root Cargo manifests, fuzz Cargo manifests, or workflow files) that
#     matches the ecosystem named by the head branch;
#   - the commit's update metadata lists at least one dependency and every
#     entry is a patch or minor update that Cargo treats as compatible. Major
#     updates, 0.x minor updates, 0.0.x patch updates, and entries without a
#     recognized update type or version require manual review.
#
# reconcile merges an eligible pull request only when every required status
# check declared in scripts/sync-branch-protection.sh succeeded for the exact
# head commit. The merge is bound to that commit, and the branch ruleset still
# applies to it.
#
# ensure-mainline-runs dispatches the push-triggered mainline workflows for the
# current main commit when no run exists for it. Merges made with the Actions
# token do not start push workflows, and workflow_dispatch is the supported
# event that the same token can raise.

BOT_LOGIN="dependabot[bot]"
BRANCH="main"
# GitHub Actions. Only check runs reported by this app satisfy a required
# context.
APP_ID=15368
MAINLINE_WORKFLOWS=(ci.yml audit.yml)

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

usage() {
  echo "usage: $0 classify <pull-request-number> | reconcile | ensure-mainline-runs" >&2
  exit 64
}

REPO="${GITHUB_REPOSITORY:-}"
if ! [[ "$REPO" =~ ^[A-Za-z0-9][A-Za-z0-9_.-]*/[A-Za-z0-9][A-Za-z0-9_.-]*$ ]]; then
  echo "error: GITHUB_REPOSITORY must be owner/name" >&2
  exit 2
fi

work_dir=$(mktemp -d)
trap 'rm -rf "$work_dir"' EXIT

api() {
  gh api --method GET "$@"
}

api_pages() {
  gh api --method GET --paginate "$@"
}

report() {
  echo "$1"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    echo "- $1" >> "$GITHUB_STEP_SUMMARY"
  fi
}

# Prints {decision, reason, number, head_sha, mergeable_state}. Returns
# nonzero only when metadata is unreadable.
classify() {
  local number="$1"
  [[ "$number" =~ ^[1-9][0-9]*$ ]] || {
    echo "error: pull request number is malformed" >&2
    return 2
  }

  api "repos/${REPO}/pulls/${number}" > "$work_dir/pull.json" || return 2
  api_pages "repos/${REPO}/pulls/${number}/commits?per_page=100" \
    | jq -s '[.[][] | {
        sha,
        author: .author.login,
        committer: .committer.login,
        verified: .commit.verification.verified,
        message: .commit.message
      }]' > "$work_dir/commits.json" || return 2
  api_pages "repos/${REPO}/pulls/${number}/files?per_page=100" \
    | jq -s '[.[][] | {filename, status}]' > "$work_dir/files.json" || return 2

  jq -n \
    --argjson number "$number" \
    --arg repo "$REPO" \
    --arg bot "$BOT_LOGIN" \
    --arg branch "$BRANCH" \
    --slurpfile pull "$work_dir/pull.json" \
    --slurpfile commits "$work_dir/commits.json" \
    --slurpfile files "$work_dir/files.json" '
    def metadata:
      split("\n") as $lines
      | [range(0; $lines | length)
          | select($lines[.] == "---" and $lines[. + 1] == "updated-dependencies:")] as $starts
      | if ($starts | length) != 1 then null else
          ($starts[0] + 2) as $from
          | ([range($from; $lines | length) | select($lines[.] == "...")] | first) as $to
          | if $to == null then null else
              reduce $lines[$from:$to][] as $line ({ok: true, items: []};
                if .ok | not then .
                elif $line | test("^- dependency-name: \\S") then
                  .items += [{"dependency-name": ($line | sub("^- dependency-name: "; ""))}]
                elif ((.items | length) > 0) and ($line | test("^  [a-z-]+: \\S")) then
                  ($line | capture("^  (?<key>[a-z-]+): (?<value>.*)$")) as $pair
                  | .items[-1][$pair.key] = $pair.value
                else .ok = false
                end)
              | if .ok and (.items | length) > 0 then .items else null end
            end
        end;

    def level:
      (."update-type" // "") as $type
      | (."dependency-version" // "") as $version
      | if $version | test("^[0-9]+(\\.[0-9]+){0,2}(\\+[0-9A-Za-z.-]+)?$") | not then "unclassified"
        elif $type == "version-update:semver-patch" then
          (if $version | test("^0\\.0\\.") then "breaking" else "compatible" end)
        elif $type == "version-update:semver-minor" then
          (if $version | test("^0\\.") then "breaking" else "compatible" end)
        elif $type == "version-update:semver-major" then "breaking"
        else "unclassified"
        end;

    def file_class:
      if test("^Cargo\\.(toml|lock)$") then "cargo-root"
      elif test("^fuzz/Cargo\\.(toml|lock)$") then "cargo-fuzz"
      elif test("^\\.github/workflows/[^/]+\\.ya?ml$") then "github-actions"
      else "other"
      end;

    def branch_prefix:
      if . == "github-actions" then "dependabot/github_actions/" else "dependabot/cargo/" end;

    def decide:
      $pull[0] as $p
      | $commits[0] as $c
      | $files[0] as $f
      | if $p.number != $number or $p.state != "open" or $p.draft != false then
          "the pull request is not open and ready"
        elif $p.user.login != $bot or $p.user.type != "Bot" then
          "the pull request is not a Dependabot update"
        elif $p.base.ref != $branch or $p.base.repo.full_name != $repo then
          "the pull request does not target the protected branch"
        elif $p.head.repo.full_name != $repo or (($p.head.ref // "") | startswith("dependabot/") | not) then
          "the head branch is not a Dependabot branch in this repository"
        elif ($c | length) != 1 or $p.commits != 1 or $c[0].sha != $p.head.sha then
          "the pull request is not a single Dependabot commit"
        elif $c[0].author != $bot or $c[0].committer != "web-flow" or $c[0].verified != true then
          "the head commit is not a verified Dependabot commit"
        elif ($f | length) == 0 or ($f | length) != $p.changed_files then
          "the changed file list is empty or incomplete"
        elif any($f[]; .status != "modified") then
          "the update adds, removes, or renames files"
        else
          ($f | map(.filename | file_class) | unique) as $classes
          | if ($classes | length) != 1 or $classes[0] == "other" then
              "the changed files are outside one eligible manifest set"
            elif $p.head.ref | startswith($classes[0] | branch_prefix) | not then
              "the changed files do not match the head branch ecosystem"
            else
              (($c[0].message // "") | metadata) as $items
              | if $items == null then
                  "the update metadata is missing or malformed"
                else
                  ($items | map(level)) as $levels
                  | if any($levels[]; . == "unclassified") then
                      "an update has no recognized type or version"
                    elif any($levels[]; . == "breaking") then
                      "the update includes a major or otherwise incompatible version"
                    else null
                    end
                end
            end
        end;

    decide as $reason
    | {
        decision: (if $reason == null then "eligible" else "manual" end),
        reason: ($reason // "every update is a compatible patch or minor version"),
        number: $number,
        head_sha: ($pull[0].head.sha // ""),
        mergeable_state: ($pull[0].mergeable_state // "unknown")
      }
    | if (.decision == "eligible") and (.head_sha | test("^[0-9a-f]{40}$") | not)
      then error("head commit is malformed")
      else .
      end
  ' || return 2
}

# Succeeds when the newest GitHub Actions check run for every required context
# completed successfully on the commit. Prints the first unmet context.
required_checks_succeeded() {
  local sha="$1" context
  local -a contexts
  mapfile -t contexts < <("$script_dir/sync-branch-protection.sh" --list)
  [ "${#contexts[@]}" -gt 0 ] || return 2

  api_pages "repos/${REPO}/commits/${sha}/check-runs?filter=latest&per_page=100" \
    | jq -s '[.[].check_runs[]]' > "$work_dir/check-runs.json" || return 2

  for context in "${contexts[@]}"; do
    if ! jq -e --arg sha "$sha" --arg context "$context" --argjson app_id "$APP_ID" '
        [.[] | select(.head_sha == $sha and .name == $context and .app.id == $app_id)]
        | sort_by(.started_at // "", .id)
        | last
        | . != null and .status == "completed" and .conclusion == "success"
      ' "$work_dir/check-runs.json" > /dev/null; then
      echo "$context"
      return 1
    fi
  done
}

reconcile() {
  local numbers number result decision reason sha state unmet status failures=0

  numbers=$(api_pages "repos/${REPO}/pulls?state=open&base=${BRANCH}&per_page=100" \
    | jq -s -r --arg bot "$BOT_LOGIN" '.[][] | select(.user.login == $bot) | .number')

  for number in $numbers; do
    if ! result=$(classify "$number"); then
      report "#${number}: error, pull request metadata is unreadable"
      failures=$((failures + 1))
      continue
    fi
    decision=$(jq -r '.decision' <<< "$result")
    reason=$(jq -r '.reason' <<< "$result")
    sha=$(jq -r '.head_sha' <<< "$result")
    state=$(jq -r '.mergeable_state' <<< "$result")

    if [ "$decision" != "eligible" ]; then
      report "#${number}: manual review, ${reason}"
      continue
    fi

    status=0
    unmet=$(required_checks_succeeded "$sha") || status=$?
    if [ "$status" -eq 1 ]; then
      report "#${number}: waiting, required check has not succeeded: ${unmet}"
      continue
    elif [ "$status" -ne 0 ]; then
      report "#${number}: error, required checks are unreadable"
      failures=$((failures + 1))
      continue
    fi

    case "$state" in
      clean|unstable|has_hooks) ;;
      *)
        report "#${number}: waiting, mergeable state is ${state}"
        continue
        ;;
    esac

    if gh pr merge "$number" --repo "$REPO" --squash --match-head-commit "$sha"; then
      report "#${number}: merged at ${sha}"
    else
      report "#${number}: error, merge was refused at ${sha}"
      failures=$((failures + 1))
    fi
  done

  [ "$failures" -eq 0 ]
}

main_head() {
  api "repos/${REPO}/git/ref/heads/${BRANCH}" \
    | jq -er '.object.sha | strings | select(test("^[0-9a-f]{40}$"))'
}

ensure_mainline_runs() {
  local head workflow count failures=0

  head=$(main_head) || {
    echo "error: the ${BRANCH} head commit is unreadable" >&2
    return 2
  }

  for workflow in "${MAINLINE_WORKFLOWS[@]}"; do
    if ! count=$(api "repos/${REPO}/actions/workflows/${workflow}/runs?head_sha=${head}&per_page=100" \
        | jq -e --arg head "$head" --arg branch "$BRANCH" '
            [.workflow_runs[] | select(.head_sha == $head and .head_branch == $branch)] | length
          '); then
      report "${workflow}: error, runs are unreadable for ${head}"
      failures=$((failures + 1))
      continue
    fi
    if [ "$count" -gt 0 ]; then
      report "${workflow}: a run exists for ${head}"
      continue
    fi
    if [ "$(main_head)" != "$head" ]; then
      report "${workflow}: ${BRANCH} moved past ${head}; the next reconcile covers the new head"
      continue
    fi
    if gh workflow run "$workflow" --repo "$REPO" --ref "$BRANCH"; then
      report "${workflow}: dispatched for ${head}"
    else
      report "${workflow}: error, dispatch failed for ${head}"
      failures=$((failures + 1))
    fi
  done

  [ "$failures" -eq 0 ]
}

case "${1:-}" in
  classify)
    [ "$#" -eq 2 ] || usage
    classify "$2"
    ;;
  reconcile)
    [ "$#" -eq 1 ] || usage
    reconcile
    ;;
  ensure-mainline-runs)
    [ "$#" -eq 1 ] || usage
    ensure_mainline_runs
    ;;
  *) usage ;;
esac
