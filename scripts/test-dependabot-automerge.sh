#!/usr/bin/env bash
set -euo pipefail

# Exercises scripts/dependabot-automerge.sh against a stub gh CLI, and checks
# the trust boundaries of the workflows that run it. No network access or
# token is used: the stub serves fixtures for read requests and records every
# write request so the tests can assert exactly which ones were made.

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
subject="$root/scripts/dependabot-automerge.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

export GITHUB_REPOSITORY="example/guard"
unset GITHUB_STEP_SUMMARY GH_TOKEN GITHUB_TOKEN || true
bot="dependabot[bot]"
failures=0
tests=0

mkdir "$tmp/bin"
cat > "$tmp/bin/gh" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
if [ "$1" != "api" ]; then
  printf '%s\n' "$*" >> "$FIXTURES/writes"
  [ ! -e "$FIXTURES/refuse-writes" ]
  exit
fi
shift
path=""
method="GET"
while [ "$#" -gt 0 ]; do
  case "$1" in
    --method) method="$2"; shift ;;
    --paginate) ;;
    -*) echo "stub gh: unsupported option $1" >&2; exit 1 ;;
    *) path="$1" ;;
  esac
  shift
done
if [ "$method" != "GET" ]; then
  printf 'api %s %s\n' "$method" "$path" >> "$FIXTURES/writes"
  exit 1
fi
file="$FIXTURES/$(printf '%s' "$path" | tr -c 'A-Za-z0-9\n' '_')"
if [ ! -f "$file" ]; then
  echo "stub gh: no fixture for $path" >&2
  exit 1
fi
cat "$file"
STUB
chmod +x "$tmp/bin/gh"
export PATH="$tmp/bin:$PATH"

fixture() {
  cat > "$FIXTURES/$(printf '%s' "$1" | tr -c 'A-Za-z0-9\n' '_')"
}

new_case() {
  FIXTURES=$(mktemp -d "$tmp/case.XXXXXX")
  export FIXTURES
  : > "$FIXTURES/writes"
}

sha_for() {
  printf '%s' "$1" | sha1sum | cut -d ' ' -f 1
}

# message <name:version:update-type>...
message() {
  local entry name version type
  printf 'chore(deps): bump dependencies\n\nBumps dependencies.\n\n---\nupdated-dependencies:\n'
  for entry in "$@"; do
    IFS=: read -r name version type <<< "$entry"
    printf -- '- dependency-name: %s\n' "$name"
    [ -z "$version" ] || printf '  dependency-version: %s\n' "$version"
    printf '  dependency-type: direct:production\n'
    [ -z "$type" ] || printf '  update-type: version-update:semver-%s\n' "$type"
  done
  printf '...\n\nSigned-off-by: %s <support@github.com>\n' "$bot"
}

required_contexts() {
  "$root/scripts/sync-branch-protection.sh" --list
}

# Writes fixtures for one pull request. Arguments: number, head ref, commit
# message, then changed files. Overrides come from the P_* variables.
pull() {
  local number="$1" ref="$2" text="$3" sha
  shift 3
  sha=$(sha_for "$number")

  jq -n \
    --argjson number "$number" --arg ref "$ref" --arg sha "$sha" \
    --arg repo "${P_HEAD_REPO:-$GITHUB_REPOSITORY}" --arg base_repo "$GITHUB_REPOSITORY" \
    --arg user "${P_USER:-$bot}" --arg type "${P_TYPE:-Bot}" \
    --arg state "${P_STATE:-open}" --argjson draft "${P_DRAFT:-false}" \
    --arg base "${P_BASE:-main}" --arg mergeable "${P_MERGEABLE:-clean}" \
    --argjson commits "${P_COMMITS:-1}" --argjson changed "${P_CHANGED:-$#}" '{
      number: $number, state: $state, draft: $draft,
      user: {login: $user, type: $type},
      base: {ref: $base, repo: {full_name: $base_repo}},
      head: {ref: $ref, sha: $sha, repo: {full_name: $repo}},
      commits: $commits, changed_files: $changed, mergeable_state: $mergeable,
      auto_merge: null
    }' | fixture "repos/$GITHUB_REPOSITORY/pulls/$number"

  jq -n \
    --arg sha "${P_COMMIT_SHA:-$sha}" --arg author "${P_AUTHOR:-$bot}" \
    --arg committer "${P_COMMITTER:-web-flow}" --argjson verified "${P_VERIFIED:-true}" \
    --arg message "$text" --argjson count "${P_COMMITS:-1}" '
      [range(0; $count) | {
        sha: $sha, author: {login: $author}, committer: {login: $committer},
        commit: {message: $message, verification: {verified: $verified}}
      }]' | fixture "repos/$GITHUB_REPOSITORY/pulls/$number/commits?per_page=100"

  printf '%s\n' "$@" \
    | jq -R --arg status "${P_FILE_STATUS:-modified}" '{filename: ., status: $status, patch: "ignored"}' \
    | jq -s . | fixture "repos/$GITHUB_REPOSITORY/pulls/$number/files?per_page=100"
}

# Writes check runs for a pull request head. Arguments: number, then
# name=conclusion overrides ("name=" removes the run, "name=pending" leaves it
# in progress, "name=foreign" reports success from another app).
checks() {
  local number="$1" sha context override conclusion
  shift
  sha=$(sha_for "$number")
  required_contexts | while IFS= read -r context; do
    conclusion="success"
    for override in "$@"; do
      [ "${override%%=*}" = "$context" ] && conclusion="${override#*=}"
    done
    [ -n "$conclusion" ] || continue
    jq -n --arg name "$context" --arg sha "$sha" --arg conclusion "$conclusion" '{
      id: 1, name: $name, head_sha: $sha, started_at: "2026-01-01T00:00:00Z",
      app: {id: (if $conclusion == "foreign" then 1 else 15368 end)},
      status: (if $conclusion == "pending" then "in_progress" else "completed" end),
      conclusion: (if $conclusion == "pending" then null
                   elif $conclusion == "foreign" then "success"
                   else $conclusion end)
    }'
  done | jq -s '{check_runs: .}' \
    | fixture "repos/$GITHUB_REPOSITORY/commits/$sha/check-runs?filter=latest&per_page=100"
}

open_pulls() {
  local number
  for number in "$@"; do
    cat "$FIXTURES/$(printf '%s' "repos/$GITHUB_REPOSITORY/pulls/$number" | tr -c 'A-Za-z0-9\n' '_')"
  done | jq -s . | fixture "repos/$GITHUB_REPOSITORY/pulls?state=open&base=main&per_page=100"
}

pass() {
  tests=$((tests + 1))
}

fail() {
  tests=$((tests + 1))
  failures=$((failures + 1))
  echo "FAIL: $1" >&2
}

expect_decision() {
  local name="$1" expected="$2" number="$3" actual
  if ! actual=$("$subject" classify "$number" | jq -r '.decision'); then
    fail "$name: classify failed"
  elif [ "$actual" != "$expected" ]; then
    fail "$name: expected $expected, got $actual"
  elif [ -s "$FIXTURES/writes" ]; then
    fail "$name: classify made a write request"
  else
    pass
  fi
}

expect_writes() {
  local name="$1" expected="$2" actual
  actual=$(cat "$FIXTURES/writes")
  if [ "$actual" = "$expected" ]; then
    pass
  else
    fail "$name: expected writes [$expected], got [$actual]"
  fi
}

cargo_ref="dependabot/cargo/rust-safe-dependencies-0000000000"
fuzz_ref="dependabot/cargo/fuzz/serde_json-1.0.151"
actions_ref="dependabot/github_actions/codeql-action-0000000000"

# --- Classifier policy -------------------------------------------------------

new_case
pull 1 "$cargo_ref" "$(message clap:4.6.7:patch tokio:1.50.0:minor rand:0.10.3:patch toml:0.9.12+spec-1.1.0:patch)" Cargo.toml Cargo.lock
expect_decision "root cargo patch and minor group" eligible 1

new_case
pull 1 "$fuzz_ref" "$(message serde_json:1.0.151:patch)" fuzz/Cargo.lock
expect_decision "fuzz cargo patch" eligible 1

new_case
pull 1 "$actions_ref" "$(message github/codeql-action/init:4.37.3:patch github/codeql-action/analyze:4.37.3:patch)" .github/workflows/audit.yml
expect_decision "grouped actions patch" eligible 1

new_case
pull 1 "$cargo_ref" "$(message dirs:7.0.0:major)" Cargo.toml Cargo.lock
expect_decision "major update" manual 1

new_case
pull 1 "$cargo_ref" "$(message clap:4.6.7:patch dirs:7.0.0:major)" Cargo.toml Cargo.lock
expect_decision "group containing a major update" manual 1

new_case
pull 1 "$cargo_ref" "$(message base64:0.23.1:minor)" Cargo.toml Cargo.lock
expect_decision "0.x minor update" manual 1

new_case
pull 1 "$cargo_ref" "$(message tiny:0.0.4:patch)" Cargo.lock
expect_decision "0.0.x patch update" manual 1

new_case
pull 1 "$actions_ref" "$(message actions/checkout:8:major)" .github/workflows/ci.yml
expect_decision "major action update" manual 1

new_case
pull 1 "$cargo_ref" "$(message clap:4.6.7:)" Cargo.lock
expect_decision "missing update type" manual 1

new_case
pull 1 "$cargo_ref" "$(message clap::patch)" Cargo.lock
expect_decision "missing version" manual 1

new_case
pull 1 "$cargo_ref" "$(message clap:5.0.0-rc.1:minor)" Cargo.lock
expect_decision "prerelease version" manual 1

new_case
pull 1 "$cargo_ref" "chore(deps): bump clap" Cargo.lock
expect_decision "missing metadata" manual 1

new_case
pull 1 "$cargo_ref" "$(message clap:4.6.7:patch | sed 's/^  dependency-type:.*/  nested:\n    - value/')" Cargo.lock
expect_decision "malformed metadata" manual 1

new_case
pull 1 "$cargo_ref" "$(message clap:4.6.7:patch; message dirs:7.0.0:major)" Cargo.lock
expect_decision "duplicate metadata blocks" manual 1

new_case
pull 1 "dependabot/docker/.clusterfuzzlite/base-1.2.3" "$(message base:1.2.3:patch)" .clusterfuzzlite/Dockerfile
expect_decision "docker update" manual 1

new_case
pull 1 "$cargo_ref" "$(message clap:4.6.7:patch)" Cargo.lock src/main.rs
expect_decision "source file change" manual 1

new_case
pull 1 "$cargo_ref" "$(message clap:4.6.7:patch)" Cargo.lock fuzz/Cargo.lock
expect_decision "mixed manifest sets" manual 1

new_case
pull 1 "$cargo_ref" "$(message actions/checkout:7.0.2:patch)" .github/workflows/ci.yml
expect_decision "files outside the branch ecosystem" manual 1

new_case
pull 1 "$actions_ref" "$(message actions/checkout:7.0.2:patch)" .github/actions/setup/action.yml
expect_decision "non-workflow file" manual 1

new_case
P_FILE_STATUS=added pull 1 "$actions_ref" "$(message actions/checkout:7.0.2:patch)" .github/workflows/new.yml
expect_decision "added workflow file" manual 1

new_case
P_CHANGED=3 pull 1 "$cargo_ref" "$(message clap:4.6.7:patch)" Cargo.lock
expect_decision "incomplete file list" manual 1

# --- Classifier trust boundaries ---------------------------------------------

new_case
P_USER=contributor P_TYPE=User pull 1 "$cargo_ref" "$(message clap:4.6.7:patch)" Cargo.lock
expect_decision "pull request by another author" manual 1

new_case
P_TYPE=User pull 1 "$cargo_ref" "$(message clap:4.6.7:patch)" Cargo.lock
expect_decision "author is not a bot account" manual 1

new_case
P_HEAD_REPO=fork/guard pull 1 "$cargo_ref" "$(message clap:4.6.7:patch)" Cargo.lock
expect_decision "head branch in another repository" manual 1

new_case
pull 1 "feature/cargo" "$(message clap:4.6.7:patch)" Cargo.lock
expect_decision "head branch outside dependabot/" manual 1

new_case
P_BASE=release pull 1 "$cargo_ref" "$(message clap:4.6.7:patch)" Cargo.lock
expect_decision "base branch is not main" manual 1

new_case
P_DRAFT=true pull 1 "$cargo_ref" "$(message clap:4.6.7:patch)" Cargo.lock
expect_decision "draft pull request" manual 1

new_case
P_STATE=closed pull 1 "$cargo_ref" "$(message clap:4.6.7:patch)" Cargo.lock
expect_decision "closed pull request" manual 1

new_case
P_COMMITS=2 pull 1 "$cargo_ref" "$(message clap:4.6.7:patch)" Cargo.lock
expect_decision "additional commit on the branch" manual 1

new_case
P_AUTHOR=contributor pull 1 "$cargo_ref" "$(message clap:4.6.7:patch)" Cargo.lock
expect_decision "commit by another author" manual 1

new_case
P_COMMITTER=contributor pull 1 "$cargo_ref" "$(message clap:4.6.7:patch)" Cargo.lock
expect_decision "commit signed by another committer" manual 1

new_case
P_VERIFIED=false pull 1 "$cargo_ref" "$(message clap:4.6.7:patch)" Cargo.lock
expect_decision "unverified commit" manual 1

new_case
P_COMMIT_SHA=$(sha_for other) pull 1 "$cargo_ref" "$(message clap:4.6.7:patch)" Cargo.lock
expect_decision "commit differs from the head" manual 1

new_case
if "$subject" classify 1 > /dev/null 2>&1; then
  fail "unreadable metadata: classify succeeded"
else
  pass
fi

new_case
if "$subject" classify "1; echo injected" > /dev/null 2>&1; then
  fail "malformed number: classify succeeded"
else
  pass
fi

# --- Reconcile ---------------------------------------------------------------

eligible_pull() {
  pull "$1" "$cargo_ref" "$(message clap:4.6.7:patch)" Cargo.lock
}

merge_call() {
  printf 'pr merge %s --repo %s --squash --match-head-commit %s' \
    "$1" "$GITHUB_REPOSITORY" "$(sha_for "$1")"
}

new_case
eligible_pull 1
checks 1
open_pulls 1
"$subject" reconcile > /dev/null || fail "eligible and green: reconcile failed"
expect_writes "eligible and green merges at the exact head" "$(merge_call 1)"

new_case
eligible_pull 1
checks 1
pull 2 "$cargo_ref" "$(message dirs:7.0.0:major)" Cargo.toml Cargo.lock
checks 2
P_USER=contributor P_TYPE=User pull 3 "$cargo_ref" "$(message clap:4.6.7:patch)" Cargo.lock
checks 3
pull 4 "$fuzz_ref" "$(message serde_json:1.0.151:patch)" fuzz/Cargo.lock
checks 4
open_pulls 1 2 3 4
"$subject" reconcile > /dev/null || fail "backfill: reconcile failed"
expect_writes "backfill merges only eligible Dependabot pull requests" \
  "$(merge_call 1; echo; merge_call 4)"

for override in "Test & Lint=failure" "Security Audit (CVEs)=failure" \
  "CodeQL (rust)=pending" "Classify dependency update=" \
  "GitHub Actions Security=foreign" "Dependency Review=skipped" \
  "Build (aarch64-apple-darwin)=cancelled"; do
  new_case
  eligible_pull 1
  checks 1 "$override"
  open_pulls 1
  "$subject" reconcile > /dev/null || fail "$override: reconcile failed"
  expect_writes "no merge when $override" ""
done

for state in blocked behind dirty unknown draft; do
  new_case
  P_MERGEABLE=$state eligible_pull 1
  checks 1
  open_pulls 1
  "$subject" reconcile > /dev/null || fail "$state: reconcile failed"
  expect_writes "no merge when mergeable state is $state" ""
done

new_case
P_MERGEABLE=unstable eligible_pull 1
checks 1
open_pulls 1
"$subject" reconcile > /dev/null || fail "unstable: reconcile failed"
expect_writes "optional check failures do not block" "$(merge_call 1)"

new_case
eligible_pull 1
open_pulls 1
if "$subject" reconcile > /dev/null 2>&1; then
  fail "unreadable checks: reconcile succeeded"
fi
expect_writes "no merge when check runs are unreadable" ""

new_case
eligible_pull 1
checks 1
open_pulls 1
touch "$FIXTURES/refuse-writes"
if "$subject" reconcile > /dev/null 2>&1; then
  fail "refused merge: reconcile succeeded"
else
  pass
fi

new_case
open_pulls
"$subject" reconcile > /dev/null || fail "no pull requests: reconcile failed"
expect_writes "no pull requests" ""

# --- Mainline runs -----------------------------------------------------------

head=$(sha_for main)
runs_path() {
  printf 'repos/%s/actions/workflows/%s/runs?head_sha=%s&per_page=100' \
    "$GITHUB_REPOSITORY" "$1" "$head"
}
main_ref() {
  jq -n --arg sha "$1" '{object: {sha: $sha}}' \
    | fixture "repos/$GITHUB_REPOSITORY/git/ref/heads/main"
}
runs() {
  jq -n --arg sha "$head" --arg branch "$2" --argjson count "$3" '{
    workflow_runs: [range(0; $count) | {head_sha: $sha, head_branch: $branch, event: "push"}]
  }' | fixture "$(runs_path "$1")"
}

new_case
main_ref "$head"
runs ci.yml main 0
runs audit.yml main 0
"$subject" ensure-mainline-runs > /dev/null || fail "missing runs: command failed"
expect_writes "missing mainline runs are dispatched on main" \
  "$(printf 'workflow run ci.yml --repo %s --ref main\nworkflow run audit.yml --repo %s --ref main' \
    "$GITHUB_REPOSITORY" "$GITHUB_REPOSITORY")"

new_case
main_ref "$head"
runs ci.yml main 1
runs audit.yml main 2
"$subject" ensure-mainline-runs > /dev/null || fail "existing runs: command failed"
expect_writes "existing mainline runs are not repeated" ""

new_case
main_ref "$head"
runs ci.yml feature 1
runs audit.yml main 1
"$subject" ensure-mainline-runs > /dev/null || fail "branch run: command failed"
expect_writes "a run on another branch is not mainline evidence" \
  "workflow run ci.yml --repo $GITHUB_REPOSITORY --ref main"

new_case
main_ref "not-a-commit"
if "$subject" ensure-mainline-runs > /dev/null 2>&1; then
  fail "malformed head: command succeeded"
fi
expect_writes "no dispatch when the main head is unreadable" ""

# --- Workflow and configuration contract -------------------------------------

workflows="$root/.github/workflows"
reconcile="$workflows/dependabot-reconcile.yml"
gate="$workflows/dependabot-automerge.yml"

contract() {
  local name="$1"
  shift
  if "$@" > /dev/null 2>&1; then
    pass
  else
    fail "contract: $name"
  fi
}

refute() {
  local name="$1"
  shift
  if "$@" > /dev/null 2>&1; then
    fail "contract: $name"
  else
    pass
  fi
}

refute "no workflow uses pull_request_target or workflow_run" \
  grep -rnE '^\s*(pull_request_target|workflow_run):' "$workflows"
refute "the privileged workflow has no pull request trigger" \
  grep -nE '^\s*pull_request' "$reconcile"
contract "the privileged workflow runs on a schedule" grep -qE '^  schedule:$' "$reconcile"
contract "the privileged workflow accepts manual dispatch" grep -qE '^  workflow_dispatch:$' "$reconcile"
contract "the privileged workflow grants nothing by default" grep -qx 'permissions: {}' "$reconcile"
contract "the review gate grants nothing by default" grep -qx 'permissions: {}' "$gate"
refute "the review gate holds no write permission" grep -nE ':\s*write\b' "$gate"
refute "neither workflow checks out a pull request ref" \
  grep -nE 'ref:.*(head|pull_request\.(number|head)|refs/pull)' "$reconcile" "$gate"
refute "neither workflow interpolates event text into a script" \
  grep -nE 'run:.*\$\{\{|^\s+[^#]*\$\{\{\s*github\.event\.pull_request\.(title|body|head\.ref)' "$reconcile" "$gate"
contract "the privileged jobs run only on main" \
  test "$(grep -c "github.ref == 'refs/heads/main'" "$reconcile")" -eq 2
contract "checkouts do not persist credentials" \
  test "$(grep -c 'persist-credentials: false' "$reconcile")" -eq "$(grep -c 'uses: actions/checkout@' "$reconcile")"
contract "the review gate keeps its required context name" \
  grep -qx '    name: Classify dependency update' "$gate"
contract "the required context list still names the review gate" \
  grep -qx 'Classify dependency update' <(required_contexts)
contract "thirteen required contexts are declared" test "$(required_contexts | wc -l)" -eq 13
contract "CI accepts dispatch for mainline runs" grep -qE '^  workflow_dispatch:$' "$workflows/ci.yml"
contract "the audit accepts dispatch for mainline runs" grep -qE '^  workflow_dispatch:$' "$workflows/audit.yml"
contract "release validation accepts dispatched mainline CI" \
  grep -q 'event == \\"workflow_dispatch\\"' "$workflows/release.yml"
contract "release validation requires the main branch" \
  grep -q 'headBranch == \\"main\\"' "$workflows/release.yml"
refute "the script makes no write request through the raw API" \
  grep -nE 'gh api .*(-X|--method) *(POST|PUT|PATCH|DELETE)|--admin|--auto' "$subject"

dependabot="$root/.github/dependabot.yml"
contract "every update entry keeps its cooldown" \
  test "$(grep -c 'default-days: 7' "$dependabot")" -eq "$(grep -c 'package-ecosystem:' "$dependabot")"
contract "the CodeQL actions are grouped" grep -q '"github/codeql-action\*"' "$dependabot"
contract "transitive cargo dependencies are updated" grep -q 'dependency-type: "all"' "$dependabot"

echo "${tests} checks, ${failures} failures"
[ "$failures" -eq 0 ]
