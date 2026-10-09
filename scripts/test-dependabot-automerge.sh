#!/usr/bin/env bash
set -euo pipefail

# Exercises scripts/dependabot-automerge.sh and scripts/dependency-repair.sh
# against stub gh, opencode, and cargo commands, and checks the trust
# boundaries of the workflows that run them. No network access, token, or model
# credential is used: the gh stub serves fixtures for read requests and records
# every write request so the tests can assert exactly which ones were made.

root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
subject="$root/scripts/dependabot-automerge.sh"
engine="$root/scripts/dependency-repair.sh"
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

export GITHUB_REPOSITORY="example/guard"
export DISPATCH_POLLS=2 DISPATCH_POLL_SECONDS=0
unset GITHUB_STEP_SUMMARY GH_TOKEN GITHUB_TOKEN EXPECTED_HEAD OPENROUTER_API_KEY \
  DEPENDENCY_REPAIR_AUDIT_LOG AGENT_AUDIT_LOG_CLI || true
bot="dependabot[bot]"
repair_bot="github-actions[bot]"
failures=0
tests=0

mkdir "$tmp/bin"
cat > "$tmp/bin/gh" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
key() {
  printf '%s' "$1" | tr -c 'A-Za-z0-9\n' '_'
}
if [ "$1" != "api" ]; then
  printf '%s\n' "$*" >> "$FIXTURES/writes"
  [ ! -e "$FIXTURES/refuse-writes" ]
  exit
fi
shift
if [ "$1" = "graphql" ]; then
  number=""
  while [ "$#" -gt 0 ]; do
    case "$1" in number=*) number="${1#number=}" ;; esac
    shift
  done
  cat "$FIXTURES/graphql_$number"
  exit
fi
path=""
method="GET"
input=0
while [ "$#" -gt 0 ]; do
  case "$1" in
    --method) method="$2"; shift ;;
    --paginate) ;;
    --input) input=1; shift ;;
    -*) echo "stub gh: unsupported option $1" >&2; exit 1 ;;
    *) path="$1" ;;
  esac
  shift
done
if [ "$method" != "GET" ]; then
  body=""
  [ "$input" -eq 0 ] || body=$(jq -c .)
  # A scratch branch has a name made per invocation. Its request is recorded
  # under one name, and the name itself beside it.
  scratch=$(printf '%s' "$path" | sed -n 's#.*/git/refs/heads/dependency-refresh/\(.*\)$#\1#p')
  if [ -n "$scratch" ]; then
    printf '%s\n' "$scratch" >> "$FIXTURES/scratch-$method"
    path="${path%"$scratch"}SCRATCH"
  fi
  printf 'api %s %s\n' "$method" "$path" >> "$FIXTURES/writes"
  [ -z "$body" ] || printf '%s\n' "$body" >> "$FIXTURES/bodies"
  [ ! -e "$FIXTURES/refuse-writes" ] || exit 1
  file="$FIXTURES/$(key "$method $path")"
  [ -f "$file" ] || exit 1
  # A created ref is reported as requested unless the fixture says otherwise.
  if [ "$method" = "POST" ] && [ "${path##*/git/}" = "refs" ]; then
    jq --argjson body "$body" '.ref //= $body.ref | .object.sha //= $body.sha' "$file"
  else
    cat "$file"
  fi
  exit
fi
file="$FIXTURES/$(key "$path")"
# "<fixture>.dispatched" replaces a fixture once its workflow was dispatched, and
# "<fixture>.again" replaces it from the second read onward.
workflow=$(printf '%s' "$path" | sed -n 's#.*/actions/workflows/\([^/]*\)/runs.*#\1#p')
if [ -f "$file.dispatched" ] && grep -q "^workflow run $workflow " "$FIXTURES/writes"; then
  file="$file.dispatched"
elif [ -f "$file.again" ] && [ -e "$file.read" ]; then
  file="$file.again"
fi
if [ ! -f "$file" ]; then
  echo "stub gh: no fixture for $path" >&2
  exit 1
fi
: > "${file%.again}.read"
cat "$file"
STUB
chmod +x "$tmp/bin/gh"
export PATH="$tmp/bin:$PATH"

fixture_path() {
  printf '%s/%s' "$FIXTURES" "$(printf '%s' "$1" | tr -c 'A-Za-z0-9\n' '_')"
}

fixture() {
  cat > "$(fixture_path "$1")"
}

sha_for() {
  printf '%s' "$1" | sha1sum | cut -d ' ' -f 1
}

main_sha=$(sha_for main)
api="repos/$GITHUB_REPOSITORY"

required_contexts() {
  "$root/scripts/sync-branch-protection.sh" --list
}

# rules [jq filter applied to the default effective rules]
rules() {
  required_contexts | jq -R '{context: ., integration_id: 15368}' | jq -s '[
    {type: "deletion"},
    {type: "non_fast_forward"},
    {type: "pull_request", parameters: {
      allowed_merge_methods: ["merge", "squash", "rebase"],
      require_code_owner_review: false, require_last_push_approval: false,
      required_approving_review_count: 0, required_review_thread_resolution: true,
      required_reviewers: []}},
    {type: "required_status_checks", parameters: {
      strict_required_status_checks_policy: false, required_status_checks: .}}
  ]' | jq "${1:-.}" | fixture "$api/rules/branches/main?per_page=100"
}

# check_runs <sha> [name=conclusion]... ("name=" removes the run, "name=pending"
# leaves it in progress, "name=foreign" reports success from another app).
# CHECKS_STARTED sets the start time of every run.
check_runs() {
  local sha="$1" context override conclusion
  CHECK_SHA="$sha"
  shift
  required_contexts | while IFS= read -r context; do
    conclusion="success"
    for override in "$@"; do
      [ "${override%%=*}" = "$context" ] && conclusion="${override#*=}"
    done
    [ -n "$conclusion" ] || continue
    jq -n --arg name "$context" --arg sha "$sha" --arg conclusion "$conclusion" \
      --arg started "${CHECKS_STARTED:-2026-01-01T00:00:00Z}" '{
        name: $name, head_sha: $sha, started_at: $started,
        app: {id: (if $conclusion == "foreign" then 1 else 15368 end)},
        status: (if $conclusion == "pending" then "in_progress" else "completed" end),
        conclusion: (if $conclusion == "pending" then null
                     elif $conclusion == "foreign" then "success"
                     else $conclusion end)
      }'
  done | jq -s '{check_runs: [to_entries[] | .value + {id: (77 + .key)}]}' \
    | fixture "$api/commits/$sha/check-runs?filter=latest&per_page=100"
  job_attempt "$JOB_ATTEMPT" "$JOB_CONCLUSION"
}

checks() {
  local number="$1"
  shift
  check_runs "$(sha_for "$number")" "$@"
}

main_ref() {
  jq -n --arg sha "$1" '{object: {sha: $sha}}' | fixture "$api/git/ref/heads/main"
}

# Starts a case with the declared branch rules and failed jobs that a rerun
# reproduced.
new_case() {
  FIXTURES=$(mktemp -d "$tmp/case.XXXXXX")
  export FIXTURES
  : > "$FIXTURES/writes"
  : > "$FIXTURES/bodies"
  main_ref "$main_sha"
  rules
  jq -n '[{name: "workflows", type: "dir", sha: "workflows-tree"}]' \
    | fixture "$api/contents/.github?ref=$main_sha"
  unset CHECK_SHA
  job_attempt 2 failure
}

# job_attempt <run attempt> <conclusion> [previous]: Actions job and
# workflow-run fixtures. From the second attempt on, the attempt before holds a
# job of the same name under its own ID with the previous conclusion (default
# "failure"); "absent" leaves that job out and "unreadable" omits the attempt.
job_attempt() {
  local check id run_id job previous="${3:-failure}"
  JOB_ATTEMPT="$1"
  JOB_CONCLUSION="$2"
  [ -n "${CHECK_SHA:-}" ] || return 0
  while IFS= read -r check; do
    id=$(jq -r '.id' <<< "$check")
    run_id=$((500 + id))
    job=$(jq -n --argjson check "$check" --argjson run_id "$run_id" \
      --arg conclusion "$2" --arg repo "$GITHUB_REPOSITORY" '{
        id: $check.id, run_id: $run_id,
        check_run_url: ("https://api.github.com/repos/" + $repo + "/check-runs/" + ($check.id | tostring)),
        head_sha: $check.head_sha, name: $check.name, status: "completed",
        conclusion: $conclusion
      }')
    fixture "$api/actions/jobs/$id" <<< "$job"
    jq -n --argjson run_id "$run_id" --arg sha "$CHECK_SHA" \
      --argjson attempt "$1" '{id: $run_id, head_sha: $sha,
        status: "completed", run_attempt: $attempt}' \
      | fixture "$api/actions/runs/$run_id"
    jq -n --argjson job "$job" '{total_count: 1, jobs: [$job]}' \
      | fixture "$api/actions/runs/$run_id/attempts/$1/jobs?per_page=100"
    [ "$1" -ge 2 ] || continue
    rm -f "$(fixture_path "$api/actions/runs/$run_id/attempts/$(($1 - 1))/jobs?per_page=100")"
    [ "$previous" != "unreadable" ] || continue
    jq -n --argjson job "$job" --arg previous "$previous" --argjson id "$((1000 + id))" \
      --arg repo "$GITHUB_REPOSITORY" '{jobs: (if $previous == "absent" then [] else [$job + {
        id: $id, conclusion: $previous,
        check_run_url: ("https://api.github.com/repos/" + $repo + "/check-runs/" + ($id | tostring))
      }] end)} | .total_count = (.jobs | length)' \
      | fixture "$api/actions/runs/$run_id/attempts/$(($1 - 1))/jobs?per_page=100"
  done < <(jq -c '.check_runs[] | select(.status == "completed")' \
    "$(fixture_path "$api/commits/$CHECK_SHA/check-runs?filter=latest&per_page=100")")
}

check_id_for() {
  jq -r --arg name "$1" '.check_runs[] | select(.name == $name) | .id' \
    "$(fixture_path "$api/commits/$CHECK_SHA/check-runs?filter=latest&per_page=100")"
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

pin() {
  printf '@@ -1 +1 @@\n-        uses: %s@%s  # v1\n+        uses: %s@%s  # v2' \
    "$1" "$(sha_for old)" "$1" "${2:-$(sha_for new)}"
}

default_patch() {
  case "$1" in
    .github/workflows/*) pin actions/checkout ;;
    *) printf '@@ -1 +1 @@\n-old %s\n+new %s' "$1" "$1" ;;
  esac
}

# files_json <patch override or empty> <file>...
files_json() {
  local override="$1" file
  shift
  for file in "$@"; do
    jq -n --arg file "$file" --arg status "${P_FILE_STATUS:-modified}" \
      --arg patch "${override:-$(default_patch "$file")}" \
      '{filename: $file, status: $status} + (if $patch == "none" then {} else {patch: $patch} end)'
  done | jq -s .
}

# Writes fixtures for one pull request. Arguments: number, head ref, commit
# message, then changed files. Overrides come from the P_* variables:
#   P_REPAIRS   later commits, each "update" or "merge";
#   P_PATCH     patch of every changed file ("none" omits it);
#   P_CONTAINS  comparison of main with the head (default "ahead": the head
#               contains main).
pull() {
  local number="$1" ref="$2" text="$3" sha first previous index=0 kind commits
  local -a repairs
  shift 3
  sha=$(sha_for "$number")
  read -r -a repairs <<< "${P_REPAIRS:-}"
  first="$sha"
  [ "${#repairs[@]}" -eq 0 ] || first=$(sha_for "$number-first")

  jq -n \
    --argjson number "$number" --arg ref "$ref" --arg sha "$sha" \
    --arg repo "${P_HEAD_REPO:-$GITHUB_REPOSITORY}" --arg base_repo "$GITHUB_REPOSITORY" \
    --arg user "${P_USER:-$bot}" --arg type "${P_TYPE:-Bot}" \
    --arg state "${P_STATE:-open}" --argjson draft "${P_DRAFT:-false}" \
    --arg base "${P_BASE:-main}" --arg mergeable "${P_MERGEABLE:-clean}" \
    --argjson commits "${P_COMMITS:-$((1 + ${#repairs[@]}))}" --argjson changed "${P_CHANGED:-$#}" '{
      number: $number, state: $state, draft: $draft,
      user: {login: $user, type: $type},
      base: {ref: $base, repo: {full_name: $base_repo}},
      head: {ref: $ref, sha: $sha, repo: {full_name: $repo}},
      commits: $commits, changed_files: $changed, mergeable_state: $mergeable,
      auto_merge: null
    }' | fixture "$api/pulls/$number"

  commits=$(jq -n \
    --arg sha "${P_COMMIT_SHA:-$first}" --arg author "${P_AUTHOR:-$bot}" \
    --arg committer "${P_COMMITTER:-web-flow}" --argjson verified "${P_VERIFIED:-true}" \
    --arg message "$text" --argjson count "${P_COMMITS:-1}" '
      [range(0; if $count > 1 then $count else 1 end) | {
        sha: $sha, author: {login: $author}, committer: {login: $committer},
        commit: {message: $message, verification: {verified: $verified}},
        parents: [{sha: "base"}]
      }]')
  previous="$first"
  for kind in "${repairs[@]}"; do
    index=$((index + 1))
    [ "$index" -eq "${#repairs[@]}" ] && next="$sha" || next=$(sha_for "$number-repair-$index")
    commits=$(jq \
      --arg sha "$next" --arg previous "${P_REPAIR_PARENT:-$previous}" --arg kind "$kind" \
      --arg merged "$(sha_for merged)" --arg author "${P_REPAIR_AUTHOR:-$repair_bot}" \
      --argjson verified "${P_REPAIR_VERIFIED:-true}" '. + [{
        sha: $sha, author: {login: $author}, committer: {login: "web-flow"},
        commit: {message: "chore(deps): repair dependency update", verification: {verified: $verified}},
        parents: ([{sha: $previous}] + (if $kind == "merge" then [{sha: $merged}] else [] end))
      }]' <<< "$commits")
    previous="$next"
  done
  fixture "$api/pulls/$number/commits?per_page=100" <<< "$commits"
  jq -n --arg status "${P_MERGED_STATUS:-ahead}" '{status: $status}' \
    | fixture "$api/compare/$(sha_for merged)...main"

  jq -n --arg status "${P_CONTAINS:-ahead}" '{status: $status}' \
    | fixture "$api/compare/$main_sha...$sha"

  files_json "${P_PATCH:-}" "$@" | fixture "$api/pulls/$number/files?per_page=100"

  echo '[]' | fixture "$api/pulls/$number/reviews?per_page=100"
  threads "$number" true
}

# review <number> <login> <state> <association> [commit]
review() {
  local path
  path=$(fixture_path "$api/pulls/$1/reviews?per_page=100")
  jq --arg login "$2" --arg state "$3" --arg association "$4" \
    --arg commit "${5:-$(sha_for "$1")}" --arg at "2026-03-0$(jq length "$path")T00:00:00Z" \
    '. + [{user: {login: $login, type: "User"}, state: $state,
           author_association: $association, commit_id: $commit, submitted_at: $at}]' \
    "$path" > "$path.next"
  mv "$path.next" "$path"
}

# threads <number> <resolved>... (one page; THREADS_HEAD and THREADS_MORE override)
threads() {
  local number="$1"
  shift
  printf '%s\n' "$@" | jq -R 'select(length > 0) | {isResolved: (. == "true")}' | jq -s \
    --arg sha "${THREADS_HEAD:-$(sha_for "$number")}" --argjson more "${THREADS_MORE:-false}" '{
      data: {repository: {pullRequest: {
        headRefOid: $sha,
        reviewThreads: {nodes: ., pageInfo: {hasNextPage: $more, endCursor: null}}
      }}}
    }' > "$FIXTURES/graphql_$number"
}

open_pulls() {
  local number
  for number in "$@"; do
    cat "$(fixture_path "$api/pulls/$number")"
  done | jq -s . | fixture "$api/pulls?state=open&base=main&per_page=100"
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

# expect_status <name> <expected: ok|fail> <command>...
expect_status() {
  local name="$1" expected="$2" status=ok
  shift 2
  "$@" > "$tmp/output" 2>&1 || status=fail
  if [ "$status" = "$expected" ]; then
    pass
  else
    fail "$name: expected $expected, got $status: $(tail -n 3 "$tmp/output")"
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
pull 1 "$cargo_ref" "$(message base64:0.23.1:minor)" Cargo.toml Cargo.lock
expect_decision "0.x minor update" eligible 1

new_case
pull 1 "$cargo_ref" "$(message tiny:0.0.4:patch)" Cargo.lock
expect_decision "0.0.x patch update" eligible 1

new_case
pull 1 "$actions_ref" "$(message actions/checkout:8:major)" .github/workflows/ci.yml
expect_decision "SHA-pinned major action update" eligible 1

new_case
P_PATCH=$(pin actions/checkout v8) pull 1 "$actions_ref" "$(message actions/checkout:8:major)" .github/workflows/ci.yml
expect_decision "action update pinned to a tag" review 1

new_case
P_PATCH=$'@@ -1 +1 @@\n-    run: old\n+    run: new' pull 1 "$actions_ref" "$(message actions/checkout:7.0.2:patch)" .github/workflows/ci.yml
expect_decision "workflow change that is not an action pin" review 1

new_case
P_PATCH=none pull 1 "$actions_ref" "$(message actions/checkout:7.0.2:patch)" .github/workflows/ci.yml
expect_decision "workflow change without a readable patch" review 1

new_case
pull 1 "$cargo_ref" "$(message dirs:7.0.0:major)" Cargo.toml Cargo.lock
expect_decision "major update" review 1

new_case
pull 1 "$cargo_ref" "$(message clap:4.6.7:patch dirs:7.0.0:major)" Cargo.toml Cargo.lock
expect_decision "group containing a major update" review 1

new_case
pull 1 "$cargo_ref" "$(message clap:4.6.7:)" Cargo.lock
expect_decision "missing update type" review 1

new_case
pull 1 "$cargo_ref" "$(message clap::patch)" Cargo.lock
expect_decision "missing version" review 1

new_case
pull 1 "$cargo_ref" "$(message clap:5.0.0-rc.1:minor)" Cargo.lock
expect_decision "prerelease version" review 1

new_case
pull 1 "$cargo_ref" "chore(deps): bump clap" Cargo.lock
expect_decision "missing metadata" review 1

new_case
pull 1 "$cargo_ref" "$(message clap:4.6.7:patch | sed 's/^  dependency-type:.*/  nested:\n    - value/')" Cargo.lock
expect_decision "malformed metadata" review 1

new_case
pull 1 "$cargo_ref" "$(message clap:4.6.7:patch; message dirs:7.0.0:major)" Cargo.lock
expect_decision "duplicate metadata blocks" review 1

new_case
pull 1 "dependabot/docker/.clusterfuzzlite/base-1.2.3" "$(message base:1.2.3:patch)" .clusterfuzzlite/Dockerfile
expect_decision "docker update" review 1

new_case
pull 1 "$cargo_ref" "$(message clap:4.6.7:patch)" Cargo.lock src/main.rs
expect_decision "source file change without a repair" review 1

new_case
pull 1 "$cargo_ref" "$(message clap:4.6.7:patch)" Cargo.lock fuzz/Cargo.lock
expect_decision "mixed manifest sets" review 1

new_case
pull 1 "$cargo_ref" "$(message actions/checkout:7.0.2:patch)" .github/workflows/ci.yml
expect_decision "files outside the branch ecosystem" review 1

new_case
pull 1 "$actions_ref" "$(message actions/checkout:7.0.2:patch)" .github/actions/setup/action.yml
expect_decision "non-workflow file" review 1

new_case
P_FILE_STATUS=added pull 1 "$actions_ref" "$(message actions/checkout:7.0.2:patch)" .github/workflows/new.yml
expect_decision "added workflow file" review 1

new_case
P_CHANGED=3 pull 1 "$cargo_ref" "$(message clap:4.6.7:patch)" Cargo.lock
expect_decision "incomplete file list" review 1

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
expect_decision "additional commit that is not a repair" manual 1

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

# --- Repair provenance -------------------------------------------------------

new_case
P_REPAIRS=update pull 1 "$cargo_ref" "$(message clap:4.6.7:patch)" Cargo.toml Cargo.lock
expect_decision "lockfile repair on top of the Dependabot commit" eligible 1

new_case
P_REPAIRS="merge update" pull 1 "$cargo_ref" "$(message clap:4.6.7:patch)" Cargo.toml Cargo.lock
expect_decision "merge of main followed by a lockfile repair" eligible 1

new_case
P_REPAIRS=merge pull 1 "$actions_ref" "$(message actions/checkout:7.0.2:patch)" .github/workflows/ci.yml
expect_decision "merge of main into a workflow update" eligible 1

new_case
P_REPAIRS=merge P_MERGED_STATUS=diverged pull 1 "$cargo_ref" "$(message clap:4.6.7:patch)" Cargo.lock
expect_decision "merge of a commit that main does not contain" manual 1

new_case
P_REPAIRS=update P_REPAIR_AUTHOR=contributor pull 1 "$cargo_ref" "$(message clap:4.6.7:patch)" Cargo.lock
expect_decision "later commit by another author" manual 1

new_case
P_REPAIRS=update P_REPAIR_VERIFIED=false pull 1 "$cargo_ref" "$(message clap:4.6.7:patch)" Cargo.lock
expect_decision "unverified repair commit" manual 1

new_case
P_REPAIRS=update P_REPAIR_PARENT=$(sha_for elsewhere) pull 1 "$cargo_ref" "$(message clap:4.6.7:patch)" Cargo.lock
expect_decision "repair that is not on top of the Dependabot commit" manual 1

new_case
P_REPAIRS=update pull 1 "$cargo_ref" "$(message clap:4.6.7:patch)" Cargo.toml Cargo.lock src/server/execute.rs tests/cli_output.rs
expect_decision "repair that changes the manifest and Rust source" eligible 1

new_case
P_REPAIRS=update pull 1 "$fuzz_ref" "$(message serde_json:1.0.151:patch)" fuzz/Cargo.lock fuzz/fuzz_targets/parse.rs
expect_decision "fuzz repair that changes a fuzz target" eligible 1

new_case
P_REPAIRS=update pull 1 "$fuzz_ref" "$(message serde_json:1.0.151:patch)" fuzz/Cargo.lock src/main.rs
expect_decision "fuzz repair that changes root source" review 1

new_case
P_REPAIRS=update pull 1 "$cargo_ref" "$(message clap:4.6.7:patch)" Cargo.lock build.rs
expect_decision "repair that changes a build script" review 1

new_case
P_REPAIRS=update pull 1 "$cargo_ref" "$(message clap:4.6.7:patch)" Cargo.lock scripts/dependabot-automerge.sh
expect_decision "repair that changes the automation" review 1

new_case
P_REPAIRS=update pull 1 "$actions_ref" "$(message actions/checkout:7.0.2:patch)" .github/workflows/ci.yml src/main.rs
expect_decision "workflow update that carries Rust source" review 1

new_case
P_REPAIRS="update update update update update update update update update" \
  pull 1 "$cargo_ref" "$(message clap:4.6.7:patch)" Cargo.lock src/main.rs
expect_decision "the number of repairs does not end automation" eligible 1

new_case
P_REPAIRS=update pull 1 "$cargo_ref" "$(message dirs:7.0.0:major)" Cargo.toml Cargo.lock
expect_decision "repaired major update" review 1

# --- Review gate -------------------------------------------------------------

new_case
pull 1 "$cargo_ref" "$(message clap:4.6.7:patch)" Cargo.lock
expect_status "gate passes a routine update" ok "$subject" gate 1

new_case
pull 1 "$cargo_ref" "$(message dirs:7.0.0:major)" Cargo.toml Cargo.lock
expect_status "gate blocks an unreviewed major update" fail "$subject" gate 1

new_case
pull 1 "$cargo_ref" "$(message dirs:7.0.0:major)" Cargo.toml Cargo.lock
review 1 owner APPROVED OWNER
expect_status "gate passes a major update approved at its head" ok "$subject" gate 1

new_case
pull 1 "$cargo_ref" "$(message dirs:7.0.0:major)" Cargo.toml Cargo.lock
review 1 owner APPROVED OWNER "$(sha_for earlier)"
expect_status "gate ignores an approval of an earlier commit" fail "$subject" gate 1

new_case
pull 1 "$cargo_ref" "$(message dirs:7.0.0:major)" Cargo.toml Cargo.lock
review 1 visitor APPROVED NONE
review 1 helper APPROVED CONTRIBUTOR
expect_status "gate ignores approvals from accounts without repository access" fail "$subject" gate 1

new_case
pull 1 "$cargo_ref" "$(message dirs:7.0.0:major)" Cargo.toml Cargo.lock
review 1 owner APPROVED OWNER
review 1 owner CHANGES_REQUESTED OWNER
expect_status "gate honors a later change request by the same reviewer" fail "$subject" gate 1

new_case
pull 1 "$cargo_ref" "$(message dirs:7.0.0:major)" Cargo.toml Cargo.lock
review 1 owner APPROVED OWNER
review 1 member CHANGES_REQUESTED MEMBER
expect_status "gate honors a change request by another reviewer" fail "$subject" gate 1

new_case
pull 1 "$cargo_ref" "$(message dirs:7.0.0:major)" Cargo.toml Cargo.lock
review 1 member CHANGES_REQUESTED MEMBER
review 1 member APPROVED MEMBER
review 1 member COMMENTED MEMBER
expect_status "gate uses each reviewer's latest decision" ok "$subject" gate 1

new_case
P_USER=contributor P_TYPE=User pull 1 "$cargo_ref" "$(message clap:4.6.7:patch)" Cargo.lock
expect_status "gate blocks a pull request it does not recognize" fail "$subject" gate 1

new_case
pull 1 "$cargo_ref" "$(message clap:4.6.7:patch)" Cargo.lock
EXPECTED_HEAD=$(sha_for 1) expect_status "dispatched gate accepts the pull request head" ok "$subject" gate 1
EXPECTED_HEAD=$(sha_for other) expect_status "dispatched gate rejects another commit" fail "$subject" gate 1

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
pull 2 "$cargo_ref" "$(message dirs:7.0.0:major)" Cargo.toml Cargo.lock
checks 2
P_USER=contributor P_TYPE=User pull 3 "$cargo_ref" "$(message clap:4.6.7:patch)" Cargo.lock
checks 3
pull 4 "$fuzz_ref" "$(message serde_json:1.0.151:patch)" fuzz/Cargo.lock
checks 4
eligible_pull 5
checks 5
open_pulls 2 3 4 5
"$subject" reconcile > /dev/null || fail "backfill: reconcile failed"
expect_writes "one eligible pull request merges per run" "$(merge_call 4)"

new_case
pull 1 "$cargo_ref" "$(message dirs:7.0.0:major)" Cargo.toml Cargo.lock
review 1 owner APPROVED OWNER
checks 1
open_pulls 1
"$subject" reconcile > /dev/null || fail "approved major: reconcile failed"
expect_writes "an approved major update merges" "$(merge_call 1)"

new_case
P_REPAIRS="merge update" eligible_pull 1
checks 1
open_pulls 1
"$subject" reconcile > /dev/null || fail "repaired: reconcile failed"
expect_writes "a lockfile-repaired update merges" "$(merge_call 1)"

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
expect_status "a refused merge fails the run" fail "$subject" reconcile

new_case
open_pulls
"$subject" reconcile > /dev/null || fail "no pull requests: reconcile failed"
expect_writes "no pull requests" ""

# Review threads.

new_case
eligible_pull 1
threads 1 true false true
checks 1
open_pulls 1
"$subject" reconcile > /dev/null || fail "unresolved thread: reconcile failed"
expect_writes "no merge with an unresolved review thread" ""

new_case
eligible_pull 1
rm "$FIXTURES/graphql_1"
checks 1
open_pulls 1
"$subject" reconcile > /dev/null 2>&1 || fail "unreadable threads: reconcile failed"
expect_writes "no merge when review threads are unreadable" ""

new_case
eligible_pull 1
THREADS_MORE=true threads 1 true
checks 1
open_pulls 1
"$subject" reconcile > /dev/null || fail "partial threads: reconcile failed"
expect_writes "no merge when the thread list is incomplete" ""

new_case
eligible_pull 1
THREADS_HEAD=$(sha_for moved) threads 1 true
checks 1
open_pulls 1
"$subject" reconcile > /dev/null || fail "thread head: reconcile failed"
expect_writes "no merge when threads were read for another head" ""

# Effective branch rules.

for change in \
  '(.[] | select(.type == "required_status_checks") | .parameters.required_status_checks) += [{context: "New Required Check", integration_id: 15368}]' \
  '(.[] | select(.type == "required_status_checks") | .parameters.required_status_checks) |= .[1:]' \
  '(.[] | select(.type == "required_status_checks") | .parameters.required_status_checks[0].integration_id) = 1' \
  '(.[] | select(.type == "required_status_checks") | .parameters.required_status_checks[0].integration_id) = null' \
  'map(select(.type != "required_status_checks"))' \
  '. + [{type: "required_deployments", parameters: {}}]' \
  '(.[] | select(.type == "pull_request") | .parameters.required_approving_review_count) = 1' \
  '(.[] | select(.type == "pull_request") | .parameters.require_code_owner_review) = true' \
  '(.[] | select(.type == "pull_request") | .parameters.require_last_push_approval) = true' \
  '(.[] | select(.type == "pull_request") | .parameters.allowed_merge_methods) = ["merge"]' \
  '{message: "Not Found"}'; do
  new_case
  rules "$change"
  eligible_pull 1
  checks 1
  open_pulls 1
  if "$subject" reconcile > /dev/null 2>&1; then
    fail "rules [$change]: reconcile succeeded"
  fi
  expect_writes "no merge when the effective rules are [$change]" ""
done

new_case
rules '(.[] | select(.type == "pull_request") | .parameters.required_approving_review_count) = 1'
pull 1 "$cargo_ref" "$(message dirs:7.0.0:major)" Cargo.toml Cargo.lock
review 1 owner APPROVED OWNER
checks 1
open_pulls 1
"$subject" reconcile > /dev/null || fail "one required approval: reconcile failed"
expect_writes "one required approval is met by an approving review" "$(merge_call 1)"

# Metadata that changes while the head stays fixed.

new_case
eligible_pull 1
checks 1
open_pulls 1
jq '.base.ref = "release"' "$(fixture_path "$api/pulls/1")" > "$(fixture_path "$api/pulls/1").again"
"$subject" reconcile > /dev/null || fail "retargeted base: reconcile failed"
expect_writes "no merge when the base is retargeted during evaluation" ""

new_case
eligible_pull 1
checks 1
open_pulls 1
files_json "" Cargo.lock | jq '.[0].patch = "@@ -1 +1 @@\n-old\n+other"' \
  > "$(fixture_path "$api/pulls/1/files?per_page=100").again"
"$subject" reconcile > /dev/null || fail "changed files: reconcile failed"
expect_writes "no merge when the changed files move during evaluation" ""

new_case
eligible_pull 1
checks 1
open_pulls 1
main_ref "$(sha_for main-moved)"
mv "$(fixture_path "$api/git/ref/heads/main")" "$(fixture_path "$api/git/ref/heads/main").again"
main_ref "$main_sha"
"$subject" reconcile > /dev/null || fail "moved main: reconcile failed"
expect_writes "no merge when main moves during evaluation" ""

# Integration evidence: the head must contain the current main commit.

refresh_message=$'chore(deps): merge main into dependency update\n\nDependency-Repair: refresh\n[dependabot skip]'

# refresh_result <number> [verified] [author] [committer] [first parent] [branch]
refresh_result() {
  echo '{}' | fixture "POST $api/git/refs"
  jq -n --arg sha "$(sha_for refreshed)" '{sha: $sha}' | fixture "POST $api/merges"
  jq -n --argjson verified "${2:-true}" --arg author "${3:-$repair_bot}" \
    --arg committer "${4:-web-flow}" --arg head "${5:-$(sha_for "$1")}" --arg main "$main_sha" '{
      author: {login: $author}, committer: {login: $committer},
      commit: {verification: {verified: $verified}},
      parents: [{sha: $head}, {sha: $main}]
    }' | fixture "$api/commits/$(sha_for refreshed)"
  echo '{}' | fixture "PATCH $api/git/refs/heads/${6:-$cargo_ref}"
  : | fixture "DELETE $api/git/refs/heads/dependency-refresh/SCRATCH"
}

scratch_created="api POST $api/git/refs"
scratch_merged="api POST $api/merges"
scratch_removed="api DELETE $api/git/refs/heads/dependency-refresh/SCRATCH"

# refresh_calls [branch]: the write requests of one completed refresh.
refresh_calls() {
  printf '%s\n%s\napi PATCH %s/git/refs/heads/%s\n%s' \
    "$scratch_created" "$scratch_merged" "$api" "${1:-$cargo_ref}" "$scratch_removed"
}

# The write requests of a refresh that stopped after the merge.
refresh_abandoned=$(printf '%s\n%s\n%s' "$scratch_created" "$scratch_merged" "$scratch_removed")

# Succeeds when no request advanced or removed a pull request branch.
branches_unchanged() {
  ! grep -qE '^api (PATCH|PUT|DELETE) .*/git/refs/heads/dependabot/' "$FIXTURES/writes"
}

new_case
P_CONTAINS=diverged eligible_pull 1
checks 1
refresh_result 1
open_pulls 1
GITHUB_RUN_ID=4242 "$subject" reconcile > /dev/null || fail "stale head: reconcile failed"
expect_writes "a green head without the main commit is refreshed, not merged" "$(refresh_calls)"
if jq -s -e --arg head "$(sha_for 1)" --arg main "$main_sha" --arg message "$refresh_message" \
    --arg commit "$(sha_for refreshed)" '
      (.[0].ref | ltrimstr("refs/heads/")) as $scratch
      | ($scratch | test("^dependency-refresh/1-4242-[0-9a-f]{16}$"))
        and . == [
          {ref: ("refs/heads/" + $scratch), sha: $head},
          {base: $scratch, head: $main, commit_message: $message},
          {sha: $commit, force: false}
        ]' "$FIXTURES/bodies" > /dev/null; then
  pass
else
  fail "the refresh merges the exact main commit on a scratch branch at the head, then fast-forwards"
fi
if [ "dependency-refresh/$(cat "$FIXTURES/scratch-DELETE")" = "$(jq -r '.ref | ltrimstr("refs/heads/")' "$FIXTURES/bodies" | head -n 1)" ]; then
  pass
else
  fail "the refresh removes exactly the scratch branch that it created"
fi

new_case
P_CONTAINS=behind pull 1 "$actions_ref" "$(message actions/checkout:7.0.2:patch)" .github/workflows/ci.yml
checks 1
refresh_result 1 true "$repair_bot" web-flow "$(sha_for 1)" "$actions_ref"
open_pulls 1
"$subject" reconcile > /dev/null || fail "stale workflow update: reconcile failed"
expect_writes "a stale workflow update is refreshed" "$(refresh_calls "$actions_ref")"

new_case
P_CONTAINS=diverged eligible_pull 1
checks 1 "Test & Lint=failure"
refresh_result 1
open_pulls 1
"$subject" reconcile > /dev/null || fail "stale failing head: reconcile failed"
expect_writes "a failing head without the main commit is refreshed before anything else" "$(refresh_calls)"

new_case
P_CONTAINS=diverged eligible_pull 1
checks 1
P_CONTAINS=diverged eligible_pull 2
checks 2
refresh_result 1
open_pulls 1 2
"$subject" reconcile > /dev/null || fail "two stale heads: reconcile failed"
expect_writes "one branch is refreshed per run" "$(refresh_calls)"

new_case
P_CONTAINS=diverged eligible_pull 1
checks 1
eligible_pull 2
checks 2
refresh_result 1
open_pulls 1 2
"$subject" reconcile > /dev/null || fail "stale and current heads: reconcile failed"
expect_writes "a current green head still merges after a refresh" \
  "$(printf '%s\n%s' "$(refresh_calls)" "$(merge_call 2)")"

for ref in "$cargo_ref" "$actions_ref"; do
  new_case
  if [ "$ref" = "$cargo_ref" ]; then
    P_CONTAINS=diverged P_MERGEABLE=dirty eligible_pull 1
  else
    P_CONTAINS=diverged P_MERGEABLE=dirty pull 1 "$ref" "$(message actions/checkout:7.0.2:patch)" .github/workflows/ci.yml
  fi
  checks 1
  open_pulls 1
  "$subject" reconcile > /dev/null || fail "conflicting head: reconcile failed"
  expect_writes "a conflicting branch on $ref is neither refreshed nor merged" ""
done

new_case
P_CONTAINS=diverged pull 1 "$cargo_ref" "$(message dirs:7.0.0:major)" Cargo.toml Cargo.lock
checks 1
open_pulls 1
"$subject" reconcile > /dev/null || fail "stale unapproved major: reconcile failed"
expect_writes "an update that awaits review is not refreshed" ""

new_case
P_CONTAINS=diverged eligible_pull 1
checks 1
open_pulls 1
touch "$FIXTURES/refuse-writes"
expect_status "a refused refresh fails the run" fail "$subject" reconcile
expect_writes "a refresh whose scratch branch was refused writes nothing else" "$scratch_created"

# A name that is taken refuses the creation. The existing branch is neither
# merged into nor removed.
new_case
P_CONTAINS=diverged eligible_pull 1
checks 1
refresh_result 1
rm "$(fixture_path "POST $api/git/refs")"
open_pulls 1
expect_status "a scratch branch name that is taken fails the run" fail "$subject" reconcile
expect_writes "a scratch branch that this run did not create is never merged into or removed" "$scratch_created"

new_case
P_CONTAINS=diverged eligible_pull 1
checks 1
refresh_result 1
jq -n '{ref: "refs/heads/dependency-refresh/another"}' | fixture "POST $api/git/refs"
open_pulls 1
expect_status "a scratch branch reported under another name fails the run" fail "$subject" reconcile
expect_writes "a scratch branch reported under another name is not merged into" \
  "$(printf '%s\n%s' "$scratch_created" "$scratch_removed")"
if [ "refs/heads/dependency-refresh/$(cat "$FIXTURES/scratch-DELETE")" = "$(jq -r '.ref' "$FIXTURES/bodies")" ]; then
  pass
else
  fail "only the requested scratch branch name is removed"
fi

new_case
P_CONTAINS=diverged eligible_pull 1
checks 1
refresh_result 1
rm "$(fixture_path "POST $api/merges")"
open_pulls 1
expect_status "a refused merge on the scratch branch fails the run" fail "$subject" reconcile
expect_writes "a refused merge leaves the pull request branch unchanged" "$refresh_abandoned"

for fault in "false $repair_bot web-flow" "true contributor web-flow" "true $repair_bot contributor" \
  "true $repair_bot web-flow $(sha_for elsewhere)"; do
  new_case
  P_CONTAINS=diverged eligible_pull 1
  checks 1
  read -r -a fields <<< "$fault"
  refresh_result 1 "${fields[@]}"
  open_pulls 1
  expect_status "a refresh commit that is not a verified repair [$fault] fails the run" fail "$subject" reconcile
  expect_writes "a refresh commit that is not a verified repair [$fault] never reaches the pull request branch" \
    "$refresh_abandoned"
  if branches_unchanged; then
    pass
  else
    fail "no write to the pull request branch when the refresh commit fails the predicate [$fault]"
  fi
done

new_case
P_CONTAINS=diverged eligible_pull 1
checks 1
refresh_result 1
rm "$(fixture_path "$api/commits/$(sha_for refreshed)")"
open_pulls 1
expect_status "an unreadable refresh commit fails the run" fail "$subject" reconcile
expect_writes "an unreadable refresh commit never reaches the pull request branch" "$refresh_abandoned"

new_case
P_CONTAINS=diverged eligible_pull 1
checks 1
echo '' | fixture "POST $api/merges"
echo '{}' | fixture "POST $api/git/refs"
: | fixture "DELETE $api/git/refs/heads/dependency-refresh/SCRATCH"
open_pulls 1
expect_status "a refresh that finds nothing to merge is not an error" ok "$subject" reconcile
expect_writes "a refresh that finds nothing to merge leaves the pull request branch unchanged" "$refresh_abandoned"

# The pull request moves while the merge is computed.
for moved in '.head.sha = "0000000000000000000000000000000000000000"' '.state = "closed"' \
  '.head.ref = "dependabot/cargo/another"'; do
  new_case
  P_CONTAINS=diverged eligible_pull 1
  checks 1
  refresh_result 1
  jq "$moved" "$(fixture_path "$api/pulls/1")" > "$(fixture_path "$api/pulls/1").again"
  open_pulls 1
  expect_status "a pull request that changed during the refresh is not an error [$moved]" ok "$subject" reconcile
  expect_writes "a pull request that changed during the refresh keeps its branch [$moved]" "$refresh_abandoned"
done

new_case
P_CONTAINS=diverged eligible_pull 1
checks 1
refresh_result 1
rm "$(fixture_path "PATCH $api/git/refs/heads/$cargo_ref")"
open_pulls 1
expect_status "a branch that refuses the fast-forward fails the run" fail "$subject" reconcile
expect_writes "a refused fast-forward is not forced and the scratch branch is removed" "$(refresh_calls)"
if jq -s -e 'all(.[]; .force != true)' "$FIXTURES/bodies" > /dev/null; then
  pass
else
  fail "no refresh request forces a ref"
fi

# An outcome that did not advance a branch does not use the one refresh of the
# run: the next stale branch is tried.
new_case
P_CONTAINS=diverged eligible_pull 1
checks 1
P_CONTAINS=diverged pull 2 "$fuzz_ref" "$(message serde_json:1.0.151:patch)" fuzz/Cargo.lock
checks 2
refresh_result 2 true "$repair_bot" web-flow "$(sha_for 2)" "$fuzz_ref"
open_pulls 1 2
expect_status "a refresh that failed its predicate still fails the run when a later one succeeds" fail "$subject" reconcile
expect_writes "the next stale branch is refreshed after the first refresh failed its predicate" \
  "$(printf '%s\n%s' "$refresh_abandoned" "$(refresh_calls "$fuzz_ref")")"
if [ "$(sort -u "$FIXTURES/scratch-DELETE" | wc -l)" -eq 2 ] \
    && [ "$(jq -r 'select(.ref) | .ref | ltrimstr("refs/heads/dependency-refresh/")' "$FIXTURES/bodies")" = "$(cat "$FIXTURES/scratch-DELETE")" ] \
    && [ "$(jq -c 'select(.force != null)' "$FIXTURES/bodies")" = "{\"sha\":\"$(sha_for refreshed)\",\"force\":false}" ]; then
  pass
else
  fail "each refresh uses and removes its own scratch branch and only the verified commit is published"
fi

new_case
P_CONTAINS=diverged eligible_pull 1
checks 1
P_CONTAINS=diverged pull 2 "$fuzz_ref" "$(message serde_json:1.0.151:patch)" fuzz/Cargo.lock
checks 2
refresh_result 2 true "$repair_bot" web-flow "$(sha_for 2)" "$fuzz_ref"
jq '.head.sha = "0000000000000000000000000000000000000000"' "$(fixture_path "$api/pulls/1")" \
  > "$(fixture_path "$api/pulls/1").again"
jq -n --arg head "$(sha_for 1)" --arg main "$main_sha" --arg bot "$repair_bot" '{
    author: {login: $bot}, committer: {login: "web-flow"},
    commit: {verification: {verified: true}}, parents: [{sha: $head}, {sha: $main}]
  }' | fixture "$api/commits/$(sha_for refreshed)"
jq -n --arg head "$(sha_for 2)" --arg main "$main_sha" --arg bot "$repair_bot" '{
    author: {login: $bot}, committer: {login: "web-flow"},
    commit: {verification: {verified: true}}, parents: [{sha: $head}, {sha: $main}]
  }' > "$(fixture_path "$api/commits/$(sha_for refreshed)").again"
open_pulls 1 2
expect_status "a pull request that moved does not use the refresh of the run" ok "$subject" reconcile
expect_writes "the next stale branch is refreshed after the first pull request moved" \
  "$(printf '%s\n%s' "$refresh_abandoned" "$(refresh_calls "$fuzz_ref")")"

new_case
P_CONTAINS=diverged eligible_pull 1
checks 1
P_CONTAINS=diverged pull 2 "$fuzz_ref" "$(message serde_json:1.0.151:patch)" fuzz/Cargo.lock
checks 2
refresh_result 1
open_pulls 1 2
rm "$(fixture_path "POST $api/git/refs")"
expect_status "refused scratch branches fail the run" fail "$subject" reconcile
expect_writes "every stale branch is tried when no refresh advanced one" \
  "$(printf '%s\n%s' "$scratch_created" "$scratch_created")"

# A scratch branch that cannot be removed is reported by name and left alone.
new_case
P_CONTAINS=diverged eligible_pull 1
checks 1
P_CONTAINS=diverged pull 2 "$fuzz_ref" "$(message serde_json:1.0.151:patch)" fuzz/Cargo.lock
checks 2
refresh_result 1
rm "$(fixture_path "DELETE $api/git/refs/heads/dependency-refresh/SCRATCH")"
open_pulls 1 2
expect_status "a scratch branch that cannot be removed fails the run" fail "$subject" reconcile
expect_writes "a completed refresh uses the refresh of the run even when its scratch branch remains" "$(refresh_calls)"
if grep -qF "error, the scratch branch dependency-refresh/$(cat "$FIXTURES/scratch-DELETE") could not be removed and is left in place" "$tmp/output" \
    && [ "$(wc -l < "$FIXTURES/scratch-DELETE")" -eq 1 ]; then
  pass
else
  fail "a scratch branch that cannot be removed is reported by name and its removal is tried once"
fi

new_case
P_CONTAINS=diverged eligible_pull 1
checks 1
refresh_result 1 false
rm "$(fixture_path "DELETE $api/git/refs/heads/dependency-refresh/SCRATCH")"
open_pulls 1
expect_status "a failed predicate with a scratch branch that cannot be removed fails the run" fail "$subject" reconcile
if grep -qF "the branch is unchanged" "$tmp/output" \
    && grep -qF "dependency-refresh/$(cat "$FIXTURES/scratch-DELETE") could not be removed and is left in place" "$tmp/output" \
    && branches_unchanged && [ "$(wc -l < "$FIXTURES/scratch-DELETE")" -eq 1 ]; then
  pass
else
  fail "a remaining scratch branch of a failed refresh is reported and the pull request branch is unchanged"
fi

# Two runs at once each use a branch of their own.
new_case
P_CONTAINS=diverged eligible_pull 1
checks 1
refresh_result 1
open_pulls 1
"$subject" reconcile > /dev/null 2>&1 &
first=$!
"$subject" reconcile > /dev/null 2>&1 &
second=$!
wait "$first" || fail "concurrent refresh: the first run failed"
wait "$second" || fail "concurrent refresh: the second run failed"
if [ "$(sort -u "$FIXTURES/scratch-DELETE" | wc -l)" -eq 2 ] \
    && [ "$(sort "$FIXTURES/scratch-DELETE")" = "$(jq -r 'select(.ref) | .ref | ltrimstr("refs/heads/dependency-refresh/")' "$FIXTURES/bodies" | sort)" ]; then
  pass
else
  fail "concurrent runs create and remove distinct scratch branches"
fi

new_case
eligible_pull 1
checks 1
rm "$(fixture_path "$api/compare/$main_sha...$(sha_for 1)")"
open_pulls 1
"$subject" reconcile > /dev/null 2>&1 || true
if grep -q '^pr merge' "$FIXTURES/writes"; then
  fail "an unreadable comparison with main allowed a merge"
else
  pass
fi

new_case
main_ref "not-a-commit"
eligible_pull 1
checks 1
open_pulls 1
if "$subject" reconcile > /dev/null 2>&1; then
  fail "unreadable main: reconcile succeeded"
fi
expect_writes "no merge when the main head is unreadable" ""

# --- Repair planning ---------------------------------------------------------

plan() {
  "$subject" repair-plan "$FIXTURES/plan" > /dev/null 2>&1 || true
  jq -c "${1:-.}" "$FIXTURES/plan/plan.json" 2> /dev/null || echo unreadable
}

expect_plan() {
  local name="$1" filter="$2" expected="$3" actual
  actual=$(plan "$filter")
  if [ "$actual" != "$expected" ]; then
    fail "$name: expected $expected, got $actual"
  elif [ -s "$FIXTURES/writes" ]; then
    fail "$name: planning made a write request"
  else
    pass
  fi
}

# record_name <number> <merge> [failed context]...: the record name of the plan
# for a pull request whose Dependabot commit is its head.
record_name() {
  local number="$1" merge="$2" failed=""
  shift 2
  [ "$#" -eq 0 ] || failed=$(required_contexts | grep -xFf <(printf '%s\n' "$@"))
  printf 'repair-attempt-%s-%s' "$number" \
    "$(printf '%s\n' "$(sha_for "$number")" "$main_sha" "$merge" "$failed" | sha256sum | cut -d ' ' -f 1)"
}

# contains <number> <status> [merge] [failed context]...: whether the head
# contains the main commit, and the plan whose record is looked up (default:
# no merge, "Test & Lint" failed; "-" for no failed check). No record exists
# unless ATTEMPTS says otherwise.
contains() {
  local number="$1" status="$2" merge="${3:-false}"
  shift 2
  [ "$#" -eq 0 ] || shift
  [ "$#" -gt 0 ] || set -- "Test & Lint"
  [ "$1" != "-" ] || set --
  jq -n --arg status "$status" '{status: $status}' \
    | fixture "$api/compare/$main_sha...$(sha_for "$number")"
  jq -n "{artifacts: ${ATTEMPTS:-[]}}" \
    | fixture "$api/actions/artifacts?name=$(record_name "$number" "$merge" "$@")&per_page=100"
}

new_case
eligible_pull 1
checks 1 "Security Audit (CVEs)=failure" "License & Dependency Policy=failure"
contains 1 ahead false "Security Audit (CVEs)" "License & Dependency Policy"
open_pulls 1
printf '2026-10-08T00:00:00.0000000Z error: 1 vulnerability found!\n' \
  | fixture "$api/actions/jobs/$(check_id_for "Security Audit (CVEs)")/logs"
expect_plan "failing checks on a current branch plan a repair without a merge" \
  '[.repair, .number, .merge, .manifest, .updates[0].name, .updates[0].version, .attempt]' \
  "[true,1,false,\"Cargo.toml\",\"clap\",\"4.6.7\",\"$(record_name 1 false "Security Audit (CVEs)" "License & Dependency Policy")\"]"
if grep -q '^## Security Audit (CVEs)$' "$FIXTURES/plan/context.md" \
    && grep -q '^error: 1 vulnerability found!$' "$FIXTURES/plan/context.md"; then
  pass
else
  fail "the repair context names the failing check and the end of its log"
fi

new_case
eligible_pull 1
checks 1 "Test & Lint=failure"
ATTEMPTS='[{expired: false}]' contains 1 ahead
open_pulls 1
expect_plan "a recorded repair is not generated again for the same update, main commit, and failing checks" '.repair' false

new_case
eligible_pull 1
checks 1 "Test & Lint=failure" "Security Audit (CVEs)=failure"
ATTEMPTS='[{expired: false}]' contains 1 ahead
contains 1 ahead false "Test & Lint" "Security Audit (CVEs)"
open_pulls 1
expect_plan "a different set of failing checks is repaired again" '.repair' true

new_case
eligible_pull 1
checks 1 "Test & Lint=failure"
contains 1 ahead
job_attempt 1 failure
open_pulls 1
expect_plan "a failure that no rerun reproduced is not repaired" '.repair' false

new_case
eligible_pull 1
checks 1 "Test & Lint=cancelled"
contains 1 ahead
job_attempt 2 cancelled
open_pulls 1
expect_plan "cancelled checks alone are not repaired" '.repair' false

# A failure is reproduced when the same job failed in the attempt before.
for previous in failure timed_out; do
  new_case
  eligible_pull 1
  checks 1 "Test & Lint=failure"
  contains 1 ahead
  job_attempt 2 failure "$previous"
  open_pulls 1
  expect_plan "a job that ended as [$previous] and then failed again is repaired" '.repair' true
done

new_case
eligible_pull 1
checks 1 "Test & Lint=failure"
contains 1 ahead
job_attempt 3 failure
open_pulls 1
expect_plan "a failure reproduced on a later attempt is repaired" '.repair' true

for previous in cancelled success skipped absent unreadable; do
  new_case
  eligible_pull 1
  checks 1 "Test & Lint=failure"
  contains 1 ahead
  job_attempt 2 failure "$previous"
  open_pulls 1
  expect_plan "a first failure on a rerun is not repaired when the attempt before was [$previous]" '.repair' false
done

new_case
eligible_pull 1
checks 1 "Test & Lint=failure"
contains 1 ahead
job_id=$(check_id_for "Test & Lint")
jobs_fixture=$(jq '.jobs[0].name = "Another job"' \
  "$(fixture_path "$api/actions/runs/$((500 + job_id))/attempts/1/jobs?per_page=100")")
fixture "$api/actions/runs/$((500 + job_id))/attempts/1/jobs?per_page=100" <<< "$jobs_fixture"
open_pulls 1
expect_plan "a job that fails for the first time beside an earlier failure of another job is not repaired" '.repair' false

new_case
eligible_pull 1
checks 1 "Test & Lint=failure"
contains 1 ahead
rm "$(fixture_path "$api/actions/jobs/$(check_id_for "Test & Lint")")"
open_pulls 1
expect_plan "an unreadable job is not repaired" '.repair' false

new_case
eligible_pull 1
checks 1 "Test & Lint=failure"
contains 1 ahead
job_id=$(check_id_for "Test & Lint")
job_fixture=$(jq '.check_run_url = "https://api.github.com/repos/example/guard/check-runs/999"' \
  "$(fixture_path "$api/actions/jobs/$job_id")")
fixture "$api/actions/jobs/$job_id" <<< "$job_fixture"
open_pulls 1
expect_plan "a check run with no matching Actions job is not repaired" '.repair' false

new_case
eligible_pull 1
checks 1 "Test & Lint=failure"
contains 1 ahead
job_id=$(check_id_for "Test & Lint")
rm "$(fixture_path "$api/actions/runs/$((500 + job_id))")"
open_pulls 1
expect_plan "an unreadable workflow run is not repaired" '.repair' false

new_case
eligible_pull 1
checks 1 "Test & Lint=failure"
contains 1 ahead
job_id=$(check_id_for "Test & Lint")
run_fixture=$(jq 'del(.run_attempt)' "$(fixture_path "$api/actions/runs/$((500 + job_id))")")
fixture "$api/actions/runs/$((500 + job_id))" <<< "$run_fixture"
open_pulls 1
expect_plan "a missing workflow-run attempt is not repaired" '.repair' false

new_case
eligible_pull 1
checks 1 "Test & Lint=failure"
contains 1 ahead
job_id=$(check_id_for "Test & Lint")
jobs_fixture=$(jq '.jobs[0].id = 999' \
  "$(fixture_path "$api/actions/runs/$((500 + job_id))/attempts/2/jobs?per_page=100")")
fixture "$api/actions/runs/$((500 + job_id))/attempts/2/jobs?per_page=100" <<< "$jobs_fixture"
open_pulls 1
expect_plan "a job mismatched to the rerun attempt is not repaired" '.repair' false

new_case
eligible_pull 1
checks 1 "Test & Lint=failure"
ATTEMPTS='[{expired: true}]' contains 1 ahead
open_pulls 1
expect_plan "an expired record allows the repair again" '.repair' true

new_case
eligible_pull 1
checks 1 "Test & Lint=failure"
contains 1 ahead
rm "$(fixture_path "$api/actions/artifacts?name=$(record_name 1 false "Test & Lint")&per_page=100")"
open_pulls 1
expect_plan "unreadable attempt records stop the repair" '.repair' false

new_case
eligible_pull 1
checks 1 "Test & Lint=failure"
contains 1 diverged true
open_pulls 1
expect_plan "failing checks on a stale branch plan a merge" '[.repair, .merge, .main_sha]' \
  "[true,true,\"$main_sha\"]"

new_case
P_MERGEABLE=dirty eligible_pull 1
checks 1
contains 1 diverged true -
open_pulls 1
expect_plan "a conflicting branch plans a merge" '[.repair, .merge]' '[true,true]'

new_case
pull 1 "$fuzz_ref" "$(message serde_json:1.0.151:patch)" fuzz/Cargo.lock
checks 1 "Test & Lint=failure"
contains 1 ahead
open_pulls 1
expect_plan "a fuzz update is repaired through its own manifest" '[.repair, .manifest]' \
  '[true,"fuzz/Cargo.toml"]'

new_case
pull 1 "$cargo_ref" "$(message dirs:7.0.0:major)" Cargo.toml Cargo.lock
checks 1 "Test & Lint=failure" "Classify dependency update=failure"
contains 1 ahead
open_pulls 1
expect_plan "a failing major update is repaired but still needs review" '.repair' true

new_case
pull 1 "$cargo_ref" "$(message dirs:7.0.0:major)" Cargo.toml Cargo.lock
checks 1 "Classify dependency update=failure"
contains 1 ahead
open_pulls 1
expect_plan "a failing gate alone is not repaired" '.repair' false

new_case
eligible_pull 1
checks 1
contains 1 diverged
open_pulls 1
expect_plan "a green update is not repaired" '.repair' false

new_case
eligible_pull 1
checks 1 "Test & Lint=failure" "CodeQL (rust)=pending"
contains 1 ahead
open_pulls 1
expect_plan "an update with running checks is not repaired" '.repair' false

new_case
pull 1 "$actions_ref" "$(message actions/checkout:7.0.2:patch)" .github/workflows/ci.yml
checks 1 "CodeQL (actions)=failure"
contains 1 diverged
open_pulls 1
expect_plan "a workflow update is not repaired" '.repair' false

new_case
P_USER=contributor P_TYPE=User pull 1 "$cargo_ref" "$(message clap:4.6.7:patch)" Cargo.lock
checks 1 "Test & Lint=failure"
contains 1 ahead
open_pulls 1
expect_plan "an unrecognized pull request is not repaired" '.repair' false

new_case
P_REPAIRS="update update update update" eligible_pull 1
checks 1 "Test & Lint=failure"
contains 1 ahead
jq -n '{artifacts: []}' | fixture "$api/actions/artifacts?name=repair-attempt-1-$(printf '%s\n' \
  "$(sha_for 1-first)" "$main_sha" false "Test & Lint" | sha256sum | cut -d ' ' -f 1)&per_page=100"
open_pulls 1
expect_plan "earlier repairs do not stop a repair for a new failure record" '.repair' true

# --- Repair publication ------------------------------------------------------

# candidate <number> <merge> <file>...
candidate() {
  local number="$1" merge="$2" file
  shift 2
  CANDIDATE="$FIXTURES/candidate"
  mkdir -p "$CANDIDATE/files"
  jq -n --argjson number "$number" --arg head "$(sha_for "$number")" --arg main "$main_sha" \
    --argjson merge "$merge" '{number: $number, head_sha: $head, main_sha: $main, merge: $merge}' \
    > "$CANDIDATE/manifest.json"
  for file in "$@"; do
    mkdir -p "$CANDIDATE/files/$(dirname "$file")"
    printf 'source = "registry+https://github.com/rust-lang/crates.io-index"\n' > "$CANDIDATE/files/$file"
  done
}

# Fixtures for the Git database requests of one publication.
git_database() {
  local number="$1" verified="${2:-true}" author="${3:-$repair_bot}" committer="${4:-web-flow}"
  jq -n '{tree: {sha: "head-tree"}}' | fixture "$api/git/commits/$(sha_for "$number")"
  jq -n '{tree: {sha: "main-tree"}}' | fixture "$api/git/commits/$main_sha"
  for tree in head-tree main-tree; do
    jq -n '{truncated: false, tree: [
      {path: "Cargo.lock", type: "blob", mode: "100644"},
      {path: "Cargo.toml", type: "blob", mode: "100644"},
      {path: "src/main.rs", type: "blob", mode: "100644"},
      {path: "src/run.rs", type: "blob", mode: "100755"}
    ]}' | fixture "$api/git/trees/$tree?recursive=1"
  done
  jq -n '{status: "identical"}' | fixture "$api/compare/$main_sha...main"
  jq -n '{sha: "new-blob"}' | fixture "POST $api/git/blobs"
  jq -n '{sha: "new-tree"}' | fixture "POST $api/git/trees"
  jq -n --arg sha "$(sha_for repaired)" '{sha: $sha}' | fixture "POST $api/git/commits"
  jq -n --arg author "$author" --argjson verified "$verified" --arg committer "$committer" \
    --arg head "${REPAIR_PARENT:-$(sha_for "$number")}" --arg main "$main_sha" --argjson merge "${REPAIR_MERGE:-false}" '{
      author: {login: $author}, committer: {login: $committer},
      commit: {verification: {verified: $verified}},
      parents: ([{sha: $head}] + (if $merge then [{sha: $main}] else [] end))
    }' | fixture "$api/commits/$(sha_for repaired)"
  echo '{}' | fixture "PATCH $api/git/refs/heads/$cargo_ref"
}

publication="api POST $api/git/blobs
api POST $api/git/trees
api POST $api/git/commits
api PATCH $api/git/refs/heads/$cargo_ref"

new_case
eligible_pull 1
git_database 1
candidate 1 false Cargo.lock
expect_status "a lockfile repair is published" ok "$subject" publish-repair "$CANDIDATE"
expect_writes "publication creates a blob, a tree, a commit, then advances the branch" "$publication"
if jq -s -e --arg head "$(sha_for 1)" --arg commit "$(sha_for repaired)" '
    (.[0] | .encoding == "base64" and (.content | @base64d | startswith("source = ")))
    and (.[1] == {base_tree: "head-tree", tree: [{path: "Cargo.lock", mode: "100644", type: "blob", sha: "new-blob"}]})
    and (.[2] | .tree == "new-tree" and .parents == [$head]
          and (has("author") or has("committer") or has("signature") | not))
    and (.[3] == {sha: $commit, force: false})' "$FIXTURES/bodies" > /dev/null; then
  pass
else
  fail "publication sends the repaired file, no author, and a fast-forward"
fi

new_case
eligible_pull 1
REPAIR_MERGE=true git_database 1
candidate 1 true Cargo.lock
expect_status "a merge repair is published" ok "$subject" publish-repair "$CANDIDATE"
if jq -s -e --arg head "$(sha_for 1)" --arg main "$main_sha" \
    '.[1].base_tree == "main-tree" and .[2].parents == [$head, $main]' "$FIXTURES/bodies" > /dev/null; then
  pass
else
  fail "a merge repair builds on the main tree with the head as first parent"
fi

new_case
eligible_pull 1
git_database 1
jq -n '{status: "diverged"}' | fixture "$api/compare/$main_sha...main"
candidate 1 true Cargo.lock
status=0
"$subject" publish-repair "$CANDIDATE" > /dev/null 2>&1 || status=$?
if [ "$status" -eq 1 ]; then
  pass
else
  fail "a refused merge is an error, not a repair without progress: status $status"
fi
expect_writes "no write for a merge of a commit outside main" ""

new_case
eligible_pull 1
git_database 1 false
candidate 1 false Cargo.lock
expect_status "an unsigned repair commit fails publication" fail "$subject" publish-repair "$CANDIDATE"
expect_writes "an unsigned repair commit never reaches the branch" \
  "$(head -n 3 <<< "$publication")"

new_case
eligible_pull 1
git_database 1 true contributor
candidate 1 false Cargo.lock
expect_status "a repair commit by another author fails publication" fail "$subject" publish-repair "$CANDIDATE"
expect_writes "a repair commit by another author never reaches the branch" \
  "$(head -n 3 <<< "$publication")"

for fault in "committer:1 true $repair_bot contributor" "parent:1 true $repair_bot web-flow"; do
  new_case
  eligible_pull 1
  read -r -a fields <<< "${fault#*:}"
  if [ "${fault%%:*}" = "parent" ]; then
    REPAIR_PARENT=$(sha_for elsewhere) git_database "${fields[@]}"
  else
    git_database "${fields[@]}"
  fi
  candidate 1 false Cargo.lock
  expect_status "a repair commit with another ${fault%%:*} fails publication" fail "$subject" publish-repair "$CANDIDATE"
  expect_writes "a repair commit with another ${fault%%:*} never reaches the branch" \
    "$(head -n 3 <<< "$publication")"
done

# expect_dropped <name>: the candidate is dropped with status 4 and no write.
expect_dropped() {
  local status=0
  "$subject" publish-repair "$CANDIDATE" > /dev/null 2>&1 || status=$?
  if [ "$status" -eq 4 ]; then
    pass
  else
    fail "$1: expected status 4, got $status"
  fi
  expect_writes "no write when $1" ""
}

new_case
eligible_pull 1
git_database 1
candidate 1 false Cargo.lock
jq --arg head "$(sha_for stale)" '.head_sha = $head' "$CANDIDATE/manifest.json" > "$CANDIDATE/m" \
  && mv "$CANDIDATE/m" "$CANDIDATE/manifest.json"
expect_dropped "a repair is for a head that moved"

new_case
P_USER=contributor P_TYPE=User pull 1 "$cargo_ref" "$(message clap:4.6.7:patch)" Cargo.lock
git_database 1
candidate 1 false Cargo.lock
expect_dropped "a repair is for an unrecognized pull request"

new_case
pull 1 "$actions_ref" "$(message actions/checkout:7.0.2:patch)" .github/workflows/ci.yml
git_database 1
candidate 1 false Cargo.lock
expect_dropped "a repair is for a workflow update"

for file in README.md build.rs .github/workflows/ci.yml scripts/dependabot-automerge.sh \
  fuzz/Cargo.lock src/main.txt .cargo/config.toml deny.toml; do
  new_case
  eligible_pull 1
  git_database 1
  candidate 1 false "$file"
  expect_status "a repair of $file is refused" fail "$subject" publish-repair "$CANDIDATE"
  expect_writes "no write for a repair of $file" ""
done

new_case
eligible_pull 1
git_database 1
candidate 1 false Cargo.lock src/new.rs
expect_status "a repair that adds a file is refused" fail "$subject" publish-repair "$CANDIDATE"
expect_writes "no branch update for a repair that adds a file" "api POST $api/git/blobs"

new_case
eligible_pull 1
git_database 1
candidate 1 false src/run.rs
expect_status "a repair of an executable file is refused" fail "$subject" publish-repair "$CANDIDATE"
expect_writes "no write for a repair of an executable file" ""

new_case
eligible_pull 1
git_database 1
candidate 1 false Cargo.lock
ln -s /etc/hostname "$CANDIDATE/files/Cargo.toml"
expect_status "a candidate with a symbolic link is refused" fail "$subject" publish-repair "$CANDIDATE"
expect_writes "no write for a candidate with a symbolic link" ""

new_case
eligible_pull 1
git_database 1
candidate 1 false Cargo.lock
printf 'source = "git+https://example.invalid/crate"\n' >> "$CANDIDATE/files/Cargo.lock"
expect_status "a lockfile with a source outside crates.io is refused" fail "$subject" publish-repair "$CANDIDATE"
expect_writes "no write for a lockfile with a source outside crates.io" ""

new_case
eligible_pull 1
git_database 1
candidate 1 false Cargo.toml
printf '<<<<<<< HEAD\n' >> "$CANDIDATE/files/Cargo.toml"
expect_status "a file with a conflict marker is refused" fail "$subject" publish-repair "$CANDIDATE"
expect_writes "no write for a file with a conflict marker" ""

new_case
eligible_pull 1
git_database 1
candidate 1 false Cargo.lock
jq -n '{sha: "head-tree"}' | fixture "POST $api/git/trees"
status=0
"$subject" publish-repair "$CANDIDATE" > /dev/null 2>&1 || status=$?
if [ "$status" -eq 3 ]; then
  pass
else
  fail "a repair without a change reports no progress: status $status"
fi
expect_writes "no commit for a repair without a change" "$(head -n 2 <<< "$publication")"

new_case
P_REPAIRS="update update update update" eligible_pull 1
git_database 1
candidate 1 false Cargo.lock src/main.rs
expect_status "a further source repair on a repaired update is published" ok "$subject" publish-repair "$CANDIDATE"

# --- Workflow runs -----------------------------------------------------------

# runs <workflow> <sha> <branch> <count> [fixture suffix]. RUN_EVENT,
# RUN_STATUS, RUN_CONCLUSION, and RUN_ATTEMPT describe every run.
runs() {
  jq -n --arg sha "$2" --arg branch "$3" --argjson count "$4" --arg event "${RUN_EVENT:-push}" \
    --arg status "${RUN_STATUS:-completed}" --arg conclusion "${RUN_CONCLUSION:-success}" \
    --argjson attempt "${RUN_ATTEMPT:-1}" '{
      workflow_runs: [range(0; $count) | {
        id: (500 + .), head_sha: $sha, head_branch: $branch, event: $event, status: $status,
        conclusion: (if $status == "completed" then $conclusion else null end),
        run_attempt: $attempt, run_started_at: "2026-01-01T00:00:0\(.)Z"}]
    }' > "$(fixture_path "$api/actions/workflows/$1/runs?head_sha=$2&per_page=100")${5:-}"
}

repaired_pull() {
  P_REPAIRS=update eligible_pull 1
  jq -n --arg tree "${1:-workflows-tree}" '[{name: "workflows", type: "dir", sha: $tree}]' \
    | fixture "$api/contents/.github?ref=$(sha_for 1)"
  open_pulls 1
}

new_case
repaired_pull
for workflow in ci.yml audit.yml dependabot-automerge.yml; do
  runs "$workflow" "$(sha_for 1)" "$cargo_ref" 0
  RUN_EVENT=workflow_dispatch runs "$workflow" "$(sha_for 1)" "$cargo_ref" 1 .dispatched
done
expect_status "validation is dispatched for a repaired head" ok "$subject" ensure-validation-runs
expect_writes "a repaired head gets every required workflow by dispatch" \
  "workflow run ci.yml --repo $GITHUB_REPOSITORY --ref $cargo_ref
workflow run audit.yml --repo $GITHUB_REPOSITORY --ref $cargo_ref -f dependency_review_base=$main_sha
workflow run dependabot-automerge.yml --repo $GITHUB_REPOSITORY --ref $cargo_ref -f pull_request=1"

new_case
repaired_pull
for workflow in ci.yml audit.yml dependabot-automerge.yml; do
  runs "$workflow" "$(sha_for 1)" "$cargo_ref" 0
done
expect_status "a dispatch without a run for the head fails" fail "$subject" ensure-validation-runs

new_case
repaired_pull
for workflow in ci.yml audit.yml dependabot-automerge.yml; do
  RUN_EVENT=workflow_dispatch runs "$workflow" "$(sha_for 1)" "$cargo_ref" 1
done
"$subject" ensure-validation-runs > /dev/null || fail "existing validation: command failed"
expect_writes "existing validation runs are not repeated" ""

new_case
repaired_pull
for workflow in ci.yml audit.yml dependabot-automerge.yml; do
  RUN_EVENT=pull_request runs "$workflow" "$(sha_for 1)" "$cargo_ref" 1
  RUN_EVENT=workflow_dispatch runs "$workflow" "$(sha_for 1)" "$cargo_ref" 1 .dispatched
done
"$subject" ensure-validation-runs > /dev/null || fail "approval-gated runs: command failed"
if [ "$(grep -c '^workflow run ' "$FIXTURES/writes")" -eq 3 ]; then
  pass
else
  fail "pull request runs that wait for approval do not count as validation"
fi

new_case
repaired_pull branch-workflows-tree
for workflow in ci.yml audit.yml dependabot-automerge.yml; do
  runs "$workflow" "$(sha_for 1)" "$cargo_ref" 0
done
"$subject" ensure-validation-runs > /dev/null || fail "differing workflows: command failed"
expect_writes "no dispatch when the branch workflows differ from main" ""

# A refreshed workflow update differs from main by its own pinned actions.
refreshed_actions_pull() {
  P_REPAIRS=merge pull 1 "$actions_ref" "$1" .github/workflows/ci.yml
  jq -n '[{name: "workflows", type: "dir", sha: "branch-workflows-tree"}]' \
    | fixture "$api/contents/.github?ref=$(sha_for 1)"
  open_pulls 1
  for workflow in ci.yml audit.yml dependabot-automerge.yml; do
    runs "$workflow" "$(sha_for 1)" "$actions_ref" 0
    RUN_EVENT=workflow_dispatch runs "$workflow" "$(sha_for 1)" "$actions_ref" 1 .dispatched
  done
}

new_case
refreshed_actions_pull "$(message actions/checkout:8:major)"
expect_status "validation is dispatched for a refreshed workflow update" ok "$subject" ensure-validation-runs
if [ "$(grep -c '^workflow run ' "$FIXTURES/writes")" -eq 3 ]; then
  pass
else
  fail "a refreshed, eligible workflow update gets every required workflow by dispatch"
fi

new_case
P_PATCH=$'@@ -1 +1 @@\n-    run: old\n+    run: new' refreshed_actions_pull "$(message actions/checkout:7.0.2:patch)"
"$subject" ensure-validation-runs > /dev/null || fail "ineligible workflow change: command failed"
expect_writes "no dispatch for a workflow change that is not a pinned action" ""

new_case
P_CONTAINS=diverged refreshed_actions_pull "$(message actions/checkout:8:major)"
"$subject" ensure-validation-runs > /dev/null || fail "stale workflow update: command failed"
expect_writes "no dispatch for a workflow update that lacks the main commit" ""

new_case
eligible_pull 1
open_pulls 1
for workflow in ci.yml audit.yml dependabot-automerge.yml; do
  runs "$workflow" "$(sha_for 1)" "$cargo_ref" 0
done
"$subject" ensure-validation-runs > /dev/null || fail "unrepaired: command failed"
expect_writes "no dispatch for a head that Dependabot pushed" ""

# Recovery of runs that did not succeed.

rerun_call() {
  printf 'run rerun 500 --repo %s --failed' "$GITHUB_REPOSITORY"
}

for outcome in "failure 1" "cancelled 1" "cancelled 3" "timed_out 2" "startup_failure 1"; do
  new_case
  eligible_pull 1
  open_pulls 1
  for workflow in ci.yml audit.yml dependabot-automerge.yml; do
    RUN_EVENT=pull_request runs "$workflow" "$(sha_for 1)" "$cargo_ref" 1
  done
  RUN_EVENT=pull_request RUN_CONCLUSION=${outcome% *} RUN_ATTEMPT=${outcome#* } \
    runs ci.yml "$(sha_for 1)" "$cargo_ref" 1
  "$subject" ensure-validation-runs > /dev/null || fail "$outcome: command failed"
  expect_writes "a pull request run that ended as [$outcome] is rerun" "$(rerun_call)"
done

# run_jobs <attempt> <name=conclusion>...: the jobs of one attempt of run 500.
# Every attempt gives a job a new ID.
run_jobs() {
  local attempt="$1"
  shift
  printf '%s\n' "$@" | jq -R 'select(length > 0) | split("=")
      | {name: .[0], conclusion: .[1], status: "completed", run_id: 500}' \
    | jq -s --argjson attempt "$attempt" \
      '{jobs: [to_entries[] | .value + {id: (9000 + $attempt * 100 + .key)}]} | .total_count = (.jobs | length)' \
    | fixture "$api/actions/runs/500/attempts/$attempt/jobs?per_page=100"
}

# failed_runs <attempt>: every validation workflow run failed on that attempt.
failed_runs() {
  eligible_pull 1
  open_pulls 1
  for workflow in ci.yml audit.yml dependabot-automerge.yml; do
    RUN_EVENT=pull_request RUN_CONCLUSION=failure RUN_ATTEMPT="$1" \
      runs "$workflow" "$(sha_for 1)" "$cargo_ref" 1
  done
}

for sequence in "failure" "timed_out"; do
  new_case
  failed_runs 2
  run_jobs 1 "Test & Lint=$sequence" "Build=success"
  run_jobs 2 "Test & Lint=failure" "Build=success"
  "$subject" ensure-validation-runs > /dev/null || fail "$sequence then failure: command failed"
  expect_writes "a job that ended as [$sequence] and failed again on the rerun is a finding" ""
done

new_case
failed_runs 3
run_jobs 2 "Test & Lint=failure"
run_jobs 3 "Test & Lint=timed_out"
"$subject" ensure-validation-runs > /dev/null || fail "reproduced on a later attempt: command failed"
expect_writes "a failure reproduced on a later attempt is a finding" ""

new_case
failed_runs 2
run_jobs 1 "Test & Lint=cancelled" "Build=cancelled"
run_jobs 2 "Test & Lint=failure" "Build=success"
"$subject" ensure-validation-runs > /dev/null || fail "cancelled then failure: command failed"
if [ "$(grep -c '^run rerun 500 ' "$FIXTURES/writes")" -eq 3 ]; then
  pass
else
  fail "a first failure after a cancelled attempt is rerun"
fi

new_case
failed_runs 2
run_jobs 1 "Test & Lint=failure" "Build=success"
run_jobs 2 "Test & Lint=failure" "Build=failure"
"$subject" ensure-validation-runs > /dev/null || fail "newly failing job: command failed"
if [ "$(grep -c '^run rerun 500 ' "$FIXTURES/writes")" -eq 3 ]; then
  pass
else
  fail "a job that fails for the first time on a rerun is rerun"
fi

new_case
failed_runs 2
run_jobs 1
run_jobs 2 "Test & Lint=failure"
"$subject" ensure-validation-runs > /dev/null || fail "job absent before: command failed"
if [ "$(grep -c '^run rerun 500 ' "$FIXTURES/writes")" -eq 3 ]; then
  pass
else
  fail "a failed job that the attempt before did not hold is rerun"
fi

for missing in 1 2; do
  new_case
  failed_runs 2
  run_jobs "$((3 - missing))" "Test & Lint=failure"
  expect_status "unreadable jobs of attempt $missing fail the run" fail "$subject" ensure-validation-runs
  expect_writes "unreadable jobs of attempt $missing request no rerun" ""
done

for outcome in "failure 2" "success 1"; do
  new_case
  eligible_pull 1
  open_pulls 1
  run_jobs 1 "Test & Lint=failure"
  run_jobs 2 "Test & Lint=failure"
  for workflow in ci.yml audit.yml dependabot-automerge.yml; do
    RUN_EVENT=pull_request RUN_CONCLUSION=${outcome% *} RUN_ATTEMPT=${outcome#* } \
      runs "$workflow" "$(sha_for 1)" "$cargo_ref" 1
  done
  "$subject" ensure-validation-runs > /dev/null || fail "$outcome: command failed"
  expect_writes "a run that ended as [$outcome] is left alone" ""
done

new_case
eligible_pull 1
open_pulls 1
for workflow in ci.yml audit.yml dependabot-automerge.yml; do
  RUN_EVENT=pull_request RUN_STATUS=in_progress runs "$workflow" "$(sha_for 1)" "$cargo_ref" 1
done
"$subject" ensure-validation-runs > /dev/null || fail "running: command failed"
expect_writes "a run in progress is left alone" ""

new_case
repaired_pull
for workflow in ci.yml audit.yml dependabot-automerge.yml; do
  RUN_EVENT=workflow_dispatch RUN_CONCLUSION=cancelled runs "$workflow" "$(sha_for 1)" "$cargo_ref" 1
done
"$subject" ensure-validation-runs > /dev/null || fail "cancelled dispatch: command failed"
if [ "$(grep -c '^run rerun 500 ' "$FIXTURES/writes")" -eq 3 ] && ! grep -q '^workflow run ' "$FIXTURES/writes"; then
  pass
else
  fail "a cancelled dispatched run is rerun, not counted as validation and not dispatched twice"
fi

new_case
eligible_pull 1
open_pulls 1
for workflow in ci.yml audit.yml dependabot-automerge.yml; do
  RUN_EVENT=pull_request RUN_CONCLUSION=failure runs "$workflow" "$(sha_for 1)" "$cargo_ref" 1
done
touch "$FIXTURES/refuse-writes"
expect_status "a refused rerun fails the run" fail "$subject" ensure-validation-runs

new_case
RUN_CONCLUSION=cancelled runs ci.yml "$main_sha" main 1
RUN_CONCLUSION=failure RUN_ATTEMPT=2 runs audit.yml "$main_sha" main 1
run_jobs 1 "Security Audit (CVEs)=failure"
run_jobs 2 "Security Audit (CVEs)=failure"
"$subject" ensure-mainline-runs > /dev/null || fail "cancelled mainline: command failed"
expect_writes "a cancelled mainline run is rerun and a reproduced failure is left alone" "$(rerun_call)"

new_case
runs ci.yml "$main_sha" main 1
RUN_CONCLUSION=failure RUN_ATTEMPT=2 runs audit.yml "$main_sha" main 1
run_jobs 1 "Security Audit (CVEs)=cancelled"
run_jobs 2 "Security Audit (CVEs)=failure"
"$subject" ensure-mainline-runs > /dev/null || fail "first mainline failure on a rerun: command failed"
expect_writes "a first mainline failure after a cancelled attempt is rerun" "$(rerun_call)"

new_case
runs ci.yml "$main_sha" main 0
runs audit.yml "$main_sha" main 0
RUN_EVENT=workflow_dispatch runs ci.yml "$main_sha" main 1 .dispatched
RUN_EVENT=workflow_dispatch runs audit.yml "$main_sha" main 1 .dispatched
"$subject" ensure-mainline-runs > /dev/null || fail "missing runs: command failed"
expect_writes "missing mainline runs are dispatched on main" \
  "$(printf 'workflow run ci.yml --repo %s --ref main\nworkflow run audit.yml --repo %s --ref main' \
    "$GITHUB_REPOSITORY" "$GITHUB_REPOSITORY")"

new_case
runs ci.yml "$main_sha" main 0
runs audit.yml "$main_sha" main 1
expect_status "a mainline dispatch without a run for the commit fails" fail "$subject" ensure-mainline-runs

new_case
runs ci.yml "$main_sha" main 1
runs audit.yml "$main_sha" main 2
"$subject" ensure-mainline-runs > /dev/null || fail "existing runs: command failed"
expect_writes "existing mainline runs are not repeated" ""

new_case
runs ci.yml "$main_sha" feature 1
RUN_EVENT=workflow_dispatch runs ci.yml "$main_sha" main 1 .dispatched
runs audit.yml "$main_sha" main 1
"$subject" ensure-mainline-runs > /dev/null || fail "branch run: command failed"
expect_writes "a run on another branch is not mainline evidence" \
  "workflow run ci.yml --repo $GITHUB_REPOSITORY --ref main"

new_case
main_ref "not-a-commit"
if "$subject" ensure-mainline-runs > /dev/null 2>&1; then
  fail "malformed head: command succeeded"
fi
expect_writes "no dispatch when the main head is unreadable" ""

# --- Repair engine -----------------------------------------------------------

# The credential is generated here so that no credential-shaped literal exists
# in the repository.
credential=$(head -c 24 /dev/urandom | base64 | tr -d '/+=')

# Fixture commits are signed with a key made for this run.
ssh-keygen -q -t ed25519 -N '' -C dependency-automation-test -f "$tmp/signing-key"
printf 'test@example.invalid %s\n' "$(cat "$tmp/signing-key.pub")" > "$tmp/allowed-signers"
pinned_opencode=$(sed -n 's/^OPENCODE_VERSION="\(.*\)"$/\1/p' "$engine")

cat > "$tmp/bin/opencode" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
# Records what the model run could see, then performs the scripted edits. The
# run has no inherited environment, so the record is found beside the stub.
AGENT_RECORD="$(dirname "$0")/../agent-record"
[ -z "${MODEL_KEY+set}" ] || touch "$AGENT_RECORD/internal-variable-inherited"
if [ "${1:-}" = "--version" ]; then
  [ -z "${OPENROUTER_API_KEY:-}" ] || touch "$AGENT_RECORD/credential-seen-early"
  cat "$AGENT_RECORD/version"
  exit
fi
compgen -e | LC_ALL=C sort > "$AGENT_RECORD/environment"
printf '%s' "$HOME" > "$AGENT_RECORD/home"
printf '%s' "${TMPDIR:-}" > "$AGENT_RECORD/temporary"
printf '%s' "$XDG_CONFIG_HOME" > "$AGENT_RECORD/state"
printf '%s\n' "$@" > "$AGENT_RECORD/arguments"
printf '%s' "$OPENCODE_CONFIG_CONTENT" > "$AGENT_RECORD/configuration"
[ "${OPENROUTER_API_KEY:-}" = "$(cat "$AGENT_RECORD/credential")" ] && touch "$AGENT_RECORD/credential-seen"
cp .dependency-repair/context.md "$AGENT_RECORD/context"
# shellcheck disable=SC1091
. "$AGENT_RECORD/script"
STUB
cat > "$tmp/bin/cargo" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
# Cargo runs with a reduced environment, so the record is found beside the stub.
CARGO_RECORD="$(dirname "$0")/../cargo-record"
printf '%s\n' "$*" >> "$CARGO_RECORD/calls"
compgen -e | LC_ALL=C sort > "$CARGO_RECORD/environment"
[ -z "${OPENROUTER_API_KEY:-}" ] || touch "$CARGO_RECORD/credential-seen"
case "$*" in
  *"--package"*)
    printf '# %s\n' "$*" >> Cargo.lock
    [ ! -e "$CARGO_RECORD/lock-entry" ] || cat "$CARGO_RECORD/lock-entry" >> Cargo.lock
    ;;
esac
[ ! -e "$CARGO_RECORD/fail" ]
STUB
cat > "$tmp/bin/curl" <<'STUB'
#!/usr/bin/env bash
set -euo pipefail
# Serves the crates.io index entry that the test wrote for the requested path.
CARGO_RECORD="$(dirname "$0")/../cargo-record"
for argument in "$@"; do url="$argument"; done
printf '%s\n' "$url" >> "$CARGO_RECORD/index-requests"
cat "$CARGO_RECORD/index/$(basename "$url")"
STUB
chmod +x "$tmp/bin/opencode" "$tmp/bin/cargo" "$tmp/bin/curl"

registry='source = "registry+https://github.com/rust-lang/crates.io-index"'

# Creates a repository with a main commit, an update commit, and a later main
# commit that conflicts with the update in the lockfile.
new_repository() {
  REPO=$(mktemp -d "$tmp/repo.XXXXXX")
  AGENT_RECORD=$(mktemp -d "$tmp/agent.XXXXXX")
  CARGO_RECORD=$(mktemp -d "$tmp/cargo.XXXXXX")
  OUT=$(mktemp -d "$tmp/out.XXXXXX")
  ln -sfn "$AGENT_RECORD" "$tmp/agent-record"
  ln -sfn "$CARGO_RECORD" "$tmp/cargo-record"
  printf '%s' "$credential" > "$AGENT_RECORD/credential"
  printf '%s\n' "$pinned_opencode" > "$AGENT_RECORD/version"
  : > "$CARGO_RECORD/calls"
  echo ':' > "$AGENT_RECORD/script"
  (
    cd "$REPO"
    git init --quiet --initial-branch main
    git config user.name test
    git config user.email test@example.invalid
    git config gpg.format ssh
    git config user.signingkey "$tmp/signing-key.pub"
    git config gpg.ssh.allowedSignersFile "$tmp/allowed-signers"
    git config commit.gpgsign true
    mkdir -p src fuzz/fuzz_targets .github/workflows
    printf '[package]\nname = "guard"\n' > Cargo.toml
    printf 'name = "clap"\nversion = "4.6.6"\n%s\n' "$registry" > Cargo.lock
    printf 'fn main() {}\n' > src/main.rs
    printf '# guard\n' > README.md
    printf 'name: CI\n' > .github/workflows/ci.yml
    git add -A
    git commit --quiet -m base
    git checkout --quiet -b update
    printf 'name = "clap"\nversion = "4.6.7"\n%s\n' "$registry" > Cargo.lock
    git commit --quiet -am update
    git checkout --quiet main
    printf 'name = "clap"\nversion = "4.6.5"\n%s\n' "$registry" > Cargo.lock
    printf 'fn main() { run() }\n' > src/main.rs
    git commit --quiet -am main
  )
  REPO_HEAD=$(git -C "$REPO" rev-parse update)
  REPO_MAIN=$(git -C "$REPO" rev-parse main)
  repair_plan false
}

# expect_exit <name> <status> <command>...
expect_exit() {
  local name="$1" expected="$2" status=0
  shift 2
  "$@" > "$tmp/output" 2>&1 || status=$?
  if [ "$status" -eq "$expected" ]; then
    pass
  else
    fail "$name: expected status $expected, got $status: $(tail -n 3 "$tmp/output")"
  fi
}

repair_plan() {
  jq -n --arg head "$REPO_HEAD" --arg main "$REPO_MAIN" --argjson merge "$1" \
    --arg manifest "${2:-Cargo.toml}" '{
      repair: true, number: 7, head_sha: $head, main_sha: $main, merge: $merge,
      manifest: $manifest, updates: [{name: "clap", version: "4.6.7"}, {name: "bad name", version: "1"}]
    }' > "$OUT/plan.json"
  printf '# Failing required checks\n\n## Security Audit (CVEs)\n' > "$OUT/context.md"
}

agent() {
  cat > "$AGENT_RECORD/script"
}

generate() {
  OPENROUTER_API_KEY="$credential" "$engine" generate "$REPO" "$OUT/plan.json" "$OUT/context.md" "$OUT/generated"
}

apply() {
  "$engine" apply "$REPO" "$OUT/plan.json" "$OUT/generated" "$OUT/candidate"
}

new_repository
if git -C "$REPO" verify-commit "$REPO_HEAD" > /dev/null 2>&1 && git -C "$REPO" verify-commit "$REPO_MAIN" > /dev/null 2>&1 \
    && [ "$(git -C "$REPO" config --get commit.gpgsign)" = "true" ]; then
  pass
else
  fail "fixture commits are signed and verify against the key made for this run"
fi
"$engine" prepare "$REPO" "$OUT/plan.json"
agent <<'EOF'
echo 'rustls@0.23.42 0.23.45' > .dependency-repair/cargo-update
echo 'fn main() { repaired() }' > src/main.rs
EOF
expect_status "generate accepts a lockfile request and a source edit" ok generate
if [ "$(cat "$OUT/generated/cargo-update")" = "rustls@0.23.42 0.23.45" ] \
    && [ "$(find "$OUT/generated/files" -type f | sed "s|$OUT/generated/files/||")" = "src/main.rs" ] \
    && [ ! -e "$REPO/.dependency-repair" ]; then
  pass
else
  fail "generate collects the request and exactly the edited file"
fi
if [ "$(grep -vxE 'PWD|SHLVL|OLDPWD|_|TMPDIR' "$AGENT_RECORD/environment" | tr '\n' ' ')" = "HOME OPENCODE_CONFIG_CONTENT OPENCODE_DISABLE_AUTOUPDATE OPENCODE_DISABLE_CLAUDE_CODE OPENCODE_DISABLE_EXTERNAL_SKILLS OPENCODE_DISABLE_LSP_DOWNLOAD OPENCODE_DISABLE_PROJECT_CONFIG OPENROUTER_API_KEY PATH TERM XDG_CACHE_HOME XDG_CONFIG_HOME XDG_DATA_HOME XDG_STATE_HOME " ] \
    && [ "$(cat "$AGENT_RECORD/home")" = "$HOME" ] && [ "$(cat "$AGENT_RECORD/state")" != "$HOME/.config" ]; then
  pass
else
  fail "the model run sees only its own environment: $(tr '\n' ' ' < "$AGENT_RECORD/environment")"
fi
if [ -e "$AGENT_RECORD/credential-seen" ] && [ ! -e "$AGENT_RECORD/credential-seen-early" ] \
    && ! grep -qF "$credential" "$AGENT_RECORD/arguments" \
    && grep -qx -- '--pure' "$AGENT_RECORD/arguments" \
    && grep -qx -- 'openrouter/anthropic/claude-sonnet-5.5' "$AGENT_RECORD/arguments"; then
  pass
else
  fail "the credential reaches the model run through the environment only"
fi
if jq -e '
    .permission["*"] == "deny" and .permission.bash == "deny" and .permission.webfetch == "deny"
    and .permission.task == "deny" and .permission.external_directory == "deny"
    and .permission.edit["*"] == "deny" and .permission.edit["Cargo.toml"] == "allow"
    and (.permission.edit | has("Cargo.lock") | not)
    and .lsp == false and .formatter == false and .mcp == {} and .plugin == []
    and .share == "disabled" and .enabled_providers == ["openrouter"]
  ' "$AGENT_RECORD/configuration" > /dev/null; then
  pass
else
  fail "the model configuration denies commands, network tools, servers, and plugins"
fi
if grep -q 'Security Audit (CVEs)' "$AGENT_RECORD/context"; then
  pass
else
  fail "the model run receives the failure context"
fi
if jq -s -e 'map(.action) == ["prepare", "generate", "generate"] and all(.[]; .tool == "dependency-repair")' \
    "$OUT/generated/audit.jsonl" > /dev/null 2>&1 \
    || jq -s -e 'map(.action) == ["generate", "generate"] and all(.[]; .tool == "dependency-repair")' \
    "$OUT/generated/audit.jsonl" > /dev/null 2>&1; then
  pass
else
  fail "generate writes an audit record for each action"
fi
if grep -rqF "$credential" "$OUT"; then
  fail "the credential is written to the output or the audit log"
else
  pass
fi

git -C "$REPO" reset --quiet --hard
echo changed >> "$REPO/README.md"
expect_status "prepare refuses a checkout with local changes" fail "$engine" prepare "$REPO" "$OUT/plan.json"
git -C "$REPO" reset --quiet --hard
expect_status "apply runs the requested lockfile update" ok apply
if [ "$(cat "$CARGO_RECORD/calls")" = "update --quiet --manifest-path Cargo.toml --workspace
update --quiet --manifest-path Cargo.toml --package rustls@0.23.42 --precise 0.23.45
metadata --quiet --locked --manifest-path Cargo.toml --format-version 1" ]; then
  pass
else
  fail "apply runs exactly the validated Cargo operations: $(cat "$CARGO_RECORD/calls")"
fi
if [ "$(cd "$OUT/candidate/files" && find . -type f | LC_ALL=C sort | tr '\n' ' ')" = "./Cargo.lock ./src/main.rs " ] \
    && jq -e --arg head "$REPO_HEAD" '.number == 7 and .head_sha == $head and .merge == false' \
      "$OUT/candidate/manifest.json" > /dev/null; then
  pass
else
  fail "apply writes the candidate files and manifest"
fi
if [ -e "$CARGO_RECORD/credential-seen" ]; then
  fail "Cargo ran with the model credential"
else
  pass
fi
OPENROUTER_API_KEY="$credential" expect_exit "apply refuses to run beside the model credential" 1 apply
git -C "$REPO" reset --quiet --hard
: > "$CARGO_RECORD/calls"
DEPLOY_PROBE="$credential" GH_PROBE="$credential" expect_status "apply runs beside unrelated variables" ok apply
if [ "$(grep -vxE 'PWD|SHLVL|OLDPWD|_|TMPDIR' "$CARGO_RECORD/environment" | tr '\n' ' ')" = "HOME PATH " ]; then
  pass
else
  fail "Cargo sees a reduced environment: $(tr '\n' ' ' < "$CARGO_RECORD/environment")"
fi

# Publication age of versions that the repair locks.

# age_case <publication time>: a repair that locks fresh 1.2.3.
age_case() {
  new_repository
  "$engine" prepare "$REPO" "$OUT/plan.json"
  agent <<< "echo 'fresh' > .dependency-repair/cargo-update"
  generate > /dev/null 2>&1
  git -C "$REPO" reset --quiet --hard
  printf 'name = "fresh"\nversion = "1.2.3"\n%s\n' "$registry" > "$CARGO_RECORD/lock-entry"
  mkdir "$CARGO_RECORD/index"
  jq -cn --arg time "$1" '{name: "fresh", vers: "1.2.2", pubtime: "2020-01-01T00:00:00Z"},
    ({name: "fresh", vers: "1.2.3"} + (if $time == "" then {} else {pubtime: $time} end))' \
    > "$CARGO_RECORD/index/fresh"
}

age_case "$(date -u -d '10 minutes ago' +%Y-%m-%dT%H:%M:%SZ)"
expect_exit "apply refuses a version published within the hour, as an operational failure" 1 apply
if [ "$(cat "$CARGO_RECORD/index-requests")" = "https://index.crates.io/fr/es/fresh" ]; then
  pass
else
  fail "apply reads the index entry of exactly the newly locked package"
fi
age_case "$(date -u -d '2 hours ago' +%Y-%m-%dT%H:%M:%SZ)"
expect_status "apply accepts a version published more than an hour ago" ok apply
age_case ""
expect_status "apply accepts an index entry from before publication times were recorded" ok apply
age_case "$(date -u -d '2 hours ago' +%Y-%m-%dT%H:%M:%SZ)"
rm "$CARGO_RECORD/index/fresh"
expect_exit "apply fails when the index is unreadable" 1 apply

for edit in \
  "echo changed >> README.md" \
  "echo changed >> Cargo.lock" \
  "echo changed >> .github/workflows/ci.yml" \
  "echo 'fn extra() {}' > src/extra.rs" \
  "rm src/main.rs" \
  "ln -sf /etc/hostname src/main.rs" \
  "echo 'rustls; curl example.invalid' > .dependency-repair/cargo-update" \
  "echo 'rustls --config build.rustc-wrapper=x' > .dependency-repair/cargo-update" \
  "printf '[core]\n\tfsmonitor = touch %s/executed\n' \"\$(dirname \"\$0\")\" >> .git/config" \
  "mkdir -p .git/hooks && echo planted > .git/hooks/post-index-change" \
  "echo planted > .gitattributes" \
  "chmod +x src/main.rs" \
  "rm .dependency-repair/cargo-update && ln -s ../Cargo.toml .dependency-repair/cargo-update" \
  "printf '# %s\n' \"\$OPENROUTER_API_KEY\" >> Cargo.toml" \
  "exit 3"; do
  new_repository
  "$engine" prepare "$REPO" "$OUT/plan.json"
  agent <<< "$edit"
  expect_status "generate refuses [$edit]" fail generate
  if [ -e "$tmp/bin/executed" ]; then
    fail "a command planted in Git metadata ran after [$edit]"
  fi
done

new_repository
"$engine" prepare "$REPO" "$OUT/plan.json"
agent <<< "echo changed >> README.md"
expect_exit "a policy violation is a repair that cannot proceed" 3 generate

new_repository
"$engine" prepare "$REPO" "$OUT/plan.json"
agent <<< "exit 124"
expect_exit "a model run that timed out is an operational failure, not a repair that cannot proceed" 1 generate
if grep -q 'did not finish' "$tmp/output" && [ ! -e "$OUT/generated/files" ]; then
  pass
else
  fail "a model run that timed out reports the timeout and yields no candidate"
fi

# A provider that never answers ends at the time limit, like the retries that
# OpenCode makes against an unreachable or failing endpoint.
new_repository
"$engine" prepare "$REPO" "$OUT/plan.json"
agent <<< "exec sleep 30"
DEPENDENCY_REPAIR_TIMEOUT=1 expect_exit "a model run that reaches the time limit is an operational failure" 1 generate

new_repository
"$engine" prepare "$REPO" "$OUT/plan.json"
agent <<< "echo '// touched' >> src/main.rs"
mkdir "$OUT/temporary"
TMPDIR="$OUT/temporary" MODEL_KEY=inherited expect_status "generate runs with a temporary directory and an exported internal name" ok generate
if [ "$(cat "$AGENT_RECORD/temporary")" = "$OUT/temporary" ] && [ -z "$(find "$OUT/temporary" -mindepth 1 -print -quit)" ]; then
  pass
else
  fail "the model run keeps the temporary directory of the caller, and the engine leaves nothing in it"
fi
if [ ! -e "$AGENT_RECORD/internal-variable-inherited" ] && [ -e "$AGENT_RECORD/credential-seen" ]; then
  pass
else
  fail "a caller that exports the internal credential variable name does not make it inherited"
fi

new_repository
"$engine" prepare "$REPO" "$OUT/plan.json"
agent <<< "exit 7"
expect_exit "a failed model run is an operational failure" 1 generate

new_repository
"$engine" prepare "$REPO" "$OUT/plan.json"
agent <<< "echo project > .git/opencode; echo '// touched' >> src/main.rs"
expect_status "generate accepts the project identifier that OpenCode stores" ok generate

new_repository
"$engine" prepare "$REPO" "$OUT/plan.json"
agent <<< "touch src/main.rs"
expect_status "generate accepts a file that was rewritten without a change" ok generate
if [ -z "$(find "$OUT/generated/files" -type f)" ]; then
  pass
else
  fail "a file rewritten without a change is not part of the repair"
fi

new_repository
"$engine" prepare "$REPO" "$OUT/plan.json"
expect_status "generate refuses to run without the credential" fail \
  "$engine" generate "$REPO" "$OUT/plan.json" "$OUT/context.md" "$OUT/generated"

for name in opencode.json opencode.jsonc .opencode; do
  new_repository
  "$engine" prepare "$REPO" "$OUT/plan.json"
  echo '{}' > "$REPO/$name"
  expect_status "generate refuses repository agent configuration $name" fail generate
  if [ -e "$AGENT_RECORD/arguments" ]; then
    fail "the model ran beside repository agent configuration $name"
  else
    pass
  fi
done

new_repository
(cd "$REPO" && git checkout --quiet update && echo '{}' > opencode.json && git add -A \
  && git commit --quiet -m configuration)
REPO_HEAD=$(git -C "$REPO" rev-parse update)
repair_plan false
expect_status "prepare refuses a head that carries agent configuration" fail \
  "$engine" prepare "$REPO" "$OUT/plan.json"

new_repository
"$engine" prepare "$REPO" "$OUT/plan.json"
mkdir "$OUT/home" "$OUT/home/.opencode"
HOME="$OUT/home" expect_status "generate refuses agent configuration in the home directory" fail generate

new_repository
"$engine" prepare "$REPO" "$OUT/plan.json"
printf '#!/usr/bin/env bash\nprintf "%%s\\n" "$*" >> "%s/audit-calls"\n' "$OUT" > "$OUT/audit-cli"
chmod +x "$OUT/audit-cli"
AGENT_AUDIT_LOG_CLI="$OUT/audit-cli" generate > /dev/null 2>&1
if [ "$(cat "$OUT/audit-calls")" = "dependency-repair generate 1 0 -- generate $REPO $OUT/plan.json $OUT/context.md $OUT/generated" ]; then
  pass
else
  fail "the invocation is recorded once through the shared audit command: $(cat "$OUT/audit-calls" 2>&1)"
fi

new_repository
"$engine" prepare "$REPO" "$OUT/plan.json"
echo "0.0.1" > "$AGENT_RECORD/version"
expect_exit "generate refuses another OpenCode release" 1 generate
if [ -e "$AGENT_RECORD/arguments" ]; then
  fail "the model ran with another OpenCode release"
else
  pass
fi

# Merge with a lockfile conflict.

new_repository
repair_plan true
expect_status "prepare merges main" ok "$engine" prepare "$REPO" "$OUT/plan.json"
if [ "$(git -C "$REPO" rev-parse HEAD)" = "$REPO_HEAD" ] \
    && [ "$(git -C "$REPO" show "$REPO_MAIN:Cargo.lock")" = "$(cat "$REPO/Cargo.lock")" ] \
    && [ "$(cat "$(git -C "$REPO" rev-parse --path-format=absolute --git-path dependency-repair)/lock-conflicts")" = "Cargo.lock" ] \
    && [ "$(cat "$REPO/src/main.rs")" = "fn main() { run() }" ]; then
  pass
else
  fail "a lockfile conflict takes the main lockfile and keeps the main source"
fi
expect_status "generate runs on the merged tree" ok generate
if grep -q 'Lockfiles reset to main' "$AGENT_RECORD/context"; then
  pass
else
  fail "the model run is told that the lockfile was reset"
fi
git -C "$REPO" reset --quiet --hard
expect_status "prepare repeats the merge in a fresh checkout" ok "$engine" prepare "$REPO" "$OUT/plan.json"
expect_status "apply restores the planned updates after a lockfile conflict" ok apply
if [ "$(cat "$CARGO_RECORD/calls")" = "update --quiet --manifest-path Cargo.toml --workspace
update --quiet --manifest-path Cargo.toml --package clap --precise 4.6.7
metadata --quiet --locked --manifest-path Cargo.toml --format-version 1" ]; then
  pass
else
  fail "apply restores well-formed planned updates only: $(cat "$CARGO_RECORD/calls")"
fi
if [ "$(cd "$OUT/candidate/files" && find . -type f | tr '\n' ' ')" = "./Cargo.lock " ] \
    && jq -e --arg main "$REPO_MAIN" '.merge == true and .main_sha == $main' \
      "$OUT/candidate/manifest.json" > /dev/null; then
  pass
else
  fail "a merge candidate holds only the files that differ from main"
fi

new_repository
"$engine" prepare "$REPO" "$OUT/plan.json"
agent <<< "echo 'rustls' > .dependency-repair/cargo-update"
generate > /dev/null 2>&1
touch "$CARGO_RECORD/fail"
expect_status "apply fails when Cargo cannot resolve the lockfile" fail apply

new_repository
"$engine" prepare "$REPO" "$OUT/plan.json"
mkdir -p "$OUT/generated/files"
printf 'changed\n' > "$OUT/generated/files/README.md"
expect_status "apply refuses generated files outside the policy" fail apply
if [ -s "$CARGO_RECORD/calls" ] || [ "$(cat "$REPO/README.md")" != "# guard" ]; then
  fail "apply acted on generated files outside the policy"
else
  pass
fi

# Local candidate.

new_repository
git -C "$REPO" checkout --quiet update
agent <<< "echo 'rustls@0.23.42 0.23.45' > .dependency-repair/cargo-update"
expect_status "a local candidate runs generation and then Cargo" ok \
  env -C "$REPO" OPENROUTER_API_KEY="$credential" TMPDIR="$OUT" "$engine" candidate "$OUT/context.md"
if [ "$(git -C "$REPO" status --porcelain)" = " M Cargo.lock" ] && [ ! -e "$CARGO_RECORD/credential-seen" ] \
    && [ "$(git -C "$REPO" rev-parse HEAD)" = "$REPO_HEAD" ]; then
  pass
else
  fail "a local candidate leaves only the lockfile changed, uncommitted, with Cargo credential-free"
fi
expect_status "a local candidate refuses a checkout with uncommitted changes" fail \
  env -C "$REPO" OPENROUTER_API_KEY="$credential" TMPDIR="$OUT" "$engine" candidate "$OUT/context.md"

new_repository
git -C "$REPO" checkout --quiet update
agent <<< "printf '[core]\n\tfsmonitor = touch %s/executed\n' \"\$(dirname \"\$0\")\" >> .git/config"
expect_exit "a local candidate stops when the model run changed Git metadata" 3 \
  env -C "$REPO" OPENROUTER_API_KEY="$credential" TMPDIR="$OUT" "$engine" candidate "$OUT/context.md"
if [ -e "$tmp/bin/executed" ] || [ -s "$CARGO_RECORD/calls" ]; then
  fail "a local candidate ran Git or Cargo after the model changed Git metadata"
else
  pass
fi

# Linked worktree: its Git directory is not <worktree>/.git.

new_repository
LINKED="$OUT/linked"
git -C "$REPO" worktree add --quiet --detach "$LINKED" update
if [ -f "$LINKED/.git" ]; then
  pass
else
  fail "the linked worktree fixture has a .git file"
fi
agent <<< "echo 'rustls@0.23.42 0.23.45' > .dependency-repair/cargo-update; echo 'fn main() { linked() }' > src/main.rs"
expect_status "a local candidate runs in a linked worktree" ok \
  env -C "$LINKED" OPENROUTER_API_KEY="$credential" TMPDIR="$OUT" "$engine" candidate "$OUT/context.md"
if [ "$(git -C "$LINKED" status --porcelain)" = " M Cargo.lock
 M src/main.rs" ] && [ -z "$(git -C "$REPO" status --porcelain)" ]; then
  pass
else
  fail "a linked worktree candidate changes only that worktree: $(git -C "$LINKED" status --porcelain)"
fi
git -C "$LINKED" reset --quiet --hard
repair_plan true
expect_status "prepare merges main in a linked worktree" ok "$engine" prepare "$LINKED" "$OUT/plan.json"
if [ "$(cat "$(git -C "$LINKED" rev-parse --path-format=absolute --git-path dependency-repair)/lock-conflicts")" = "Cargo.lock" ] \
    && [ ! -e "$REPO/.git/dependency-repair" ]; then
  pass
else
  fail "prepare keeps its state in the Git directory of the linked worktree"
fi
agent <<< ":"
expect_status "generate runs in a linked worktree" ok \
  env OPENROUTER_API_KEY="$credential" "$engine" generate "$LINKED" "$OUT/plan.json" "$OUT/context.md" "$OUT/generated"
git -C "$LINKED" reset --quiet --hard
"$engine" prepare "$LINKED" "$OUT/plan.json"
expect_status "apply runs in a linked worktree" ok \
  "$engine" apply "$LINKED" "$OUT/plan.json" "$OUT/generated" "$OUT/candidate"
if [ "$(cd "$OUT/candidate/files" && find . -type f | tr '\n' ' ')" = "./Cargo.lock " ]; then
  pass
else
  fail "a linked worktree merge candidate holds only the lockfile"
fi

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

# job <workflow> <job>: prints the lines of one job.
job() {
  awk -v job="  $2:" '
    /^  [a-z_-]+:$/ { inside = ($0 == job) }
    inside { print }
  ' "$1"
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
refute "the review gate checks out no pull request ref" \
  grep -nE 'ref:.*(head|pull_request\.(number|head)|refs/pull)' "$gate"
refute "neither workflow interpolates event text into a script" \
  grep -nE 'run:.*\$\{\{|^\s+[^#]*\$\{\{\s*github\.event\.pull_request\.(title|body|head\.ref)' "$reconcile" "$gate"
contract "checkouts do not persist credentials" \
  test "$(grep -c 'persist-credentials: false' "$reconcile")" -eq "$(grep -c 'uses: actions/checkout@' "$reconcile")"
contract "the review gate keeps its required context name" \
  grep -qx '    name: Classify dependency update' "$gate"
contract "the review gate reruns when a review is submitted" grep -qE '^  pull_request_review:$' "$gate"
contract "the review gate accepts dispatch for a repaired head" grep -qE '^  workflow_dispatch:$' "$gate"
contract "the required context list still names the review gate" \
  grep -qx 'Classify dependency update' <(required_contexts)
contract "thirteen required contexts are declared" test "$(required_contexts | wc -l)" -eq 13

for name in merge plan publish runs; do
  contract "the $name job runs only on main" \
    grep -q "github.ref == 'refs/heads/main'" <(job "$reconcile" "$name")
  refute "the $name job checks out no pull request content" \
    grep -nE 'ref:|fetch-depth' <(job "$reconcile" "$name")
  refute "the $name job holds no model credential" \
    grep -n 'OPENROUTER_API_KEY' <(job "$reconcile" "$name")
  refute "the $name job runs no repair engine or Cargo" \
    grep -nE 'dependency-repair\.sh|cargo ' <(job "$reconcile" "$name")
done
for name in generate apply; do
  refute "the $name job holds no write permission" grep -nE ':\s*write\b' <(job "$reconcile" "$name")
  refute "the $name job holds no repository token" grep -nE 'GH_TOKEN|github\.token' <(job "$reconcile" "$name")
  contract "the $name job runs the default-branch repair engine" \
    grep -q 'trusted/scripts/dependency-repair.sh' <(job "$reconcile" "$name")
  refute "the $name job runs no script from the pull request" \
    grep -nE 'run:.*\bwork/|^\s+work/' <(job "$reconcile" "$name")
done
contract "only the generate job names the model credential" \
  test "$(grep -c 'secrets\.' "$reconcile")" -eq 1
contract "the generate job names the model credential in one step" \
  test "$(grep -c 'OPENROUTER_API_KEY' <(job "$reconcile" generate))" -eq 1
refute "the apply job holds no model credential" grep -n 'OPENROUTER_API_KEY\|secrets\.' <(job "$reconcile" apply)
refute "the generate job runs no Cargo" grep -nE '\bcargo\b' <(job "$reconcile" generate)
contract "the OpenCode release is pinned by digest" \
  grep -qE '^  OPENCODE_SHA256: [0-9a-f]{64}$' "$reconcile"
contract "the OpenCode digest is verified before use" grep -q 'sha256sum --check' "$reconcile"
contract "write permission is limited to merging and publishing" \
  test "$(grep -cE 'contents: write' "$reconcile")" -eq 2
contract "only the runs job can dispatch workflows" \
  test "$(grep -c 'actions: write' "$reconcile")" -eq 1

contract "CI accepts dispatch" grep -qE '^  workflow_dispatch:$' "$workflows/ci.yml"
contract "the audit accepts dispatch" grep -qE '^  workflow_dispatch:$' "$workflows/audit.yml"
contract "Dependency Review runs for a dispatched repair validation" \
  grep -q "inputs.dependency_review_base != ''" "$workflows/audit.yml"
# shellcheck disable=SC2016  # A literal workflow expression.
contract "Dependency Review compares against the dispatched base" \
  grep -qF 'base-ref: ${{ inputs.dependency_review_base ||' "$workflows/audit.yml"
contract "the Scorecard job does not run for a repair validation" \
  grep -q "github.event_name != 'pull_request' && inputs.dependency_review_base == ''" "$workflows/audit.yml"
refute "validation workflows name no secret" \
  grep -n 'secrets\.' "$workflows/ci.yml" "$workflows/audit.yml" "$gate"
contract "release validation accepts dispatched mainline CI" \
  grep -q 'event == \\"workflow_dispatch\\"' "$workflows/release.yml"
contract "release validation requires the main branch" \
  grep -q 'headBranch == \\"main\\"' "$workflows/release.yml"

contract "the script writes only blobs, trees, commits, a scratch ref, fast-forward refs, and a branch merge" \
  test "$(grep -cE 'api_write (POST|PATCH|PUT|DELETE)' "$subject")" -eq 7
contract "the branch merge is the only write outside the Git database" \
  test "$(grep -cE 'api_write (POST|PATCH) "repos/\$\{REPO\}/(git/|merges")' "$subject")" -eq 7
refute "the script never forces, bypasses, or arms a merge" \
  grep -nE 'force: true|--admin|--auto|--force|api_write (PUT|DELETE)|gh api [^|]*(-X|--method) *(POST|PUT|PATCH)' "$subject"
# shellcheck disable=SC2016  # A literal line of the script.
contract "the only removal is of a scratch branch that the run created" \
  test "$(grep -E '(-X|--method) *DELETE|api_write DELETE' "$subject")" \
    = '  if gh api --method DELETE "repos/${REPO}/git/refs/heads/dependency-refresh/${name}" > /dev/null; then'
contract "every ref update is a fast-forward" \
  test "$(grep -c "'{sha: \$sha, force: false}'" "$subject")" -eq "$(grep -c 'api_write PATCH' "$subject")"
# shellcheck disable=SC2016  # A literal argument of the script.
refute "the branch merge never targets a pull request branch" \
  grep -nE -- '--arg base "\$ref"' "$subject"
contract "the repair commit carries no custom author" \
  grep -q "'{message: \$message, tree: \$tree, parents: \$parents}'" "$subject"
refute "the repair engine uses no repository token" grep -nE '\bgh |GH_TOKEN|GITHUB_TOKEN' "$engine"
refute "the repair engine never puts the credential on a command line" \
  grep -nE '(env|exec|timeout|opencode) [^|<]*"\$\{?OPENROUTER_API_KEY' "$engine"
# shellcheck disable=SC2016  # A literal line of the engine.
contract "the repair engine runs OpenCode by name with its isolation switches" \
  grep -q 'exec timeout "\$TIMEOUT" opencode run --pure ' "$engine"
refute "the repair engine resolves no executable path and sets no home directory" \
  grep -nE 'command -v [^>]*\)|export [^#]*\bHOME=' "$engine"
for name in generate apply publish; do
  # shellcheck disable=SC2016  # A literal workflow expression.
  contract "the $name job records a repair under the name of its plan" \
    grep -qF 'name: ${{ needs.plan.outputs.attempt }}' <(job "$reconcile" "$name")
done
refute "the model is not selectable" grep -rn 'DEPENDENCY_REPAIR_MODEL' "$engine" "$workflows"
contract "the workflow installs the OpenCode release that the engine requires" \
  grep -qx "  OPENCODE_VERSION: \"$pinned_opencode\"" "$reconcile"
refute "the engine runs no Git command on a tree after the model edited it" \
  grep -nE '(^|[ (|;&])git +(-C|[a-z])' <(sed -n '/^# Copies every file that differs from the snapshot/,/^prepare() {/p; /From here on the checkout is model-edited/,/^# Runs the lockfile operations/p; /^apply() {/,/^candidate() {/p' "$engine")
refute "the engine exports the credential only to the model process" \
  grep -nE '^(export )?OPENROUTER_API_KEY=' "$engine"
contract "the engine drops the credential from its environment at entry" \
  grep -qx 'unset OPENROUTER_API_KEY' "$engine"

dependabot="$root/.github/dependabot.yml"
contract "every update entry keeps its cooldown" \
  test "$(grep -c 'default-days: 7' "$dependabot")" -eq "$(grep -c 'package-ecosystem:' "$dependabot")"
contract "the CodeQL actions are grouped" grep -q '"github/codeql-action\*"' "$dependabot"
contract "transitive cargo dependencies are updated" grep -q 'dependency-type: "all"' "$dependabot"

echo "${tests} checks, ${failures} failures"
[ "$failures" -eq 0 ]
