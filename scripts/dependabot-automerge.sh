#!/usr/bin/env bash
set -euo pipefail

# Classifies, repairs, validates, and merges Dependabot pull requests, and keeps
# mainline workflow evidence present for commits that the Actions token merged.
#
# Usage:
#   scripts/dependabot-automerge.sh classify <pull-request-number>
#   scripts/dependabot-automerge.sh gate <pull-request-number>
#   scripts/dependabot-automerge.sh reconcile
#   scripts/dependabot-automerge.sh repair-plan <output-directory>
#   scripts/dependabot-automerge.sh publish-repair <candidate-directory>
#   scripts/dependabot-automerge.sh ensure-validation-runs
#   scripts/dependabot-automerge.sh ensure-mainline-runs
#
# Environment:
#   GITHUB_REPOSITORY  owner/name of the repository to act on.
#   GH_TOKEN           token for the gh CLI.
#   EXPECTED_HEAD      gate only: the commit a dispatched gate reports on.
#
# Every decision is derived from GitHub API metadata. The script never checks
# out, builds, or executes pull request content, so it is safe to run from the
# default branch with a write token. Repair content is produced elsewhere, by
# scripts/dependency-repair.sh in jobs that hold no write token, and reaches
# publish-repair only as files that are validated before they are committed.
#
# classify prints one JSON object. Its decision is one of:
#   eligible  the update merges automatically once its checks pass;
#   review    a genuine Dependabot update that needs an approving review;
#   manual    the pull request is not a Dependabot update this automation
#             recognizes, and it is never merged automatically.
#
# A pull request is recognized only when it is open, not a draft, authored by
# dependabot[bot], targets main, and its head branch lives in this repository
# under dependabot/. Its first commit is authored by dependabot[bot], committed
# by GitHub, and verified. Any later commit is a repair: authored by
# github-actions[bot], verified, and directly on top of the previous commit. A
# repair with two parents merges a commit that main contains.
#
# A recognized update is eligible when every changed file is a modification
# inside one manifest set that matches the head branch ecosystem and:
#   - Cargo (root or fuzz manifests): every listed update is a patch or minor
#     version update, including 0.x versions;
#   - GitHub Actions (workflow files): every added line pins an action to a
#     full commit SHA, whatever the update type.
# Major Cargo updates, unclassified updates, and other ecosystems need review.
#
# A repaired update stays eligible when its repair is confined to the same
# manifest set and that crate's Rust source. Its required checks, the resolved
# review threads, and the integration evidence below are what admit it.
#
# An approving review counts when a repository owner, member, or collaborator
# approved the exact head commit and no such reviewer requests changes.
#
# gate succeeds for an eligible update and for any update with an approving
# review. It fails otherwise, so the required check blocks an unreviewed major
# update.
#
# reconcile merges at most one pull request per run. It merges only when the
# effective branch rules match the declared required checks, the head commit
# contains the current main commit, every required check succeeded for that
# exact head commit, every review thread is resolved, and the classification
# is unchanged immediately before the merge. A head that contains main has the
# tree that the squash merge produces, so its checks are the integration
# evidence. reconcile refreshes at most one branch per run that lacks the main
# commit and does not conflict with it, through the branch merge API. The
# refresh commit carries the marker that lets Dependabot keep rebasing the
# branch. A conflicting Cargo update is left to repair-plan; a conflicting
# workflow update is left to the rebase that Dependabot performs on a conflict.
#
# repair-plan selects at most one Cargo update whose required checks failed or
# whose branch conflicts with main, and writes plan.json and context.md. A
# failed check counts once a rerun reproduced it. Each plan has a record name
# derived from the Dependabot commit, the main commit, and the failing checks.
# The workflow stores a record under that name when a repair was published or
# cannot proceed, and repair-plan skips a plan whose record exists, so the
# model runs again only after one of the three changed. An operational failure
# leaves no record and is tried again on the next run.
#
# publish-repair commits validated repair files to the pull request branch
# through the Git database API. GitHub signs a commit created this way without
# custom author information, and the branch advances only after the commit
# meets everything classify requires of a repair, as a fast-forward. It exits
# with status 3 when the candidate made no progress: it changes nothing,
# violates the policy, or was refused. It exits with status 4 when the pull
# request changed and the candidate was dropped.
#
# ensure-validation-runs dispatches the required workflows on a head that this
# automation committed. A branch update made with the Actions token leaves
# pull request workflows waiting for approval, and workflow_dispatch is the
# supported event that the same token can raise. Dispatch is refused unless
# the branch workflows equal the main workflows, or differ from them only by
# an eligible workflow update on a head that contains main. It also reruns a
# workflow run that was cancelled, or that failed and has not been rerun yet.
#
# ensure-mainline-runs dispatches the push-triggered mainline workflows for the
# current main commit when no run exists for it, and reruns them the same way.

BOT_LOGIN="dependabot[bot]"
REPAIR_LOGIN="github-actions[bot]"
BRANCH="main"
# GitHub Actions. Only check runs reported by this app satisfy a required
# context.
APP_ID=15368
MAINLINE_WORKFLOWS=(ci.yml audit.yml)
VALIDATION_WORKFLOWS=(ci.yml audit.yml dependabot-automerge.yml)
GATE_CONTEXT="Classify dependency update"
# The bracketed marker lets Dependabot force push over the commit.
REFRESH_MESSAGE=$'chore(deps): merge main into dependency update\n\nDependency-Repair: refresh\n[dependabot skip]'
LOG_TAIL_LINES=120
DISPATCH_POLLS="${DISPATCH_POLLS:-6}"
DISPATCH_POLL_SECONDS="${DISPATCH_POLL_SECONDS:-5}"

script_dir=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)

usage() {
  cat >&2 <<EOF
usage: $0 classify <pull-request-number>
       $0 gate <pull-request-number>
       $0 reconcile
       $0 repair-plan <output-directory>
       $0 publish-repair <candidate-directory>
       $0 ensure-validation-runs
       $0 ensure-mainline-runs
EOF
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

# Sends the JSON document on standard input.
api_write() {
  gh api --method "$1" "$2" --input -
}

report() {
  echo "$1"
  if [ -n "${GITHUB_STEP_SUMMARY:-}" ]; then
    echo "- $1" >> "$GITHUB_STEP_SUMMARY"
  fi
}

is_sha() {
  [[ "$1" =~ ^[0-9a-f]{40}$ ]]
}

# Succeeds when the first commit is the second commit or one of its ancestors.
is_ancestor() {
  api "repos/${REPO}/compare/${1}...${2}" \
    | jq -e '.status == "ahead" or .status == "identical"' > /dev/null
}

# Prints the classification object. Returns nonzero only when metadata is
# unreadable.
classify() {
  local number="$1" dir parent merges_ok=true repairs fingerprint
  [[ "$number" =~ ^[1-9][0-9]*$ ]] || {
    echo "error: pull request number is malformed" >&2
    return 2
  }
  dir=$(mktemp -d "$work_dir/classify.XXXXXX")

  api "repos/${REPO}/pulls/${number}" > "$dir/pull.json" || return 2
  api_pages "repos/${REPO}/pulls/${number}/commits?per_page=100" \
    | jq -s '[.[][] | {
        sha,
        author: .author.login,
        committer: .committer.login,
        verified: .commit.verification.verified,
        message: .commit.message,
        parents: [.parents[]?.sha]
      }]' > "$dir/commits.json" || return 2
  api_pages "repos/${REPO}/pulls/${number}/files?per_page=100" \
    | jq -s '[.[][] | {filename, status, patch: (.patch // null)}]' > "$dir/files.json" || return 2
  api_pages "repos/${REPO}/pulls/${number}/reviews?per_page=100" \
    | jq -s '[.[][] | {
        login: .user.login,
        type: .user.type,
        association: .author_association,
        state,
        commit_id,
        submitted_at: (.submitted_at // "")
      }]' > "$dir/reviews.json" || return 2

  # Every commit that a repair merged must be part of main.
  repairs=$(jq '[.[1:][]] | length' "$dir/commits.json")
  if [ "$repairs" -gt 0 ]; then
    while IFS= read -r parent; do
      is_sha "$parent" || return 2
      is_ancestor "$parent" "$BRANCH" || merges_ok=false
    done < <(jq -r '.[1:][] | select((.parents | length) == 2) | .parents[1]' "$dir/commits.json")
  fi

  fingerprint=$(jq -cS -n \
    --slurpfile pull "$dir/pull.json" \
    --slurpfile commits "$dir/commits.json" \
    --slurpfile files "$dir/files.json" '{
      pull: ($pull[0] | {state, draft, user: .user.login, base: .base.ref,
        base_repo: .base.repo.full_name, head: .head.sha, head_ref: .head.ref,
        head_repo: .head.repo.full_name, commits, changed_files}),
      commits: $commits[0],
      files: $files[0]
    }' | sha256sum | cut -d ' ' -f 1) || return 2

  jq -n \
    --argjson number "$number" \
    --arg repo "$REPO" \
    --arg bot "$BOT_LOGIN" \
    --arg repair_bot "$REPAIR_LOGIN" \
    --arg branch "$BRANCH" \
    --arg fingerprint "$fingerprint" \
    --argjson merges_ok "$merges_ok" \
    --slurpfile pull "$dir/pull.json" \
    --slurpfile commits "$dir/commits.json" \
    --slurpfile files "$dir/files.json" \
    --slurpfile reviews "$dir/reviews.json" '
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
        elif $type == "version-update:semver-patch" or $type == "version-update:semver-minor"
        then "compatible"
        elif $type == "version-update:semver-major" then "major"
        else "unclassified"
        end;

    def file_class:
      if test("^Cargo\\.(toml|lock)$") then "cargo-root"
      elif test("^fuzz/Cargo\\.(toml|lock)$") then "cargo-fuzz"
      elif test("^\\.github/workflows/[^/]+\\.ya?ml$") then "github-actions"
      else "other"
      end;

    def is_source($class):
      if $class == "cargo-root"
      then test("^(src|tests|benches)/([A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+\\.rs$")
      elif $class == "cargo-fuzz"
      then test("^fuzz/fuzz_targets/([A-Za-z0-9_-]+/)*[A-Za-z0-9_-]+\\.rs$")
      else false
      end;

    def branch_prefix:
      if . == "github-actions" then "dependabot/github_actions/" else "dependabot/cargo/" end;

    def changed_lines:
      if . == null then null else [split("\n")[] | select(test("^[+-]"))] end;

    # Every added line is an action reference pinned to a full commit SHA.
    def pinned_actions:
      all(.[]; .patch != null
        and (.patch | changed_lines | map(select(startswith("+"))) | length > 0)
        and all(.patch | changed_lines[] | select(startswith("+"));
          test("^\\+\\s*(- )?uses: [^\\s@]+@[0-9a-f]{40}(\\s+#.*)?$")));

    def trust:
      $pull[0] as $p
      | $commits[0] as $c
      | if $p.number != $number or $p.state != "open" or $p.draft != false then
          "the pull request is not open and ready"
        elif $p.user.login != $bot or $p.user.type != "Bot" then
          "the pull request is not a Dependabot update"
        elif $p.base.ref != $branch or $p.base.repo.full_name != $repo then
          "the pull request does not target the protected branch"
        elif $p.head.repo.full_name != $repo or (($p.head.ref // "") | startswith("dependabot/") | not) then
          "the head branch is not a Dependabot branch in this repository"
        elif ($c | length) == 0 or $p.commits != ($c | length) or $c[-1].sha != $p.head.sha then
          "the commit list is empty, incomplete, or does not end at the head"
        elif $c[0].author != $bot or $c[0].committer != "web-flow" or $c[0].verified != true then
          "the first commit is not a verified Dependabot commit"
        elif any(range(1; $c | length); . as $i
            | $c[$i].author != $repair_bot
              or $c[$i].verified != true
              or (($c[$i].committer == "web-flow" or $c[$i].committer == $repair_bot) | not)
              or (($c[$i].parents | length) < 1 or ($c[$i].parents | length) > 2)
              or $c[$i].parents[0] != $c[$i - 1].sha) then
          "a later commit is not a verified repair on top of the Dependabot commit"
        elif $merges_ok | not then
          "a repair merges a commit that main does not contain"
        else null
        end;

    def policy:
      $pull[0] as $p
      | $commits[0] as $c
      | $files[0] as $f
      | (($c | length) > 1) as $repaired
      | if ($f | length) == 0 or ($f | length) != $p.changed_files then
          {class: "other", reason: "the changed file list is empty or incomplete"}
        elif any($f[]; .status != "modified") then
          {class: "other", reason: "the update adds, removes, or renames files"}
        else
          ($f | map(.filename | file_class) | map(select(. != "other")) | unique) as $classes
          | (if ($classes | length) == 1 then $classes[0] else "other" end) as $class
          | ($f | map(select((.filename | file_class) != $class))) as $outside
          | if $class == "other" then
              {class: "other", reason: "the changed files are outside one eligible manifest set"}
            elif $p.head.ref | startswith($class | branch_prefix) | not then
              {class: "other", reason: "the changed files do not match the head branch ecosystem"}
            elif any($outside[]; .filename | is_source($class) | not) then
              {class: "other", reason: "the changed files are outside one eligible manifest set"}
            elif ($repaired | not) and ($outside | length) > 0 then
              {class: $class, reason: "the update changes files outside its manifest set"}
            else
              (($c[0].message // "") | metadata) as $items
              | if $items == null then
                  {class: $class, reason: "the update metadata is missing or malformed"}
                elif $class == "github-actions" and ($f | pinned_actions | not) then
                  {class: $class, reason: "an added line is not an action pinned to a full commit SHA"}
                elif $class != "github-actions" and any($items[] | level; . == "unclassified") then
                  {class: $class, reason: "an update has no recognized type or version"}
                elif $class != "github-actions" and any($items[] | level; . == "major") then
                  {class: $class, reason: "the update includes a major version"}
                else
                  {class: $class, reason: null}
                end
            end
        end;

    def approved:
      $pull[0].head.sha as $head
      | [$reviews[0][]
          | select(.type == "User"
              and (.association == "OWNER" or .association == "MEMBER" or .association == "COLLABORATOR")
              and (.state == "APPROVED" or .state == "CHANGES_REQUESTED" or .state == "DISMISSED"))]
      | group_by(.login)
      | map(sort_by(.submitted_at) | last)
      | any(.[]; .state == "APPROVED" and .commit_id == $head)
        and all(.[]; .state != "CHANGES_REQUESTED");

    trust as $distrust
    | (if $distrust == null then policy else {class: "other", reason: $distrust} end) as $policy
    | $commits[0] as $c
    | {
        decision: (if $distrust != null then "manual"
                   elif $policy.reason == null then "eligible"
                   else "review" end),
        reason: ($policy.reason // (if ($c | length) > 1
          then "the update is routine and its repair stays inside its manifest set and Rust source"
          else "the update is routine" end)),
        approved: approved,
        number: $number,
        ecosystem: $policy.class,
        head_sha: ($pull[0].head.sha // ""),
        head_ref: ($pull[0].head.ref // ""),
        update_sha: ($c[0].sha // ""),
        mergeable_state: ($pull[0].mergeable_state // "unknown"),
        repairs: ([$c[1:][]] | length),
        updates: (if $distrust != null then [] else
          [(($c[0].message // "") | metadata // [])[]
            | {name: ."dependency-name", version: (."dependency-version" // "")}] end),
        fingerprint: $fingerprint
      }
    | if (.decision != "manual") and (.head_sha | test("^[0-9a-f]{40}$") | not)
      then error("head commit is malformed")
      else .
      end
  ' || return 2
}

gate() {
  local result decision approved
  result=$(classify "$1") || return 2
  decision=$(jq -r '.decision' <<< "$result")
  approved=$(jq -r '.approved' <<< "$result")
  report "Decision: ${decision}. Reason: $(jq -r '.reason' <<< "$result"). Approving review: ${approved}."
  # A dispatched gate reports on the dispatched commit, so it must be the
  # pull request head.
  if [ -n "${EXPECTED_HEAD:-}" ] && [ "$(jq -r '.head_sha' <<< "$result")" != "$EXPECTED_HEAD" ]; then
    report "The dispatched commit is not the pull request head."
    return 1
  fi
  [ "$decision" = "eligible" ] || [ "$approved" = "true" ]
}

declared_contexts() {
  "$script_dir/sync-branch-protection.sh" --list
}

# Succeeds when the effective rules for main are the ones this script verifies
# on its own: the declared required checks from GitHub Actions, and pull
# request rules that an unreviewed squash merge satisfies. Prints the reason
# otherwise. A rule of any other type fails closed.
effective_rules_verified() {
  local approved="$1" declared
  declared=$(declared_contexts | jq -R . | jq -s .) || return 2
  api_pages "repos/${REPO}/rules/branches/${BRANCH}?per_page=100" \
    | jq -s 'add' > "$work_dir/rules.json" || return 2
  jq -r --argjson declared "$declared" --argjson app_id "$APP_ID" --argjson approved "$approved" '
    ["deletion", "non_fast_forward", "pull_request", "required_status_checks",
     "required_linear_history", "required_signatures"] as $known
    | [.[] | select(.type == "required_status_checks")] as $status
    | [.[] | select(.type == "pull_request") | .parameters] as $pull
    | if type != "array" then "the effective rules are unreadable"
      elif any(.[]; .type as $type | $known | index($type) | not) then
        "an effective rule is not verified by this automation: "
        + ([.[] | .type | select(. as $type | $known | index($type) | not)] | unique | join(", "))
      elif ($status | length) != 1 then
        "the effective rules do not hold exactly one required status check rule"
      elif any($status[0].parameters.required_status_checks[]; .integration_id != $app_id) then
        "a required status check is not bound to GitHub Actions"
      elif ([$status[0].parameters.required_status_checks[].context] | sort) != ($declared | sort) then
        "the effective required status checks differ from the declared list"
      elif any($pull[]; .require_code_owner_review == true or .require_last_push_approval == true
          or ((.required_reviewers // []) | length) > 0) then
        "the effective rules require a review this automation cannot verify"
      elif any($pull[]; (.required_approving_review_count // 0) > (if $approved then 1 else 0 end)) then
        "the effective rules require more approving reviews than the pull request has"
      elif any($pull[]; (.allowed_merge_methods // ["squash"]) | index("squash") | not) then
        "the effective rules do not allow a squash merge"
      else empty
      end
  ' "$work_dir/rules.json"
}

# Writes the newest GitHub Actions check run per context for a commit.
read_check_runs() {
  api_pages "repos/${REPO}/commits/${1}/check-runs?filter=latest&per_page=100" \
    | jq -s --arg sha "$1" --argjson app_id "$APP_ID" '
        [.[].check_runs[] | select(.head_sha == $sha and .app.id == $app_id)]
        | group_by(.name)
        | map(sort_by(.started_at // "", .id) | last)
      ' > "$2"
}

# Prints "<state><TAB><context>" for the given contexts, where state is one of
# success, failed, pending, or missing.
context_states() {
  local file="$1"
  shift
  printf '%s\n' "$@" | jq -R . | jq -s -r --slurpfile runs "$file" '
    .[] as $context
    | ($runs[0] | map(select(.name == $context)) | first) as $run
    | (if $run == null then "missing"
       elif $run.status != "completed" then "pending"
       elif $run.conclusion == "success" then "success"
       else "failed" end) + "\t" + $context'
}

required_contexts() {
  local -a contexts
  mapfile -t contexts < <(declared_contexts)
  [ "${#contexts[@]}" -gt 0 ] || return 2
  printf '%s\n' "${contexts[@]}"
}

main_head() {
  api "repos/${REPO}/git/ref/heads/${BRANCH}" \
    | jq -er '.object.sha | strings | select(test("^[0-9a-f]{40}$"))'
}

# Succeeds when every review thread is resolved and the thread list was read in
# full for the given head commit.
review_threads_resolved() {
  local number="$1" sha="$2"
  # shellcheck disable=SC2016  # GraphQL variables, not shell expansions.
  gh api graphql --paginate \
    -f owner="${REPO%%/*}" -f name="${REPO##*/}" -F number="$number" \
    -f query='
      query($owner: String!, $name: String!, $number: Int!, $endCursor: String) {
        repository(owner: $owner, name: $name) {
          pullRequest(number: $number) {
            headRefOid
            reviewThreads(first: 100, after: $endCursor) {
              nodes { isResolved }
              pageInfo { hasNextPage endCursor }
            }
          }
        }
      }' \
    | jq -s -e --arg sha "$sha" '
        map(.data.repository.pullRequest) as $pages
        | ($pages | length) > 0
          and all($pages[]; . != null and .headRefOid == $sha)
          and ($pages[-1].reviewThreads.pageInfo.hasNextPage == false)
          and all($pages[].reviewThreads.nodes[]; .isResolved == true)
      ' > /dev/null
}

open_dependabot_pulls() {
  api_pages "repos/${REPO}/pulls?state=open&base=${BRANCH}&per_page=100" \
    | jq -s -r --arg bot "$BOT_LOGIN" '.[][] | select(.user.login == $bot) | .number'
}

# Succeeds when the commit meets what classify requires of a repair commit
# with the given parents. Reads the commit JSON on standard input.
repair_commit_verified() {
  jq -e --arg bot "$REPAIR_LOGIN" --argjson parents "$1" '
    .commit.verification.verified == true
    and .author.login == $bot
    and (.committer.login == "web-flow" or .committer.login == $bot)
    and ([.parents[]?.sha] == $parents)' > /dev/null
}

# Merges the main commit into a pull request branch. GitHub computes the merge
# and creates the commit; nothing is checked out.
refresh_branch() {
  local number="$1" ref="$2" sha="$3" main="$4" response commit
  if ! [[ "$ref" =~ ^dependabot/[A-Za-z0-9._/+-]+$ ]]; then
    report "#${number}: error, the head branch name is malformed"
    return 1
  fi
  if ! response=$(jq -n --arg base "$ref" --arg head "$main" --arg message "$REFRESH_MESSAGE" \
      '{base: $base, head: $head, commit_message: $message}' \
      | api_write POST "repos/${REPO}/merges"); then
    report "#${number}: error, the refresh of ${ref} with ${main} was refused"
    return 1
  fi
  commit=$(jq -r '.sha // ""' <<< "$response")
  if ! is_sha "$commit"; then
    report "#${number}: the branch already contains ${main}, or moved during the refresh"
    return 0
  fi
  if ! api "repos/${REPO}/commits/${commit}" \
      | repair_commit_verified "$(jq -n --arg head "$sha" --arg main "$main" '[$head, $main]')"; then
    report "#${number}: error, the refresh commit ${commit} is not a verified ${REPAIR_LOGIN} merge of ${main} into ${sha}"
    return 1
  fi
  report "#${number}: refreshed with ${main} as ${commit}; it merges once its checks pass"
}

reconcile() {
  local numbers number result decision approved reason sha state states unmet main ecosystem
  local problem again refreshed=0 failures=0

  main=$(main_head) || {
    report "error, the ${BRANCH} head commit is unreadable"
    return 1
  }
  numbers=$(open_dependabot_pulls) || {
    report "error, open pull requests are unreadable"
    return 1
  }

  for number in $numbers; do
    if ! result=$(classify "$number"); then
      report "#${number}: error, pull request metadata is unreadable"
      failures=$((failures + 1))
      continue
    fi
    decision=$(jq -r '.decision' <<< "$result")
    approved=$(jq -r '.approved' <<< "$result")
    reason=$(jq -r '.reason' <<< "$result")
    sha=$(jq -r '.head_sha' <<< "$result")
    state=$(jq -r '.mergeable_state' <<< "$result")
    ecosystem=$(jq -r '.ecosystem' <<< "$result")

    if [ "$decision" = "manual" ]; then
      report "#${number}: manual, ${reason}"
      continue
    fi
    if [ "$decision" = "review" ] && [ "$approved" != "true" ]; then
      report "#${number}: needs an approving review, ${reason}"
      continue
    fi

    if ! problem=$(effective_rules_verified "$approved"); then
      report "#${number}: error, the effective branch rules are unreadable"
      failures=$((failures + 1))
      continue
    fi
    if [ -n "$problem" ]; then
      report "#${number}: error, ${problem}"
      failures=$((failures + 1))
      continue
    fi

    # Checks on a head without the main commit say nothing about the tree
    # that a merge would produce.
    if ! is_ancestor "$main" "$sha"; then
      if [ "$state" = "dirty" ]; then
        case "$ecosystem" in
          cargo-*) report "#${number}: waiting, the branch conflicts with ${BRANCH}; a repair resolves it" ;;
          *) report "#${number}: waiting, the branch conflicts with ${BRANCH}; Dependabot rebases it" ;;
        esac
      elif [ "$refreshed" -eq 1 ]; then
        report "#${number}: waiting, the branch lacks ${main}; one branch is refreshed per run"
      else
        refreshed=1
        refresh_branch "$number" "$(jq -r '.head_ref' <<< "$result")" "$sha" "$main" \
          || failures=$((failures + 1))
      fi
      continue
    fi

    mapfile -t contexts < <(required_contexts)
    if ! read_check_runs "$sha" "$work_dir/runs.json" \
        || ! states=$(context_states "$work_dir/runs.json" "${contexts[@]}"); then
      report "#${number}: error, required checks are unreadable"
      failures=$((failures + 1))
      continue
    fi
    unmet=$(grep -v '^success'$'\t' <<< "$states" | head -n 1 | cut -f 2- || true)
    if [ -n "$unmet" ]; then
      report "#${number}: waiting, required check has not succeeded: ${unmet}"
      continue
    fi

    case "$state" in
      clean|unstable|has_hooks) ;;
      *)
        report "#${number}: waiting, mergeable state is ${state}"
        continue
        ;;
    esac

    if ! review_threads_resolved "$number" "$sha"; then
      report "#${number}: waiting, a review thread is unresolved or unreadable"
      continue
    fi

    # The decision is bound to the metadata it was made from. A retargeted
    # base, a changed file list, or a new commit changes the fingerprint.
    if ! again=$(classify "$number") \
        || [ "$(jq -cS 'del(.mergeable_state)' <<< "$again")" != "$(jq -cS 'del(.mergeable_state)' <<< "$result")" ] \
        || [ "$(main_head)" != "$main" ]; then
      report "#${number}: waiting, the pull request or ${BRANCH} changed during evaluation"
      continue
    fi

    if gh pr merge "$number" --repo "$REPO" --squash --match-head-commit "$sha"; then
      report "#${number}: merged at ${sha}"
      report "every other update now lacks the new ${BRANCH} commit and is refreshed first"
      break
    else
      report "#${number}: error, merge was refused at ${sha}"
      failures=$((failures + 1))
    fi
  done

  [ "$failures" -eq 0 ]
}

# Prints the tail of a failed job log. Log text is untrusted and is only ever
# handed to the repair model as data.
failed_log_tail() {
  api "repos/${REPO}/actions/jobs/${1}/logs" 2> /dev/null \
    | sed -E 's/^[0-9]{4}-[0-9]{2}-[0-9]{2}T[0-9:.]+Z //; s/\x1b\[[0-9;]*[A-Za-z]//g' \
    | tail -n "$LOG_TAIL_LINES" \
    | cut -c 1-400 || true
}

workflow_tree() {
  api "repos/${REPO}/contents/.github?ref=${1}" \
    | jq -er '.[] | select(.name == "workflows" and .type == "dir") | .sha'
}

# Succeeds when a rerun reproduced the failed required checks: every failed
# job ran at least twice and at least one of them failed on its own, as
# opposed to being cancelled. Takes the failed context names.
failures_reproduced() {
  local context job detail own=1
  for context in "$@"; do
    job=$(jq -r --arg context "$context" \
      'map(select(.name == $context)) | first | .id // empty' "$work_dir/runs.json")
    [[ "$job" =~ ^[0-9]+$ ]] || return 1
    detail=$(api "repos/${REPO}/actions/jobs/${job}") || return 1
    jq -e '(.run_attempt // 1) >= 2' <<< "$detail" > /dev/null || return 1
    if jq -e '.conclusion == "failure" or .conclusion == "timed_out"' <<< "$detail" > /dev/null; then
      own=0
    fi
  done
  return "$own"
}

# Selects one pull request to repair and writes plan.json and context.md.
repair_plan() {
  local out="$1" numbers number result decision sha state states failed main merge
  local ecosystem manifest job context attempt
  local -a failed_contexts
  mkdir -p "$out"
  echo '{"repair": false}' > "$out/plan.json"
  : > "$out/context.md"

  main=$(main_head) || return 2
  numbers=$(open_dependabot_pulls) || return 2
  mapfile -t contexts < <(required_contexts)

  for number in $numbers; do
    result=$(classify "$number") || {
      report "#${number}: error, pull request metadata is unreadable"
      continue
    }
    decision=$(jq -r '.decision' <<< "$result")
    ecosystem=$(jq -r '.ecosystem' <<< "$result")
    sha=$(jq -r '.head_sha' <<< "$result")
    state=$(jq -r '.mergeable_state' <<< "$result")
    [ "$decision" != "manual" ] || continue
    case "$ecosystem" in
      cargo-root) manifest="Cargo.toml" ;;
      cargo-fuzz) manifest="fuzz/Cargo.toml" ;;
      *)
        # The Actions token cannot write workflow files, so a workflow update
        # is left to Dependabot.
        continue
        ;;
    esac

    read_check_runs "$sha" "$work_dir/runs.json" || continue
    states=$(context_states "$work_dir/runs.json" "${contexts[@]}") || continue
    # The gate fails for an update that only needs a review; that is not a
    # defect a repair can fix.
    states=$(grep -vF $'\t'"$GATE_CONTEXT" <<< "$states" || true)
    failed=$(grep '^failed'$'\t' <<< "$states" | cut -f 2- || true)

    merge=false
    if [ "$state" = "dirty" ]; then
      merge=true
    elif grep -q '^pending'$'\t' <<< "$states" || [ -z "$failed" ]; then
      continue
    else
      mapfile -t failed_contexts <<< "$failed"
      if ! failures_reproduced "${failed_contexts[@]}"; then
        report "#${number}: waiting, the failed checks at ${sha} have not been reproduced by a rerun"
        continue
      fi
      is_ancestor "$main" "$sha" || merge=true
    fi

    # The workflow stores a record under this name once a repair for this
    # plan was published or cannot proceed.
    attempt="repair-attempt-${number}-$(printf '%s\n' "$(jq -r '.update_sha' <<< "$result")" \
      "$main" "$merge" "$failed" | sha256sum | cut -d ' ' -f 1)"
    if ! api "repos/${REPO}/actions/artifacts?name=${attempt}&per_page=100" \
        | jq -e '[.artifacts[]? | select(.expired == false)] | length == 0' > /dev/null; then
      report "#${number}: a repair for the same update, ${BRANCH} commit, and failing checks was already made, or its record is unreadable"
      continue
    fi

    jq -n --argjson result "$result" --arg main "$main" --arg manifest "$manifest" \
      --argjson merge "$merge" --arg attempt "$attempt" '{
        repair: true,
        attempt: $attempt,
        number: $result.number,
        head_sha: $result.head_sha,
        head_ref: $result.head_ref,
        main_sha: $main,
        merge: $merge,
        ecosystem: $result.ecosystem,
        manifest: $manifest,
        updates: $result.updates
      }' > "$out/plan.json"

    {
      echo "# Failing required checks"
      echo
      if [ -z "$failed" ]; then
        echo "None reported. The branch conflicts with ${BRANCH}."
      fi
      while IFS= read -r context; do
        [ -n "$context" ] || continue
        job=$(jq -r --arg context "$context" \
          'map(select(.name == $context)) | first | .id // empty' "$work_dir/runs.json")
        echo "## ${context}"
        echo
        echo '```text'
        [[ "$job" =~ ^[0-9]+$ ]] && failed_log_tail "$job"
        echo '```'
        echo
      done <<< "$failed"
    } > "$out/context.md"

    report "#${number}: repair planned at ${sha} (merge ${BRANCH}: ${merge}; failing: $(tr '\n' ';' <<< "$failed"))"
    return 0
  done

  report "no pull request needs a repair"
}

# Commits a validated repair candidate to its pull request branch.
publish_repair() {
  local dir="$1" manifest="$1/manifest.json" number head main merge result ref ecosystem
  local base_commit base_tree head_tree parents message path blob tree commit entries

  jq -e 'type == "object"' "$manifest" > /dev/null || {
    report "error, the repair manifest is unreadable"
    return 1
  }
  number=$(jq -r '.number' "$manifest")
  head=$(jq -r '.head_sha' "$manifest")
  main=$(jq -r '.main_sha' "$manifest")
  merge=$(jq -r '.merge' "$manifest")
  if ! [[ "$number" =~ ^[1-9][0-9]*$ ]] || ! is_sha "$head" || ! is_sha "$main" \
      || ! [[ "$merge" =~ ^(true|false)$ ]]; then
    report "error, the repair manifest is malformed"
    return 1
  fi

  result=$(classify "$number") || {
    report "#${number}: error, pull request metadata is unreadable"
    return 1
  }
  ref=$(jq -r '.head_ref' <<< "$result")
  ecosystem=$(jq -r '.ecosystem' <<< "$result")
  if [ "$(jq -r '.decision' <<< "$result")" = "manual" ] \
      || [ "$(jq -r '.head_sha' <<< "$result")" != "$head" ]; then
    report "#${number}: repair dropped, the pull request changed or is no longer repairable"
    return 4
  fi
  case "$ecosystem" in
    cargo-root|cargo-fuzz) ;;
    *)
      report "#${number}: repair dropped, the ecosystem is not repairable"
      return 4
      ;;
  esac

  if ! "$script_dir/dependency-repair.sh" check-policy "$dir" "$ecosystem" final; then
    report "#${number}: error, the repair candidate violates the path or content policy"
    return 3
  fi
  if [ -z "$(find "$dir/files" -type f -print -quit)" ] && [ "$merge" = "false" ]; then
    report "#${number}: the repair produced no change"
    return 3
  fi

  head_tree=$(api "repos/${REPO}/git/commits/${head}" | jq -er '.tree.sha') || return 1
  if [ "$merge" = "true" ]; then
    is_ancestor "$main" "$BRANCH" || {
      report "#${number}: error, the merged commit is not part of ${BRANCH}"
      return 1
    }
    base_commit="$main"
    parents=$(jq -n --arg head "$head" --arg main "$main" '[$head, $main]')
    message=$'chore(deps): merge main and repair dependency update\n\nDependency-Repair: merge'
  else
    base_commit="$head"
    parents=$(jq -n --arg head "$head" '[$head]')
    message=$'chore(deps): repair dependency update\n\nDependency-Repair: update'
  fi
  base_tree=$(api "repos/${REPO}/git/commits/${base_commit}" | jq -er '.tree.sha') || return 1

  # Every repaired path already exists as a regular file. The repair cannot
  # add, remove, or change the mode of a file.
  api "repos/${REPO}/git/trees/${base_tree}?recursive=1" > "$work_dir/tree.json" || return 1
  jq -e '.truncated == false' "$work_dir/tree.json" > /dev/null || {
    report "#${number}: error, the base tree listing is incomplete"
    return 1
  }
  entries='[]'
  while IFS= read -r -d '' path; do
    path=${path#"$dir/files/"}
    jq -e --arg path "$path" \
      'any(.tree[]; .path == $path and .type == "blob" and .mode == "100644")' \
      "$work_dir/tree.json" > /dev/null || {
        report "#${number}: error, a repaired path is not an existing regular file: ${path}"
        return 3
      }
    blob=$(base64 -w 0 "$dir/files/$path" \
      | jq -R -s '{content: ., encoding: "base64"}' \
      | api_write POST "repos/${REPO}/git/blobs" | jq -er '.sha') || {
        report "#${number}: error, a blob could not be created"
        return 1
      }
    entries=$(jq --arg path "$path" --arg sha "$blob" \
      '. + [{path: $path, mode: "100644", type: "blob", sha: $sha}]' <<< "$entries")
  done < <(find "$dir/files" -type f -print0 | LC_ALL=C sort -z)

  tree=$(jq -n --arg base "$base_tree" --argjson entries "$entries" \
    '{base_tree: $base, tree: $entries}' \
    | api_write POST "repos/${REPO}/git/trees" | jq -er '.sha') || {
      report "#${number}: error, the tree could not be created"
      return 1
    }
  if [ "$tree" = "$head_tree" ]; then
    report "#${number}: the repair produced no change"
    return 3
  fi

  # No author or committer is sent: GitHub then signs the commit itself.
  commit=$(jq -n --arg message "$message" --arg tree "$tree" --argjson parents "$parents" \
    '{message: $message, tree: $tree, parents: $parents}' \
    | api_write POST "repos/${REPO}/git/commits" | jq -er '.sha') || {
      report "#${number}: error, the commit could not be created"
      return 1
    }
  if ! is_sha "$commit" || ! api "repos/${REPO}/commits/${commit}" | repair_commit_verified "$parents"; then
    report "#${number}: error, the repair commit is not a verified ${REPAIR_LOGIN} commit; the branch is unchanged"
    return 3
  fi

  # A fast-forward only: the update fails if the branch moved.
  if jq -n --arg sha "$commit" '{sha: $sha, force: false}' \
      | api_write PATCH "repos/${REPO}/git/refs/heads/${ref}" > /dev/null; then
    report "#${number}: repair published as ${commit} on top of ${head}"
  else
    report "#${number}: error, the branch refused the repair commit ${commit}"
    return 3
  fi
}

# Prints "<state> <run id>" for the newest run of a workflow for a commit on a
# branch, among runs raised by the given events (a JSON array). The state is:
#   missing  no such run exists;
#   active   the run has not completed;
#   passed   the run succeeded;
#   failed   the run failed again after a rerun, which makes it a finding;
#   retry    the run was cancelled, or failed and has not been rerun.
run_state() {
  api "repos/${REPO}/actions/workflows/${1}/runs?head_sha=${2}&per_page=100" \
    | jq -er --arg head "$2" --arg branch "$3" --argjson events "$4" '
        [.workflow_runs[] | select(.head_sha == $head and .head_branch == $branch
          and (.event as $event | $events | index($event) != null))]
        | sort_by(.run_started_at // "", .id) | last
        | if . == null then "missing 0"
          elif .status != "completed" then "active \(.id)"
          elif .conclusion == "success" then "passed \(.id)"
          elif .conclusion == "failure" and (.run_attempt // 1) >= 2 then "failed \(.id)"
          else "retry \(.id)"
          end'
}

# Reruns the jobs of a run that did not succeed.
rerun() {
  local workflow="$1" run="$2" sha="$3"
  [[ "$run" =~ ^[1-9][0-9]*$ ]] || return 1
  # A cancelled run may hold no failed job, which the first form refuses.
  if gh run rerun "$run" --repo "$REPO" --failed || gh run rerun "$run" --repo "$REPO"; then
    report "${workflow}: rerun requested for run ${run} at ${sha}"
  else
    report "${workflow}: error, the rerun of run ${run} at ${sha} was refused"
    return 1
  fi
}

# Dispatches a workflow and confirms that a run exists for the intended commit.
dispatch_and_confirm() {
  local workflow="$1" ref="$2" sha="$3" state attempt
  shift 3
  if ! gh workflow run "$workflow" --repo "$REPO" --ref "$ref" "$@"; then
    report "${workflow}: error, dispatch failed for ${sha}"
    return 1
  fi
  for ((attempt = 0; attempt < DISPATCH_POLLS; attempt++)); do
    if state=$(run_state "$workflow" "$sha" "$ref" '["push", "workflow_dispatch"]') \
        && [ "${state%% *}" != "missing" ]; then
      report "${workflow}: dispatched for ${sha} on ${ref}"
      return 0
    fi
    sleep "$DISPATCH_POLL_SECONDS"
  done
  report "${workflow}: error, no run appeared for ${sha} on ${ref} after dispatch"
  return 1
}

ensure_validation_runs() {
  local numbers number result sha ref main workflow state events dispatchable failures=0
  local -a inputs

  main=$(main_head) || return 2
  numbers=$(open_dependabot_pulls) || return 2
  for number in $numbers; do
    result=$(classify "$number") || continue
    [ "$(jq -r '.decision' <<< "$result")" != "manual" ] || continue
    sha=$(jq -r '.head_sha' <<< "$result")
    ref=$(jq -r '.head_ref' <<< "$result")
    [[ "$ref" =~ ^dependabot/[A-Za-z0-9._/+-]+$ ]] || continue

    # Dependabot's own push starts pull request runs. A head that this
    # automation committed has none that count, and is validated by dispatch.
    if [ "$(jq -r '.repairs' <<< "$result")" -gt 0 ]; then
      events='["push", "workflow_dispatch"]'
    else
      events='["pull_request", "pull_request_review", "push", "workflow_dispatch"]'
    fi
    dispatchable=""

    for workflow in "${VALIDATION_WORKFLOWS[@]}"; do
      if ! state=$(run_state "$workflow" "$sha" "$ref" "$events"); then
        report "#${number}: error, ${workflow} runs are unreadable for ${sha}"
        failures=$((failures + 1))
        continue
      fi
      case "${state%% *}" in
        retry)
          rerun "$workflow" "${state##* }" "$sha" || failures=$((failures + 1))
          continue
          ;;
        missing) [ "$(jq -r '.repairs' <<< "$result")" -gt 0 ] || continue ;;
        *) continue ;;
      esac

      # The dispatched run executes the branch copy of each workflow. That
      # copy is the main copy, or the main copy with an eligible update whose
      # added lines are all actions pinned to a commit.
      if [ -z "$dispatchable" ]; then
        dispatchable=false
        if [ "$(workflow_tree "$sha")" = "$(workflow_tree "$main")" ] \
            || { [ "$(jq -r '.ecosystem + " " + .decision' <<< "$result")" = "github-actions eligible" ] \
              && is_ancestor "$main" "$sha"; }; then
          dispatchable=true
        fi
      fi
      if [ "$dispatchable" = "false" ]; then
        report "#${number}: validation not dispatched, the branch workflows differ from ${BRANCH}"
        break
      fi
      if [ "$(api "repos/${REPO}/pulls/${number}" | jq -r '.head.sha')" != "$sha" ]; then
        report "#${number}: the head moved past ${sha}; the next run covers the new head"
        break
      fi
      case "$workflow" in
        audit.yml) inputs=(-f "dependency_review_base=${main}") ;;
        dependabot-automerge.yml) inputs=(-f "pull_request=${number}") ;;
        *) inputs=() ;;
      esac
      dispatch_and_confirm "$workflow" "$ref" "$sha" "${inputs[@]}" || failures=$((failures + 1))
    done
  done

  [ "$failures" -eq 0 ]
}

ensure_mainline_runs() {
  local head workflow state failures=0

  head=$(main_head) || {
    echo "error: the ${BRANCH} head commit is unreadable" >&2
    return 2
  }

  for workflow in "${MAINLINE_WORKFLOWS[@]}"; do
    if ! state=$(run_state "$workflow" "$head" "$BRANCH" '["push", "workflow_dispatch"]'); then
      report "${workflow}: error, runs are unreadable for ${head}"
      failures=$((failures + 1))
      continue
    fi
    case "${state%% *}" in
      retry)
        rerun "$workflow" "${state##* }" "$head" || failures=$((failures + 1))
        continue
        ;;
      missing) ;;
      *)
        report "${workflow}: a run exists for ${head}"
        continue
        ;;
    esac
    if [ "$(main_head)" != "$head" ]; then
      report "${workflow}: ${BRANCH} moved past ${head}; the next reconcile covers the new head"
      continue
    fi
    dispatch_and_confirm "$workflow" "$BRANCH" "$head" || failures=$((failures + 1))
  done

  [ "$failures" -eq 0 ]
}

case "${1:-}" in
  classify)
    [ "$#" -eq 2 ] || usage
    classify "$2"
    ;;
  gate)
    [ "$#" -eq 2 ] || usage
    gate "$2"
    ;;
  reconcile)
    [ "$#" -eq 1 ] || usage
    reconcile
    ;;
  repair-plan)
    [ "$#" -eq 2 ] || usage
    repair_plan "$2"
    ;;
  publish-repair)
    [ "$#" -eq 2 ] || usage
    publish_repair "$2"
    ;;
  ensure-validation-runs)
    [ "$#" -eq 1 ] || usage
    ensure_validation_runs
    ;;
  ensure-mainline-runs)
    [ "$#" -eq 1 ] || usage
    ensure_mainline_runs
    ;;
  *) usage ;;
esac
