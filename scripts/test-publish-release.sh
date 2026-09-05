#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
publication_script="$repo_root/scripts/publish-release.sh"

test -x "$publication_script" || {
  echo "release publication script is not executable" >&2
  exit 1
}

workspace=$(mktemp -d)
trap 'rm -r -- "$workspace"' EXIT
mkdir -p "$workspace/artifacts/a" "$workspace/artifacts/b" "$workspace/artifacts/c"
create_archive_fixture() {
  local output="$1" entry="$2" content="$3"
  python3 - "$output" "$entry" "$content" <<'PY'
import gzip
import io
import pathlib
import sys
import tarfile

output = pathlib.Path(sys.argv[1])
entry = sys.argv[2]
content = sys.argv[3].encode()
with output.open("wb") as raw:
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            root = tarfile.TarInfo("fixture")
            root.type = tarfile.DIRTYPE
            root.mode = 0o755
            root.mtime = 1_700_000_000
            archive.addfile(root)
            item = tarfile.TarInfo(f"fixture/{entry}")
            item.mode = 0o644
            item.mtime = root.mtime
            item.size = len(content)
            archive.addfile(item, io.BytesIO(content))
PY
}

write_checksums() {
  local artifacts="$1" destination="$2"
  find "$artifacts" -type f \( -name '*.tar.gz' -o -name '*.cdx.json' \) -print \
    | LC_ALL=C sort | while IFS= read -r asset; do
      printf '%s  %s\n' "$(sha256sum "$asset" | cut -d ' ' -f 1)" "$(basename "$asset")"
    done > "$destination"
}

create_archive_fixture "$workspace/artifacts/a/one.tar.gz" one.txt one
create_archive_fixture "$workspace/artifacts/b/two.tar.gz" two.txt two
printf sbom > "$workspace/artifacts/c/three.cdx.json"
printf ignore > "$workspace/artifacts/c/notes.txt"
write_checksums "$workspace/artifacts" "$workspace/SHA256SUMS"
[ "$(wc -l < "$workspace/SHA256SUMS")" -eq 3 ]
if grep -Fq notes.txt "$workspace/SHA256SUMS"; then
  echo "checksum manifest included an unexpected file type" >&2
  exit 1
fi

gh() {
  local command="$1" subcommand="$2"
  shift 2
  printf '%q ' "$command" "$subcommand" "$@" >> "$MOCK_RELEASE_STATE/calls"
  printf '\n' >> "$MOCK_RELEASE_STATE/calls"
  case "$command:$subcommand" in
    api:--include)
      case "$(<"$MOCK_RELEASE_STATE/mode")" in
        missing)
          printf 'HTTP/2.0 404 Not Found\n\n'
          return 1
          ;;
        api-error)
          printf 'HTTP/2.0 503 Service Unavailable\n\n'
          printf 'temporary API failure\n' >&2
          return 1
          ;;
        *) printf 'HTTP/2.0 200 OK\n\n' ;;
      esac
      ;;
    release:view)
      local tag="$1" is_draft=false assets
      shift
      [ "$(<"$MOCK_RELEASE_STATE/mode")" != missing ] || return 1
      if [[ " $* " == *" --jq "* ]]; then
        find "$MOCK_RELEASE_STATE/assets" -maxdepth 1 -type f -printf '%f\n' | LC_ALL=C sort
        return 0
      fi
      [ "$(<"$MOCK_RELEASE_STATE/mode")" = draft ] && is_draft=true
      assets=$(find "$MOCK_RELEASE_STATE/assets" -maxdepth 1 -type f -printf '%f\n' | LC_ALL=C sort | jq -R . | jq -s 'map({name: .})')
      jq -n --arg tag "$tag" --argjson draft "$is_draft" --argjson assets "$assets" '{isDraft: $draft, tagName: $tag, assets: $assets}'
      ;;
    release:create) printf '%s\n' draft > "$MOCK_RELEASE_STATE/mode" ;;
    release:upload)
      local tag="$1"
      shift
      for asset in "$@"; do cp -- "$asset" "$MOCK_RELEASE_STATE/assets/$(basename "$asset")"; done
      ;;
    release:download)
      local tag="$1" directory="" asset=""
      shift
      while (($#)); do
        case "$1" in
          --dir) directory="$2"; shift 2 ;;
          --pattern) asset="$2"; shift 2 ;;
          *) exit 1 ;;
        esac
      done
      cp -- "$MOCK_RELEASE_STATE/assets/$asset" "$directory/$asset"
      ;;
    release:edit) printf '%s\n' published > "$MOCK_RELEASE_STATE/mode" ;;
    attestation:verify) ;;
    *)
      printf 'unexpected gh invocation: %s %s\n' "$command" "$subcommand" >&2
      return 1
      ;;
  esac
}
export -f gh

run_case() {
  local initial_state="$1" case_directory="$2"
  mkdir -p "$case_directory/state/assets"
  : > "$case_directory/state/calls"
  cp -R "$workspace/artifacts" "$case_directory/artifacts"
  cp "$workspace/SHA256SUMS" "$case_directory/SHA256SUMS"
  case "$initial_state" in
    draft-stale)
      printf '%s\n' draft > "$case_directory/state/mode"
      printf stale > "$case_directory/state/assets/stale.tar.gz"
      ;;
    draft-partial)
      printf '%s\n' draft > "$case_directory/state/mode"
      cp "$case_directory/artifacts/a/one.tar.gz" "$case_directory/state/assets/"
      ;;
    draft-clean) printf '%s\n' draft > "$case_directory/state/mode" ;;
    published|mismatched)
      printf '%s\n' published > "$case_directory/state/mode"
      cp "$case_directory/artifacts/a/one.tar.gz" "$case_directory/artifacts/b/two.tar.gz" "$case_directory/artifacts/c/three.cdx.json" "$case_directory/SHA256SUMS" "$case_directory/state/assets/"
      [ "$initial_state" = mismatched ] && printf stale > "$case_directory/state/assets/two.tar.gz"
      ;;
    nonreproducible)
      printf '%s\n' missing > "$case_directory/state/mode"
      python3 - "$case_directory/artifacts/a/one.tar.gz" <<'PY'
import pathlib
import sys

archive = pathlib.Path(sys.argv[1])
content = bytearray(archive.read_bytes())
content[4:8] = (1).to_bytes(4, "little")
archive.write_bytes(content)
PY
      write_checksums "$case_directory/artifacts" "$case_directory/SHA256SUMS"
      ;;
    *) printf '%s\n' "$initial_state" > "$case_directory/state/mode" ;;
  esac
  (
    cd "$case_directory"
    export MOCK_RELEASE_STATE="$case_directory/state"
    export GITHUB_REPOSITORY=example/guard
    export RELEASE_TAG=v0.0.1
    bash "$publication_script" --artifacts-dir artifacts --checksums SHA256SUMS >/dev/null
  )
}

stale_case="$workspace/stale"
if run_case draft-stale "$stale_case"; then
  echo "draft release with an unexpected asset was accepted" >&2
  exit 1
fi
[ "$(<"$stale_case/state/mode")" = draft ]
if grep -Eq '^release (create|upload|edit) ' "$stale_case/state/calls"; then
  echo "invalid draft state was mutated" >&2
  exit 1
fi

for state in draft-partial draft-clean; do
  case_directory="$workspace/$state"
  run_case "$state" "$case_directory"
  [ "$(<"$case_directory/state/mode")" = published ]
  grep -q '^release upload ' "$case_directory/state/calls"
  grep -q '^release edit ' "$case_directory/state/calls"
done

matching_case="$workspace/matching"
run_case published "$matching_case"
[ "$(<"$matching_case/state/mode")" = published ]
if grep -Eq '^release (create|upload|edit) ' "$matching_case/state/calls"; then
  echo "matching published release was mutated" >&2
  exit 1
fi

for state in mismatched api-error nonreproducible; do
  case_directory="$workspace/$state"
  if run_case "$state" "$case_directory"; then
    echo "invalid release state was accepted: $state" >&2
    exit 1
  fi
  if grep -Eq '^release (create|upload|edit) ' "$case_directory/state/calls"; then
    echo "invalid release state was mutated: $state" >&2
    exit 1
  fi
done

echo "release publication mock tests passed"
