#!/usr/bin/env bash
set -euo pipefail

# Publishes already-attested release assets for one signed tag. The caller is
# responsible for validation and provenance creation; this script verifies the
# local manifest, resumes only an identical draft, and verifies a published
# release before treating it as complete.

usage() {
  echo "usage: $0 --artifacts-dir <directory> --checksums <file>" >&2
  exit 64
}

artifacts_dir=""
checksums_file=""
while (($#)); do
  case "$1" in
    --artifacts-dir)
      artifacts_dir="${2:-}"
      shift 2
      ;;
    --checksums)
      checksums_file="${2:-}"
      shift 2
      ;;
    *) usage ;;
  esac
done

if [ -z "$artifacts_dir" ] || [ -z "$checksums_file" ]; then
  usage
fi
[ -d "$artifacts_dir" ] || { echo "artifact directory is missing" >&2; exit 1; }
[ -f "$checksums_file" ] || { echo "checksum manifest is missing" >&2; exit 1; }
: "${RELEASE_TAG:?RELEASE_TAG is required}"
: "${GITHUB_REPOSITORY:?GITHUB_REPOSITORY is required}"
[[ "$RELEASE_TAG" =~ ^v[0-9]+\.[0-9]+\.[0-9]+$ ]] || {
  echo "release tag is malformed" >&2
  exit 1
}

mapfile -d '' archives < <(
  find "$artifacts_dir" -type f \( -name '*.tar.gz' -o -name '*.cdx.json' \) -print0 | LC_ALL=C sort -z
)
[ "${#archives[@]}" -gt 0 ] || { echo "no release assets found" >&2; exit 1; }

validate_reproducible_archive() {
  local archive="$1"
  python3 - "$archive" <<'PY'
import pathlib
import sys
import tarfile

archive_path = pathlib.Path(sys.argv[1])
header = archive_path.read_bytes()[:10]
if len(header) != 10 or header[:3] != b"\x1f\x8b\x08":
    raise SystemExit(f"release archive is not gzip encoded: {archive_path.name}")
flags = header[3]
mtime = int.from_bytes(header[4:8], "little")
if mtime != 0 or flags & 0x08:
    raise SystemExit(f"release archive has non-reproducible gzip metadata: {archive_path.name}")

with tarfile.open(archive_path, mode="r:gz") as release_archive:
    members = release_archive.getmembers()

if not members:
    raise SystemExit(f"release archive is empty: {archive_path.name}")
names = [member.name for member in members]
if names != sorted(names) or len(names) != len(set(names)):
    raise SystemExit(f"release archive members are not uniquely sorted: {archive_path.name}")
epochs = {member.mtime for member in members}
if len(epochs) != 1 or next(iter(epochs)) <= 0:
    raise SystemExit(f"release archive member timestamps are not canonical: {archive_path.name}")
for member in members:
    path = pathlib.PurePosixPath(member.name)
    if path.is_absolute() or ".." in path.parts:
        raise SystemExit(f"release archive contains an unsafe path: {archive_path.name}")
    if member.uid != 0 or member.gid != 0 or member.uname or member.gname:
        raise SystemExit(f"release archive ownership is not canonical: {archive_path.name}")
    expected_mode = 0o755 if member.isdir() else 0o777 if member.issym() else None
    if member.isfile():
        expected_mode = 0o755 if member.mode & 0o111 else 0o644
    if expected_mode is None or member.mode != expected_mode:
        raise SystemExit(f"release archive mode is not canonical: {archive_path.name}")
PY
}

for archive in "${archives[@]}"; do
  [[ "$archive" == *.tar.gz ]] || continue
  validate_reproducible_archive "$archive"
done

declare -A local_asset_paths=()
for local_asset in "${archives[@]}" "$checksums_file"; do
  asset_name=$(basename "$local_asset")
  if [[ -n "${local_asset_paths[$asset_name]+present}" ]]; then
    echo "duplicate release asset name: $asset_name" >&2
    exit 1
  fi
  local_asset_paths["$asset_name"]="$local_asset"
done
mapfile -t expected_assets < <(printf '%s\n' "${!local_asset_paths[@]}" | LC_ALL=C sort)

expected_checksums=$(mktemp)
cleanup_directory=$(mktemp -d)
trap 'rm -f -- "$expected_checksums"; rm -r -- "$cleanup_directory"' EXIT
for archive in "${archives[@]}"; do
  printf '%s  %s\n' "$(sha256sum "$archive" | cut -d ' ' -f 1)" "$(basename "$archive")"
done > "$expected_checksums"
diff -u "$expected_checksums" "$checksums_file"

verify_release_assets() {
  local published_directory asset verified attempt
  published_directory=$(mktemp -d "$cleanup_directory/published.XXXXXX")
  for asset in "${expected_assets[@]}"; do
    gh release download "$RELEASE_TAG" --dir "$published_directory" --pattern "$asset"
  done
  cmp --silent "$checksums_file" "$published_directory/$(basename "$checksums_file")"
  (
    cd "$published_directory"
    sha256sum --check "$(basename "$checksums_file")"
  )
  for asset in "${expected_assets[@]}"; do
    verified=false
    for attempt in 1 2 3 4 5 6; do
      if gh attestation verify "$published_directory/$asset" --repo "$GITHUB_REPOSITORY"; then
        verified=true
        break
      fi
      [ "$attempt" -lt 6 ] && sleep 5
    done
    [ "$verified" = true ] || {
      echo "provenance verification did not succeed for $asset" >&2
      exit 1
    }
  done
}

release_endpoint="repos/${GITHUB_REPOSITORY}/releases/tags/${RELEASE_TAG}"
headers="$cleanup_directory/headers"
api_error="$cleanup_directory/api-error"
if gh api --include --silent "$release_endpoint" > "$headers" 2> "$api_error"; then
  [ "$(awk 'NR == 1 { print $2 }' "$headers")" = 200 ] || {
    echo "release lookup returned an unexpected response" >&2
    exit 1
  }
  release=$(gh release view "$RELEASE_TAG" --json isDraft,tagName,assets)
  [ "$(jq -er '.tagName' <<< "$release")" = "$RELEASE_TAG" ] || exit 1
  is_draft=$(jq -r '.isDraft' <<< "$release")
  if [ "$is_draft" != true ]; then
    mapfile -t published_assets < <(jq -r '.assets[].name' <<< "$release" | LC_ALL=C sort -u)
    diff -u <(printf '%s\n' "${expected_assets[@]}") <(printf '%s\n' "${published_assets[@]}")
    verify_release_assets
    exit 0
  fi
else
  status=$(awk 'NR == 1 { print $2 }' "$headers")
  if [ "$status" != 404 ]; then
    sed -n '1,20p' "$api_error" >&2
    exit 1
  fi
  gh release create "$RELEASE_TAG" --draft --generate-notes --verify-tag
fi

mapfile -t existing_assets < <(gh release view "$RELEASE_TAG" --json assets --jq '.assets[].name' | LC_ALL=C sort -u)
for asset in "${existing_assets[@]}"; do
  if ! printf '%s\n' "${expected_assets[@]}" | grep -Fxq -- "$asset"; then
    echo "draft release contains an unexpected asset: $asset" >&2
    exit 1
  fi
done
existing_directory=$(mktemp -d "$cleanup_directory/existing.XXXXXX")
for asset in "${expected_assets[@]}"; do
  if printf '%s\n' "${existing_assets[@]}" | grep -Fxq -- "$asset"; then
    gh release download "$RELEASE_TAG" --dir "$existing_directory" --pattern "$asset"
    cmp --silent "${local_asset_paths[$asset]}" "$existing_directory/$asset" || {
      echo "draft release asset differs from the validated build: $asset" >&2
      exit 1
    }
  else
    gh release upload "$RELEASE_TAG" "${local_asset_paths[$asset]}"
  fi
done
mapfile -t actual_assets < <(gh release view "$RELEASE_TAG" --json assets --jq '.assets[].name' | LC_ALL=C sort -u)
diff -u <(printf '%s\n' "${expected_assets[@]}") <(printf '%s\n' "${actual_assets[@]}")
verify_release_assets
gh release edit "$RELEASE_TAG" --draft=false
