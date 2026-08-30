#!/usr/bin/env bash
set -euo pipefail

# Build one release target and package its canonical deployment archive. The
# workflow runs this script twice from independent clean source and target
# directories, then requires byte-identical archives before publication.

release_target_rows() {
  printf '%s\t%s\t%s\t%s\n' \
    x86_64-unknown-linux-gnu ubuntu-latest guard false \
    aarch64-unknown-linux-gnu ubuntu-latest guard true \
    x86_64-pc-windows-msvc windows-latest guard.exe false
}

write_archive_evidence() {
  local archive="$1" artifact="$2" manifest="$3" binary="$4"
  python3 - "$archive" "$artifact" "$binary" > "$manifest" <<'PY'
import hashlib
import pathlib
import sys
import tarfile

archive_path = pathlib.Path(sys.argv[1])
artifact_name = sys.argv[2]
binary_path = pathlib.Path(sys.argv[3])
binary_count = 0
file_count = 0

try:
    with tarfile.open(archive_path, mode="r:gz") as archive:
        for member in sorted(archive.getmembers(), key=lambda entry: entry.name):
            path = pathlib.PurePosixPath(member.name)
            if path.is_absolute() or ".." in path.parts:
                raise ValueError("archive contains an unsafe member name")
            if not member.isfile():
                continue
            file_count += 1
            if file_count > 200:
                raise ValueError("archive contains more than 200 files")
            source = archive.extractfile(member)
            if source is None:
                raise ValueError("archive file member is unreadable")
            is_binary = len(path.parts) == 2 and path.name == artifact_name
            if is_binary:
                binary_count += 1
                output = binary_path.open("wb")
            else:
                output = None
            digest = hashlib.sha256()
            try:
                while chunk := source.read(1024 * 1024):
                    digest.update(chunk)
                    if output is not None:
                        output.write(chunk)
            finally:
                source.close()
                if output is not None:
                    output.close()
            print(f"{digest.hexdigest()}  {member.name}")
except (OSError, tarfile.TarError, ValueError) as error:
    raise SystemExit(f"release archive diagnostics failed: {error}") from None

if binary_count != 1:
    raise SystemExit("release archive diagnostics require exactly one packaged binary")
PY
}

binary_contains_literal() {
  local binary="$1" literal="$2"
  if strings -a "$binary" | grep -F -- "$literal" >/dev/null; then
    printf 'yes'
  else
    printf 'no'
  fi
}

describe_binary() {
  local label="$1" binary="$2" source_root="$3" format build_id
  format=$(file -b "$binary")
  printf '%s binary format: %s\n' "$label" "$format" >&2
  printf '%s binary contains its source root: %s\n' \
    "$label" "$(binary_contains_literal "$binary" "$source_root")" >&2
  if [[ "$format" == ELF* ]]; then
    build_id=$(readelf -n "$binary" | sed -n 's/^[[:space:]]*Build ID: /Build ID: /p' | sed -n '1p')
    printf '%s %s\n' "$label" "${build_id:-Build ID: unavailable}" >&2
    printf '%s ELF sections (first 80 lines):\n' "$label" >&2
    readelf -SW "$binary" | sed -n '1,80p' | sed "s/^/${label} /" >&2
  fi
}

compare_release_archives() {
  local primary="$1" replica="$2" artifact="$3" target="$4"
  local primary_source="$5" replica_source="$6" diagnostic_root
  local primary_manifest replica_manifest primary_binary replica_binary
  if [ ! -f "$primary" ] || [ ! -f "$replica" ]; then
    echo "release archive comparison requires two regular files" >&2
    return 2
  fi
  case "$artifact" in
    guard|guard.exe) ;;
    *)
      echo "release archive comparison received an unexpected artifact name" >&2
      return 2
      ;;
  esac
  if [ -z "$primary_source" ] || [ -z "$replica_source" ]; then
    echo "release archive comparison requires both source roots" >&2
    return 2
  fi
  if cmp --silent "$primary" "$replica"; then
    return 0
  fi

  diagnostic_root=$(mktemp -d "${TMPDIR:-/tmp}/guard-release-compare.XXXXXX")
  primary_manifest="$diagnostic_root/primary.manifest"
  replica_manifest="$diagnostic_root/replica.manifest"
  primary_binary="$diagnostic_root/primary.binary"
  replica_binary="$diagnostic_root/replica.binary"
  write_archive_evidence "$primary" "$artifact" "$primary_manifest" "$primary_binary"
  write_archive_evidence "$replica" "$artifact" "$replica_manifest" "$replica_binary"

  echo "independent release builds produced different archives for $target" >&2
  echo "archive member digest differences (first 200 lines):" >&2
  diff -u --label primary-members --label replica-members \
    "$primary_manifest" "$replica_manifest" | sed -n '1,200p' >&2 || true
  describe_binary primary "$primary_binary" "$primary_source"
  describe_binary replica "$replica_binary" "$replica_source"
  echo "first differing packaged-binary bytes (offset, primary, replica; first 32 lines):" >&2
  set +o pipefail
  timeout 5s cmp -l "$primary_binary" "$replica_binary" | head -32 >&2
  set -o pipefail
  rm -rf -- "$diagnostic_root"
  return 1
}

test_archive_comparison() {
  local test_root bundle shell_binary diagnostic
  test_root=$(mktemp -d "${TMPDIR:-/tmp}/guard-release-test.XXXXXX")
  bundle="$test_root/guard-fixture-aarch64-unknown-linux-gnu"
  shell_binary=$(readlink -f "/proc/$$/exe")
  diagnostic="$test_root/diagnostic.txt"
  mkdir -p "$bundle"
  cp "$shell_binary" "$bundle/guard"
  printf 'primary fixture\n' > "$bundle/README.md"
  tar -C "$test_root" -czf "$test_root/primary.tar.gz" "$(basename "$bundle")"
  compare_release_archives \
    "$test_root/primary.tar.gz" "$test_root/primary.tar.gz" guard fixture-target \
    "$test_root/source-primary" "$test_root/source-replica"
  printf 'replica fixture\n' > "$bundle/README.md"
  tar -C "$test_root" -czf "$test_root/replica.tar.gz" "$(basename "$bundle")"
  if compare_release_archives \
    "$test_root/primary.tar.gz" "$test_root/replica.tar.gz" guard fixture-target \
    "$test_root/source-primary" "$test_root/source-replica" \
    > "$diagnostic" 2>&1; then
    echo "release archive comparison accepted different archives" >&2
    rm -rf -- "$test_root"
    return 1
  fi
  grep -Fq 'archive member digest differences' "$diagnostic"
  grep -Fq 'primary ELF sections' "$diagnostic"
  grep -Fq 'first differing packaged-binary bytes' "$diagnostic"
  rm -rf -- "$test_root"
  echo "release archive comparison tests passed"
}

case "${1:-}" in
  --matrix-json)
    release_target_rows | python3 -c '
import json
import sys

rows = []
for line in sys.stdin:
    target, operating_system, artifact_name, use_cross = line.rstrip("\n").split("\t")
    rows.append({
        "target": target,
        "os": operating_system,
        "artifact_name": artifact_name,
        "use_cross": use_cross == "true",
    })
print(json.dumps({"include": rows}, separators=(",", ":")))
'
    exit 0
    ;;
  --targets)
    release_target_rows | cut -f1
    exit 0
    ;;
  --compare-archives)
    [ "$#" -eq 7 ] || {
      echo "usage: $0 --compare-archives PRIMARY REPLICA ARTIFACT TARGET PRIMARY_SOURCE REPLICA_SOURCE" >&2
      exit 2
    }
    compare_release_archives "$2" "$3" "$4" "$5" "$6" "$7"
    exit $?
    ;;
  --test-archive-comparison)
    [ "$#" -eq 1 ] || {
      echo "usage: $0 --test-archive-comparison" >&2
      exit 2
    }
    test_archive_comparison
    exit 0
    ;;
  "") ;;
  *)
    echo "usage: $0 [--matrix-json|--targets|--test-archive-comparison]" >&2
    exit 2
    ;;
esac

: "${BUILD_TARGET:?BUILD_TARGET is required}"
: "${ARTIFACT_NAME:?ARTIFACT_NAME is required}"
: "${RELEASE_LABEL:?RELEASE_LABEL is required}"
: "${SOURCE_DATE_EPOCH:?SOURCE_DATE_EPOCH is required}"

expected_artifact=""
expected_cross=""
while IFS=$'\t' read -r target _ artifact use_cross; do
  if [ "$target" = "$BUILD_TARGET" ]; then
    expected_artifact="$artifact"
    expected_cross="$use_cross"
  fi
done < <(release_target_rows)
[ -n "$expected_artifact" ] || {
  echo "unsupported release target: $BUILD_TARGET" >&2
  exit 1
}
[ "$ARTIFACT_NAME" = "$expected_artifact" ] || {
  echo "release artifact does not match target $BUILD_TARGET" >&2
  exit 1
}
[ "${USE_CROSS:-false}" = "$expected_cross" ] || {
  echo "release compiler selection does not match target $BUILD_TARGET" >&2
  exit 1
}
[[ "$SOURCE_DATE_EPOCH" =~ ^[1-9][0-9]*$ ]] || {
  echo "source commit has an invalid timestamp" >&2
  exit 1
}

source_root="${SOURCE_ROOT:-$PWD}"
dist_dir="${DIST_DIR:-$source_root/dist}"
export CARGO_TARGET_DIR="${CARGO_TARGET_DIR:-$source_root/target}"
bundle="guard-${RELEASE_LABEL}-${BUILD_TARGET}"
archive="$dist_dir/${bundle}.tar.gz"
root="$dist_dir/$bundle"
if [ -e "$root" ] || [ -e "$archive" ]; then
  echo "release output already exists for $BUILD_TARGET" >&2
  exit 1
fi

cd "$source_root"
if [ "${USE_CROSS:-false}" = true ]; then
  [ "$BUILD_TARGET" = aarch64-unknown-linux-gnu ] || {
    echo "cross compilation selected for an unexpected target" >&2
    exit 1
  }
  cross build --locked --release --target "$BUILD_TARGET"
else
  [ "$BUILD_TARGET" != aarch64-unknown-linux-gnu ] || {
    echo "aarch64 Linux release requires cross compilation" >&2
    exit 1
  }
  cargo build --locked --release --target "$BUILD_TARGET"
fi

binary="$CARGO_TARGET_DIR/$BUILD_TARGET/release/$ARTIFACT_NAME"
if [ "$BUILD_TARGET" = x86_64-unknown-linux-gnu ]; then
  strip "$binary"
fi

mkdir -p "$root/deployment/systemd" "$root/deployment/hardening" \
  "$root/deployment/windows" "$root/examples" "$root/docs" "$root/ctf"
cp "$binary" "$root/$ARTIFACT_NAME"
binary_hash=$(sha256sum "$root/$ARTIFACT_NAME" | cut -d ' ' -f 1)
printf '%s  %s\n' "$binary_hash" "$ARTIFACT_NAME" > "$root/BINARY-SHA256"
cp README.md INSTALL.md DEPLOYMENT.md DEVELOPMENT.md SECURITY.md \
  ARCHITECTURE.md ROADMAP.md LICENSE .env.example "$root/"
cp docs/*.md "$root/docs/"
cp ctf/DESIGN.md "$root/ctf/"
cp examples/*.yaml examples/*.md examples/fallback-models.env "$root/examples/"
cp deployment/systemd/guard.service \
  deployment/systemd/guard-exec-as-caller.service \
  deployment/systemd/guard.env.example \
  deployment/systemd/guard-operator \
  deployment/systemd/test-guard-service-expansion.sh \
  deployment/systemd/upgrade-guard \
  deployment/systemd/test-upgrade-guard.sh \
  "$root/deployment/systemd/"
cp deployment/hardening/guard.apparmor.example \
  deployment/hardening/seccomp-deny-escape.json \
  "$root/deployment/hardening/"
cp deployment/windows/install-guard.ps1 \
  deployment/windows/install-guard.Tests.ps1 \
  "$root/deployment/windows/"

case "$BUILD_TARGET" in
  *-linux-gnu)
    chmod 0755 "$root/$ARTIFACT_NAME" \
      "$root/deployment/systemd/guard-operator" \
      "$root/deployment/systemd/test-guard-service-expansion.sh" \
      "$root/deployment/systemd/upgrade-guard" \
      "$root/deployment/systemd/test-upgrade-guard.sh"
    (
      cd "$root"
      sha256sum \
        "$ARTIFACT_NAME" \
        deployment/systemd/guard-operator \
        deployment/systemd/guard.service \
        deployment/systemd/guard-exec-as-caller.service \
        deployment/systemd/upgrade-guard \
        > INSTALL-SHA256
    )
    ;;
  x86_64-pc-windows-msvc) ;;
esac

find "$root" -type f -printf '%P\n' | LC_ALL=C sort > "$root/ARCHIVE-MANIFEST"
ROOT="$root" BUNDLE="$bundle" ARCHIVE="$archive" python3 <<'PY'
import gzip
import os
import pathlib
import tarfile

bundle = os.environ["BUNDLE"]
source_date_epoch = int(os.environ["SOURCE_DATE_EPOCH"])
root = pathlib.Path(os.environ["ROOT"])
output = pathlib.Path(os.environ["ARCHIVE"])

paths = [root, *sorted(root.rglob("*"), key=lambda path: path.relative_to(root).as_posix())]
with output.open("wb") as raw:
    with gzip.GzipFile(filename="", mode="wb", fileobj=raw, mtime=0, compresslevel=9) as compressed:
        with tarfile.open(fileobj=compressed, mode="w", format=tarfile.USTAR_FORMAT) as archive:
            for path in paths:
                arcname = bundle if path == root else f"{bundle}/{path.relative_to(root).as_posix()}"
                info = archive.gettarinfo(str(path), arcname=arcname)
                info.uid = 0
                info.gid = 0
                info.uname = ""
                info.gname = ""
                info.mtime = source_date_epoch
                if info.isdir():
                    info.mode = 0o755
                elif info.isfile():
                    info.mode = 0o755 if info.mode & 0o111 else 0o644
                elif info.issym():
                    info.mode = 0o777
                if info.isfile():
                    with path.open("rb") as source:
                        archive.addfile(info, source)
                else:
                    archive.addfile(info)
PY
