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
  "") ;;
  *)
    echo "usage: $0 [--matrix-json|--targets]" >&2
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
