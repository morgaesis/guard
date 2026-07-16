FROM gcr.io/oss-fuzz-base/base-builder-rust:latest@sha256:d1b7545a6a5680d66886e9ee729f6575e0e885143a1bb74289f14e7e91de3463

# The base image ships the nightly toolchain that OSS-Fuzz pins and tests
# against cargo-fuzz, so no toolchain is installed or pinned here: a
# hand-maintained date pin rots silently, while the image digest above is
# kept current by Dependabot, advancing the toolchain together with the rest
# of the fuzzing environment.

COPY . $SRC/guard
WORKDIR $SRC/guard
COPY .clusterfuzzlite/build.sh $SRC/
