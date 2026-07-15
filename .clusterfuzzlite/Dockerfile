FROM gcr.io/oss-fuzz-base/base-builder-rust:latest@sha256:d1b7545a6a5680d66886e9ee729f6575e0e885143a1bb74289f14e7e91de3463

ENV RUSTUP_TOOLCHAIN=nightly-2026-07-15
RUN rustup toolchain install "$RUSTUP_TOOLCHAIN" --profile minimal

COPY . $SRC/guard
WORKDIR $SRC/guard
COPY .clusterfuzzlite/build.sh $SRC/
