FROM gcr.io/oss-fuzz-base/base-builder-rust:latest@sha256:d1b7545a6a5680d66886e9ee729f6575e0e885143a1bb74289f14e7e91de3463

# The dependency tree needs a newer nightly than the base image ships
# (libsqlite3-sys's build script uses the unstable `cfg_select` feature), so
# track the nightly channel instead of a hand-rotated date pin: this image is
# rebuilt on every fuzzing run, so the channel resolves to the current nightly
# at build time and cannot rot silently.
ENV RUSTUP_TOOLCHAIN=nightly
RUN rustup toolchain install "$RUSTUP_TOOLCHAIN" --profile minimal

COPY . $SRC/guard
WORKDIR $SRC/guard
COPY .clusterfuzzlite/build.sh $SRC/
