FROM gcr.io/oss-fuzz-base/base-builder-rust:latest@sha256:e916d1cb7c6a7062cdd3851f216d4ecce7a6720da5f1f1964f90802bf25081c4

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
