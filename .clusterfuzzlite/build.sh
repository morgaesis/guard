#!/bin/bash -eu

cd "$SRC/guard"
cargo fuzz build -O --debug-assertions

host_target="$(rustc -vV | sed -n 's/^host: //p')"
for target_source in fuzz/fuzz_targets/*.rs; do
    target_name="$(basename "${target_source%.rs}")"
    cp "fuzz/target/${host_target}/release/${target_name}" "$OUT/${target_name}"
done
