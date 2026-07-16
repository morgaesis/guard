#!/bin/bash -eu

cd "$SRC/guard"
cargo fuzz build -O --debug-assertions

host_target="$(rustc -vV | sed -n 's/^host: //p')"
for target_source in fuzz/fuzz_targets/*.rs; do
    target_name="$(basename "${target_source%.rs}")"
    cp "fuzz/target/${host_target}/release/${target_name}" "$OUT/${target_name}"

    # Package the checked-in seeds per ClusterFuzzLite convention
    # (<target>_seed_corpus.zip next to the fuzzer binary) so every CI run
    # starts from the seed corpus even without a storage repository.
    corpus_dir="fuzz/corpus/${target_name}"
    if [ -d "$corpus_dir" ]; then
        zip -q -j "$OUT/${target_name}_seed_corpus.zip" "$corpus_dir"/*
    fi
done
