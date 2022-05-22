#!/bin/bash

# Build HTML coverage report. Requires Rust 1.60+ with llvm-tools-preview component
# Run this script from the root directory of the repo.

set -eux

ROOT_PATH=$(dirname "$(readlink -f "$0")")/..

cd $ROOT_PATH
rm -rf ./coverage

export LLVM_PROFILE_FILE="$ROOT_PATH/coverage/profiles/%p.profraw"

# Run all tests with coverage
RUSTFLAGS="-C instrument-coverage" cargo test --all-features

# Merge different profraw files
$(rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-profdata \
    merge -sparse ./coverage/profiles/*.profraw -o coverage/profiles/merge.profdata

# Build list of executables, should be the list of test binaries :/
BINS=$(find target/debug/deps -type f -executable | grep -v '.so$')

# Generate HTML report in coverage directory
$(rustc --print sysroot)/lib/rustlib/x86_64-unknown-linux-gnu/bin/llvm-cov \
    show --Xdemangler=rustfilt \
    $(echo $BINS | xargs -d' ' -I{} echo --object '{}') \
    --instr-profile=./coverage/profiles/merge.profdata \
    --show-line-counts-or-regions \
    --show-instantiations \
    --ignore-filename-regex='/.cargo/(registry|git)' \
    --use-color \
    --output-dir coverage \
    --format html
