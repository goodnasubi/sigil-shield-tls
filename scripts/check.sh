#!/usr/bin/env bash
set -euo pipefail

sigil_sha=7a256dedd61fa0888486f98a95e17006e2948813
rust_version=1.100.0
repo_root=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")/.." && pwd)
scratch=$(mktemp -d)
trap 'rm -rf -- "$scratch"' EXIT

fetch_pinned() {
  local url=$1 sha=$2 dir=$3
  git init -q "$dir"
  git -C "$dir" fetch --no-tags --depth=1 "$url" "$sha"
  git -C "$dir" checkout --detach FETCH_HEAD
  test "$(git -C "$dir" rev-parse HEAD)" = "$sha"
  test -z "$(git -C "$dir" status --porcelain --untracked-files=all)"
}

# The compiler embeds both the standard library and the native core.
sigil_root=${SIGIL_SOURCE:-"$scratch/sigil"}
if [[ -z ${SIGIL_SOURCE:-} ]]; then
  fetch_pinned https://github.com/goodnasubi/sigil.git "$sigil_sha" "$sigil_root"
fi
test "$(git -C "$sigil_root" rev-parse HEAD)" = "$sigil_sha"
test -z "$(git -C "$sigil_root" status --porcelain --untracked-files=all)"

cargo_target=${CARGO_TARGET_DIR:-target}
if [[ ! -x "$sigil_root/$cargo_target/release/sigil" ]]; then
  cd "$sigil_root"
  rustup toolchain install "$rust_version" --profile minimal --component rustfmt --component clippy
  cargo +"$rust_version" fmt --check
  cargo +"$rust_version" clippy --locked --all-targets -- -D warnings
  cargo +"$rust_version" build --locked --release --bin sigil
fi
sigil="$sigil_root/$cargo_target/release/sigil"

root="$scratch/root"
mkdir -p "$root"
cp "$repo_root"/sigil/*.sigil "$root/"
cp "$repo_root/Sigil.toml" "$root/"

"$sigil" fmt --check "$repo_root"/sigil/*.sigil

run_entry() {
  local entry=$1 label=$2 evaluator native
  "$sigil" check --root "$root" "$root/$entry.sigil"
  evaluator=$("$sigil" run --root "$root" "$root/$entry.sigil" main | tail -n 1)
  if [[ "$evaluator" != 0 ]]; then
    printf '%s: evaluator test failed (%s)\n' "$label" "$evaluator" >&2
    exit 1
  fi
  "$sigil" build --root "$root" "$root/$entry.sigil" main -o "$scratch/$entry"
  native=$("$scratch/$entry" | tail -n 1)
  if [[ "$native" != 0 ]]; then
    printf '%s: native test failed (%s)\n' "$label" "$native" >&2
    exit 1
  fi
  printf '%s: evaluator and native tests passed.\n' "$label"
}

run_entry stage1_limits_test "Stage 1 limits and thresholds"
run_entry stage1_record_test "Stage 1 record layer and reassembly"
run_entry stage1_client_hello_test "Stage 1 ClientHello parsing and validation"
run_entry stage1_progress_test "Stage 1 progress and timeout invariants"
run_entry stage1_fuzz_test "Stage 1 fuzzing harnesses"

run_entry stage2_cipher_suite_test "Stage 2 cipher suite definitions and selection"
run_entry stage2_key_schedule_test "Stage 2 key schedule derivation and RFC 8448 vectors"
run_entry stage2_record_crypto_test "Stage 2 record protection and RFC 8448 records"
run_entry stage2_key_update_test "Stage 2 key update and limits"

run_entry stage3_handshake_test "Stage 3 handshake state machine and RFC 8448 traces"

run_entry stage4_certificate_test "Stage 4 certificate loading and management"

run_entry stage5_relay_test "Stage 5 relay, proxy protocol v2, limits, and safe logging"

run_entry stage6_p256_test "Stage 6 P-256 key exchange, key_share validation, and HelloRetryRequest"

run_entry stage7_interop_load_test "Stage 7 interop, benchmark, and load records"

SIGIL_BIN="$sigil" "$repo_root/scripts/test_interop.sh"

printf 'All Stage 1, Stage 2, Stage 3, Stage 4, Stage 5, Stage 6, and Stage 7 evaluator, native, and external interop tests passed.\n'

