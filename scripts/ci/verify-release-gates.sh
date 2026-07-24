#!/usr/bin/env bash
set -euo pipefail

# P15 release gate: turns docs/architecture/abuse-case-test-matrix.tsv into an
# enforced, traceable check. Fails closed (non-zero exit) if:
#   - the matrix or quarantine registry is missing, malformed, or incomplete;
#   - any AC-001..AC-032 row is missing, duplicated, or lacks a field its
#     status requires;
#   - any row marked `automated` names a test_ref that does not resolve to a
#     real, passing test (skippable with --skip-test-run for structural-only
#     checks, e.g. local iteration; CI must always run without that flag);
#   - any quarantined test has an expired (or malformed) expiry_date, or a
#     quarantined test_ref is also relied on by an `automated` gate row.
#
# See docs/architecture/abuse-case-test-matrix.md ("Minimum release gates")
# for what each status means and docs/architecture/p00-acceptance.tsv for the
# sibling P00 baseline/external-approval gate this script does not replace.

run_tests=1
for arg in "$@"; do
  case "$arg" in
    --skip-test-run) run_tests=0 ;;
    *)
      echo "usage: $0 [--skip-test-run]" >&2
      exit 64
      ;;
  esac
done

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
matrix="$repo_root/docs/architecture/abuse-case-test-matrix.tsv"
quarantine="$repo_root/docs/architecture/quarantined-tests.tsv"

fail() {
  echo "release gate verification: $*" >&2
  exit 1
}

[[ -f "$matrix" ]] || fail "missing abuse-case matrix: $matrix"
[[ -f "$quarantine" ]] || fail "missing quarantine registry: $quarantine"

# --- abuse-case matrix: header and per-row structure ---

header="$(head -n 1 "$matrix")"
expected_header=$'ac_id\tstatus\ttest_ref\towner\tcadence\tnotes'
[[ "$header" == "$expected_header" ]] || fail "matrix header is not canonical: $header"

awk -F'\t' '
  NR == 1 { next }
  {
    if (NF != 6) { printf "line %d has %d fields, expected 6\n", NR, NF; bad = 1; next }
    ac_id = $1; status = $2; test_ref = $3; owner = $4; cadence = $5; notes = $6

    if (ac_id !~ /^AC-0[0-9]{2}$/) {
      printf "line %d has an invalid ac_id: %s\n", NR, ac_id; bad = 1
    }
    if (++seen[ac_id] > 1) {
      printf "line %d duplicates ac_id %s\n", NR, ac_id; bad = 1
    }
    if (status != "automated" && status != "procedural" && status != "gap") {
      printf "line %d (%s) has an invalid status: %s\n", NR, ac_id, status; bad = 1
    }
    if (length(owner) == 0) {
      printf "line %d (%s) is missing owner\n", NR, ac_id; bad = 1
    }

    if (status == "automated") {
      if (length(test_ref) == 0) {
        printf "line %d (%s) is automated but has no test_ref\n", NR, ac_id; bad = 1
      }
      if (length(cadence) == 0) {
        printf "line %d (%s) is automated but has no cadence\n", NR, ac_id; bad = 1
      }
    } else if (status == "procedural") {
      if (length(cadence) == 0) {
        printf "line %d (%s) is procedural but has no cadence\n", NR, ac_id; bad = 1
      }
    } else if (status == "gap") {
      if (length(test_ref) != 0) {
        printf "line %d (%s) is a gap but names a test_ref; gaps must leave test_ref blank\n", NR, ac_id; bad = 1
      }
      if (length(notes) == 0) {
        printf "line %d (%s) is a gap but has no notes explaining or tracking it\n", NR, ac_id; bad = 1
      }
    }
  }
  END {
    if (NR - 1 != 32) {
      printf "matrix has %d data rows, expected exactly 32 (AC-001..AC-032)\n", NR - 1; bad = 1
    }
    for (i = 1; i <= 32; i++) {
      id = sprintf("AC-%03d", i)
      if (!(id in seen)) { printf "matrix is missing %s\n", id; bad = 1 }
    }
    exit bad
  }
' "$matrix" || fail "abuse-case matrix failed structural validation"

# --- quarantine registry: header, structure, and expiry ---

qheader="$(head -n 1 "$quarantine")"
expected_qheader=$'test_ref\towner\treason\texpiry_date'
[[ "$qheader" == "$expected_qheader" ]] || fail "quarantine header is not canonical: $qheader"

today="$(date -u +%Y-%m-%d)"
quarantined_refs=()
while IFS=$'\t' read -r test_ref owner reason expiry_date; do
  [[ "$test_ref" == "test_ref" ]] && continue
  [[ -z "$test_ref" ]] && continue
  [[ -n "$owner" && -n "$reason" && -n "$expiry_date" ]] ||
    fail "quarantine row for '$test_ref' is missing owner, reason, or expiry_date"
  [[ "$expiry_date" =~ ^[0-9]{4}-[0-9]{2}-[0-9]{2}$ ]] ||
    fail "quarantine row for '$test_ref' has a malformed expiry_date: $expiry_date"
  if [[ "$expiry_date" < "$today" ]]; then
    fail "quarantine row for '$test_ref' expired on $expiry_date (today: $today); fix or remove it"
  fi
  quarantined_refs+=("$test_ref")
done < "$quarantine"

# A quarantined test can never be the evidence backing an `automated` gate.
for ref in "${quarantined_refs[@]}"; do
  if grep -Fq "$ref" "$matrix"; then
    fail "quarantined test_ref '$ref' is referenced by the abuse-case matrix; quarantined tests cannot satisfy a gate"
  fi
done

if [[ "$run_tests" -eq 0 ]]; then
  echo "release gate verification: structural checks passed (test execution skipped via --skip-test-run)"
  exit 0
fi

# --- automated rows: test_ref must resolve to a real, passing test ---

cd "$repo_root"
checked=0
while IFS=$'\t' read -r ac_id status test_ref owner cadence notes; do
  [[ "$ac_id" == "ac_id" ]] && continue
  [[ "$status" == "automated" ]] || continue

  pkg="${test_ref%%::*}"
  test_path="${test_ref#*::}"
  [[ -n "$pkg" && -n "$test_path" && "$pkg" != "$test_path" ]] ||
    fail "$ac_id has an unparseable test_ref (expected crate::module::path::test_name): $test_ref"

  echo "release gate verification: running $ac_id -> $test_ref"
  output="$(cargo test -p "$pkg" "$test_path" -- --exact 2>&1)" ||
    { echo "$output" >&2; fail "$ac_id test_ref did not run cleanly: $test_ref"; }
  if ! grep -Eq '^test result: ok\. 1 passed; 0 failed;' <<<"$output"; then
    echo "$output" >&2
    fail "$ac_id test_ref did not resolve to exactly one passing test: $test_ref"
  fi
  checked=$((checked + 1))
done < "$matrix"

[[ "$checked" -gt 0 ]] || fail "no automated rows were verified; matrix or parser is broken"

echo "release gate verification: $checked automated abuse-case rows verified passing; matrix and quarantine registry structurally valid."
