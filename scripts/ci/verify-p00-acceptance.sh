#!/usr/bin/env bash
set -euo pipefail

mode="${1:-baseline}"
case "$mode" in
  baseline|external-ready) ;;
  *)
    echo "usage: $0 baseline|external-ready" >&2
    exit 64
    ;;
esac

repo_root="$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)"
registry="$repo_root/docs/architecture/p00-acceptance.tsv"

fail() {
  echo "P00 acceptance verification: $*" >&2
  exit 1
}

[[ -f "$registry" ]] || fail "missing registry: $registry"

header="$(head -n 1 "$registry")"
expected_header=$'gate_id\tstatus\tdue_before\tevidence_requirement\tevidence_path'
[[ "$header" == "$expected_header" ]] || fail "registry header is not canonical"

awk -F '\t' '
  NR == 1 { next }
  NF != 5 { printf "line %d has %d fields, expected 5\n", NR, NF; bad = 1 }
  $1 !~ /^P00-[A-Z0-9-]+$/ { printf "line %d has invalid gate id\n", NR; bad = 1 }
  $2 != "baseline_present" && $2 != "external_required" {
    printf "line %d has invalid status\n", NR; bad = 1
  }
  length($3) == 0 || length($4) < 24 || length($5) == 0 {
    printf "line %d has incomplete evidence requirements\n", NR; bad = 1
  }
  seen[$1]++ { printf "duplicate gate id %s\n", $1; bad = 1 }
  END { if (NR < 2) bad = 1; exit bad }
' "$registry" || fail "registry structure is invalid"

while IFS=$'\t' read -r gate_id status due_before requirement evidence_path; do
  [[ "$gate_id" == "gate_id" ]] && continue
  case "$evidence_path" in
    /*|*".."*) fail "$gate_id uses a non-repository evidence path: $evidence_path" ;;
  esac
  full_path="$repo_root/$evidence_path"
  if [[ "$status" == "baseline_present" ]]; then
    [[ -s "$full_path" ]] || fail "$gate_id baseline evidence is missing: $evidence_path"
  elif [[ "$mode" == "external-ready" ]]; then
    [[ -s "$full_path" ]] || fail "$gate_id external evidence is missing: $evidence_path"
    for field in "Status: approved" "Decision:" "Named reviewers:" "Reviewed revision:" "Evidence digests:"; do
      grep -Fq "$field" "$full_path" ||
        fail "$gate_id evidence lacks required field '$field': $evidence_path"
    done
  fi
done < "$registry"

if [[ "$mode" == "baseline" ]]; then
  external_count="$(awk -F '\t' '$2 == "external_required" { count++ } END { print count + 0 }' "$registry")"
  [[ "$external_count" -gt 0 ]] || fail "registry must not imply that external approvals are complete"
  echo "P00 baseline verified; $external_count external gates remain explicitly required."
else
  echo "P00 external evidence structure verified. ADR status still requires reviewed amendments."
fi
