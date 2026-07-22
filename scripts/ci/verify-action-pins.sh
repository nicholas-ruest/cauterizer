#!/usr/bin/env bash
set -euo pipefail

readonly workflow_dir=".github/workflows"
readonly sha_pattern='^[0-9a-f]{40}$'

if [[ ! -d "${workflow_dir}" ]]; then
  printf 'workflow directory does not exist: %s\n' "${workflow_dir}" >&2
  exit 1
fi

status=0
while IFS= read -r workflow; do
  while IFS= read -r reference; do
    # Local actions are reviewed as repository content. Docker references are
    # forbidden here because image digests need a separate policy and updater.
    if [[ "${reference}" == ./* ]]; then
      continue
    fi

    if [[ "${reference}" == docker://* ]]; then
      printf '%s: docker action is not permitted: %s\n' "${workflow}" "${reference}" >&2
      status=1
      continue
    fi

    revision="${reference##*@}"
    if [[ ! "${revision}" =~ ${sha_pattern} ]]; then
      printf '%s: action is not pinned to a full commit SHA: %s\n' "${workflow}" "${reference}" >&2
      status=1
    fi
  done < <(sed -nE 's/^[[:space:]]*uses:[[:space:]]*([^[:space:]#]+).*$/\1/p' "${workflow}")
done < <(find "${workflow_dir}" -type f \( -name '*.yml' -o -name '*.yaml' \) -print | sort)

if (( status != 0 )); then
  printf 'Action pin verification failed. Use an upstream commit SHA and retain a version comment.\n' >&2
  exit "${status}"
fi

printf 'All third-party workflow actions are pinned to immutable commit SHAs.\n'

