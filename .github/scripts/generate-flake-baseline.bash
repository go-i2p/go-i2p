#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
iterations=${1:-3}
output_file=${2:-"${repo_root}/docs/transport-flake-baseline.md"}

if ! [[ "${iterations}" =~ ^[0-9]+$ ]] || (( iterations < 1 )); then
	echo "usage: $0 [iterations>=1] [output-file]" >&2
	exit 2
fi

packages=(
	"./lib/transport"
	"./lib/transport/ntcp2"
	"./lib/transport/ssu2"
	"./lib/tunnel"
	"./lib/tunnel/build"
	"./lib/tunnel/buildrecord"
)

tmp_dir=$(mktemp -d)
trap 'rm -rf "${tmp_dir}"' EXIT

results_file="${tmp_dir}/results.tsv"
: > "${results_file}"

for pkg in "${packages[@]}"; do
	passes=0
	fails=0
	echo "sampling ${pkg} (${iterations} runs)" >&2
	for ((i = 1; i <= iterations; i++)); do
		if (cd "${repo_root}" && go test -count=1 -timeout=2m "${pkg}" >/dev/null); then
			passes=$((passes + 1))
		else
			fails=$((fails + 1))
		fi
	done
	printf '%s\t%d\t%d\n' "${pkg}" "${passes}" "${fails}" >> "${results_file}"
done

total_runs=$(( ${#packages[@]} * iterations ))
total_failures=$(awk -F '\t' '{sum += $3} END {print sum+0}' "${results_file}")
total_passes=$((total_runs - total_failures))

generated_at=$(date -u +"%Y-%m-%dT%H:%M:%SZ")

mkdir -p "$(dirname "${output_file}")"

{
	echo "# Transport and Tunnel Flake Baseline"
	echo
	echo "- Generated: ${generated_at}"
	echo "- Iterations per package: ${iterations}"
	echo "- Scope: transport and tunnel critical-path packages"
	echo "- Result: ${total_passes}/${total_runs} passing runs"
	echo
	echo "## Package Results"
	echo
	echo "| Package | Passes | Failures |"
	echo "|---|---:|---:|"
	awk -F '\t' '{printf "| %s | %d | %d |\n", $1, $2, $3}' "${results_file}"
	echo
	echo "## Remediation Backlog and Owners"
	echo
	echo "| Priority | Scope | Trigger | Owner | Next Action |"
	echo "|---|---|---|---|---|"
	awk -F '\t' '$3 > 0 {printf "| P1 | %s | %d/%d failed runs | transport-maintainers | Capture failing seed/logs and stabilize nondeterminism in this package |\n", $1, $3, ($2+$3)}' "${results_file}"
	if (( total_failures == 0 )); then
		echo "| P2 | transport+tunnel | No flaky failures observed in this sample | transport-maintainers | Keep scheduled sampling and gate on new failures |"
	fi
	echo
	echo "## Reproduction"
	echo
	echo '```bash'
	echo "bash .github/scripts/generate-flake-baseline.bash ${iterations} ${output_file}"
	echo '```'
} > "${output_file}"

echo "wrote ${output_file}"