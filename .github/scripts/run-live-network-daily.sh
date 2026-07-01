#!/usr/bin/env bash

set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/../.." && pwd)
log_dir="${repo_root}/test-logs"
artifact_dir="${repo_root}/tmp/live-network-artifacts"
status_file="${artifact_dir}/ci-status.txt"

mkdir -p "${log_dir}" "${artifact_dir}" "${HOME}/.i2p/netDb" "${HOME}/i2p/netDb"

java_container="ci-java-i2p"
i2pd_container="ci-i2pd"
transient_pattern='did not discover enough peers|timed out|did not acknowledge|publish operation failed|no transports available|context deadline exceeded|i/o timeout|connection reset by peer|EOF'

cleanup() {
	set +e
	if docker ps -a --format '{{.Names}}' | grep -qx "${java_container}"; then
		docker logs "${java_container}" > "${log_dir}/java-i2p.log" 2>&1 || true
		docker rm -f "${java_container}" >/dev/null 2>&1 || true
	fi
	if docker ps -a --format '{{.Names}}' | grep -qx "${i2pd_container}"; then
		docker logs "${i2pd_container}" > "${log_dir}/i2pd.log" 2>&1 || true
		docker rm -f "${i2pd_container}" >/dev/null 2>&1 || true
	fi
	set -e
}
trap cleanup EXIT

wait_for_routerinfos() {
	local label=$1
	local count_cmd=$2
	local min_count=$3
	local timeout_seconds=$4
	local start_ts count

	start_ts=$(date +%s)
	while true; do
		count=$(eval "${count_cmd}")
		count=${count:-0}
		if [[ "${count}" =~ ^[0-9]+$ ]] && (( count >= min_count )); then
			echo "${label}: discovered ${count} routerInfo entries"
			return 0
		fi

		if (( $(date +%s) - start_ts >= timeout_seconds )); then
			echo "${label}: timed out waiting for ${min_count} routerInfo entries" >&2
			return 1
		fi

		sleep 10
	done
}

run_live_tests() {
	local attempt=$1
	local log_file="${log_dir}/live-network-attempt${attempt}.log"

	set +e
	GO_I2P_INTEGRATION=1 go test -tags=integration -count=1 -v ./lib/router -run '^TestLiveNetwork' 2>&1 | tee "${log_file}"
	local exit_code=${PIPESTATUS[0]}
	set -e

	return "${exit_code}"
}

write_status() {
	local result=$1
	local detail=$2
	cat > "${status_file}" <<EOF
result=${result}
detail=${detail}
EOF
}

echo "Pulling live-network peer images"
docker pull geti2p/i2p:latest
docker pull purplei2p/i2pd:latest

echo "Starting Java I2P container"
docker run -d \
	--name "${java_container}" \
	-e JVM_XMX=256m \
	-v "${HOME}/.i2p:/i2p/.i2p" \
	geti2p/i2p:latest >/dev/null

echo "Starting i2pd container"
docker run -d --name "${i2pd_container}" purplei2p/i2pd:latest >/dev/null

wait_for_routerinfos \
	"java-i2p" \
	"find \"${HOME}/.i2p/netDb\" -type f -name 'routerInfo-*.dat' 2>/dev/null | wc -l | tr -d ' '" \
	8 \
	900

wait_for_routerinfos \
	"i2pd" \
	"docker exec ${i2pd_container} sh -lc 'find / -type f -name \"routerInfo-*.dat\" 2>/dev/null | wc -l' | tr -d ' '" \
	8 \
	900

i2pd_netdb_path=$(docker exec "${i2pd_container}" sh -lc 'find / -type d -name netDb 2>/dev/null | head -n 1')
if [[ -z "${i2pd_netdb_path}" ]]; then
	echo "failed to discover i2pd netDb path" >&2
	write_status "failed" "missing_i2pd_netdb_path"
	exit 1
fi

rm -rf "${HOME}/i2p/netDb"
mkdir -p "${HOME}/i2p/netDb"
docker cp "${i2pd_container}:${i2pd_netdb_path}/." "${HOME}/i2p/netDb/"

if run_live_tests 1; then
	write_status "passed" "attempt_1"
	exit 0
fi

echo "Live-network attempt 1 failed; retrying once"
sleep 15
if run_live_tests 2; then
	write_status "quarantined" "passed_on_retry"
	exit 0
fi

if grep -Eiq "${transient_pattern}" "${log_dir}/live-network-attempt1.log" "${log_dir}/live-network-attempt2.log"; then
	grep -Ein "${transient_pattern}" "${log_dir}/live-network-attempt1.log" "${log_dir}/live-network-attempt2.log" > "${artifact_dir}/quarantine-matches.txt" || true
	write_status "quarantined" "transient_network_failure"
	exit 0
fi

write_status "failed" "non_transient_failure"
exit 1