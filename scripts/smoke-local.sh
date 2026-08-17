#!/usr/bin/env bash
set -euo pipefail

repo_root=$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)
cd "$repo_root"
smoke_root=$(mktemp -d "${TMPDIR:-/tmp}/airlock-smoke.XXXXXX")
requester_pid=
trusted_pid=

cleanup() {
	local status=$?
	trap - EXIT
  if [[ -n "$trusted_pid" ]]; then
    kill "$trusted_pid" 2>/dev/null || true
    wait "$trusted_pid" 2>/dev/null || true
  fi
  if [[ -n "$requester_pid" ]]; then
    kill "$requester_pid" 2>/dev/null || true
    wait "$requester_pid" 2>/dev/null || true
  fi
	if [[ "$status" -ne 0 ]]; then
		for log_file in requester.log trusted.log; do
			if [[ -s "$smoke_root/$log_file" ]]; then
				echo "smoke-local: $log_file" >&2
				tail -n 20 "$smoke_root/$log_file" >&2
			fi
		done
	fi
  rm -rf -- "$smoke_root"
	exit "$status"
}
trap cleanup EXIT

mkdir -m 700 "$smoke_root/requester-state" "$smoke_root/trusted-state" "$smoke_root/keys" "$smoke_root/fake-bin" "$smoke_root/fake-gh-config"
GOCACHE="$smoke_root/go-cache" go build -buildvcs=false -trimpath -o "$smoke_root/airlock" ./cmd/airlock
"$smoke_root/airlock" keygen --private "$smoke_root/keys/trusted.key" --public "$smoke_root/keys/trusted.pub" >/dev/null

provider_marker="$smoke_root/provider-was-invoked"
provider_argv="$smoke_root/provider-argv"
provider_environment="$smoke_root/provider-environment"
cat >"$smoke_root/fake-bin/gh" <<EOF
#!/bin/sh
set -eu
: "\${GH_CONFIG_DIR:?}"
printf '%s\n' "\$@" >>"$provider_argv"
env | LC_ALL=C sort >>"$provider_environment"
touch "$provider_marker"
exit 0
EOF
chmod 700 "$smoke_root/fake-bin/gh"

cat >"$smoke_root/requester.json" <<EOF
{
  "listen": "127.0.0.1:0",
  "state_dir": "$smoke_root/requester-state",
  "trusted_public_key_file": "$smoke_root/keys/trusted.pub",
  "request_max_ttl": "15m",
  "catalog_max_ttl": "1h",
  "receipt_max_ttl": "1h"
}
EOF

"$smoke_root/airlock" requester serve --config "$smoke_root/requester.json" >"$smoke_root/requester.log" 2>&1 &
requester_pid=$!

wait_for_address() {
  local log_file=$1
  local address=
  for _ in $(seq 1 100); do
    address=$(sed -n 's/.*listening on \(127\.0\.0\.1:[0-9][0-9]*\).*/\1/p' "$log_file" | head -n 1)
    if [[ -n "$address" ]]; then
      printf '%s' "$address"
      return 0
    fi
    sleep 0.05
  done
  return 1
}

wait_for_http() {
  local target=$1
  for _ in $(seq 1 100); do
    if curl --fail --silent --show-error "$target" >/dev/null 2>&1; then
      return 0
    fi
    sleep 0.05
  done
  return 1
}

requester_address=$(wait_for_address "$smoke_root/requester.log")
wait_for_http "http://$requester_address/healthz"
printf '%s\n' \
  '{"jsonrpc":"2.0","id":1,"method":"initialize","params":{}}' \
  '{"jsonrpc":"2.0","id":2,"method":"tools/list","params":{}}' |
  "$smoke_root/airlock" mcp --requester-url "http://$requester_address" >"$smoke_root/mcp.jsonl"
for mcp_tool in airlock_capabilities airlock_create_request airlock_requests; do
  grep -q "\"$mcp_tool\"" "$smoke_root/mcp.jsonl"
done
test "$(grep -o '"name":"airlock_' "$smoke_root/mcp.jsonl" | wc -l)" -eq 3

cat >"$smoke_root/requester-client.json" <<EOF
{
  "listen": "$requester_address",
  "state_dir": "$smoke_root/requester-state",
  "trusted_public_key_file": "$smoke_root/keys/trusted.pub",
  "request_max_ttl": "15m",
  "catalog_max_ttl": "1h",
  "receipt_max_ttl": "1h"
}
EOF

cat >"$smoke_root/trusted.json" <<EOF
{
  "listen": "127.0.0.1:0",
  "state_dir": "$smoke_root/trusted-state",
  "control_socket": "$smoke_root/trusted-state/control.sock",
  "private_key_file": "$smoke_root/keys/trusted.key",
  "requester_url": "http://$requester_address",
  "github_cli_path": "$smoke_root/fake-bin/gh",
  "github_config_dir": "$smoke_root/fake-gh-config",
  "execution_timeout": "10s",
  "poll_interval": "100ms",
  "request_max_ttl": "15m",
  "catalog_ttl": "1h",
  "receipt_ttl": "1h",
  "allowed_logins": ["reviewer@example.invalid"],
  "capabilities": [{
    "id": "github:example-owner",
    "display_name": "Example GitHub authority",
    "adapter": "github.repo.add_collaborator/v1",
    "owner": "example-owner",
    "collaborator": "example-agent",
    "permissions": ["pull", "push"]
  }]
}
EOF

"$smoke_root/airlock" trusted serve --dev --config "$smoke_root/trusted.json" >"$smoke_root/trusted.log" 2>&1 &
trusted_pid=$!
trusted_address=$(wait_for_address "$smoke_root/trusted.log")
wait_for_http "http://$trusted_address/healthz"
for _ in $(seq 1 100); do
  test -S "$smoke_root/trusted-state/control.sock" && break
  sleep 0.05
done
test -S "$smoke_root/trusted-state/control.sock"

for _ in $(seq 1 100); do
  if curl --fail --silent "http://$requester_address/api/v1/catalog" >"$smoke_root/catalog.json" 2>/dev/null; then
    break
  fi
  sleep 0.05
done
test -s "$smoke_root/catalog.json"

"$smoke_root/airlock" request create \
  --config "$smoke_root/requester-client.json" \
  --capability github:example-owner \
  --action github.repo.add_collaborator \
  --repository smoke-project \
  --permission push \
  --reason "Local vertical smoke" \
  --ttl 10m >"$smoke_root/request.json"

"$smoke_root/airlock" request create \
  --config "$smoke_root/requester-client.json" \
  --capability github:example-owner \
  --action github.repo.add_collaborator \
  --repository cli-smoke-project \
  --permission pull \
  --reason "Local trusted CLI smoke" \
  --ttl 10m >"$smoke_root/cli-request.json"

request_id=$(sed -n 's/^[[:space:]]*"id": "\(req_[^"]*\)",*$/\1/p' "$smoke_root/request.json" | head -n 1)
request_digest=$(sed -n 's/^[[:space:]]*"digest": "\([a-f0-9]*\)",*$/\1/p' "$smoke_root/request.json" | head -n 1)
cli_request_id=$(sed -n 's/^[[:space:]]*"id": "\(req_[^"]*\)",*$/\1/p' "$smoke_root/cli-request.json" | head -n 1)
cli_request_digest=$(sed -n 's/^[[:space:]]*"digest": "\([a-f0-9]*\)",*$/\1/p' "$smoke_root/cli-request.json" | head -n 1)
test -n "$request_id"
test "${#request_digest}" -eq 64
test -n "$cli_request_id"
test "${#cli_request_digest}" -eq 64

review_url="http://$trusted_address/requests/$request_id"
for _ in $(seq 1 100); do
  if curl --fail --silent \
    -H 'X-Airlock-Dev-Identity: reviewer@example.invalid' \
    -c "$smoke_root/cookies" "$review_url" >"$smoke_root/review.html" 2>/dev/null &&
    grep -q "$request_digest" "$smoke_root/review.html"; then
    break
  fi
  sleep 0.05
done
grep -Fq "$smoke_root/fake-bin/gh api --method PUT repos/example-owner/smoke-project/collaborators/example-agent -f permission=push --silent" "$smoke_root/review.html"
csrf_token=$(sed -n 's/.*name="csrf_token" value="\([A-Za-z0-9_-]*\)".*/\1/p' "$smoke_root/review.html" | head -n 1)
test -n "$csrf_token"

curl --fail --silent --show-error \
  -H 'X-Airlock-Dev-Identity: reviewer@example.invalid' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -b "$smoke_root/cookies" \
  --data-urlencode "csrf_token=$csrf_token" \
  "http://$trusted_address/requests/$request_id/execute" >/dev/null

for _ in $(seq 1 100); do
  if "$smoke_root/airlock" trusted request show --config "$smoke_root/trusted.json" --id "$cli_request_id" >"$smoke_root/cli-review.json" 2>/dev/null; then
    break
  fi
  sleep 0.05
done
test -s "$smoke_root/cli-review.json"
"$smoke_root/airlock" trusted request execute \
  --config "$smoke_root/trusted.json" \
  --id "$cli_request_id" >"$smoke_root/cli-execute.json"

for _ in $(seq 1 100); do
  curl --fail --silent "http://$requester_address/api/v1/requests/$request_id" >"$smoke_root/requester-state-check.json"
  if grep -q '"state":"executed"' "$smoke_root/requester-state-check.json"; then
    break
  fi
  sleep 0.05
done
grep -q '"state":"executed"' "$smoke_root/requester-state-check.json"
grep -q '"decision":"approved_for_execution"' "$smoke_root/requester-state-check.json"
grep -q '"decision":"executed"' "$smoke_root/requester-state-check.json"
for _ in $(seq 1 100); do
  curl --fail --silent "http://$requester_address/api/v1/requests/$cli_request_id" >"$smoke_root/cli-requester-state-check.json"
  if grep -q '"state":"executed"' "$smoke_root/cli-requester-state-check.json"; then
    break
  fi
  sleep 0.05
done
grep -q '"state":"executed"' "$smoke_root/cli-requester-state-check.json"
grep -q '"decision":"approved_for_execution"' "$smoke_root/cli-requester-state-check.json"
grep -q '"decision":"executed"' "$smoke_root/cli-requester-state-check.json"
grep -q '"outcome": "executed"' "$smoke_root/cli-execute.json"
grep -q '"state": "executed"' "$smoke_root/cli-execute.json"
test -f "$provider_marker"
test "$(wc -l <"$provider_argv")" -eq 14
test "$(grep -Fxc 'api' "$provider_argv")" -eq 2
test "$(grep -Fxc -- '--method' "$provider_argv")" -eq 2
test "$(grep -Fxc 'PUT' "$provider_argv")" -eq 2
test "$(grep -Fxc 'repos/example-owner/smoke-project/collaborators/example-agent' "$provider_argv")" -eq 1
test "$(grep -Fxc 'repos/example-owner/cli-smoke-project/collaborators/example-agent' "$provider_argv")" -eq 1
test "$(grep -Fxc -- '-f' "$provider_argv")" -eq 2
test "$(grep -Fxc 'permission=push' "$provider_argv")" -eq 1
test "$(grep -Fxc 'permission=pull' "$provider_argv")" -eq 1
test "$(grep -Fxc -- '--silent' "$provider_argv")" -eq 2
test "$(grep -Fxc "GH_CONFIG_DIR=$smoke_root/fake-gh-config" "$provider_environment")" -eq 2
test "$(grep -Fxc 'GH_PROMPT_DISABLED=1' "$provider_environment")" -eq 2
test "$(grep -Fxc 'GH_NO_UPDATE_NOTIFIER=1' "$provider_environment")" -eq 2
test "$(grep -Fxc 'NO_COLOR=1' "$provider_environment")" -eq 2
test "$(grep -Fxc 'TERM=dumb' "$provider_environment")" -eq 2
test "$(grep -Fxc "HOME=$smoke_root/fake-gh-config" "$provider_environment")" -eq 2
test "$(grep -Fxc 'LC_ALL=C' "$provider_environment")" -eq 2
test "$(grep -Fxc 'PATH=/usr/bin:/bin' "$provider_environment")" -eq 2
cut -d= -f1 "$provider_environment" | LC_ALL=C sort -u >"$smoke_root/provider-environment-keys"
if grep -Ev '^(GH_CONFIG_DIR|GH_PROMPT_DISABLED|GH_NO_UPDATE_NOTIFIER|NO_COLOR|TERM|HOME|LC_ALL|PATH|PWD)$' "$smoke_root/provider-environment-keys"; then
  echo "fake gh received an unexpected environment key" >&2
  exit 1
fi
if grep -Eq '^(GH_TOKEN|GITHUB_TOKEN|HTTP_PROXY|HTTPS_PROXY|ALL_PROXY)=' "$provider_environment"; then
  echo "fake gh received a forbidden environment value" >&2
  exit 1
fi

private_canary=$(tr -d '\n' <"$smoke_root/keys/trusted.key")
for artifact in requester.log trusted.log request.json cli-request.json requester-state-check.json cli-requester-state-check.json review.html cli-review.json cli-execute.json provider-argv provider-environment provider-environment-keys; do
  if grep -Fq "$private_canary" "$smoke_root/$artifact"; then
    echo "private-key canary leaked into $artifact" >&2
    exit 1
  fi
done
printf 'smoke-local: PASS web_request=%s web_digest=%s cli_request=%s cli_digest=%s state=executed receipts=2 provider_invocations=2\n' "$request_id" "$request_digest" "$cli_request_id" "$cli_request_digest"
