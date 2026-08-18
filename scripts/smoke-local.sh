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

curl_local() {
  command curl --noproxy '*' "$@"
}

# Pollute the daemon's parent environment on purpose. The exact sandbox-env
# assertion below proves none of these authority or routing variables cross the
# trusted execution boundary.
export GH_TOKEN=smoke-forbidden-gh-token
export GITHUB_TOKEN=smoke-forbidden-github-token
export HTTP_PROXY=http://127.0.0.1:9
export HTTPS_PROXY=http://127.0.0.1:9
export ALL_PROXY=socks5://127.0.0.1:9
export NO_PROXY=untrusted.invalid
export http_proxy="$HTTP_PROXY"
export https_proxy="$HTTPS_PROXY"
export all_proxy="$ALL_PROXY"
export no_proxy="$NO_PROXY"

mkdir -m 700 "$smoke_root/requester-state" "$smoke_root/trusted-state" "$smoke_root/keys" "$smoke_root/fake-bin" "$smoke_root/fake-gh-config"
GOCACHE="$smoke_root/go-cache" go build -buildvcs=false -trimpath -o "$smoke_root/airlock" ./cmd/airlock
CGO_ENABLED=0 GOCACHE="$smoke_root/go-cache" go build -buildvcs=false -trimpath -o "$smoke_root/fake-bin/gh" ./internal/trusted/testdata/fakegh
"$smoke_root/airlock" keygen --private "$smoke_root/keys/trusted.key" --public "$smoke_root/keys/trusted.pub" >/dev/null
printf '%s\n' 'github.example.invalid:' '  user: smoke-test' >"$smoke_root/fake-gh-config/hosts.yml"
chmod 600 "$smoke_root/fake-gh-config/hosts.yml"

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
    if curl_local --fail --silent --show-error "$target" >/dev/null 2>&1; then
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
  "sandbox_cli_path": "/usr/bin/bwrap",
  "execution_timeout": "10s",
  "profile_config_version": "smoke-v1",
  "credential_authority_label": "Test-only broad GitHub authority",
  "execution_identity_label": "Local smoke service account",
  "sandbox_label": "Linux bubblewrap namespaces with a private copied GitHub auth snapshot",
  "network_label": "GitHub network authority; fake executable in smoke",
  "cwd_label": "Fresh ephemeral working directory",
  "output_label": "Bounded sanitized stdout and stderr preview for trusted reviewers only",
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
  if curl_local --fail --silent "http://$requester_address/api/v1/catalog" >"$smoke_root/catalog.json" 2>/dev/null; then
    break
  fi
  sleep 0.05
done
test -s "$smoke_root/catalog.json"

"$smoke_root/airlock" request create \
  --config "$smoke_root/requester-client.json" \
  --profile github.command \
  --profile-version v1 \
  --arg api \
  --arg --method \
  --arg POST \
  --arg repos/example-owner/smoke-project/dispatches \
  --arg -f \
  --arg event_type=smoke \
  --arg ';' \
  --arg '$(id)' \
  --reason "Local vertical smoke" \
  --ttl 10m >"$smoke_root/request.json"

"$smoke_root/airlock" request create \
  --config "$smoke_root/requester-client.json" \
  --profile github.command \
  --profile-version v1 \
  --arg repo \
  --arg view \
  --arg example-owner/cli-smoke-project \
  --arg --json \
  --arg name \
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
  if curl_local --fail --silent \
    -H 'X-Airlock-Dev-Identity: reviewer@example.invalid' \
    -c "$smoke_root/cookies" "$review_url" >"$smoke_root/review.html" 2>/dev/null &&
    grep -q "$request_digest" "$smoke_root/review.html"; then
    break
  fi
  sleep 0.05
done
grep -Fq 'argv[0] = api' "$smoke_root/review.html"
grep -Fq 'argv[6] = ;' "$smoke_root/review.html"
grep -Fq 'argv[7] = $(id)' "$smoke_root/review.html"
grep -Fq 'Write-capable GitHub API method' "$smoke_root/review.html"
csrf_token=$(sed -n 's/.*name="csrf_token" value="\([A-Za-z0-9_-]*\)".*/\1/p' "$smoke_root/review.html" | head -n 1)
plan_digest=$(sed -n 's/.*name="plan_digest" value="\([a-f0-9]*\)".*/\1/p' "$smoke_root/review.html" | head -n 1)
test -n "$csrf_token"
test "${#plan_digest}" -eq 64

curl_local --fail --silent --show-error \
  -H 'X-Airlock-Dev-Identity: reviewer@example.invalid' \
  -H 'Content-Type: application/x-www-form-urlencoded' \
  -b "$smoke_root/cookies" \
  --data-urlencode "csrf_token=$csrf_token" \
  --data-urlencode "plan_digest=$plan_digest" \
	--data-urlencode "confirm_full_authority=true" \
  "http://$trusted_address/requests/$request_id/execute" >/dev/null

for _ in $(seq 1 100); do
  if "$smoke_root/airlock" trusted request show --config "$smoke_root/trusted.json" --id "$cli_request_id" >"$smoke_root/cli-review.json" 2>/dev/null; then
    break
  fi
  sleep 0.05
done
test -s "$smoke_root/cli-review.json"
cli_plan_digest=$(sed -n 's/^[[:space:]]*"plan_digest": "\([a-f0-9]*\)",*$/\1/p' "$smoke_root/cli-review.json" | head -n 1)
test "${#cli_plan_digest}" -eq 64
"$smoke_root/airlock" trusted request execute \
  --config "$smoke_root/trusted.json" \
  --id "$cli_request_id" \
  --plan-digest "$cli_plan_digest" \
  --confirm-full-authority >"$smoke_root/cli-execute.json"

for _ in $(seq 1 100); do
  curl_local --fail --silent "http://$requester_address/api/v1/requests/$request_id" >"$smoke_root/requester-state-check.json"
  if grep -q '"state":"executed"' "$smoke_root/requester-state-check.json"; then
    break
  fi
  sleep 0.05
done
grep -q '"state":"executed"' "$smoke_root/requester-state-check.json"
grep -q '"decision":"approved_for_execution"' "$smoke_root/requester-state-check.json"
grep -q '"decision":"executed"' "$smoke_root/requester-state-check.json"
for _ in $(seq 1 100); do
  curl_local --fail --silent "http://$requester_address/api/v1/requests/$cli_request_id" >"$smoke_root/cli-requester-state-check.json"
  if grep -q '"state":"executed"' "$smoke_root/cli-requester-state-check.json"; then
    break
  fi
  sleep 0.05
done
grep -q '"state":"executed"' "$smoke_root/cli-requester-state-check.json"
grep -q '"decision":"approved_for_execution"' "$smoke_root/cli-requester-state-check.json"
grep -q '"outcome": "executed"' "$smoke_root/cli-execute.json"
grep -q '"state": "executed"' "$smoke_root/cli-execute.json"

"$smoke_root/airlock" trusted request show --config "$smoke_root/trusted.json" --id "$request_id" >"$smoke_root/web-trusted-record.json"
"$smoke_root/airlock" trusted request show --config "$smoke_root/trusted.json" --id "$cli_request_id" >"$smoke_root/cli-trusted-record.json"
python3 - "$smoke_root/web-trusted-record.json" "$smoke_root/cli-trusted-record.json" <<'PY'
import json
import re
import sys

expected_environment = {
    "GH_CONFIG_DIR": "/airlock/home/.config/gh",
    "GH_PROMPT_DISABLED": "1",
    "GH_NO_UPDATE_NOTIFIER": "1",
    "NO_COLOR": "1",
    "TERM": "dumb",
    "HOME": "/airlock/home",
    "LC_ALL": "C",
    "PATH": "/airlock/bin",
    "XDG_CONFIG_HOME": "/airlock/home/.config",
    "XDG_DATA_HOME": "/airlock/home/.local",
    "XDG_CACHE_HOME": "/airlock/home/.cache",
    # Bubblewrap publishes the fixed --chdir target; this is sandbox-derived,
    # not inherited from the trusted daemon's ambient working directory.
    "PWD": "/airlock/work",
}
expected_argv = (
    ["api", "--method", "POST", "repos/example-owner/smoke-project/dispatches", "-f", "event_type=smoke", ";", "$(id)"],
    ["repo", "view", "example-owner/cli-smoke-project", "--json", "name"],
)


def snapshot(path):
    record = json.load(open(path, encoding="utf-8"))
    attempts = record.get("attempts", [])
    if len(attempts) != 1 or attempts[0].get("status") != "succeeded":
        raise AssertionError(f"{path}: expected one successful sandbox attempt, got {attempts!r}")
    preview = attempts[0].get("output_preview") or {}
    matches = re.findall(r"(?m)^AIRLOCK_SNAPSHOT:(\{.*\})$", preview.get("stdout", ""))
    if len(matches) != 1:
        raise AssertionError(f"{path}: expected one runtime snapshot, got {matches!r}")
    observed = json.loads(matches[0])
    observed["reviewed_environment_policy"] = (attempts[0].get("plan") or {}).get("environment_policy")
    return observed


snapshots = [snapshot(path) for path in sys.argv[1:]]
if len(snapshots) != 2:
    raise AssertionError(f"expected exactly two sandbox invocations, got {len(snapshots)}")
for observed, argv in zip(snapshots, expected_argv, strict=True):
    if observed.get("argv") != argv:
        raise AssertionError(f"sandbox argv mismatch: {observed.get('argv')!r} != {argv!r}")
    items = observed.get("env")
    if not isinstance(items, list) or any(not isinstance(item, str) or "=" not in item for item in items):
        raise AssertionError(f"sandbox env malformed: {items!r}")
    environment = dict(item.split("=", 1) for item in items)
    if len(environment) != len(items) or environment != expected_environment:
        raise AssertionError(f"sandbox env was not the fixed allowlist: {environment!r}")
    reviewed_policy = observed.get("reviewed_environment_policy")
    expected_policy = {f"{key}={value}" for key, value in expected_environment.items()}
    if not isinstance(reviewed_policy, list) or set(reviewed_policy) != expected_policy:
        raise AssertionError(f"reviewed environment policy diverged from runtime: {reviewed_policy!r}")
    if observed.get("cwd") != "/airlock/work":
        raise AssertionError(f"sandbox cwd mismatch: {observed.get('cwd')!r}")
    if observed.get("write_denied") is not True:
        raise AssertionError("sandbox could write the canonical GH config")
PY

private_canary=$(tr -d '\n' <"$smoke_root/keys/trusted.key")
output_canary='ghp_FAKEOUTPUTMUSTNEVERPERSISTOREGRESS0123456789'
for artifact in requester.log trusted.log mcp.jsonl requester-state/requester-state.json request.json cli-request.json requester-state-check.json cli-requester-state-check.json review.html cli-execute.json web-trusted-record.json cli-trusted-record.json; do
  if grep -Fq "$private_canary" "$smoke_root/$artifact"; then
    echo "private-key canary leaked into requester, MCP, or log surface: $artifact" >&2
    exit 1
  fi
  if grep -Fq "$output_canary" "$smoke_root/$artifact"; then
    echo "child-output canary leaked into requester, MCP, or log surface: $artifact" >&2
    exit 1
  fi
done
printf 'smoke-local: PASS web_request=%s web_digest=%s cli_request=%s cli_digest=%s state=executed receipts=2 sandbox_invocations=2\n' "$request_id" "$request_digest" "$cli_request_id" "$cli_request_digest"
