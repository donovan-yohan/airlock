#!/usr/bin/env bash
# Snapshot/restore the complete compatible state boundary for a command-broker
# upgrade. This is intentionally not a downgrade projection: legacy binaries
# cannot parse command records.
set -euo pipefail

# Do not allow an operator's ambient PATH to replace the utilities that copy,
# hash, or atomically rename private state. The shebang is resolved before this
# point; all subsequent external commands use this known system path.
export PATH=/usr/bin:/bin

checkpoint_names=(requester.json trusted.json requester-state.json trusted-state.json)
declare -A manifest_digests=()
effective_uid=$(id -u)
# In an id-mapped container the system root can appear as a nonzero UID. Treat
# that UID exactly like root when checking immutable system ancestors.
system_root_uid=$(stat -c '%u' -- /)

usage() {
  echo "usage: $0 {snapshot|restore} --confirm-services-stopped --requester-config PATH --trusted-config PATH --requester-state PATH --trusted-state PATH --directory PATH" >&2
  exit 2
}

owned_by_effective_user() {
  [ "$(stat -c '%u' -- "$1")" = "$effective_uid" ]
}

mode_bits() {
  local mode
  mode=$(stat -c '%a' -- "$1") || return 1
  [[ "$mode" =~ ^[0-7]{1,4}$ ]] || return 1
  printf '%s\n' "$((8#$mode))"
}

owner_private_mode() {
  local mode
  mode=$(mode_bits "$1") || return 1
  # Reject special, group, and other bits; stat's octal output has already been
  # converted to an integer, so 0044 and 0066 cannot pass as decimal numbers.
  (( (mode & 8#7077) == 0 ))
}

trusted_ancestor_dir() {
  local path=$1 uid mode
  [ ! -L "$path" ] && [ -d "$path" ] || return 1
  uid=$(stat -c '%u' -- "$path") || return 1
  mode=$(mode_bits "$path") || return 1
  if [ "$uid" = "$effective_uid" ]; then
    # A user-owned ancestor may be a read/search-only anchor (for example a
    # conventional 0755 $HOME), but cannot be writable by group/other or
    # sticky. The final mutation parent is checked more strictly below.
    (( (mode & 8#7022) == 0 ))
  elif [ "$uid" = "$system_root_uid" ]; then
    # Root-owned system ancestors such as / and /home are a filesystem TCB only
    # when no other user can mutate them; never accept sticky or writable ones.
    (( (mode & 8#7022) == 0 ))
  else
    return 1
  fi
}

require_clean_absolute_path() {
  local path=$1 label=$2
  if [[ "$path" != /* || "$path" = / || "$path" = *"//"* || "$path" = *"/."/* || "$path" = *"/.."/* || "$path" = */. || "$path" = */.. ]]; then
    echo "refusing non-clean absolute $label path" >&2
    exit 1
  fi
}

require_safe_directory_chain() {
  local parent=$1 label=$2 component current=/
  local -a components
  require_clean_absolute_path "$parent" "$label parent"
  trusted_ancestor_dir / || { echo "refusing unsafe directory ancestry for $label" >&2; exit 1; }
  IFS=/ read -r -a components <<< "${parent#/}"
  for component in "${components[@]}"; do
    current=${current%/}/$component
    trusted_ancestor_dir "$current" || { echo "refusing unsafe directory ancestry for $label" >&2; exit 1; }
  done
}

private_file() {
  [ ! -L "$1" ] && [ -f "$1" ] && owned_by_effective_user "$1" && owner_private_mode "$1"
}

private_dir() {
  [ ! -L "$1" ] && [ -d "$1" ] && owned_by_effective_user "$1" && owner_private_mode "$1"
}

require_private_dir() {
  require_safe_directory_chain "$1" "$2"
  private_dir "$1" || { echo "refusing unsafe or missing $2" >&2; exit 1; }
}

require_source_file() {
  require_clean_absolute_path "$1" "$2"
  require_private_dir "$(dirname -- "$1")" "$2 parent"
  private_file "$1" || { echo "refusing unsafe or missing $2" >&2; exit 1; }
}

require_restore_target() {
  local target=$1
  require_clean_absolute_path "$target" "restore target"
  require_private_dir "$(dirname -- "$target")" "restore target parent"
  if [ -L "$target" ] || { [ -e "$target" ] && ! private_file "$target"; }; then
    echo "refusing unsafe restore target" >&2
    exit 1
  fi
}

require_distinct_restore_targets() {
  local target inode
  declare -A seen_paths=()
  declare -A seen_inodes=()
  for target in "${target_paths[@]}"; do
    if [ -n "${seen_paths[$target]:-}" ]; then
      echo "refusing duplicate restore target path" >&2
      exit 1
    fi
    seen_paths[$target]=1
    if [ -e "$target" ]; then
      inode=$(stat -c '%d:%i' -- "$target") || { echo "refusing unreadable restore target" >&2; exit 1; }
      if [ -n "${seen_inodes[$inode]:-}" ]; then
        echo "refusing aliased restore target path" >&2
        exit 1
      fi
      seen_inodes[$inode]=1
    fi
  done
}

validate_manifest() {
  local manifest=$1 line name digest
  declare -A seen=()
  manifest_digests=()
  while IFS= read -r line || [ -n "$line" ]; do
    if [[ ! "$line" =~ ^([0-9a-f]{64})\ \ (requester\.json|trusted\.json|requester-state\.json|trusted-state\.json)$ ]]; then
      echo "rollback checkpoint manifest must contain exactly the four expected lowercase SHA-256 entries" >&2
      return 1
    fi
    digest=${BASH_REMATCH[1]}
    name=${BASH_REMATCH[2]}
    if [ -n "${seen[$name]:-}" ]; then
      echo "rollback checkpoint manifest has a duplicate entry" >&2
      return 1
    fi
    seen[$name]=1
    manifest_digests[$name]=$digest
  done < "$manifest"
  for name in "${checkpoint_names[@]}"; do
    if [ -z "${seen[$name]:-}" ]; then
      echo "rollback checkpoint manifest is missing an expected entry" >&2
      return 1
    fi
  done
}

stage_paths=()
backup_paths=()
target_paths=()
target_parents=()
target_had_original=()
replaced_indices=()

cleanup_staging() {
  local path
  for path in "${stage_paths[@]}"; do
    [ -z "$path" ] || rm -f -- "$path"
  done
}

cleanup_backups() {
  local path
  for path in "${backup_paths[@]}"; do
    [ -z "$path" ] || rm -f -- "$path"
  done
}

stage_restore_files() {
  local index source stage
  for index in "${!target_paths[@]}"; do
    source="$directory/${checkpoint_names[$index]}"
    stage=$(mktemp "${target_parents[$index]}/.airlock-rollback-stage.XXXXXX") || return 1
    if ! cp --preserve=mode -- "$source" "$stage" || ! chmod 600 -- "$stage" || ! sync -f "$stage"; then
      rm -f -- "$stage"
      return 1
    fi
    stage_paths[$index]=$stage
  done
}

validate_staged_files() {
  local index name stage digest
  for index in "${!target_paths[@]}"; do
    name=${checkpoint_names[$index]}
    stage=${stage_paths[$index]}
    if ! private_file "$stage"; then
      echo "rollback staged file is not an owner-private regular file" >&2
      return 1
    fi
    digest=$(sha256sum -- "$stage") || return 1
    digest=${digest%% *}
    if [ "$digest" != "${manifest_digests[$name]}" ]; then
      echo "rollback staged file digest mismatch" >&2
      return 1
    fi
  done
}

backup_restore_targets() {
  local index backup
  for index in "${!target_paths[@]}"; do
    if [ -e "${target_paths[$index]}" ]; then
      backup=$(mktemp "${target_parents[$index]}/.airlock-rollback-backup.XXXXXX") || return 1
      if ! cp --preserve=mode -- "${target_paths[$index]}" "$backup" || ! chmod 600 -- "$backup" || ! sync -f "$backup"; then
        rm -f -- "$backup"
        return 1
      fi
      backup_paths[$index]=$backup
      target_had_original[$index]=1
    else
      backup_paths[$index]=
      target_had_original[$index]=0
    fi
  done
}

recover_replaced_targets() {
  local position index parent recovery_failed=0
  for ((position=${#replaced_indices[@]} - 1; position >= 0; position--)); do
    index=${replaced_indices[$position]}
    parent=${target_parents[$index]}
    if [ "${target_had_original[$index]}" = 1 ]; then
      if ! mv -f -- "${backup_paths[$index]}" "${target_paths[$index]}" || ! sync -f "$parent"; then
        echo "CRITICAL: could not recover pre-restore target ${target_paths[$index]}" >&2
        recovery_failed=1
      else
        backup_paths[$index]=
      fi
    elif ! rm -f -- "${target_paths[$index]}" || ! sync -f "$parent"; then
      echo "CRITICAL: could not remove newly created target ${target_paths[$index]}" >&2
      recovery_failed=1
    fi
  done
  return "$recovery_failed"
}

replace_staged_files() {
  local index parent
  for index in "${!target_paths[@]}"; do
    parent=${target_parents[$index]}
    if ! mv -f -- "${stage_paths[$index]}" "${target_paths[$index]}"; then
      echo "restore replacement failed; attempting recovery from private backups" >&2
      recover_replaced_targets || true
      return 1
    fi
    stage_paths[$index]=
    replaced_indices+=("$index")
    if ! sync -f "$parent"; then
      echo "restore replacement durability sync failed; attempting recovery from private backups" >&2
      recover_replaced_targets || true
      return 1
    fi
  done
}

mode=${1:-}
case "$mode" in snapshot|restore) shift ;; *) usage ;; esac
requester_config=
trusted_config=
requester_state=
trusted_state=
directory=
services_stopped=false
while [ "$#" -gt 0 ]; do
  case "$1" in
    --confirm-services-stopped) services_stopped=true; shift ;;
    --requester-config) requester_config=${2:-}; shift 2 ;;
    --trusted-config) trusted_config=${2:-}; shift 2 ;;
    --requester-state) requester_state=${2:-}; shift 2 ;;
    --trusted-state) trusted_state=${2:-}; shift 2 ;;
    --directory) directory=${2:-}; shift 2 ;;
    *) usage ;;
  esac
done
[ "$services_stopped" = true ] || { echo "refusing rollback action without --confirm-services-stopped" >&2; exit 1; }
[ -n "$requester_config" ] && [ -n "$trusted_config" ] && [ -n "$requester_state" ] && [ -n "$trusted_state" ] && [ -n "$directory" ] || usage
require_clean_absolute_path "$requester_config" "requester config"
require_clean_absolute_path "$trusted_config" "trusted config"
require_clean_absolute_path "$requester_state" "requester state"
require_clean_absolute_path "$trusted_state" "trusted state"
require_clean_absolute_path "$directory" "checkpoint"

case "$mode" in
snapshot)
  require_source_file "$requester_config" "requester config"
  require_source_file "$trusted_config" "trusted config"
  require_source_file "$requester_state" "requester state"
  require_source_file "$trusted_state" "trusted state"
  [ ! -e "$directory" ] || { echo "snapshot directory already exists" >&2; exit 1; }
  parent=$(dirname -- "$directory")
  require_private_dir "$parent" "snapshot parent"
  (umask 077; mkdir -- "$directory")
  require_private_dir "$directory" "snapshot directory"
  cp --preserve=mode -- "$requester_config" "$directory/requester.json"
  cp --preserve=mode -- "$trusted_config" "$directory/trusted.json"
  cp --preserve=mode -- "$requester_state" "$directory/requester-state.json"
  cp --preserve=mode -- "$trusted_state" "$directory/trusted-state.json"
  (cd "$directory" && sha256sum -- "${checkpoint_names[@]}" > SHA256SUMS)
  chmod 600 -- "$directory"/*
  sync -f "$directory"
  echo "created complete rollback checkpoint: $directory"
  ;;
restore)
  require_private_dir "$directory" "rollback checkpoint"
  for name in "${checkpoint_names[@]}" SHA256SUMS; do
    require_source_file "$directory/$name" "checkpoint $name"
  done
  validate_manifest "$directory/SHA256SUMS" || exit 1
  (cd "$directory" && sha256sum --check --status --strict SHA256SUMS) || { echo "rollback checkpoint digest mismatch" >&2; exit 1; }
  target_paths=("$requester_config" "$trusted_config" "$requester_state" "$trusted_state")
  for target in "${target_paths[@]}"; do
    require_restore_target "$target"
    target_parents+=("$(dirname -- "$target")")
  done
  require_distinct_restore_targets
  if ! stage_restore_files || ! validate_staged_files; then
    cleanup_staging
    echo "rollback restore staging or validation failed; no targets were replaced" >&2
    exit 1
  fi
  if ! backup_restore_targets; then
    cleanup_staging
    cleanup_backups
    echo "rollback restore backup failed; no targets were replaced" >&2
    exit 1
  fi
  if ! replace_staged_files; then
    cleanup_staging
    echo "rollback restore failed; retained any unrecovered private backups for manual recovery" >&2
    exit 1
  fi
  cleanup_staging
  cleanup_backups
  echo "restored complete rollback checkpoint; start only the matching legacy binaries"
  ;;
esac
