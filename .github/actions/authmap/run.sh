#!/usr/bin/env bash
set -uo pipefail

error() {
  echo "::error::$*" >&2
}

warn() {
  echo "::warning::$*" >&2
}

die() {
  error "$*"
  exit 2
}

trim() {
  local value="$1"
  value="${value#"${value%%[![:space:]]*}"}"
  value="${value%"${value##*[![:space:]]}"}"
  printf '%s' "$value"
}

lower() {
  printf '%s' "$1" | tr '[:upper:]' '[:lower:]'
}

is_true() {
  [[ "$(lower "$(trim "$1")")" == "true" ]]
}

workspace_path() {
  local value="$1"
  printf '%s/%s' "$GITHUB_WORKSPACE" "$value"
}

validate_git_ref_input() {
  local name="$1"
  local value="$2"

  [[ -n "$value" ]] || die "$name must not be empty"
  case "$value" in
    -*|*:*|*+*|*$'\n'*|*$'\r'*|*$'\t'*)
      die "$name must be a git ref, tag, or commit SHA without refspec metacharacters, control characters, or leading '-'"
      ;;
  esac
  if printf '%s' "$value" | LC_ALL=C grep -q '[[:cntrl:][:space:]]'; then
    die "$name must not contain whitespace or control characters"
  fi
  printf '%s' "$value"
}

resolve_baseline_path() {
  local baseline_relative="$1"
  local requested_ref="$2"
  local pr_base_sha="$3"
  local trusted_ref=""
  local trusted_path

  if [[ -n "$requested_ref" ]]; then
    trusted_ref="$(validate_git_ref_input "baseline-ref" "$requested_ref")" || exit $?
  elif [[ -n "$pr_base_sha" ]]; then
    trusted_ref="$(validate_git_ref_input "pull request base SHA" "$pr_base_sha")" || exit $?
  fi

  if [[ -z "$trusted_ref" ]]; then
    workspace_path "$baseline_relative"
    return
  fi

  if ! git -C "$GITHUB_WORKSPACE" cat-file -e "${trusted_ref}^{commit}" >/dev/null 2>&1; then
    git -C "$GITHUB_WORKSPACE" fetch --no-tags --depth=1 origin "$trusted_ref" || die "failed to fetch trusted baseline ref '${trusted_ref}'"
  fi
  git -C "$GITHUB_WORKSPACE" cat-file -e "${trusted_ref}^{commit}" >/dev/null 2>&1 || die "baseline-ref '${trusted_ref}' is not a commit"

  trusted_path="${RUNNER_TEMP:-$GITHUB_WORKSPACE}/authmap-baseline-${RANDOM}-${RANDOM}.json"
  git -C "$GITHUB_WORKSPACE" show "${trusted_ref}:${baseline_relative}" > "$trusted_path" || die "baseline '${baseline_relative}' was not found at trusted ref '${trusted_ref}'"
  printf '%s' "$trusted_path"
}

validate_relative_path() {
  local name="$1"
  local value="$2"
  local allow_dot="$3"
  local normalized
  normalized="${value//\\//}"

  [[ -n "$normalized" ]] || die "$name must not be empty"
  case "$value" in
    *$'\n'*|*$'\r'*|*$'\t'*)
      die "$name must not contain control characters"
      ;;
  esac
  if printf '%s' "$value" | LC_ALL=C grep -q '[[:cntrl:]]'; then
    die "$name must not contain control characters"
  fi
  case "$normalized" in
    /*|[A-Za-z]:/*|//*)
      die "$name must be relative to GITHUB_WORKSPACE"
      ;;
  esac
  if [[ "$normalized" == "." ]]; then
    [[ "$allow_dot" == "true" ]] || die "$name must not be the workspace root"
    printf '%s' "$normalized"
    return
  fi
  case "$normalized" in
    *//*|*/)
      die "$name must not contain empty, '.', or '..' path components"
      ;;
  esac
  IFS='/' read -ra parts <<< "$normalized"
  local part
  for part in "${parts[@]}"; do
    case "$part" in
      ""|"."|"..")
        die "$name must not contain empty, '.', or '..' path components"
        ;;
    esac
  done
  printf '%s' "$normalized"
}

append_output() {
  local name="$1"
  local value="$2"
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    local delimiter="AUTHMAP_${name}_EOF_${RANDOM}_${RANDOM}"
    while [[ "$value" == *"$delimiter"* ]]; do
      delimiter="AUTHMAP_${name}_EOF_${RANDOM}_${RANDOM}"
    done
    {
      printf '%s<<%s\n' "$name" "$delimiter"
      printf '%s\n' "$value"
      printf '%s\n' "$delimiter"
    } >> "$GITHUB_OUTPUT"
  fi
}

add_artifact_path() {
  local value="$1"
  [[ -n "$value" ]] || return
  artifact_paths+=("$value")
}

add_format() {
  local format="$1"
  local existing
  if [[ "${#formats[@]}" -gt 0 ]]; then
    for existing in "${formats[@]}"; do
      if [[ "$existing" == "$format" ]]; then
        return
      fi
    done
  fi
  formats+=("$format")
}

GITHUB_WORKSPACE="${GITHUB_WORKSPACE:-}"
GITHUB_ACTION_PATH="${GITHUB_ACTION_PATH:-}"
[[ -n "$GITHUB_WORKSPACE" ]] || die "GITHUB_WORKSPACE is not set"
[[ -n "$GITHUB_ACTION_PATH" ]] || die "GITHUB_ACTION_PATH is not set"

mode="$(lower "$(trim "${INPUT_MODE:-advisory}")")"
case "$mode" in
  advisory|enforce) ;;
  *) die "unsupported AuthMap mode '$mode'; expected advisory or enforce" ;;
esac

upload_sarif="${INPUT_UPLOAD_SARIF:-false}"
case "$(lower "$(trim "$upload_sarif")")" in
  true|false) ;;
  *) die "upload-sarif must be true or false" ;;
esac

defer_exit="${AUTHMAP_DEFER_EXIT:-false}"
case "$(lower "$(trim "$defer_exit")")" in
  true|false) ;;
  *) die "AUTHMAP_DEFER_EXIT must be true or false" ;;
esac

target_input="$(trim "${INPUT_TARGET:-.}")"
target_input="$(validate_relative_path "target" "$target_input" true)" || exit $?
target_path="$(workspace_path "$target_input")"

config_input="$(trim "${INPUT_CONFIG:-}")"
config_path=""
if [[ -n "$config_input" ]]; then
  config_input="$(validate_relative_path "config" "$config_input" false)" || exit $?
  config_path="$(workspace_path "$config_input")"
fi

baseline_input="$(trim "${INPUT_BASELINE:-}")"
baseline_path=""
baseline_uses_trusted_ref="false"
if [[ -n "$baseline_input" ]]; then
  baseline_input="$(validate_relative_path "baseline" "$baseline_input" false)" || exit $?
  baseline_ref_input="$(trim "${INPUT_BASELINE_REF:-}")"
  pr_base_sha="$(trim "${AUTHMAP_PR_BASE_SHA:-}")"
  if [[ -n "$baseline_ref_input" || -n "$pr_base_sha" ]]; then
    baseline_uses_trusted_ref="true"
  fi
  baseline_path="$(resolve_baseline_path "$baseline_input" "$baseline_ref_input" "$pr_base_sha")" || exit $?
fi

fail_on_input="$(trim "${INPUT_FAIL_ON:-}")"

output_dir_input="$(trim "${INPUT_OUTPUT_DIRECTORY:-.authmap}")"
output_dir_input="$(validate_relative_path "output-directory" "$output_dir_input" false)" || exit $?
output_dir="$(workspace_path "$output_dir_input")"
mkdir -p "$output_dir"

formats=()
IFS=',' read -ra requested_formats <<< "${INPUT_OUTPUT:-markdown,json}"
for raw_format in "${requested_formats[@]}"; do
  format="$(lower "$(trim "$raw_format")")"
  [[ -n "$format" ]] || continue
  case "$format" in
    markdown|json|sarif) add_format "$format" ;;
    *) die "unsupported output format '$format'; expected markdown, json, or sarif" ;;
  esac
done

if is_true "$upload_sarif"; then
  add_format "sarif"
fi

if [[ -n "$baseline_path" ]]; then
  add_format "json"
fi

if [[ "${#formats[@]}" -eq 0 ]]; then
  die "at least one output format must be requested"
fi

json_path=""
markdown_path=""
sarif_path=""
diff_json_path=""
diff_markdown_path=""
artifact_paths=()
final_status=0

for format in "${formats[@]}"; do
  case "$format" in
    json)
      output_path="$output_dir/authmap.json"
      json_path="$output_path"
      ;;
    markdown)
      output_path="$output_dir/authmap.md"
      markdown_path="$output_path"
      ;;
    sarif)
      output_path="$output_dir/authmap.sarif"
      sarif_path="$output_path"
      ;;
  esac

  cmd=(
    cargo run --locked
    --manifest-path "$GITHUB_ACTION_PATH/Cargo.toml"
    -p authmap-cli
    --
    scan "$target_path"
    --format "$format"
    --output "$output_path"
    --mode "$mode"
  )
  if [[ -n "$config_path" ]]; then
    cmd+=(--config "$config_path")
  fi

  echo "Running AuthMap ${format} report"
  "${cmd[@]}"
  status=$?
  if [[ "$status" -eq 20 ]]; then
    final_status=20
    warn "AuthMap enforce mode returned exit code 20 for ${format}; continuing to generate requested artifacts"
    add_artifact_path "$output_path"
  elif [[ "$status" -ne 0 ]]; then
    final_status="$status"
    break
  else
    add_artifact_path "$output_path"
  fi
done

if [[ -n "$baseline_path" && ( "$final_status" -eq 0 || "$final_status" -eq 20 ) ]]; then
  if [[ -z "$json_path" || ! -s "$json_path" ]]; then
    die "baseline diff requires a generated JSON AuthMap report"
  fi

  for diff_format in json markdown; do
    case "$diff_format" in
      json)
        diff_output_path="$output_dir/authmap.diff.json"
        diff_json_path="$diff_output_path"
        ;;
      markdown)
        diff_output_path="$output_dir/authmap.diff.md"
        diff_markdown_path="$diff_output_path"
        ;;
    esac

    cmd=(
      cargo run --locked
      --manifest-path "$GITHUB_ACTION_PATH/Cargo.toml"
      -p authmap-cli
      --
      diff
      --base "$baseline_path"
      --head "$json_path"
      --format "$diff_format"
      --output "$diff_output_path"
      --mode "$mode"
    )
    if [[ -n "$config_path" ]]; then
      cmd+=(--config "$config_path")
    fi
    if [[ -n "$fail_on_input" ]]; then
      cmd+=(--fail-on "$fail_on_input")
    elif [[ "$baseline_uses_trusted_ref" == "true" ]]; then
      cmd+=(--fail-on "added_high_risk_route,auth_downgrade,new_linked_mutation")
    fi

    echo "Running AuthMap ${diff_format} drift report"
    "${cmd[@]}"
    status=$?
    if [[ "$status" -eq 20 ]]; then
      final_status=20
      warn "AuthMap drift enforce mode returned exit code 20 for ${diff_format}; continuing to generate requested artifacts"
      add_artifact_path "$diff_output_path"
    elif [[ "$status" -ne 0 ]]; then
      final_status="$status"
      break
    else
      add_artifact_path "$diff_output_path"
    fi
  done
fi

if [[ -n "$markdown_path" && -s "$markdown_path" && -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    printf '\n'
    cat "$markdown_path"
    printf '\n'
  } >> "$GITHUB_STEP_SUMMARY"
fi

if [[ -n "$diff_markdown_path" && -s "$diff_markdown_path" && -n "${GITHUB_STEP_SUMMARY:-}" ]]; then
  {
    printf '\n'
    cat "$diff_markdown_path"
    printf '\n'
  } >> "$GITHUB_STEP_SUMMARY"
fi

append_output "json-path" "$json_path"
append_output "markdown-path" "$markdown_path"
append_output "sarif-path" "$sarif_path"
append_output "diff-json-path" "$diff_json_path"
append_output "diff-markdown-path" "$diff_markdown_path"
append_output "output-directory" "$output_dir"
append_output "artifact-paths" "$(printf '%s\n' "${artifact_paths[@]}")"
append_output "exit-code" "$final_status"

if is_true "$defer_exit"; then
  exit 0
fi

exit "$final_status"
