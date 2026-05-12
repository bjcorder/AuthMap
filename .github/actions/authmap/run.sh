#!/usr/bin/env bash
set -uo pipefail

error() {
  echo "::error::$*"
}

warn() {
  echo "::warning::$*"
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
  if [[ "$value" = /* ]]; then
    printf '%s' "$value"
  else
    printf '%s/%s' "$GITHUB_WORKSPACE" "$value"
  fi
}

append_output() {
  local name="$1"
  local value="$2"
  if [[ -n "${GITHUB_OUTPUT:-}" ]]; then
    printf '%s=%s\n' "$name" "$value" >> "$GITHUB_OUTPUT"
  fi
}

add_format() {
  local format="$1"
  local existing
  for existing in "${formats[@]}"; do
    if [[ "$existing" == "$format" ]]; then
      return
    fi
  done
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
[[ -n "$target_input" ]] || die "target must not be empty"
target_path="$(workspace_path "$target_input")"

config_input="$(trim "${INPUT_CONFIG:-}")"
config_path=""
if [[ -n "$config_input" ]]; then
  config_path="$(workspace_path "$config_input")"
fi

baseline_input="$(trim "${INPUT_BASELINE:-}")"
baseline_path=""
if [[ -n "$baseline_input" ]]; then
  baseline_path="$(workspace_path "$baseline_input")"
fi

fail_on_input="$(trim "${INPUT_FAIL_ON:-}")"

output_dir_input="$(trim "${INPUT_OUTPUT_DIRECTORY:-.authmap}")"
[[ -n "$output_dir_input" ]] || die "output-directory must not be empty"
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
  elif [[ "$status" -ne 0 ]]; then
    final_status="$status"
    break
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
    fi

    echo "Running AuthMap ${diff_format} drift report"
    "${cmd[@]}"
    status=$?
    if [[ "$status" -eq 20 ]]; then
      final_status=20
      warn "AuthMap drift enforce mode returned exit code 20 for ${diff_format}; continuing to generate requested artifacts"
    elif [[ "$status" -ne 0 ]]; then
      final_status="$status"
      break
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
append_output "exit-code" "$final_status"

if is_true "$defer_exit"; then
  exit 0
fi

exit "$final_status"
