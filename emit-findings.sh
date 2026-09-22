#!/usr/bin/env bash
# Emit one JSONL finding per gem advisory.
#
# This script inspects exit codes itself -- a scanner that fails is a finding,
# not a reason to abort -- so errexit must stay off, including when a caller
# exports it through SHELLOPTS.
set -uo pipefail
set +e

command_line="${BUNDLER_AUDIT_COMMAND:-bundle exec bundler-audit}"
out="${FINDINGS_OUTPUT:-${RUNNER_TEMP:-/tmp}/findings/gems.jsonl}"
raw="${RUNNER_TEMP:-/tmp}/bundler-audit-raw.txt"
report="${RUNNER_TEMP:-/tmp}/bundler-audit.json"
mkdir -p "$(dirname "$out")"
: > "$out"

# shellcheck disable=SC2086
$command_line check --update --format json > "$raw" 2>&1
code=$?

# The advisory-database update prints progress before the JSON starts.
awk '/^\{/{found=1} found' "$raw" > "$report"

finish() {
  {
    echo "count=$(grep -c '' "$out")"
    echo "completed=$1"
  } >> "${GITHUB_OUTPUT:-/dev/null}"
}

# bundler-audit exits 1 for advisories and for operational failures alike, and
# an empty file parses as valid JSON, so neither the exit code nor `jq empty`
# distinguishes a clean report from no report. Check the report's shape.
if [ "$code" -gt 1 ] || ! jq -e '.results | type == "array"' "$report" >/dev/null 2>&1; then
  jq -cn --arg log "$(tail -30 "$raw")" --arg code "$code" '{
    key: "scan/bundler-audit",
    title: "Security scan: bundler-audit could not complete",
    body: ("bundler-audit exited \($code) without a usable report, so gem advisories are currently unchecked.\n\n```\n\($log)\n```")
  }' >> "$out"
  finish false
  echo "::warning::bundler-audit did not complete; reporting the scan failure as a finding."
  exit 0
fi

# Only unpatched_gem results describe a gem advisory. bundler-audit also emits
# insecure_source results, which carry a `source` and no `gem` or `advisory`.
jq -c '
  .results[]? | select(.type == "unpatched_gem") |
  (.advisory.id // .advisory.cve // .advisory.ghsa // "unknown") as $id |
  {
    key: ("gem/" + .gem.name + "/" + $id),
    title: ("Security: " + .gem.name + " " + .gem.version + " — " + $id
            + " (" + (.advisory.criticality // "unknown") + ")"),
    body: (
      "**Gem:** `" + .gem.name + "` " + .gem.version + "  \n" +
      "**Advisory:** [" + $id + "](" + (.advisory.url // "") + ")  \n" +
      "**Severity:** " + (.advisory.criticality // "unknown") + "  \n" +
      "**Fixed in:** " + ((.advisory.patched_versions // [])
        | if length == 0 then "no patched release yet" else join(", ") end) + "\n\n" +
      "### " + (.advisory.title // "Advisory") + "\n\n" +
      (.advisory.description // "")
    )
  }' "$report" >> "$out"

jq -c '
  .results[]? | select(.type == "insecure_source") |
  {
    key: ("gem-source/" + .source),
    title: ("Security: insecure Gemfile source " + .source),
    body: ("`" + .source + "` is fetched over an insecure transport, so the gems it serves can be tampered with in transit.\n\nPoint the source at its HTTPS equivalent in the `Gemfile`.")
  }' "$report" >> "$out"

finish true
echo "$(grep -c '' "$out") gem finding(s)."
