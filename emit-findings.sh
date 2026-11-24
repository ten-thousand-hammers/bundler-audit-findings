#!/usr/bin/env bash
# Emit one JSONL finding per vulnerable gem, covering all of its advisories.
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
# Compare the output rather than using `jq -e`: jq 1.6 exits 0 on empty input.
if [ "$code" -gt 1 ] || [ "$(jq '.results | type == "array"' "$report" 2>/dev/null)" != true ]; then
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
#
# Advisories are grouped by gem: however many advisories a gem has, fixing them
# is one upgrade, so it is one finding. The body changes when an advisory is
# added or fixed, which refreshes the issue rather than opening another.
jq -c '
  def rank: {"critical":4,"high":3,"medium":2,"moderate":2,"low":1}[. // ""] // 0;
  def sev: .advisory.criticality // "unknown";
  def aid: .advisory.id // .advisory.cve // .advisory.ghsa // "unknown";
  def fixed: (.advisory.patched_versions // [])
    | if length == 0 then "no patched release yet" else join(", ") end;
  # ruby-advisory-db hard-wraps descriptions at ~70 columns, and GitHub issues
  # render every newline as a break. Rejoin wrapped lines into paragraphs.
  # A line that is blank, a list item, heading or heading underline, quote,
  # table row, indented code or link definition is a block of its own: it is
  # never joined onto, and only a list item takes the lines after it. A fenced
  # block is left alone until a fence of the same character and at least the
  # same length closes it.
  def block: test("^(\\s*([-*+]|[0-9]+[.)])\\s|\\s*[#>|]| {4}|\\t| {0,3}\\[[^\\]]+\\]:| {0,3}(=+|-+|\\*+|_+)\\s*$)");
  def unwrap:
    reduce split("\n")[] as $l ({out: [], open: false, fence: null};
      (($l | capture("^ {0,3}(?<f>`{3,}|~{3,})") | .f) // null) as $f
      | if .fence != null then
          .out += [$l]
          | if $f != null and ($f[0:1] == .fence[0:1]) and ($f | length) >= (.fence | length)
              and ($l | test("^ {0,3}[`~]+\\s*$")) then .fence = null else . end
        elif $f != null then .out += [$l] | .fence = $f | .open = false
        elif ($l | test("^\\s*$")) then .out += [""] | .open = false
        elif ($l | block) then
          # A list item keeps its wrapped continuation lines.
          .out += [$l] | .open = ($l | test("^\\s*([-*+]|[0-9]+[.)])\\s") and (test("  $") | not))
        elif .open then
          .out[(.out | length) - 1] += " " + ($l | sub("^\\s+"; ""))
          | .open = ($l | test("  $") | not)
        else .out += [$l] | .open = ($l | test("  $") | not)
        end)
    | .out | join("\n");
  [ .results[]? | select(.type == "unpatched_gem") ]
  | group_by(.gem.name)[]
  | sort_by([-(sev | rank), aid]) as $advs
  | $advs[0] as $top
  | ($top.gem.name) as $name
  | ([$advs[].gem.version] | unique | join(", ")) as $version
  | ($top | sev) as $worst
  | {
      key: ("gem/" + $name),
      title: ("Security: " + $name + " " + $version + " — "
              + (if ($advs | length) == 1 then ($top | aid)
                 else "\($advs | length) advisories" end)
              + " (" + $worst + ")"),
      body: (
        "**Gem:** `" + $name + "` " + $version + "  \n" +
        "**Highest severity:** " + $worst + "  \n" +
        "**Advisories:** \($advs | length)\n\n" +
        "Upgrading `" + $name + "` past every \"Fixed in\" version below closes this issue.\n\n" +
        "| Advisory | Severity | Fixed in |\n| --- | --- | --- |\n" +
        ([ $advs[] | "| " + (if .advisory.url then "[" + aid + "](" + .advisory.url + ")" else aid end) + " | " + sev + " | " + fixed + " |" ]
          | join("\n")) + "\n\n" +
        ([ $advs[] | "### " + aid + ": " + (.advisory.title // "Advisory") + "\n\n"
                   + (.advisory.description // "" | unwrap) ] | join("\n\n"))
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
