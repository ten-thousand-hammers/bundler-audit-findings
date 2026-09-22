#!/usr/bin/env bash
# Drives emit-findings.sh against a stubbed bundler-audit. The payloads are the
# real shapes: the unpatched_gem fixture is the live ruby_llm advisory as
# bundler-audit reports it.
set -uo pipefail
cd "$(dirname "$0")/.."
ROOT="$PWD"

pass=0; fail=0
check() {
  if [ "$2" = "$3" ]; then printf '  ok   %s\n' "$1"; pass=$((pass+1))
  else printf '  FAIL %s\n       expected: %s\n       actual:   %s\n' "$1" "$2" "$3"; fail=$((fail+1)); fi
}
contains() { case "$2" in *"$1"*) echo yes;; *) echo no;; esac; }

setup() {
  WORK="$(mktemp -d)"
  export RUNNER_TEMP="$WORK" GITHUB_OUTPUT="$WORK/gh_output" FINDINGS_OUTPUT="$WORK/findings.jsonl"
  : > "$GITHUB_OUTPUT"; mkdir -p "$WORK/bin"
}
# $1 = stdout, $2 = exit code
stub() {
  { printf '#!/usr/bin/env bash\ncat <<%s\n' "'PAYLOAD'"; printf '%s\n' "$1"; printf 'PAYLOAD\nexit %s\n' "$2"; } > "$WORK/bin/bundler-audit"
  chmod +x "$WORK/bin/bundler-audit"
  export BUNDLER_AUDIT_COMMAND="$WORK/bin/bundler-audit"
}
run() { OUT="$(bash "$ROOT/emit-findings.sh" 2>&1)"; RC=$?; }
out_val() { local v; v="$(grep "^$1=" "$GITHUB_OUTPUT" | tail -1 | cut -d= -f2)"; echo "${v:-unset}"; }
findings() { grep -c '' "$FINDINGS_OUTPUT" 2>/dev/null; true; }

ADVISORY='{"results":[{"type":"unpatched_gem","gem":{"name":"ruby_llm","version":"1.16.0"},"advisory":{"id":"CVE-2026-67991","url":"https://nvd.nist.gov/vuln/detail/CVE-2026-67991","criticality":"high","title":"Polynomial-Time ReDoS","description":"A crafted name causes excessive CPU.","patched_versions":[">= 2.0.0.rc1"]}}]}'

echo "== one finding per advisory =="
setup; stub "$ADVISORY" 1
run
check "exit 0" "0" "$RC"
check "one finding" "1" "$(findings)"
check "count output" "1" "$(out_val count)"
check "completed" "true" "$(out_val completed)"
check "keyed gem/name/advisory" "yes" "$(contains '"key":"gem/ruby_llm/CVE-2026-67991"' "$(cat "$FINDINGS_OUTPUT")")"
check "version in title" "yes" "$(contains 'ruby_llm 1.16.0' "$(jq -r .title "$FINDINGS_OUTPUT")")"
check "patched version in body" "yes" "$(contains '>= 2.0.0.rc1' "$(jq -r .body "$FINDINGS_OUTPUT")")"

echo "== progress output before the JSON is skipped =="
setup; stub "Download ruby-advisory-db ...
Cloning into 'db'...
$ADVISORY" 1
run
check "still one finding" "1" "$(findings)"
check "completed" "true" "$(out_val completed)"

echo "== a clean bundle emits nothing =="
setup; stub '{"results":[]}' 0
run
check "no findings" "0" "$(findings)"
check "completed" "true" "$(out_val completed)"

echo "== an insecure source is its own finding, not a gem advisory =="
setup; stub '{"results":[{"type":"insecure_source","source":"http://rubygems.org/"}]}' 1
run
check "one finding" "1" "$(findings)"
check "keyed gem-source" "yes" "$(contains '"key":"gem-source/http://rubygems.org/"' "$(cat "$FINDINGS_OUTPUT")")"
check "no null gem name" "no" "$(contains 'gem/null' "$(cat "$FINDINGS_OUTPUT")")"

echo "== an empty report is a scan failure, not a clean bundle =="
setup; stub '' 1
run
check "exit 0" "0" "$RC"
check "one finding" "1" "$(findings)"
check "keyed scan/bundler-audit" "yes" "$(contains '"key":"scan/bundler-audit"' "$(cat "$FINDINGS_OUTPUT")")"
check "completed is false" "false" "$(out_val completed)"
check "warns" "yes" "$(contains '::warning::bundler-audit did not complete' "$OUT")"

echo "== a failed database download is a scan failure =="
setup; stub 'Download ruby-advisory-db ...
failed to download https://github.com/rubysec/ruby-advisory-db.git' 2
run
check "keyed scan/bundler-audit" "yes" "$(contains '"key":"scan/bundler-audit"' "$(cat "$FINDINGS_OUTPUT")")"
check "completed is false" "false" "$(out_val completed)"
check "the error is in the body" "yes" "$(contains 'failed to download' "$(cat "$FINDINGS_OUTPUT")")"

echo "== a report with no results array is a scan failure =="
setup; stub '{"version":"0.9.2"}' 1
run
check "completed is false" "false" "$(out_val completed)"

echo "== several advisories against one gem are separate findings =="
setup; stub '{"results":[{"type":"unpatched_gem","gem":{"name":"rack","version":"2.0.1"},"advisory":{"id":"CVE-1","criticality":"high","patched_versions":[">= 2.0.2"]}},{"type":"unpatched_gem","gem":{"name":"rack","version":"2.0.1"},"advisory":{"id":"CVE-2","criticality":"low","patched_versions":[">= 2.0.3"]}}]}' 1
run
check "two findings" "2" "$(findings)"
check "no duplicate keys" "0" "$(jq -r .key "$FINDINGS_OUTPUT" | sort | uniq -d | grep -c '')"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
