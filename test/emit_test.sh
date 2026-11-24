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

echo "== one advisory is one finding =="
setup; stub "$ADVISORY" 1
run
check "exit 0" "0" "$RC"
check "one finding" "1" "$(findings)"
check "count output" "1" "$(out_val count)"
check "completed" "true" "$(out_val completed)"
check "keyed gem/name" "yes" "$(contains '"key":"gem/ruby_llm"' "$(cat "$FINDINGS_OUTPUT")")"
check "advisory id in title" "yes" "$(contains 'CVE-2026-67991 (high)' "$(jq -r .title "$FINDINGS_OUTPUT")")"
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

echo "== several advisories against one gem are one finding =="
setup; stub '{"results":[{"type":"unpatched_gem","gem":{"name":"rack","version":"2.0.1"},"advisory":{"id":"CVE-1","criticality":"low","patched_versions":[">= 2.0.2"]}},{"type":"unpatched_gem","gem":{"name":"rack","version":"2.0.1"},"advisory":{"id":"CVE-2","criticality":"high","patched_versions":[">= 2.0.3"]}},{"type":"unpatched_gem","gem":{"name":"rack","version":"2.0.1"},"advisory":{"id":"CVE-3","criticality":null,"patched_versions":[]}},{"type":"unpatched_gem","gem":{"name":"net-ssh","version":"7.3.2"},"advisory":{"id":"GHSA-x","criticality":"medium","patched_versions":[">= 7.3.3"]}}]}' 1
run
check "one finding per gem" "2" "$(findings)"
check "count output" "2" "$(out_val count)"
check "no duplicate keys" "0" "$(jq -r .key "$FINDINGS_OUTPUT" | sort | uniq -d | grep -c '')"
RACK="$(jq -c 'select(.key == "gem/rack")' "$FINDINGS_OUTPUT")"
check "rack keyed by gem" "yes" "$(contains '"key":"gem/rack"' "$RACK")"
check "title counts advisories, worst severity" "Security: rack 2.0.1 — 3 advisories (high)" "$(jq -r .title <<<"$RACK")"
BODY="$(jq -r .body <<<"$RACK")"
check "every advisory in body" "yesyesyes" "$(contains 'CVE-1' "$BODY")$(contains 'CVE-2' "$BODY")$(contains 'CVE-3' "$BODY")"
check "worst advisory listed first" "CVE-2" "$(grep -o 'CVE-[0-9]' <<<"$BODY" | head -1)"
check "unpatched advisory says so" "yes" "$(contains 'no patched release yet' "$BODY")"
check "single-advisory gem names it" "Security: net-ssh 7.3.2 — GHSA-x (medium)" "$(jq -r 'select(.key == "gem/net-ssh") | .title' "$FINDINGS_OUTPUT")"

echo "== an advisory set that changes keeps the same key =="
setup; stub '{"results":[{"type":"unpatched_gem","gem":{"name":"rack","version":"2.0.1"},"advisory":{"id":"CVE-1","criticality":"low"}}]}' 1
run
check "same key with one advisory" "gem/rack" "$(jq -r .key "$FINDINGS_OUTPUT")"

echo "== hard-wrapped descriptions are rejoined into paragraphs =="
setup
DESC='Net::SSH::Service::Forward#initialize registers channel handlers for\nthe server-initiated channel types auth-agent and\nat the moment the forwarding service is instantiated.\n\nRelated paths, for contrast:\n\n- forward_agent: true sets\n  the flag\n- auth-agent-req is sent\n\n```ruby\nNet::SSH.start(host,\n  user)\n```\n\n    indented code\n    stays put\n\n| a | b |\n| - | - |\n\n## Heading\nAfter heading.'
jq -n --arg d "$(printf '%b' "$DESC")" '{results:[{type:"unpatched_gem",gem:{name:"net-ssh",version:"7.3.2"},advisory:{id:"GHSA-x",criticality:"high",description:$d}}]}' > "$WORK/report.json"
stub "$(cat "$WORK/report.json")" 1
run
BODY="$(jq -r .body "$FINDINGS_OUTPUT")"
check "paragraph is one line" "yes" "$(contains 'registers channel handlers for the server-initiated channel types auth-agent and at the moment the forwarding service is instantiated.' "$BODY")"
check "paragraphs stay separate" "yes" "$(contains $'instantiated.\n\nRelated paths, for contrast:' "$BODY")"
check "list items stay separate" "yes" "$(contains $'- forward_agent: true sets the flag\n- auth-agent-req is sent' "$BODY")"
check "fenced code untouched" "yes" "$(contains $'Net::SSH.start(host,\n  user)' "$BODY")"
check "indented code untouched" "yes" "$(contains $'    indented code\n    stays put' "$BODY")"
check "table rows untouched" "yes" "$(contains $'| a | b |\n| - | - |' "$BODY")"
check "heading not merged" "yes" "$(contains $'## Heading\nAfter heading.' "$BODY")"

echo
echo "$pass passed, $fail failed"
[ "$fail" -eq 0 ]
