# bundler-audit-findings

Audit the whole bundle and emit one JSONL finding per gem advisory, for
[`security-findings-issues`](https://github.com/ten-thousand-hammers/security-findings-issues)
to track as issues.

## Why this is not redundant with Dependabot

It looks like it should be. Dependabot alerts check the same lockfile for the
same kind of problem, and where they overlap Dependabot is better — it
discovers every manifest in a repository and can raise a pull request that
fixes the advisory.

But they read different databases, and the coverage differs.

Dependabot alerts fire only on **reviewed** GitHub advisories. An unreviewed
advisory carries no ecosystem or version ranges, so there is nothing to match a
lockfile against:

```
GHSA-42r3-x6vx-x49x  (ruby_llm)   type: unreviewed   vulnerabilities: 0
GHSA-...             (xmldom)     type: reviewed     vulnerabilities: 3
```

`CVE-2026-67991` is a real, high-severity ReDoS in `ruby_llm`. It is in
GitHub's database as that first entry — unreviewed, unmapped, invisible to
Dependabot. `ruby-advisory-db`, which bundler-audit reads, maps it to the gem
and the affected versions.

So this covers gem advisories that have not been reviewed into GitHub's
database yet. Leave Dependabot to raise pull requests for the ones it can see;
this catches what it cannot.

## Usage

```yaml
- name: Bundler audit
  id: gems
  uses: ten-thousand-hammers/bundler-audit-findings@v1
  with:
    output: ${{ runner.temp }}/findings/gems.jsonl

- uses: ten-thousand-hammers/security-findings-issues@v1
  with:
    findings: ${{ runner.temp }}/findings.jsonl
    token: ${{ secrets.GITHUB_TOKEN }}
    close-resolved: ${{ steps.gems.outputs.completed }}
```

### Inputs

| input | default | description |
| --- | --- | --- |
| `bundler-audit-command` | `bundle exec bundler-audit` | How to invoke it. Use `bundler-audit` when installed standalone, or `bin/bundler-audit` for a binstub. |
| `output` | `$RUNNER_TEMP/findings/gems.jsonl` | JSONL file to append findings to. |

### Outputs

| output | description |
| --- | --- |
| `count` | Number of findings written. |
| `completed` | `false` when bundler-audit produced no usable report. |

## Keys

| finding | key |
| --- | --- |
| gem advisory | `gem/<name>/<advisory id>` |
| insecure Gemfile source | `gem-source/<source>` |
| a scan that could not run | `scan/bundler-audit` |

One advisory is one issue. Two advisories against the same gem are two issues,
because they can carry different patched versions and be resolved separately.

`insecure_source` results carry a `source` and no `gem` or `advisory`. Counting
every result as a gem advisory inflates the total and renders a row of nulls,
so they are keyed and described separately.

## A scan that did not run is not a clean result

bundler-audit exits 1 for advisories and for operational failures alike — a
failed advisory-database download among them — and an empty file parses as
valid JSON. Neither the exit code nor `jq empty` distinguishes a clean report
from no report, so this checks that `.results` is an array and otherwise emits
a `scan/bundler-audit` finding with `completed=false`.

Pass that to `security-findings-issues`' `close-resolved`, or a run where the
database could not be fetched will retire every live gem finding.

## Tests

```bash
bash test/emit_test.sh
```

25 assertions covering a real advisory payload, progress output before the
JSON, a clean bundle, an insecure source, an empty report, a failed database
download, a report with no `results` array, and several advisories against one
gem.
