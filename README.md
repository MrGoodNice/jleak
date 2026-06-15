# 🔐 jleak

**Catch leaked secrets before they reach your git history.**

`jleak` is a fast, dependency-free secret scanner for the command line. It walks a
source tree — or your git staging area — and flags AWS keys, GitHub tokens, private
keys and other high-risk strings *before* they become a commit you can't take back.

[![CI](https://github.com/MrGoodNice/jleak/actions/workflows/ci.yml/badge.svg)](https://github.com/MrGoodNice/jleak/actions)
![Java](https://img.shields.io/badge/Java-21-orange.svg)
![License](https://img.shields.io/badge/License-MIT-blue.svg)
![Version](https://img.shields.io/badge/version-0.1.0-purple.svg)

![jleak scan demo](docs/assets/demo.gif)

---

## The staging trap

It rarely happens on purpose. You're debugging, you paste a *real* key into
`config.txt` to reproduce something, you fix the bug, and then — on autopilot —
you run `git add .`. The secret is now staged. One `git commit` away from your
history, your remote, and everyone who clones the repo.

`jleak pre-commit` reads what git is *about to commit* and stops you:

~~~text
$ git add .
$ jleak pre-commit

CRITICAL AWS Access Key ID         config.txt:1:21  AKIA********...  (entropy=0.00)
HIGH     GitHub Token              config.txt:2:16  ghp_********...  (entropy=0.00)
2 finding(s) | files scanned: 1 | skipped: 0 | bytes: 96 | errors: 0

$ echo $?
1
~~~

Read that output line by line:

- **CRITICAL / HIGH** — severity, so the worst leaks jump out first.
- **AWS Access Key ID** — which detector fired.
- **config.txt:1:21** — file, line and column. Click-to-jump in most terminals.
- **AKIA********...** — a *masked preview*. jleak shows enough to recognise the
  secret, never enough to leak it again through its own output.
- **(entropy=0.00)** — the Shannon entropy of the match (used by the generic detector).
- **2 finding(s) | ...** — a one-line summary of the run.
- **echo $? -> 1** — exit code `1` means "secrets found". Your pre-commit hook
  fails and the commit never happens.

### Reproduce in 30 seconds

~~~bash
mkdir jleak-demo && cd jleak-demo && git init -q
printf 'aws_key = "AKIAIOSFODNN7EXAMPLE"\ngithub = "ghp_0123456789abcdefghijklmnopqrstuvwx"\n' > config.txt
git add .

jleak pre-commit   # exits 1 and prints the findings above
~~~

---

## GitHub Action

The easiest way to use `jleak` is to drop it into your CI/CD pipeline. Add this step to your `.github/workflows/` files:

~~~yaml
- name: Scan for secrets
  uses: MrGoodNice/jleak@v1
~~~

---

## Quick start

~~~bash
# Build
gradle wrapper --gradle-version 8.8   # first time only
./gradlew build

# Run straight from Gradle
./gradlew run --args="scan ."

# Or install a runnable distribution
./gradlew installDist
./build/install/jleak/bin/jleak scan .
~~~

<details>
<summary><b>I just want to use it</b></summary>

~~~bash
jleak scan .                 # scan the current tree
jleak scan src/              # scan a specific path
jleak pre-commit             # scan what's staged for commit
jleak scan . --format json   # machine-readable output
~~~

That's the whole surface. `scan` looks at files on disk; `pre-commit` looks at the
git index. Both share the same detectors, the same masking and the same exit codes.
</details>

<details>
<summary><b>I want to trust it (exit codes, allowlisting, truncation)</b></summary>

**Exit codes are the contract** — see the table below. `0` is clean, `1` is "found
something", `2` is "you called me wrong", `3` is "I broke". CI and hooks key off
these and nothing else.

**Allowlisting** — if a match is a known false positive (a sample, a fixture, a docs
example), add `jleak:ignore` anywhere on the same line. jleak drops every finding on
that line and keeps scanning everything else.

~~~text
example_key = "AKIAIOSFODNN7EXAMPLE"   # jleak:ignore - documentation sample
~~~

**Truncation** — jleak caps how many findings it keeps (global, per-file and
per-detector) so a generated or vendored file can't bury the signal or exhaust
memory. When a cap is hit, scanning continues but the run is flagged `truncated`
(`TRUNCATED` in text output, `"truncated": true` in JSON). A truncated run still
exits `1` if anything was found — you're never told "clean" because results were dropped.
</details>

<details>
<summary><b>I want to understand why it's quick</b></summary>

jleak keeps the per-line hot path allocation-light:

- **Anchor prefilter** — before any regex runs, each line is checked for a cheap
  literal anchor (e.g. `AKIA`, `ghp_`, `-----BEGIN`). Lines without an anchor never
  touch the regex engine.
- **ThreadLocal matchers** — compiled patterns are shared; each worker thread reuses
  its own `Matcher` instances instead of allocating per line.
- **Zero-copy line views** — lines are scanned in place over per-thread buffers
  rather than copied into throwaway strings.
- **Multi-threaded walk** — files are distributed across a worker pool (one task per
  file), defaulting to your CPU count.

See docs/architecture.md and the diagram in *How it works*.
</details>

---

## Why jleak

| Feature | jleak | gitleaks | truffleHog |
|---------|-------|----------|------------|
| Zero runtime deps | ✅ | ❌ | ❌ |
| Zero-copy parsing | ✅ | ❌ | ❌ |
| Auto-masking in output | ✅ | ⚠️ | ⚠️ |
| Pure Java | ✅ | Go | Python |

- **Zero runtime dependencies.** One self-contained tool. JUnit is used for tests only.
- **Two surfaces, one engine.** Scan a tree (`scan`) or the git index (`pre-commit`).
- **Output you can pipe.** Human-readable `text` or stable `json` (`schemaVersion=1`).
- **Safe by default.** Every preview is masked; the scanner never re-leaks a secret.
- **Predictable.** A documented exit-code contract and deterministic, sorted output.

---

## How it works

jleak splits every line into a *fast path* (no anchor, skipped immediately) and a
*slow path* (anchor hit, hand off to the regex + entropy stage).

<details>
<summary>Fast path vs slow path</summary>

~~~mermaid
flowchart TD
    A["Line (zero-copy view)"] --> B{"Anchor prefilter / cheap literal scan"}
    B -- "no anchor" --> C["Skip line - fast path"]
    B -- "anchor hit" --> D["ThreadLocal Matcher - run detector regex"]
    D -- "no match" --> C
    D -- "match" --> E["Mask preview + build Finding"]
    E --> F{"Within limits?"}
    F -- "yes" --> G["Record finding"]
    F -- "no" --> H["Set truncated = true"]
~~~
</details>

The directory walk runs across a worker pool; binaries, oversized files and noisy
directories (`.git`, `node_modules`, `build`) are skipped before any line is read.

---

## Anatomy of a finding

Most detectors are one row in the matrix below. The AWS Access Key detector is worth
walking end to end, because every other detector follows the same shape.

**1. Input.** A single line reaches the scanner:

~~~text
aws_key = "AKIAIOSFODNN7EXAMPLE"
~~~

**2. Anchor / prefilter.** Before any regex runs, jleak scans the line for the literal
anchor `AKIA`. No anchor -> the line takes the fast path and the regex never runs.
Here the anchor is present, so the line is promoted to the slow path.

**3. Matching.** A `ThreadLocal` `Matcher` for `AKIA[0-9A-Z]{16}` runs against the
line and matches `AKIAIOSFODNN7EXAMPLE` at column 21.

**4. Masking.** jleak keeps a short, masked preview — leading characters plus
asterisks — so the report identifies the secret without reprinting it:
`AKIA********...`.

**5. Limits / truncation.** The finding is recorded unless a global, per-file or
per-detector cap is already reached; if so it's dropped and the run is marked
`truncated`.

**6. Output.** The same finding rendered in each format:

~~~text
CRITICAL AWS Access Key ID         config.txt:1:21  AKIA********...  (entropy=0.00)
~~~

~~~json
{
  "detector": "aws-access-key-id",
  "title": "AWS Access Key ID",
  "severity": "CRITICAL",
  "path": "config.txt",
  "line": 1,
  "column": 21,
  "preview": "AKIA********...",
  "entropy": 0.0
}
~~~

---

## Detectors

| Detector | Severity | Anchor / idea |
| --- | --- | --- |
| AWS Access Key ID | CRITICAL | `AKIA` + fixed-shape key |
| AWS Secret Access Key | CRITICAL | 40-char high-entropy secret |
| GitHub Token | HIGH | `ghp_` prefix |
| Google API Key | HIGH | `AIza` prefix |
| Slack Token | HIGH | `xox[baprs]-` prefix |
| PEM Private Key | CRITICAL | `-----BEGIN ... PRIVATE KEY-----` (once per block) |
| Telegram Bot Token | HIGH | `<digits>:<token>` shape |
| Generic High-Entropy | MEDIUM | Shannon-entropy fallback |

PEM keys are reported **once per BEGIN block**, not once per line, so a 40-line key
is a single finding.

---

## Output formats

`--format text` (default) is for humans; `--format json` is for everything else.

The JSON document is hand-built (no serialization dependency) and stable:

~~~json
{
  "schemaVersion": 1,
  "toolVersion": "0.1.0",
  "findings": [ ],
  "stats": { "findings": 0, "filesScanned": 0, "skipped": 0, "bytes": 0, "errors": 0 },
  "truncated": false
}
~~~

Full examples: examples/sample-output.txt and
examples/sample-output.json.

---

## Limits & truncation

jleak enforces caps so one pathological file can't dominate a run:

- **Global**, **per-file** and **per-detector** finding caps.
- When any cap is hit, scanning continues but the run is flagged `truncated`
  (`TRUNCATED` in text, `"truncated": true` in JSON).
- A truncated run that found anything still exits `1`. jleak never reports "clean"
  because it stopped early.

---

## Exit codes

The exit-code contract is the heart of jleak's CI and pre-commit integration:

| Code | Meaning | Typical cause |
| --- | --- | --- |
| `0` | Clean | No findings |
| `1` | Findings | One or more secrets detected |
| `2` | Usage error | Bad arguments / unknown option |
| `3` | Internal error | Unexpected failure during the run |

~~~bash
# Fail a CI job on any finding
jleak scan .

# Distinguish "findings" from "tool misuse"
jleak scan .
case "$?" in
  0) echo "clean" ;;
  1) echo "secrets found"; exit 1 ;;
  2) echo "bad usage"; exit 2 ;;
  3) echo "jleak errored"; exit 3 ;;
esac

# Gate a deploy step on a clean scan
jleak scan . && ./deploy.sh
~~~

---

## CLI reference

~~~text
jleak <command> [path] [options]

Commands:
  scan [path]     Scan a directory tree (default path: .)
  pre-commit      Scan the current git staging area

Options:
  --threads N            Worker threads (default: CPU count)
  --max-file-size BYTES  Skip files larger than this (default: 5242880 = 5 MiB)
  --format text|json     Output format (default: text)
  -h, --help             Show help
~~~

---

## Pre-commit hook

Install the bundled hook so every commit is scanned automatically:

~~~bash
cp hooks/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
~~~

Now a `git commit` that stages a secret fails with exit code `1` and is aborted.
Need a commit through anyway (e.g. an intentional fixture)? Add `jleak:ignore` to the
line, or bypass with `git commit --no-verify` (use sparingly).

---

## Allowlisting

Add `jleak:ignore` anywhere on a line to suppress every finding on that line:

~~~text
test_key = "AKIAIOSFODNN7EXAMPLE"   # jleak:ignore - fixture, not a real key
~~~

Everything else in the file is still scanned.

---

## Performance

> **Truth first:** there are **no published benchmark numbers** for jleak yet. The
> points below are design facts you can verify by reading the code — not marketing.

- The per-line hot path avoids per-line allocations (ThreadLocal matchers, zero-copy
  line views, per-thread buffers).
- An anchor prefilter keeps the regex engine off lines that can't match.
- The directory walk is multi-threaded (one task per file, defaulting to CPU count).
- Binaries, oversized files and noisy directories are skipped before they're read.

Want numbers for *your* repo? Measure it:

~~~bash
./gradlew installDist
time ./build/install/jleak/bin/jleak scan /path/to/your/repo
~~~

---

## FAQ

**Does jleak send anything over the network?** No. It reads local files only.

**Will it print my secrets?** No — previews are masked, so its output is safe to paste into an issue.

**A match is a false positive. Now what?** Add `jleak:ignore` to the line, or rely on limits/truncation for noisy generated files.

**Why a manual JSON writer?** To keep the tool dependency-free. The format is versioned via `schemaVersion`.

---

## Contributing

Issues and pull requests are welcome — see CONTRIBUTING.md. Found
a security issue? Read SECURITY.md first.

## License

MIT (c) 2026 the jleak authors.