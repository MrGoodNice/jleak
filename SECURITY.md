# Security Policy

## Supported versions

jleak is at an early stage. Security fixes target the latest released version.

| Version | Supported |
| --- | --- |
| 0.1.x | yes |

## Reporting a vulnerability

Please **do not** open a public issue for security problems.

Instead, report privately via GitHub's private vulnerability reporting
(https://github.com/MrGoodNice/jleak/security/advisories/new -> Security ->
Report a vulnerability). Include:

- a description of the issue and its impact,
- steps to reproduce,
- the jleak version (`jleak --help` shows the tool version), and
- any relevant environment details.

We aim to acknowledge reports promptly and to coordinate a fix and disclosure.

## A note on jleak's own output

jleak is a security tool, so it's careful not to become a leak itself:

- Finding previews are **masked** (leading characters + asterisks).
- It performs **no network calls** — everything stays local.

If you believe jleak prints more of a secret than it should, treat that as a security
issue and report it through the channel above.

## Scope

jleak is a heuristic scanner. It can miss real secrets (false negatives) and flag
harmless strings (false positives). Use `jleak:ignore` to silence a known-safe line:

~~~text
sample = "AKIAIOSFODNN7EXAMPLE"   # jleak:ignore
~~~