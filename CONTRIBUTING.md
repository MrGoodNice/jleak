# Contributing to jleak

Thanks for considering a contribution! jleak aims to stay small, fast and
dependency-free — please keep that spirit in mind.

## Getting set up

~~~bash
git clone https://github.com/MrGoodNice/jleak.git
cd jleak
gradle wrapper --gradle-version 8.8   # first time only
./gradlew build
~~~

## Before you open a PR

~~~bash
./gradlew build                 # compiles and runs the tests
./gradlew run --args="scan ."   # sanity-check the CLI
~~~

- Keep the **runtime** dependency-free. New libraries are only acceptable in tests.
- Preserve the **exit-code contract** (0/1/2/3) — CI and hooks depend on it.
- Don't break the JSON contract without bumping `schemaVersion`.
- Match the existing style; prefer allocation-light code on the per-line hot path.

## Adding a detector

A good detector has:

1. A cheap **literal anchor** so the prefilter can skip non-matching lines.
2. A precise pattern (avoid catching obvious non-secrets).
3. A sensible **severity** (CRITICAL / HIGH / MEDIUM).
4. A **masked preview** — never emit a full secret.
5. At least one test with a positive and a negative case.

## Commit messages

Conventional-style prefixes are appreciated (`feat:`, `fix:`, `docs:`, `perf:`,
`test:`, `chore:`), but clear English wins over strict format.

## Reporting bugs & requesting features

Use the issue templates under `.github/ISSUE_TEMPLATE/`. For anything
security-sensitive, follow SECURITY.md instead of opening a public issue.