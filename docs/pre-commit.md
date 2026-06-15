# Pre-commit hook

`jleak pre-commit` scans the git **staging area** — exactly what `git commit` is
about to record — and exits `1` if it finds anything, aborting the commit.

## Install

~~~bash
cp hooks/pre-commit .git/hooks/pre-commit
chmod +x .git/hooks/pre-commit
~~~

The bundled `hooks/pre-commit` is a small POSIX `sh` script that invokes
`jleak pre-commit` and lets its exit code decide whether the commit proceeds.

## Behaviour

- **Clean (exit 0):** the commit proceeds.
- **Findings (exit 1):** the commit is aborted and the findings are printed.

## Getting a commit through

- The line is a known-safe fixture -> add `jleak:ignore` to it.
- You really must bypass the hook -> `git commit --no-verify` (use sparingly).

## Tips

- Keep `jleak` on your `PATH` (e.g. via `./gradlew installDist`) so the hook can find it.
- Pair the hook with the CI job so the same contract is enforced locally and remotely.