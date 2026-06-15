# Performance

> **Truth first:** jleak has **no published benchmark numbers** yet. This page lists
> design facts you can verify in the source, plus how to measure on your own repo.
> No "blazing fast" claims here.

## What makes the hot path cheap

- **Anchor prefilter** — a literal substring check runs before any regex, so lines
  that can't match never reach the regex engine.
- **ThreadLocal matchers** — compiled patterns are shared and immutable; each thread
  reuses its own `Matcher` instances instead of allocating per line.
- **Zero-copy line views** — lines are scanned in place over per-thread buffers.
- **Multi-threaded walk** — one task per file across a worker pool (default: CPU count).
- **Early skipping** — binaries, files over `--max-file-size`, and noisy directories
  (`.git`, `node_modules`, `build`) are excluded before they're read.

## Knobs

- `--threads N` — worker threads (default: CPU count).
- `--max-file-size BYTES` — skip large files (default: 5242880 = 5 MiB).

## Measure it yourself

~~~bash
./gradlew installDist
time ./build/install/jleak/bin/jleak scan /path/to/your/repo
~~~

Vary `--threads` and `--max-file-size` and compare wall-clock time on your own
hardware and codebase — that's the only number that matters for your setup.