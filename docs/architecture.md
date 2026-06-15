# Architecture

jleak is a small pipeline: **walk -> read -> scan lines -> collect -> report**.

## Components

- **CLI (`dev.jleak.cli.JLeakCli`)** — parses arguments, selects the source
  (filesystem tree for `scan`, git index for `pre-commit`), runs the scan and maps
  the result to an exit code.
- **Walker** — traverses the tree on a worker pool, one task per file. Skips noisy
  directories (`.git`, `node_modules`, `build`), binaries, and files larger than
  `--max-file-size` (default 5 MiB).
- **Detectors** — each owns a literal anchor, a pattern and a severity. Compiled
  patterns are shared; `Matcher` instances are `ThreadLocal`.
- **Scanner** — for each line: anchor prefilter -> regex / entropy -> mask -> limit check.
- **Reporter** — renders findings as `text` or `json`, deterministically sorted.

## The hot path

~~~mermaid
flowchart TD
    A["Line (zero-copy view)"] --> B{"Anchor prefilter"}
    B -- "no anchor" --> C["Fast path: skip"]
    B -- "anchor hit" --> D["ThreadLocal Matcher + entropy"]
    D -- "no match" --> C
    D -- "match" --> E["Mask + Finding"]
    E --> F{"Within limits?"}
    F -- "yes" --> G["Record"]
    F -- "no" --> H["truncated = true"]
~~~

Design choices that keep the per-line path light:

- **Anchor prefilter** keeps the regex engine off lines that can't match.
- **Zero-copy line views** avoid per-line `String` allocation.
- **Per-thread buffers and ThreadLocal matchers** avoid per-line allocation and
  cross-thread contention.

## Concurrency model

One task scans one file end to end; nothing about a file is shared across threads.
Shared state (compiled patterns) is immutable; mutable state (matchers, buffers) is
per-thread. Results are merged and sorted before reporting for deterministic output.