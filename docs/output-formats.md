# Output formats

Select a format with `--format text` (default) or `--format json`.

## Text

One line per finding, sorted deterministically, followed by a summary line:

~~~text
CRITICAL AWS Access Key ID         config.txt:1:21  AKIA********...  (entropy=0.00)
HIGH     GitHub Token              config.txt:2:16  ghp_********...  (entropy=0.00)
2 finding(s) | files scanned: 1 | skipped: 0 | bytes: 96 | errors: 0
~~~

Columns: severity, detector title, `path:line:column`, masked preview, entropy.

## JSON

A single, hand-built JSON document (no serialization dependency), versioned via
`schemaVersion`:

~~~json
{
  "schemaVersion": 1,
  "toolVersion": "0.1.0",
  "findings": [
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
  ],
  "stats": {
    "findings": 1,
    "filesScanned": 1,
    "skipped": 0,
    "bytes": 96,
    "errors": 0
  },
  "truncated": false
}
~~~

### Stability

- `schemaVersion` is bumped on any breaking change to the JSON shape.
- `toolVersion` mirrors the release version.
- `truncated` is `true` when any limit was hit during the run.