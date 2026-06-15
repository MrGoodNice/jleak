# Exit codes

jleak's exit code is its integration contract. CI jobs and the pre-commit hook key
off it and nothing else.

| Code | Meaning | Typical cause |
| --- | --- | --- |
| `0` | Clean | No findings |
| `1` | Findings | One or more secrets detected |
| `2` | Usage error | Bad arguments / unknown option |
| `3` | Internal error | Unexpected failure during the run |

A run that hit its limits (`truncated`) but still found something exits `1`: jleak
never reports clean because it stopped early.

## Examples

~~~bash
# Fail CI on any finding
jleak scan .

# Distinguish "findings" from "tool misuse"
jleak scan .
case "$?" in
  0) echo "clean" ;;
  1) echo "secrets found"; exit 1 ;;
  2) echo "bad usage"; exit 2 ;;
  3) echo "jleak errored"; exit 3 ;;
esac

# Gate a deploy on a clean scan
jleak scan . && ./deploy.sh
~~~