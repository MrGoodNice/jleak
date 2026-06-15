# Detectors

Each detector pairs a cheap literal **anchor** with a precise pattern and a severity.
The anchor lets the prefilter skip lines that can't possibly match before any regex runs.

| Detector | Severity | Anchor / idea | Notes |
| --- | --- | --- | --- |
| AWS Access Key ID | CRITICAL | `AKIA` | Fixed-shape 20-char key |
| AWS Secret Access Key | CRITICAL | context + entropy | 40-char high-entropy secret |
| GitHub Token | HIGH | `ghp_` | Personal access token |
| Google API Key | HIGH | `AIza` | API key shape |
| Slack Token | HIGH | `xox[baprs]-` | Bot / user / app tokens |
| PEM Private Key | CRITICAL | `-----BEGIN ... PRIVATE KEY-----` | Reported once per block |
| Telegram Bot Token | HIGH | `<digits>:<token>` | Bot API token shape |
| Generic High-Entropy | MEDIUM | Shannon entropy | Fallback for unknown secrets |

## Severities

- **CRITICAL** — high-confidence, high-impact credentials (cloud keys, private keys).
- **HIGH** — service tokens that grant meaningful access.
- **MEDIUM** — entropy-based heuristics that may need human judgement.

## The generic (entropy) detector

When no specific pattern matches, jleak falls back to a Shannon-entropy heuristic for
long, random-looking tokens. The measured entropy is reported alongside the finding
(`entropy=` in text, `"entropy"` in JSON) so you can judge confidence. Specific
detectors report `entropy=0.00` because their confidence comes from the pattern, not
randomness.

## False positives

Use `jleak:ignore` on a line to silence a known-safe match. See
allowlisting.