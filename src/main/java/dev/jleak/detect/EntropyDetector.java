package dev.jleak.detect;

import dev.jleak.entropy.ShannonEntropy;
import dev.jleak.model.Finding;
import dev.jleak.model.SecretType;

/**
 * The catch-all: flags random-looking tokens that no specific rule claimed.
 *
 * <p>It splits a line into tokens by index only - we never cut substrings while
 * scanning - and a candidate has to clear both the length window
 * [minLen, maxLen] and the Shannon-entropy floor before it's reported. Only the
 * surviving candidate gets redacted, so we don't pay that cost for tokens we
 * throw away.
 */
public final class EntropyDetector implements Detector {
    private final double minEntropy;
    private final int minLen;
    private final int maxLen;

    public EntropyDetector(double minEntropy, int minLen, int maxLen) {
        this.minEntropy = minEntropy;
        this.minLen = minLen;
        this.maxLen = maxLen;
    }

    @Override
    public SecretType type() {
        return SecretType.GENERIC_HIGH_ENTROPY;
    }

    @Override
    public void detect(LineContext ctx, FindingSink sink) {
        CharSequence s = ctx.view;
        int n = s.length();
        int i = 0;
        while (i < n) {
            // Skip separators, then take the run of token chars as [start, end).
            while (i < n && !isTokenChar(s.charAt(i))) i++;
            int start = i;
            while (i < n && isTokenChar(s.charAt(i))) i++;
            int end = i;
            int len = end - start;
            // Length gate first - it's far cheaper than computing entropy.
            if (len < minLen || len > maxLen) continue;
            // Entropy over the index range, reusing the context's scratch buffers.
            double entropy = ShannonEntropy.of(s, start, end, ctx.entropyCounts, ctx.entropyTouched);
            if (entropy >= minEntropy) {
                String redacted = Finding.redact(s, start, end);
                sink.report(Finding.from(SecretType.GENERIC_HIGH_ENTROPY, ctx, start, len, redacted, entropy));
            }
        }
    }

    // Token alphabet: letters, digits and the symbols that show up in base64 /
    // url-safe encodings, so keys aren't split apart mid-token.
    private static boolean isTokenChar(char c) {
        return (c >= 'A' && c <= 'Z') || (c >= 'a' && c <= 'z') || (c >= '0' && c <= '9')
                || c == '+' || c == '/' || c == '_' || c == '-' || c == '=';
    }
}
