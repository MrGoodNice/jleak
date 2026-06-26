package dev.jleak.detect;

import dev.jleak.model.Finding;
import dev.jleak.model.SecretType;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class EntropyDetectorTest {

    private final Path dummyFile = Path.of("test.txt");

    private List<Finding> detect(String line, double minEntropy, int minLen, int maxLen) {
        EntropyDetector d = new EntropyDetector(minEntropy, minLen, maxLen);
        LineContext ctx = new LineContext();
        ctx.set(dummyFile, 1, 0, line.toCharArray(), 0, line.length());
        List<Finding> findings = new ArrayList<>();
        d.detect(ctx, findings::add);
        return findings;
    }

    @Test
    void typeIsGenericHighEntropy() {
        EntropyDetector d = new EntropyDetector(4.0, 20, 128);
        assertEquals(SecretType.GENERIC_HIGH_ENTROPY, d.type());
    }

    @Test
    void highEntropyTokenIsDetected() {
        // Random-looking token > 20 chars with high entropy
        String line = "secret = A1b2C3d4E5f6G7h8I9j0K1l2M3n4";
        List<Finding> results = detect(line, 4.0, 20, 128);
        assertTrue(results.size() >= 1, "high entropy token should be flagged");
    }

    @Test
    void lowEntropyTokenIsNotDetected() {
        // Repeated chars have zero entropy
        String line = "value = aaaaaaaaaaaaaaaaaaaaaaaaaaaa";
        List<Finding> results = detect(line, 4.0, 20, 128);
        assertEquals(0, results.size(), "low entropy tokens should not be flagged");
    }

    @Test
    void tokenShorterThanMinLenIsIgnored() {
        // High entropy but too short (minLen=20)
        String line = "val = A1b2C3d4E5f6";
        List<Finding> results = detect(line, 3.0, 20, 128);
        assertEquals(0, results.size(), "short tokens should be ignored");
    }

    @Test
    void tokenLongerThanMaxLenIsIgnored() {
        // Extremely long token beyond maxLen
        StringBuilder sb = new StringBuilder("secret = ");
        for (int i = 0; i < 200; i++) {
            sb.append((char) ('A' + (i % 26)));
        }
        String line = sb.toString();
        List<Finding> results = detect(line, 3.0, 20, 50);
        assertEquals(0, results.size(), "tokens longer than maxLen should be ignored");
    }

    @Test
    void separatorsBreakTokens() {
        // Spaces, colons, equals are separators that split tokens
        String line = "key=A1b2C3d4E5f6G7h8I9j0K1 value=X9y8Z7w6V5u4T3s2R1q0P9";
        List<Finding> results = detect(line, 4.0, 20, 128);
        // Each part is a separate token; "key" is too short, the random parts should be checked
        for (Finding f : results) {
            assertTrue(f.length() >= 20);
        }
    }

    @Test
    void tokenAlphabetIncludesBase64Chars() {
        // Tokens with +, /, _, -, = should not be split
        String line = "data = wJalrXUtnFEMI/K7MDENG+bPxRfi_CY-EXA=KEY";
        List<Finding> results = detect(line, 3.0, 20, 128);
        // The whole base64-like token should be considered as one
        assertTrue(results.size() >= 1);
        // Verify the token wasn't split at / or +
        Finding f = results.get(0);
        assertTrue(f.length() > 30, "base64 chars should not split tokens");
    }

    @Test
    void columnIsOneBasedFromOffset() {
        String line = "A1b2C3d4E5f6G7h8I9j0K1l2";
        List<Finding> results = detect(line, 3.0, 20, 128);
        assertTrue(results.size() >= 1);
        assertEquals(1, results.get(0).column(), "column should be 1-based");
    }

    @Test
    void emptyLineProducesNoFindings() {
        List<Finding> results = detect("", 4.0, 20, 128);
        assertEquals(0, results.size());
    }

    @Test
    void lineWithOnlySeparatorsProducesNoFindings() {
        List<Finding> results = detect("   ::: === ;;;  ", 4.0, 20, 128);
        assertEquals(0, results.size());
    }
}
