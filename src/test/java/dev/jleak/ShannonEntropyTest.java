package dev.jleak;

import dev.jleak.entropy.ShannonEntropy;
import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ShannonEntropyTest {

    private final int[] counts = new int[128];
    private final int[] touched = new int[128];

    @Test
    void repeatedCharsHaveZeroEntropy() {
        String s = "aaaaaaaaaaaaaaaa";
        double e = ShannonEntropy.of(s, 0, s.length(), counts, touched);
        assertEquals(0.0, e, 1e-9);
    }

    @Test
    void randomLikeStringHasHighEntropy() {
        String s = "A1b2C3d4E5f6G7h8wXyZ09qWeRtY";
        double e = ShannonEntropy.of(s, 0, s.length(), counts, touched);
        assertTrue(e > 4.0, "expected high entropy, got " + e);
    }

    @Test
    void scratchArraysAreResetBetweenCalls() {
        String a = "abcdefgh";
        String b = "aaaaaaaa";
        ShannonEntropy.of(a, 0, a.length(), counts, touched);
        double second = ShannonEntropy.of(b, 0, b.length(), counts, touched);
        assertEquals(0.0, second, 1e-9);
    }

    @Test
    void emptyRangeIsZero() {
        String s = "whatever";
        assertEquals(0.0, ShannonEntropy.of(s, 3, 3, counts, touched), 1e-9);
    }
}
