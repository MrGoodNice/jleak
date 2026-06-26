package dev.jleak.model;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class FindingTest {

    @Test
    void redactShowsFirstFourCharsAndMasks() {
        String input = "AKIAIOSFODNN7EXAMPLE";
        String result = Finding.redact(input, 0, input.length());
        // First 4 chars visible, then asterisks, then ellipsis if masked > cap
        assertTrue(result.startsWith("AKIA"), "should start with first 4 chars");
        assertTrue(result.contains("*"), "should contain mask chars");
    }

    @Test
    void redactShortStringShowsAllAsVisible() {
        String input = "abc";
        String result = Finding.redact(input, 0, input.length());
        // n=3, show=min(4,3)=3, masked=0 -> no asterisks
        assertEquals("abc", result);
    }

    @Test
    void redactExactlyFourCharsShowsAll() {
        String input = "AKIA";
        String result = Finding.redact(input, 0, input.length());
        assertEquals("AKIA", result);
    }

    @Test
    void redactFiveCharsShowsFourPlusOneStar() {
        String input = "AKIA1";
        String result = Finding.redact(input, 0, input.length());
        assertEquals("AKIA*", result);
    }

    @Test
    void redactCapsAsterisksAtTwelve() {
        // 4 shown + more than 12 masked -> cap=12 asterisks + "..."
        String input = "AKIA" + "X".repeat(20);
        String result = Finding.redact(input, 0, input.length());
        assertEquals("AKIA" + "*".repeat(12) + "...", result);
    }

    @Test
    void redactEmptyRangeReturnsEmpty() {
        String input = "whatever";
        String result = Finding.redact(input, 3, 3);
        assertEquals("", result);
    }

    @Test
    void redactRespectsStartOffset() {
        String input = "prefix_ghp_abcdefghijklmnopqrstuvwxyz1234";
        String result = Finding.redact(input, 7, 7 + 36);
        assertTrue(result.startsWith("ghp_"), "redacted should start from the offset");
    }

    @Test
    void compareToSortsBySeverityDescending() {
        Finding critical = new Finding(SecretType.AWS_ACCESS_KEY, Severity.CRITICAL,
                Path.of("a.txt"), 1, 1, 20, "AKIA****", 0.0);
        Finding medium = new Finding(SecretType.GENERIC_HIGH_ENTROPY, Severity.MEDIUM,
                Path.of("a.txt"), 1, 1, 20, "abcd****", 4.5);
        assertTrue(critical.compareTo(medium) < 0, "CRITICAL should sort before MEDIUM");
        assertTrue(medium.compareTo(critical) > 0);
    }

    @Test
    void compareToSortsByFileAfterSeverity() {
        Finding a = new Finding(SecretType.AWS_ACCESS_KEY, Severity.CRITICAL,
                Path.of("a.txt"), 1, 1, 20, "AKIA****", 0.0);
        Finding b = new Finding(SecretType.AWS_ACCESS_KEY, Severity.CRITICAL,
                Path.of("b.txt"), 1, 1, 20, "AKIA****", 0.0);
        assertTrue(a.compareTo(b) < 0, "a.txt should sort before b.txt");
    }

    @Test
    void compareToSortsByLineAfterFile() {
        Finding line1 = new Finding(SecretType.AWS_ACCESS_KEY, Severity.CRITICAL,
                Path.of("a.txt"), 1, 1, 20, "AKIA****", 0.0);
        Finding line5 = new Finding(SecretType.AWS_ACCESS_KEY, Severity.CRITICAL,
                Path.of("a.txt"), 5, 1, 20, "AKIA****", 0.0);
        assertTrue(line1.compareTo(line5) < 0, "line 1 should sort before line 5");
    }

    @Test
    void compareToSortsByColumnAfterLine() {
        Finding col1 = new Finding(SecretType.AWS_ACCESS_KEY, Severity.CRITICAL,
                Path.of("a.txt"), 1, 1, 20, "AKIA****", 0.0);
        Finding col10 = new Finding(SecretType.AWS_ACCESS_KEY, Severity.CRITICAL,
                Path.of("a.txt"), 1, 10, 20, "AKIA****", 0.0);
        assertTrue(col1.compareTo(col10) < 0, "col 1 should sort before col 10");
    }

    @Test
    void compareToUsesTypeOrdinalAsFinalTiebreaker() {
        Finding aws = new Finding(SecretType.AWS_ACCESS_KEY, Severity.CRITICAL,
                Path.of("a.txt"), 1, 1, 20, "AKIA****", 0.0);
        Finding pem = new Finding(SecretType.PEM_PRIVATE_KEY, Severity.CRITICAL,
                Path.of("a.txt"), 1, 1, 20, "[PEM]", 0.0);
        // AWS_ACCESS_KEY has lower ordinal than PEM_PRIVATE_KEY
        assertTrue(aws.compareTo(pem) < 0);
    }
}
