package dev.jleak.detect;

import dev.jleak.engine.ScannerConfig;
import dev.jleak.model.Finding;
import dev.jleak.model.SecretType;
import dev.jleak.model.Severity;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class DetectorRegistryTest {

    private final Path dummyFile = Path.of("test.txt");

    @Test
    void specificDetectorFindingsAreReported() {
        Detector[] specific = new Detector[]{
                new RegexDetector(SecretType.AWS_ACCESS_KEY,
                        Pattern.compile("\\b(AKIA[0-9A-Z]{16})\\b"),
                        new String[]{"AKIA"}, false, 0.0, 1)
        };
        DetectorRegistry registry = new DetectorRegistry(specific, null);

        String line = "key = AKIAIOSFODNN7EXAMPLE";
        LineContext ctx = new LineContext();
        ctx.set(dummyFile, 1, 0, line.toCharArray(), 0, line.length());
        List<Finding> results = new ArrayList<>();
        registry.scanLine(ctx, results::add);

        assertEquals(1, results.size());
        assertEquals(SecretType.AWS_ACCESS_KEY, results.get(0).type());
    }

    @Test
    void genericFindingOverlappingSpecificIsSuppressed() {
        // Create a specific detector that finds "AKIA..." at columns 7-26
        Detector[] specific = new Detector[]{
                new RegexDetector(SecretType.AWS_ACCESS_KEY,
                        Pattern.compile("\\b(AKIA[0-9A-Z]{16})\\b"),
                        new String[]{"AKIA"}, false, 0.0, 1)
        };
        // Generic entropy detector that would also flag the same region
        EntropyDetector generic = new EntropyDetector(3.0, 10, 128);
        DetectorRegistry registry = new DetectorRegistry(specific, generic);

        String line = "key = AKIAIOSFODNN7EXAMPLE";
        LineContext ctx = new LineContext();
        ctx.set(dummyFile, 1, 0, line.toCharArray(), 0, line.length());
        List<Finding> results = new ArrayList<>();
        registry.scanLine(ctx, results::add);

        // Should only have the specific finding, not a duplicate generic one
        long genericCount = results.stream()
                .filter(f -> f.type() == SecretType.GENERIC_HIGH_ENTROPY)
                .count();
        assertEquals(0, genericCount, "generic finding overlapping specific should be suppressed");
        assertTrue(results.stream().anyMatch(f -> f.type() == SecretType.AWS_ACCESS_KEY));
    }

    @Test
    void genericFindingNonOverlappingIsKept() {
        // Specific detector only looks for AKIA pattern
        Detector[] specific = new Detector[]{
                new RegexDetector(SecretType.AWS_ACCESS_KEY,
                        Pattern.compile("\\b(AKIA[0-9A-Z]{16})\\b"),
                        new String[]{"AKIA"}, false, 0.0, 1)
        };
        // Very lenient generic detector
        EntropyDetector generic = new EntropyDetector(3.0, 20, 128);
        DetectorRegistry registry = new DetectorRegistry(specific, generic);

        // Line with a random token that doesn't match the regex
        String line = "secret = wJalrXUtnFEMIK7MDENGbPxRfiCYEXAMPLEKEY";
        LineContext ctx = new LineContext();
        ctx.set(dummyFile, 1, 0, line.toCharArray(), 0, line.length());
        List<Finding> results = new ArrayList<>();
        registry.scanLine(ctx, results::add);

        // No AKIA match, so generic should survive
        assertTrue(results.stream().anyMatch(f -> f.type() == SecretType.GENERIC_HIGH_ENTROPY),
                "non-overlapping generic finding should be kept");
    }

    @Test
    void nullGenericDetectorIsHandledGracefully() {
        Detector[] specific = new Detector[]{
                new RegexDetector(SecretType.AWS_ACCESS_KEY,
                        Pattern.compile("\\b(AKIA[0-9A-Z]{16})\\b"),
                        new String[]{"AKIA"}, false, 0.0, 1)
        };
        DetectorRegistry registry = new DetectorRegistry(specific, null);

        String line = "key = AKIAIOSFODNN7EXAMPLE other_random_stuff_here_1234567890abcdef";
        LineContext ctx = new LineContext();
        ctx.set(dummyFile, 1, 0, line.toCharArray(), 0, line.length());
        List<Finding> results = new ArrayList<>();
        registry.scanLine(ctx, results::add);

        // Should work fine with null generic - only specific hit
        assertEquals(1, results.size());
    }

    @Test
    void defaultsCreatesFullRegistry() {
        ScannerConfig cfg = ScannerConfig.defaults();
        DetectorRegistry registry = DetectorRegistry.defaults(cfg);

        // Should detect a known pattern
        String line = "ghp_0123456789abcdefghijklmnopqrstuvwxyz";
        LineContext ctx = new LineContext();
        ctx.set(dummyFile, 1, 0, line.toCharArray(), 0, line.length());
        List<Finding> results = new ArrayList<>();
        registry.scanLine(ctx, results::add);

        assertTrue(results.stream().anyMatch(f -> f.type() == SecretType.GITHUB_TOKEN));
    }

    @Test
    void specificFindingsClearedBetweenLines() {
        Detector[] specific = new Detector[]{
                new RegexDetector(SecretType.AWS_ACCESS_KEY,
                        Pattern.compile("\\b(AKIA[0-9A-Z]{16})\\b"),
                        new String[]{"AKIA"}, false, 0.0, 1)
        };
        EntropyDetector generic = new EntropyDetector(3.0, 10, 128);
        DetectorRegistry registry = new DetectorRegistry(specific, generic);

        LineContext ctx = new LineContext();
        List<Finding> results = new ArrayList<>();

        // First line has a specific match
        String line1 = "key = AKIAIOSFODNN7EXAMPLE";
        ctx.set(dummyFile, 1, 0, line1.toCharArray(), 0, line1.length());
        registry.scanLine(ctx, results::add);

        results.clear();

        // Second line has no specific match - generic should still work independently
        String line2 = "random = wJalrXUtnFEMIK7MDENGbPxRfiCY";
        ctx.set(dummyFile, 2, 0, line2.toCharArray(), 0, line2.length());
        registry.scanLine(ctx, results::add);

        // The specific findings list should have been cleared, so line2's
        // generic findings should not be incorrectly suppressed
        assertTrue(results.stream().anyMatch(f -> f.type() == SecretType.GENERIC_HIGH_ENTROPY),
                "generic findings on a new line should not be suppressed by previous line's specifics");
    }
}
