package dev.jleak.detect;

import dev.jleak.model.Finding;
import dev.jleak.model.SecretType;
import org.junit.jupiter.api.Test;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;
import java.util.regex.Pattern;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertTrue;

class RegexDetectorTest {

    private final Path dummyFile = Path.of("test.txt");

    private List<Finding> detect(Detector detector, String line) {
        LineContext ctx = new LineContext();
        ctx.set(dummyFile, 1, 0, line.toCharArray(), 0, line.length());
        List<Finding> findings = new ArrayList<>();
        detector.detect(ctx, findings::add);
        return findings;
    }

    @Test
    void awsAccessKeyDetected() {
        Detector d = new RegexDetector(SecretType.AWS_ACCESS_KEY,
                Pattern.compile("\\b(AKIA[0-9A-Z]{16})\\b"),
                new String[]{"AKIA"}, false, 0.0, 1);
        List<Finding> results = detect(d, "key = AKIAIOSFODNN7EXAMPLE");
        assertEquals(1, results.size());
        assertEquals(SecretType.AWS_ACCESS_KEY, results.get(0).type());
        assertEquals(7, results.get(0).column()); // 1-based: index 6 + 1
    }

    @Test
    void anchorPrefilterRejectsLinesWithoutAnchor() {
        Detector d = new RegexDetector(SecretType.AWS_ACCESS_KEY,
                Pattern.compile("\\b(AKIA[0-9A-Z]{16})\\b"),
                new String[]{"AKIA"}, false, 0.0, 1);
        List<Finding> results = detect(d, "nothing relevant here");
        assertEquals(0, results.size());
    }

    @Test
    void caseInsensitiveAnchorMatchesUppercase() {
        Detector d = new RegexDetector(SecretType.AWS_SECRET_KEY,
                Pattern.compile("(?i)aws.{0,20}?['\"]?([A-Za-z0-9/+]{40})['\"]?"),
                new String[]{"aws"}, true, 0.0, 1);
        // Line contains "AWS" in uppercase - should pass the anchor prefilter
        String line = "AWS_SECRET='aB1cD2eF3gH4iJ5kL6mN7oP8qR9sT0uV1wX2yZ3A'";
        List<Finding> results = detect(d, line);
        // Should find a match since "AWS" matches case-insensitive anchor "aws"
        assertTrue(results.size() >= 1);
    }

    @Test
    void nullAnchorsAlwaysPassPrefilter() {
        Detector d = new RegexDetector(SecretType.TELEGRAM_BOT_TOKEN,
                Pattern.compile("(?<![0-9])([0-9]{8,10}:[A-Za-z0-9_-]{35})(?![A-Za-z0-9_-])"),
                null, false, 0.0, 1);
        String line = "token = 123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ123456789";
        List<Finding> results = detect(d, line);
        assertEquals(1, results.size());
        assertEquals(SecretType.TELEGRAM_BOT_TOKEN, results.get(0).type());
    }

    @Test
    void githubTokenDetected() {
        Detector d = new RegexDetector(SecretType.GITHUB_TOKEN,
                Pattern.compile("\\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\\b"),
                new String[]{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"}, false, 0.0, 1);
        String line = "token = ghp_0123456789abcdefghijklmnopqrstuvwxyz";
        List<Finding> results = detect(d, line);
        assertEquals(1, results.size());
        assertEquals(SecretType.GITHUB_TOKEN, results.get(0).type());
    }

    @Test
    void entropyGateRejectsLowEntropyMatch() {
        // AWS secret key detector requires minEntropy of 4.0
        Detector d = new RegexDetector(SecretType.AWS_SECRET_KEY,
                Pattern.compile("(?i)aws.{0,20}?['\"]?([A-Za-z0-9/+]{40})['\"]?"),
                new String[]{"aws"}, true, 4.0, 1);
        // All same chars - zero entropy
        String line = "aws_key = 'aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa'";
        List<Finding> results = detect(d, line);
        assertEquals(0, results.size(), "low entropy match should be rejected");
    }

    @Test
    void entropyGateAcceptsHighEntropyMatch() {
        Detector d = new RegexDetector(SecretType.AWS_SECRET_KEY,
                Pattern.compile("(?i)aws.{0,20}?['\"]?([A-Za-z0-9/+]{40})['\"]?"),
                new String[]{"aws"}, true, 4.0, 1);
        String line = "aws_key = 'wJalrXUtnFEMI/K7MDENG/bPxRfiCYEXAMPLEKEY'";
        List<Finding> results = detect(d, line);
        assertEquals(1, results.size());
    }

    @Test
    void googleApiKeyDetected() {
        Detector d = new RegexDetector(SecretType.GOOGLE_API_KEY,
                Pattern.compile("\\b(AIza[0-9A-Za-z\\-_]{35})\\b"),
                new String[]{"AIza"}, false, 0.0, 1);
        String line = "key = AIzaSyA1B2C3D4E5F6G7H8I9J0K1L2M3N4O5P6Q";
        List<Finding> results = detect(d, line);
        assertEquals(1, results.size());
        assertEquals(SecretType.GOOGLE_API_KEY, results.get(0).type());
    }

    @Test
    void slackTokenDetected() {
        Detector d = new RegexDetector(SecretType.SLACK_TOKEN,
                Pattern.compile("\\b(xox[baprs]-[0-9A-Za-z-]{10,48})\\b"),
                new String[]{"xox"}, false, 0.0, 1);
        String line = "token = xoxb-123456789012-abcdefghij";
        List<Finding> results = detect(d, line);
        assertEquals(1, results.size());
        assertEquals(SecretType.SLACK_TOKEN, results.get(0).type());
    }

    @Test
    void multipleMatchesOnSameLine() {
        Detector d = new RegexDetector(SecretType.AWS_ACCESS_KEY,
                Pattern.compile("\\b(AKIA[0-9A-Z]{16})\\b"),
                new String[]{"AKIA"}, false, 0.0, 1);
        String line = "old = AKIAIOSFODNN7EXAMPLE new = AKIA1234567890ABCDEF";
        List<Finding> results = detect(d, line);
        assertEquals(2, results.size());
    }

    @Test
    void columnIsOneBased() {
        Detector d = new RegexDetector(SecretType.AWS_ACCESS_KEY,
                Pattern.compile("\\b(AKIA[0-9A-Z]{16})\\b"),
                new String[]{"AKIA"}, false, 0.0, 1);
        String line = "AKIAIOSFODNN7EXAMPLE";
        List<Finding> results = detect(d, line);
        assertEquals(1, results.size());
        assertEquals(1, results.get(0).column(), "column should be 1-based");
    }

    @Test
    void columnOffsetIsAddedToResult() {
        Detector d = new RegexDetector(SecretType.AWS_ACCESS_KEY,
                Pattern.compile("\\b(AKIA[0-9A-Z]{16})\\b"),
                new String[]{"AKIA"}, false, 0.0, 1);
        String line = "AKIAIOSFODNN7EXAMPLE";
        LineContext ctx = new LineContext();
        ctx.set(dummyFile, 1, 100, line.toCharArray(), 0, line.length());
        List<Finding> findings = new ArrayList<>();
        d.detect(ctx, findings::add);
        assertEquals(101, findings.get(0).column(), "column should include offset");
    }
}
