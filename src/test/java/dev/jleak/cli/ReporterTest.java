package dev.jleak.cli;

import dev.jleak.engine.ScanReport;
import dev.jleak.model.Finding;
import dev.jleak.model.SecretType;
import dev.jleak.model.Severity;
import org.junit.jupiter.api.Test;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.nio.file.Path;
import java.util.Collections;
import java.util.List;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ReporterTest {

    private String printToString(ScanReport report, Reporter.Format format) {
        ByteArrayOutputStream baos = new ByteArrayOutputStream();
        PrintStream ps = new PrintStream(baos);
        Reporter.print(report, format, ps);
        return baos.toString();
    }

    @Test
    void textFormatContainsSeverityAndType() {
        Finding f = new Finding(SecretType.AWS_ACCESS_KEY, Severity.CRITICAL,
                Path.of("config.txt"), 1, 21, 20, "AKIA************...", 0.0);
        ScanReport report = new ScanReport(List.of(f), 1, 0, 100, 0, false);

        String output = printToString(report, Reporter.Format.TEXT);
        assertTrue(output.contains("CRITICAL"), "output should contain severity");
        assertTrue(output.contains("AWS Access Key ID"), "output should contain type label");
        assertTrue(output.contains("config.txt:1:21"), "output should contain location");
        assertTrue(output.contains("AKIA"), "output should contain redacted preview");
    }

    @Test
    void textFormatContainsSummaryLine() {
        ScanReport report = new ScanReport(Collections.emptyList(), 5, 2, 1024, 0, false);
        String output = printToString(report, Reporter.Format.TEXT);
        assertTrue(output.contains("0 finding(s)"));
        assertTrue(output.contains("files scanned: 5"));
        assertTrue(output.contains("skipped: 2"));
        assertTrue(output.contains("bytes: 1024"));
    }

    @Test
    void textFormatShowsTruncatedFlag() {
        ScanReport report = new ScanReport(Collections.emptyList(), 1, 0, 100, 0, true);
        String output = printToString(report, Reporter.Format.TEXT);
        assertTrue(output.contains("TRUNCATED"));
    }

    @Test
    void textFormatOmitsTruncatedWhenNotTruncated() {
        ScanReport report = new ScanReport(Collections.emptyList(), 1, 0, 100, 0, false);
        String output = printToString(report, Reporter.Format.TEXT);
        assertFalse(output.contains("TRUNCATED"));
    }

    @Test
    void jsonFormatContainsSchemaVersion() {
        ScanReport report = new ScanReport(Collections.emptyList(), 1, 0, 100, 0, false);
        String output = printToString(report, Reporter.Format.JSON);
        assertTrue(output.contains("\"schemaVersion\":1"));
        assertTrue(output.contains("\"toolVersion\":\"0.1.0\""));
    }

    @Test
    void jsonFormatContainsFindingsArray() {
        Finding f = new Finding(SecretType.GITHUB_TOKEN, Severity.HIGH,
                Path.of("app.py"), 10, 5, 40, "ghp_************...", 0.0);
        ScanReport report = new ScanReport(List.of(f), 1, 0, 200, 0, false);

        String output = printToString(report, Reporter.Format.JSON);
        assertTrue(output.contains("\"findings\":["));
        assertTrue(output.contains("\"severity\":\"HIGH\""));
        assertTrue(output.contains("\"type\":\"GITHUB_TOKEN\""));
        assertTrue(output.contains("\"label\":\"GitHub Token\""));
        assertTrue(output.contains("\"file\":\"app.py\""));
        assertTrue(output.contains("\"line\":10"));
        assertTrue(output.contains("\"column\":5"));
        assertTrue(output.contains("\"length\":40"));
    }

    @Test
    void jsonFormatContainsStatsObject() {
        ScanReport report = new ScanReport(Collections.emptyList(), 10, 3, 5000, 1, true);
        String output = printToString(report, Reporter.Format.JSON);
        assertTrue(output.contains("\"stats\":{"));
        assertTrue(output.contains("\"filesScanned\":10"));
        assertTrue(output.contains("\"filesSkipped\":3"));
        assertTrue(output.contains("\"bytesScanned\":5000"));
        assertTrue(output.contains("\"errors\":1"));
        assertTrue(output.contains("\"truncated\":true"));
    }

    @Test
    void jsonEscapesSpecialCharsInStrings() {
        Finding f = new Finding(SecretType.GENERIC_HIGH_ENTROPY, Severity.MEDIUM,
                Path.of("path/with\"quote.txt"), 1, 1, 25, "tok\\en\"val", 4.5);
        ScanReport report = new ScanReport(List.of(f), 1, 0, 50, 0, false);

        String output = printToString(report, Reporter.Format.JSON);
        assertTrue(output.contains("\\\""), "should escape double quotes");
        assertTrue(output.contains("\\\\"), "should escape backslashes");
    }

    @Test
    void jsonEntropyHasFourDecimals() {
        Finding f = new Finding(SecretType.GENERIC_HIGH_ENTROPY, Severity.MEDIUM,
                Path.of("a.txt"), 1, 1, 25, "tok*****", 4.12345);
        ScanReport report = new ScanReport(List.of(f), 1, 0, 50, 0, false);

        String output = printToString(report, Reporter.Format.JSON);
        assertTrue(output.contains("\"entropy\":4.1235") || output.contains("\"entropy\":4.1234"),
                "entropy should be formatted with 4 decimals");
    }

    @Test
    void textFormatShowsEntropyWithTwoDecimals() {
        Finding f = new Finding(SecretType.GENERIC_HIGH_ENTROPY, Severity.MEDIUM,
                Path.of("a.txt"), 1, 1, 25, "tok*****", 4.5678);
        ScanReport report = new ScanReport(List.of(f), 1, 0, 50, 0, false);

        String output = printToString(report, Reporter.Format.TEXT);
        assertTrue(output.contains("entropy=4.57"), "entropy should be formatted with 2 decimals");
    }

    @Test
    void emptyReportProducesEmptyFindingsArray() {
        ScanReport report = new ScanReport(Collections.emptyList(), 0, 0, 0, 0, false);
        String output = printToString(report, Reporter.Format.JSON);
        assertTrue(output.contains("\"findings\":[]"));
    }
}
