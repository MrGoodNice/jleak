package dev.jleak.cli;

import dev.jleak.engine.ScanReport;
import dev.jleak.model.Finding;

import java.io.PrintStream;

/**
 * Turns a {@link ScanReport} into output - either the line-per-finding text
 * view for humans, or a compact JSON document for tooling.
 *
 * <p>The JSON is assembled by hand rather than via a library: it keeps the build
 * dependency-free and lets us pin the exact field order the consumers expect.
 */
public final class Reporter {

    public enum Format { TEXT, JSON }

    private static final char Q = '"';
    private static final int SCHEMA_VERSION = 1;
    private static final String TOOL_VERSION = "0.1.0";

    private Reporter() {}

    public static void print(ScanReport report, Format format, PrintStream out) {
        if (format == Format.JSON) {
            printJson(report, out);
        } else {
            printText(report, out);
        }
    }

    private static void printText(ScanReport report, PrintStream out) {
        // One aligned row per finding, then a single summary line at the end.
        for (Finding finding : report.findings()) {
            out.printf(java.util.Locale.ROOT, "%-8s %-26s %s:%d:%d  %s (entropy=%.2f)%n",
                    finding.severity(), finding.type().label(), finding.file(), finding.line(), finding.column(),
                    finding.redacted(), finding.entropy());
        }
        out.printf(java.util.Locale.ROOT, "%n%d finding(s) | files scanned: %d | skipped: %d | bytes: %d | errors: %d%s%n",
                report.findings().size(), report.filesScanned(), report.filesSkipped(),
                report.bytesScanned(), report.errors(),
                report.truncated() ? " | TRUNCATED" : "");
    }

    private static void printJson(ScanReport report, PrintStream out) {
        StringBuilder json = new StringBuilder();
        json.append('{');
        // Schema/tool version go first so consumers can branch before parsing.
        num(json, "schemaVersion", SCHEMA_VERSION).append(',');
        field(json, "toolVersion", TOOL_VERSION).append(',');
        json.append(Q).append("findings").append(Q).append(':').append('[');
        var findings = report.findings();
        for (int i = 0; i < findings.size(); i++) {
            Finding finding = findings.get(i);
            if (i > 0) json.append(',');
            json.append('{');
            field(json, "severity", finding.severity().name()).append(',');
            field(json, "type", finding.type().name()).append(',');
            field(json, "label", finding.type().label()).append(',');
            field(json, "file", String.valueOf(finding.file())).append(',');
            num(json, "line", finding.line()).append(',');
            num(json, "column", finding.column()).append(',');
            num(json, "length", finding.length()).append(',');
            field(json, "redacted", finding.redacted()).append(',');
            // Entropy is the one float in the payload - fixed 4-decimal form.
            json.append(Q).append("entropy").append(Q).append(':')
              .append(String.format(java.util.Locale.ROOT, "%.4f", finding.entropy()));
            json.append('}');
        }
        json.append(']').append(',').append(Q).append("stats").append(Q).append(':').append('{');
        num(json, "filesScanned", report.filesScanned()).append(',');
        num(json, "filesSkipped", report.filesSkipped()).append(',');
        num(json, "bytesScanned", report.bytesScanned()).append(',');
        num(json, "errors", report.errors()).append(',');
        json.append(Q).append("truncated").append(Q).append(':').append(report.truncated());
        json.append('}').append('}');
        out.println(json);
    }

    // Appends "key":"value" with the value escaped.
    private static StringBuilder field(StringBuilder sb, String key, String value) {
        return sb.append(Q).append(key).append(Q).append(':')
                 .append(Q).append(esc(value)).append(Q);
    }

    // Appends "key":value for a bare numeric (unquoted) value.
    private static StringBuilder num(StringBuilder sb, String key, long value) {
        return sb.append(Q).append(key).append(Q).append(':').append(value);
    }

    private static String esc(String s) {
        // Minimal JSON string escaping; control chars below 0x20 become \\uXXXX.
        StringBuilder escaped = new StringBuilder(s.length() + 8);
        for (int i = 0; i < s.length(); i++) {
            char ch = s.charAt(i);
            switch (ch) {
                case '"' -> { escaped.append('\\'); escaped.append('"'); }
                case '\\' -> { escaped.append('\\'); escaped.append('\\'); }
                case '\n' -> { escaped.append('\\'); escaped.append('n'); }
                case '\r' -> { escaped.append('\\'); escaped.append('r'); }
                case '\t' -> { escaped.append('\\'); escaped.append('t'); }
                default -> {
                    if (ch < 0x20) escaped.append(String.format(java.util.Locale.ROOT, "\\u%04x", (int) ch));
                    else escaped.append(ch);
                }
            }
        }
        return escaped.toString();
    }
}
