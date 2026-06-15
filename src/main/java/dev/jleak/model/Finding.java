package dev.jleak.model;

import java.nio.file.Path;

/**
 * A single secret hit: what kind, how bad, where it lives, and a redacted
 * preview of the matched text. {@link Comparable} so a report can present the
 * scariest, earliest findings first.
 */
public record Finding(
        SecretType type,
        Severity severity,
        Path file,
        int line,
        int column,
        int length,
        String redacted,
        double entropy
) implements Comparable<Finding> {

    // Ordering: severity high-to-low first (note the reversed compareTo), then
    // file, line and column so a file's hits read top-to-bottom.
    @Override
    public int compareTo(Finding o) {
        int c = o.severity.compareTo(this.severity);
        if (c != 0) return c;
        c = String.valueOf(file).compareTo(String.valueOf(o.file));
        if (c != 0) return c;
        c = Integer.compare(line, o.line);
        if (c != 0) return c;
        c = Integer.compare(column, o.column);
        if (c != 0) return c;
        // Final tiebreaker for deterministic ordering.
        return Integer.compare(type.ordinal(), o.type.ordinal());
    }

    /**
     * Builds the safe-to-print preview: keep the first few chars (so it's still
     * recognizable), mask the rest with a bounded run of '*', and add an ellipsis
     * when the masked tail was clipped. We never echo the full secret.
     */
    public static String redact(CharSequence s, int start, int end) {
        int n = end - start;
        if (n <= 0) return "";
        int show = Math.min(4, n);          // leading chars left visible
        int masked = n - show;              // how many we'd mask in full
        int cap = Math.min(masked, 12);     // but cap the asterisks so it stays short
        StringBuilder sb = new StringBuilder(show + cap + 3);
        for (int i = 0; i < show; i++) sb.append(s.charAt(start + i));
        for (int i = 0; i < cap; i++) sb.append('*');
        if (masked > cap) sb.append("...");
        return sb.toString();
    }
}
