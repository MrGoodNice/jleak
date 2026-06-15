package dev.jleak.engine;

import dev.jleak.model.Finding;

import java.util.List;

/**
 * The full outcome of one scan: the (already sorted) findings plus the run-level
 * counters. Immutable - it's only ever produced at the end of a scan and handed
 * straight to the reporter.
 */
public record ScanReport(
        List<Finding> findings,
        long filesScanned,
        long filesSkipped,
        long bytesScanned,
        long errors,
        boolean truncated
) {
    /** Convenience for the CLI exit-code decision: did we find anything at all? */
    public boolean hasFindings() {
        return !findings.isEmpty();
    }
}
