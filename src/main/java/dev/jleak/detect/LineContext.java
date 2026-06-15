package dev.jleak.detect;

import dev.jleak.model.Finding;
import dev.jleak.util.CharArraySegment;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

/**
 * Scratch state for scanning one line, owned by a single thread and recycled
 * line after line. Everything a detector needs to touch on the hot path lives
 * here, so a line scan triggers no allocations: the {@code view} window, the two
 * entropy histograms and the specific-findings list are all reused in place.
 */
public final class LineContext {
    public Path file;
    public int lineNumber;
    public int columnOffset;
    // Zero-copy window over the underlying char[]; repointed per line via set().
    public final CharArraySegment view = new CharArraySegment();
    // ASCII histograms for Shannon entropy. entropyTouched tracks which buckets
    // were used so they can be cleared without wiping all 128 slots each time.
    public final int[] entropyCounts = new int[128];
    public final int[] entropyTouched = new int[128];
    // Specific (regex) hits on the current line - the overlap set the entropy
    // pass consults before reporting a generic finding.
    public final List<Finding> specificFindings = new ArrayList<>();

    // Repoint this context at the next line. Returns this for fluent call sites.
    public LineContext set(Path file, int lineNumber, int columnOffset, char[] chars, int offset, int length) {
        this.file = file;
        this.lineNumber = lineNumber;
        this.columnOffset = columnOffset;
        this.view.set(chars, offset, length);
        return this;
    }
}
