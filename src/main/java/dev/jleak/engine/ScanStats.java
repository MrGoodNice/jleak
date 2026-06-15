package dev.jleak.engine;

import java.util.concurrent.atomic.LongAdder;

/**
 * The run counters, shared across worker threads. Backed by {@link LongAdder}
 * rather than AtomicLong because every worker updates these constantly and we
 * only read the totals once at the end - exactly the write-heavy, read-rarely
 * pattern LongAdder is built for.
 */
public final class ScanStats {
    private final LongAdder filesScanned = new LongAdder();
    private final LongAdder filesSkipped = new LongAdder();
    private final LongAdder bytesScanned = new LongAdder();
    private final LongAdder errors = new LongAdder();

    // A scanned file bumps the file count and adds its byte total in one go.
    public void scanned(long bytes) {
        filesScanned.increment();
        bytesScanned.add(bytes);
    }

    public void skip() {
        filesSkipped.increment();
    }

    public void error() {
        errors.increment();
    }

    public long filesScanned() { return filesScanned.sum(); }
    public long filesSkipped() { return filesSkipped.sum(); }
    public long bytesScanned() { return bytesScanned.sum(); }
    public long errors() { return errors.sum(); }
}
