package dev.jleak.engine;

import dev.jleak.detect.DetectorRegistry;
import dev.jleak.detect.FindingSink;
import dev.jleak.detect.LineContext;
import dev.jleak.model.Finding;
import dev.jleak.model.SecretType;
import dev.jleak.util.Sequences;

import java.io.IOException;
import java.nio.CharBuffer;
import java.nio.file.FileVisitResult;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.SimpleFileVisitor;
import java.nio.file.attribute.BasicFileAttributes;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;
import java.util.concurrent.ConcurrentLinkedQueue;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;
import java.util.concurrent.Future;
import java.util.concurrent.atomic.AtomicBoolean;
import java.util.concurrent.atomic.AtomicInteger;

/**
 * The engine. Walks a directory tree (skipping the usual noise dirs), hands one
 * task per candidate file to a fixed thread pool, and decodes + scans each file
 * through a per-thread {@code WorkerContext}.
 *
 * <p>Finding volume is capped at three levels - global, per-file and
 * per-detector - so a generated or minified file can't drown the report. A tiny
 * state machine also mutes scanning inside PEM private-key blocks: the block is
 * reported once on its BEGIN line and the body is skipped until END.
 */
public final class Scanner {
    private final ScannerConfig cfg;
    private final DetectorRegistry registry;

    public Scanner(ScannerConfig cfg, DetectorRegistry registry) {
        this.cfg = cfg;
        this.registry = registry;
    }

    public static Scanner withDefaults() {
        ScannerConfig cfg = ScannerConfig.defaults();
        return new Scanner(cfg, DetectorRegistry.defaults(cfg));
    }

    public ScannerConfig config() {
        return cfg;
    }

    public ScanReport scan(Path root) throws IOException {
        ScanStats stats = new ScanStats();
        BoundedSink sink = new BoundedSink(cfg.maxFindingsGlobal());
        ExecutorService pool = Executors.newFixedThreadPool(cfg.threads());
        // One WorkerContext per worker thread; built lazily on first use.
        ThreadLocal<WorkerContext> ctx = ThreadLocal.withInitial(() -> new WorkerContext(cfg));
        List<Future<?>> tasks = new ArrayList<>();
        try {
            // The walk itself stays on the calling thread and only enqueues work;
            // the actual decoding/scanning happens in the pool.
            Files.walkFileTree(root, new SimpleFileVisitor<>() {
                @Override
                public FileVisitResult preVisitDirectory(Path dir, BasicFileAttributes attrs) {
                    // Prune entire subtrees we never want to descend into.
                    Path name = dir.getFileName();
                    if (name != null && ScannerConfig.SKIP_DIRS.contains(name.toString())) {
                        return FileVisitResult.SKIP_SUBTREE;
                    }
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFile(Path file, BasicFileAttributes attrs) {
                    if (!attrs.isRegularFile()) {
                        return FileVisitResult.CONTINUE;
                    }
                    // Cheap up-front filters (size + extension) before we queue it.
                    long size = attrs.size();
                    if (size > cfg.maxFileSizeBytes() || !cfg.shouldScan(file)) {
                        stats.skip();
                        return FileVisitResult.CONTINUE;
                    }
                    tasks.add(pool.submit(() -> scanFile(ctx.get(), file, size, sink, stats)));
                    return FileVisitResult.CONTINUE;
                }

                @Override
                public FileVisitResult visitFileFailed(Path file, IOException exc) {
                    // Unreadable entry: note it and keep walking the rest.
                    System.err.println("jleak: failed to read " + file + " (" + exc.getMessage() + ")");
                    stats.error();
                    return FileVisitResult.CONTINUE;
                }
            });
            // Drain the futures so any worker-side exception is surfaced and counted.
            for (Future<?> t : tasks) {
                try {
                    t.get();
                } catch (java.util.concurrent.ExecutionException e) {
                    // Unwrap ExecutionException to surface the actual cause;
                    // e.getMessage() alone just prints the wrapper class name.
                    Throwable cause = e.getCause() != null ? e.getCause() : e;
                    System.err.println("jleak: worker failed (" + cause.getMessage() + ")");
                    stats.error();
                } catch (InterruptedException e) {
                    Thread.currentThread().interrupt();
                    System.err.println("jleak: scan interrupted");
                    stats.error();
                    break;
                }
            }
        } finally {
            pool.shutdown();
        }
        // Findings arrive in thread-completion order; sort for a stable report.
        List<Finding> findings = new ArrayList<>(sink.findings());
        Collections.sort(findings);
        return new ScanReport(findings, stats.filesScanned(), stats.filesSkipped(),
                stats.bytesScanned(), stats.errors(), sink.isTruncated());
    }

    private void scanFile(WorkerContext wc, Path file, long size, BoundedSink global, ScanStats stats) {
        try {
            // Read raw bytes, then sniff for binary before paying for decoding.
            int byteCount = wc.readFully(file, size);
            if (wc.looksBinary(byteCount)) {
                stats.skip();
                return;
            }
            CharBuffer chars = wc.decode(byteCount);
            FileSink fileSink = new FileSink(global, cfg.maxFindingsPerFile(), cfg.maxFindingsPerDetector());
            // Scan straight over the decoder's backing array - no extra copy.
            scanChars(wc.lineContext, file, chars.array(), chars.arrayOffset() + chars.position(),
                    chars.remaining(), fileSink);
            stats.scanned(byteCount);
        } catch (IOException e) {
            System.err.println("jleak: failed to read " + file + " (" + e.getMessage() + ")");
            stats.error();
        } finally {
            // Release oversized scratch buffers so one huge file doesn't pin memory.
            wc.resetBuffersIfNeeded();
        }
    }

    /** Line-splits and scans an already-decoded char[] region. Shared by the file walk and the pre-commit path. */
    void scanChars(LineContext ctx, Path file, char[] chars, int offset, int length, FindingSink sink) {
        int lineNumber = 1;
        int i = offset;
        int end = offset + length;
        int lineStart = i;
        boolean insidePem = false;
        final int MAX_LEN = cfg.maxLineLength();
        // Sliding-window overlap so a secret straddling a chunk boundary on an
        // over-long line still lands fully inside at least one chunk.
        final int OVERLAP = 128;
        // Hard cap on chunks per line - defends against pathological single lines.
        final int MAX_CHUNKS = 1000;

        while (i <= end) {
            boolean atEnd = i == end;
            if (atEnd || chars[i] == '\n') {
                int lineEnd = i;
                // Drop a trailing CR so CRLF files report the same columns as LF.
                if (lineEnd > lineStart && chars[lineEnd - 1] == '\r') {
                    lineEnd--;
                }
                int totalLineLen = lineEnd - lineStart;
                if (totalLineLen <= MAX_LEN) {
                    insidePem = scanLine(ctx, file, lineNumber, chars, lineStart, totalLineLen, 0, insidePem, sink);
                } else {
                    // Very long line: walk it in overlapping MAX_LEN windows.
                    int chunkStart = lineStart;
                    int chunks = 0;
                    while (chunkStart < lineEnd && chunks < MAX_CHUNKS) {
                        int chunkLen = Math.min(lineEnd - chunkStart, MAX_LEN);
                        int columnOffset = chunkStart - lineStart;
                        insidePem = scanLine(ctx, file, lineNumber, chars, chunkStart, chunkLen, columnOffset, insidePem, sink);
                        if (chunkStart + chunkLen == lineEnd) break;
                        chunkStart += MAX_LEN - OVERLAP;
                        chunks++;
                    }
                }
                lineNumber++;
                lineStart = i + 1;
                if (atEnd) break;
            }
            i++;
        }
    }

    private boolean scanLine(LineContext ctx, Path file, int lineNumber, char[] chars,
                             int start, int len, int columnOffset, boolean insidePem, FindingSink sink) {
        ctx.set(file, lineNumber, columnOffset, chars, start, len);
        CharSequence view = ctx.view;
        // Inline allowlist: a line opting out suppresses all of its findings.
        if (Sequences.indexOfIgnoreCaseLowerNeedle(view, "jleak:ignore") >= 0) {
            return insidePem;
        }
        // PEM BEGIN line: report the block once, then enter "inside" mode.
        if (Sequences.indexOfIgnoreCaseLowerNeedle(view, "begin") >= 0
                && Sequences.indexOfIgnoreCaseLowerNeedle(view, "private key") >= 0) {
            sink.report(new Finding(SecretType.PEM_PRIVATE_KEY,
                    SecretType.PEM_PRIVATE_KEY.defaultSeverity(), file, lineNumber, columnOffset + 1, len,
                    "[PEM PRIVATE KEY]", 0.0));
            return true;
        }
        // While inside the block, skip the base64 body and stay "inside" until
        // we see the matching END line.
        if (insidePem) {
            return !(Sequences.indexOfIgnoreCaseLowerNeedle(view, "end") >= 0
                    && Sequences.indexOfIgnoreCaseLowerNeedle(view, "private key") >= 0);
        }
        registry.scanLine(ctx, sink);
        return false;
    }

    /** Scans in-memory text (the git pre-commit path) and returns sorted findings. */
    public List<Finding> scanText(String displayPath, String text) {
        LineContext ctx = new LineContext();
        FileSink fileSink = new FileSink(new BoundedSink(cfg.maxFindingsGlobal()),
                cfg.maxFindingsPerFile(), cfg.maxFindingsPerDetector());
        char[] chars = text.toCharArray();
        scanChars(ctx, Path.of(displayPath), chars, 0, chars.length, fileSink);
        List<Finding> findings = new ArrayList<>(fileSink.collected());
        Collections.sort(findings);
        return findings;
    }

    /** Global, thread-safe collector that stops storing once the global cap is hit (and flags truncation). */
    static final class BoundedSink implements FindingSink {
        private final ConcurrentLinkedQueue<Finding> queue = new ConcurrentLinkedQueue<>();
        private final AtomicInteger count = new AtomicInteger();
        private final AtomicBoolean truncated = new AtomicBoolean(false);
        private final int limit;

        BoundedSink(int limit) {
            this.limit = limit;
        }

        @Override
        public void report(Finding finding) {
            // Count every attempt; anything past the limit just trips the flag.
            if (count.incrementAndGet() > limit) {
                truncated.set(true);
                return;
            }
            queue.add(finding);
        }

        List<Finding> findings() {
            return new ArrayList<>(queue);
        }

        boolean isTruncated() {
            return truncated.get();
        }
    }

    /** Single-thread sink for one file: enforces the per-file and per-detector caps, then forwards to the global sink. */
    static final class FileSink implements FindingSink {
        private final FindingSink delegate;
        private final int perFile;
        private final int perDetector;
        private final int[] perDetectorCount = new int[SecretType.values().length];
        private final List<Finding> collected = new ArrayList<>();
        private int fileCount;

        FileSink(FindingSink delegate, int perFile, int perDetector) {
            this.delegate = delegate;
            this.perFile = perFile;
            this.perDetector = perDetector;
        }

        @Override
        public void report(Finding finding) {
            // Per-file cap first, then the per-detector cap keyed by enum ordinal.
            if (fileCount >= perFile) return;
            int idx = finding.type().ordinal();
            if (perDetectorCount[idx] >= perDetector) return;
            perDetectorCount[idx]++;
            fileCount++;
            collected.add(finding);
            delegate.report(finding);
        }

        List<Finding> collected() {
            return collected;
        }
    }
}
