package dev.jleak.engine;

import java.nio.file.Path;
import java.util.Locale;
import java.util.Set;

/**
 * All the knobs, frozen once built. Construct it through the fluent
 * {@link Builder}; the instance is immutable afterwards. It also carries the two
 * static skip-lists - directories we never descend into and file extensions we
 * treat as binary.
 */
public final class ScannerConfig {

    // Directories that are pure noise for secret scanning: VCS metadata, build
    // output, dependency caches and editor folders.
    public static final Set<String> SKIP_DIRS = Set.of(
            ".git", ".hg", ".svn", "node_modules", "build", "target", ".gradle",
            "dist", "out", ".idea", ".vscode", "vendor", "__pycache__");

    // Extensions we assume are binary and skip outright - images, archives,
    // compiled artifacts, media, fonts and keystore containers.
    public static final Set<String> BINARY_EXT = Set.of(
            "png", "jpg", "jpeg", "gif", "bmp", "ico", "webp", "pdf", "zip", "gz",
            "tgz", "tar", "7z", "rar", "jar", "war", "class", "exe", "dll", "so",
            "dylib", "bin", "o", "a", "mp3", "mp4", "mov", "avi", "mkv", "wav",
            "flac", "woff", "woff2", "ttf", "otf", "eot", "lock", "keystore",
            "jks", "p12", "pfx");

    private final int threads;
    private final long maxFileSizeBytes;
    private final int maxLineLength;
    private final double genericMinEntropy;
    private final int genericMinLen;
    private final int genericMaxLen;
    private final int maxFindingsGlobal;
    private final int maxFindingsPerFile;
    private final int maxFindingsPerDetector;
    private final int binarySniffBytes;
    private final double binaryNonPrintableRatio;

    private ScannerConfig(Builder b) {
        this.threads = b.threads;
        this.maxFileSizeBytes = b.maxFileSizeBytes;
        this.maxLineLength = b.maxLineLength;
        this.genericMinEntropy = b.genericMinEntropy;
        this.genericMinLen = b.genericMinLen;
        this.genericMaxLen = b.genericMaxLen;
        this.maxFindingsGlobal = b.maxFindingsGlobal;
        this.maxFindingsPerFile = b.maxFindingsPerFile;
        this.maxFindingsPerDetector = b.maxFindingsPerDetector;
        this.binarySniffBytes = b.binarySniffBytes;
        this.binaryNonPrintableRatio = b.binaryNonPrintableRatio;
    }

    public int threads() { return threads; }
    public long maxFileSizeBytes() { return maxFileSizeBytes; }
    public int maxLineLength() { return maxLineLength; }
    public double genericMinEntropy() { return genericMinEntropy; }
    public int genericMinLen() { return genericMinLen; }
    public int genericMaxLen() { return genericMaxLen; }
    public int maxFindingsGlobal() { return maxFindingsGlobal; }
    public int maxFindingsPerFile() { return maxFindingsPerFile; }
    public int maxFindingsPerDetector() { return maxFindingsPerDetector; }
    public int binarySniffBytes() { return binarySniffBytes; }
    public double binaryNonPrintableRatio() { return binaryNonPrintableRatio; }

    /** False when the extension is on the binary skip-list; extension-less names default to scannable. */
    public boolean shouldScan(Path path) {
        Path name = path.getFileName();
        if (name == null) return true;
        String s = name.toString();
        int dot = s.lastIndexOf('.');
        // No dot, or a trailing dot with nothing after it -> treat as scannable.
        if (dot < 0 || dot == s.length() - 1) return true;
        String ext = s.substring(dot + 1).toLowerCase(Locale.ROOT);
        return !BINARY_EXT.contains(ext);
    }

    public static ScannerConfig defaults() {
        return new Builder().build();
    }

    public static Builder builder() {
        return new Builder();
    }

    /** Mutable assembler for a {@link ScannerConfig}; every field starts at a sensible default. */
    public static final class Builder {
        private int threads = Runtime.getRuntime().availableProcessors();
        private long maxFileSizeBytes = 5L * 1024 * 1024;
        private int maxLineLength = 4096;
        private double genericMinEntropy = 4.0;
        private int genericMinLen = 20;
        private int genericMaxLen = 128;
        private int maxFindingsGlobal = 10_000;
        private int maxFindingsPerFile = 1_000;
        private int maxFindingsPerDetector = 500;
        private int binarySniffBytes = 8192;
        private double binaryNonPrintableRatio = 0.30;

        // Always keep at least one worker, even if a caller passes 0 or a negative.
        public Builder threads(int v) { this.threads = Math.max(1, v); return this; }
        public Builder maxFileSizeBytes(long v) { this.maxFileSizeBytes = v; return this; }
        public Builder maxLineLength(int v) { this.maxLineLength = v; return this; }
        public Builder genericMinEntropy(double v) { this.genericMinEntropy = v; return this; }
        public Builder genericMinLen(int v) { this.genericMinLen = v; return this; }
        public Builder genericMaxLen(int v) { this.genericMaxLen = v; return this; }
        public Builder maxFindingsGlobal(int v) { this.maxFindingsGlobal = v; return this; }
        public Builder maxFindingsPerFile(int v) { this.maxFindingsPerFile = v; return this; }
        public Builder maxFindingsPerDetector(int v) { this.maxFindingsPerDetector = v; return this; }
        public Builder binarySniffBytes(int v) { this.binarySniffBytes = v; return this; }
        public Builder binaryNonPrintableRatio(double v) { this.binaryNonPrintableRatio = v; return this; }

        public ScannerConfig build() {
            return new ScannerConfig(this);
        }
    }
}
