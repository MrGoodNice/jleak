package dev.jleak.cli;

import dev.jleak.engine.ScanReport;
import dev.jleak.engine.Scanner;
import dev.jleak.model.Finding;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.List;

/**
 * The pre-commit hook path. Instead of walking the working tree it asks git what
 * is actually staged ({@code git diff --cached}) and reads each blob's staged
 * content ({@code git show :path}), so the check matches exactly what's about to
 * be committed - not whatever is currently on disk. Returns the finding count;
 * zero means the commit is clean.
 */
public final class GitPreCommit {
    private final Scanner scanner;

    public GitPreCommit(Scanner scanner) {
        this.scanner = scanner;
    }

    public int run(Reporter.Format format) throws IOException, InterruptedException {
        List<String> staged = stagedFiles();
        // Sort up front so the report order is stable regardless of git's output.
        Collections.sort(staged);
        List<Finding> all = new ArrayList<>();
        long totalBytes = 0;
        int filesScanned = 0;
        int filesSkipped = 0;
        int errors = 0;

        for (String path : staged) {
            // ":path" addresses the staged (index) version of the blob.
            long size = getBlobSize(":" + path);
            if (size < 0) {
                errors++;
                continue;
            }
            // Mirror the on-disk scanner's size/extension gates before reading.
            if (size > scanner.config().maxFileSizeBytes() || !scanner.config().shouldScan(Path.of(path))) {
                filesSkipped++;
                continue;
            }

            try {
                byte[] blob = exec(new String[]{"git", "show", ":" + path});
                int byteCount = blob.length;
                totalBytes += byteCount;
                if (looksBinary(blob, byteCount, scanner.config().binarySniffBytes(), scanner.config().binaryNonPrintableRatio())) {
                    filesSkipped++;
                    continue;
                }
                String content = new String(blob, StandardCharsets.UTF_8);
                all.addAll(scanner.scanText(path, content));
                filesScanned++;
            } catch (Exception e) {
                // One unreadable blob shouldn't sink the whole hook.
                errors++;
            }
        }

        Collections.sort(all);
        ScanReport report = new ScanReport(all, filesScanned, filesSkipped, totalBytes, errors, false);
        Reporter.print(report, format, System.out);

        // On a hit, spell out how to bypass - but make clear it's discouraged.
        if (!all.isEmpty()) {
            System.err.println();
            System.err.println("jleak: " + all.size() + " potential secret(s) in staged changes. Commit aborted.");
            System.err.println("Bypass (not recommended): git commit --no-verify");
        }
        return all.size();
    }

    // Asks git for the blob's byte size; -1 signals "couldn't stat it".
    private static long getBlobSize(String ref) {
        try {
            byte[] out = exec(new String[]{"git", "cat-file", "-s", ref});
            return Long.parseLong(new String(out, StandardCharsets.UTF_8).trim());
        } catch (Exception e) {
            return -1;
        }
    }

    // Same binary heuristic as WorkerContext, duplicated here because the hook
    // path holds the bytes itself rather than going through a WorkerContext.
    private static boolean looksBinary(byte[] data, int byteCount, int sniffBytes, double ratio) {
        int sniff = Math.min(byteCount, sniffBytes);
        if (sniff == 0) return false;
        int nonPrintable = 0;
        for (int i = 0; i < sniff; i++) {
            int b = data[i] & 0xFF;
            if (b == 0x00) return true;
            if (b == 0x7F || (b < 0x20 && b != '\t' && b != '\n' && b != '\r')) {
                nonPrintable++;
            }
        }
        return ((double) nonPrintable / sniff) > ratio;
    }

    // NUL-delimited (-z) listing of added/copied/modified staged paths; -z keeps
    // filenames with spaces or newlines intact.
    private static List<String> stagedFiles() throws IOException, InterruptedException {
        byte[] out = exec(new String[]{"git", "diff", "--cached", "--name-only", "--diff-filter=ACM", "-z"});
        List<String> files = new ArrayList<>();
        int start = 0;
        for (int i = 0; i < out.length; i++) {
            if (out[i] == 0) {
                if (i > start) files.add(new String(out, start, i - start, StandardCharsets.UTF_8));
                start = i + 1;
            }
        }
        // Tolerate a trailing entry that isn't NUL-terminated.
        if (start < out.length) {
            files.add(new String(out, start, out.length - start, StandardCharsets.UTF_8));
        }
        return files;
    }

    // Runs a git command and returns its stdout, throwing on a non-zero exit.
    private static byte[] exec(String[] command) throws IOException, InterruptedException {
        ProcessBuilder pb = new ProcessBuilder(command);
        pb.redirectErrorStream(false);
        Process p = pb.start();
        byte[] data;
        try (InputStream in = p.getInputStream()) {
            data = readAll(in);
        }
        int code = p.waitFor();
        if (code != 0) {
            throw new IllegalStateException("command failed (" + code + "): " + String.join(" ", command));
        }
        return data;
    }

    private static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int r;
        while ((r = in.read(buf)) >= 0) {
            bos.write(buf, 0, r);
        }
        return bos.toByteArray();
    }
}
