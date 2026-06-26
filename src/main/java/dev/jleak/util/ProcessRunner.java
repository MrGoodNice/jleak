package dev.jleak.util;

import java.io.ByteArrayOutputStream;
import java.io.IOException;
import java.io.InputStream;

/**
 * Runs an external process and captures its stdout. Extracted from
 * {@code GitPreCommit} so the subprocess plumbing is reusable (e.g. for
 * future git integrations or plugin hooks).
 */
public final class ProcessRunner {
    private ProcessRunner() {}

    /**
     * Executes a command, waits for it to finish, and returns its stdout.
     *
     * @throws IllegalStateException if the process exits with a non-zero code
     */
    public static byte[] exec(String[] command) throws IOException, InterruptedException {
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

    /** Drains an input stream into a byte array. */
    public static byte[] readAll(InputStream in) throws IOException {
        ByteArrayOutputStream bos = new ByteArrayOutputStream();
        byte[] buf = new byte[8192];
        int r;
        while ((r = in.read(buf)) >= 0) {
            bos.write(buf, 0, r);
        }
        return bos.toByteArray();
    }
}
