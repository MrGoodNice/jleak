package dev.jleak.engine;

import dev.jleak.detect.LineContext;

import java.io.IOException;
import java.io.InputStream;
import java.nio.ByteBuffer;
import java.nio.CharBuffer;
import java.nio.charset.CharsetDecoder;
import java.nio.charset.CodingErrorAction;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

/**
 * Everything a single worker thread needs to carry between files: growable
 * read/decode buffers, a UTF-8 decoder set to REPLACE bad input, and a reusable
 * {@link LineContext}. Held in a ThreadLocal and reused across every file that
 * thread happens to pick up, so steady-state scanning allocates almost nothing.
 */
public final class WorkerContext {
    private final ScannerConfig cfg;
    private byte[] byteBuffer;
    private char[] charBuffer;
    private final CharsetDecoder decoder;
    public final LineContext lineContext = new LineContext();

    public WorkerContext(ScannerConfig cfg) {
        this.cfg = cfg;
        this.byteBuffer = new byte[8192];
        this.charBuffer = new char[8192];
        // REPLACE (rather than throw) means an odd byte sequence turns into U+FFFD
        // instead of aborting the scan of an otherwise-readable file.
        this.decoder = StandardCharsets.UTF_8.newDecoder()
                .onMalformedInput(CodingErrorAction.REPLACE)
                .onUnmappableCharacter(CodingErrorAction.REPLACE);
    }

    /** Slurps the whole file into the (growable) byte buffer and returns how many bytes were read. */
    public int readFully(Path file, long size) throws IOException {
        // attrs.size() is just a hint; clamp it and pre-size the buffer from it.
        int hint = (int) Math.min(Math.max(size, 0), Integer.MAX_VALUE - 8);
        if (byteBuffer.length < hint) {
            byteBuffer = new byte[Math.max(hint, byteBuffer.length * 2)];
        }
        int total = 0;
        try (InputStream in = Files.newInputStream(file)) {
            while (true) {
                // Buffer full but the file isn't done: peek one byte to confirm
                // there's more, then grow. Avoids a needless grow at exact EOF.
                if (total == byteBuffer.length) {
                    int peek = in.read();
                    if (peek < 0) break;
                    byteBuffer = grow(byteBuffer, total + 1);
                    byteBuffer[total++] = (byte) peek;
                }
                int r = in.read(byteBuffer, total, byteBuffer.length - total);
                if (r < 0) break;
                total += r;
            }
        }
        return total;
    }

    /** Binary sniff: a NUL byte is a hard yes; otherwise fall back to the non-printable ratio over the sniff window. */
    public boolean looksBinary(int byteCount) {
        int sniff = Math.min(byteCount, cfg.binarySniffBytes());
        if (sniff == 0) return false;
        int nonPrintable = 0;
        for (int i = 0; i < sniff; i++) {
            int b = byteBuffer[i] & 0xFF;
            if (b == 0x00) return true;
            // DEL and the control range count as non-printable, but tab/newline/CR
            // are perfectly normal in text and don't.
            if (b == 0x7F || (b < 0x20 && b != '\t' && b != '\n' && b != '\r')) {
                nonPrintable++;
            }
        }
        return ((double) nonPrintable / sniff) > cfg.binaryNonPrintableRatio();
    }

    /** Decodes the first byteCount bytes as UTF-8 into a flipped, ready-to-read CharBuffer. */
    public CharBuffer decode(int byteCount) {
        ByteBuffer in = ByteBuffer.wrap(byteBuffer, 0, byteCount);
        // Worst case one char per byte, +1 for any flushed remainder.
        int cap = byteCount + 1;
        if (charBuffer.length < cap) {
            charBuffer = new char[Math.max(cap, charBuffer.length * 2)];
        }
        CharBuffer out = CharBuffer.wrap(charBuffer);
        decoder.reset();
        decoder.decode(in, out, true);
        decoder.flush(out);
        out.flip();
        return out;
    }

    private static byte[] grow(byte[] src, int min) {
        // Standard doubling, but never below the requested minimum.
        int newLen = Math.max(min, src.length * 2);
        byte[] dst = new byte[newLen];
        System.arraycopy(src, 0, dst, 0, src.length);
        return dst;
    }

    public void resetBuffersIfNeeded() {
        // One giant file can balloon these buffers; shrink them back afterwards so
        // the thread doesn't hold megabytes hostage for the rest of the run.
        if (byteBuffer.length > 1024 * 1024) {
            byteBuffer = new byte[8192];
        }
        if (charBuffer.length > 1024 * 1024) {
            charBuffer = new char[8192];
        }
    }
}
