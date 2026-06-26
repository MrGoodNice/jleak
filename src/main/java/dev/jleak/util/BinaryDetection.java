package dev.jleak.util;

/**
 * Shared binary-content heuristic used by both the file-walk path
 * ({@code WorkerContext}) and the pre-commit path ({@code GitPreCommit}).
 * A NUL byte is a hard "yes, binary"; otherwise the ratio of non-printable
 * bytes in the sniff window decides.
 */
public final class BinaryDetection {
    private BinaryDetection() {}

    public static boolean looksBinary(byte[] data, int byteCount, int sniffBytes, double ratio) {
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
}
