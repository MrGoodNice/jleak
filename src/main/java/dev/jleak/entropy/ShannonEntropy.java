package dev.jleak.entropy;

/**
 * Shannon entropy over the ASCII range, computed without allocating.
 *
 * <p>Callers pass in their own reusable {@code counts[128]} and
 * {@code touched[128]} scratch arrays so the scanning hot path stays
 * allocation-free. We only ever touch the buckets that actually appeared and we
 * zero those same buckets again before returning, which leaves {@code counts}
 * clean for the next call on that thread. The shared scratch arrays make this
 * not safe to call concurrently with the same buffers.
 */
public final class ShannonEntropy {
    // Pre-divided so the per-bucket loop can do log(p)/LN2 instead of log2.
    private static final double LN2 = Math.log(2.0);

    private ShannonEntropy() {}

    public static double of(CharSequence s, int start, int end, int[] counts, int[] touched) {
        int touchedCount = 0, total = 0;
        // First pass: tally ASCII chars, remembering which buckets we lit up so
        // the cleanup pass doesn't have to walk all 128 of them.
        for (int i = start; i < end; i++) {
            char c = s.charAt(i);
            if (c >= 128) continue;
            if (++counts[c] == 1) touched[touchedCount++] = c;
            total++;
        }
        if (total == 0) return 0.0;
        double entropy = 0.0, invTotal = 1.0 / total;
        // Second pass: fold each probability into the sum and reset its bucket in
        // the same step, so counts[] is zeroed again on the way out.
        for (int i = 0; i < touchedCount; i++) {
            int bin = touched[i];
            int cnt = counts[bin];
            counts[bin] = 0;
            double p = cnt * invTotal;
            entropy -= p * (Math.log(p) / LN2);
        }
        return entropy;
    }
}
