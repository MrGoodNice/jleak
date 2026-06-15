package dev.jleak.util;

/**
 * Substring search that works directly on any {@link CharSequence} without
 * calling toString() first - that's the whole point, since the haystack is
 * usually a zero-copy {@link CharArraySegment} view. Plain naive O(n*m) scan,
 * which is plenty for the short literal anchors we prefilter with.
 */
public final class Sequences {
    private Sequences() {}

    public static int indexOf(CharSequence hay, String needle) {
        int n = hay.length(), m = needle.length();
        if (m == 0) return 0;
        if (m > n) return -1;
        // Match on the first char before bothering to compare the tail.
        char first = needle.charAt(0);
        int max = n - m;
        for (int i = 0; i <= max; i++) {
            if (hay.charAt(i) != first) continue;
            int j = 1;
            while (j < m && hay.charAt(i + j) == needle.charAt(j)) j++;
            if (j == m) return i;
        }
        return -1;
    }

    public static int indexOfIgnoreCase(CharSequence hay, String needle) {
        // Lower the needle once, then defer to the lower-needle variant.
        return indexOfIgnoreCaseLowerNeedle(hay, needle.toLowerCase());
    }

    /** Case-insensitive search where the needle is ALREADY lowercased, so only the haystack gets folded per char. */
    public static int indexOfIgnoreCaseLowerNeedle(CharSequence hay, String lowerNeedle) {
        int n = hay.length(), m = lowerNeedle.length();
        if (m == 0) return 0;
        if (m > n) return -1;
        char first = lowerNeedle.charAt(0);
        int max = n - m;
        for (int i = 0; i <= max; i++) {
            if (Character.toLowerCase(hay.charAt(i)) != first) continue;
            int j = 1;
            while (j < m && Character.toLowerCase(hay.charAt(i + j)) == lowerNeedle.charAt(j)) j++;
            if (j == m) return i;
        }
        return -1;
    }
}
