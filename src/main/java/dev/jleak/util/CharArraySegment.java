package dev.jleak.util;

/**
 * A mutable {@link CharSequence} window onto a slice of some char[], with no
 * copying. The scanner keeps one of these per line and just repoints it via
 * {@link #set}, so feeding a line to the detectors costs no allocation.
 *
 * <p>Because it's a live view, it's only valid for as long as the backing array
 * and bounds stay put - it's scratch state, not something to hand out and keep.
 */
public final class CharArraySegment implements CharSequence {
    private char[] array = new char[0];
    private int offset;
    private int length;

    // Repoint the window at a new region; returns this so callers can chain.
    public CharArraySegment set(char[] array, int offset, int length) {
        this.array = array;
        this.offset = offset;
        this.length = length;
        return this;
    }

    @Override
    public int length() {
        return length;
    }

    @Override
    public char charAt(int index) {
        return array[offset + index];
    }

    // subSequence and toString do copy - they hand back a real String, so the
    // result outlives the next set() (used only off the hot path, e.g. redaction).
    @Override
    public CharSequence subSequence(int start, int end) {
        return new String(array, offset + start, end - start);
    }

    @Override
    public String toString() {
        return new String(array, offset, length);
    }
}
