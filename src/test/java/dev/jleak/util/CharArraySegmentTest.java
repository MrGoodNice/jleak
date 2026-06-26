package dev.jleak.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;

class CharArraySegmentTest {

    @Test
    void lengthReflectsSetRegion() {
        CharArraySegment seg = new CharArraySegment();
        seg.set("hello world".toCharArray(), 6, 5);
        assertEquals(5, seg.length());
    }

    @Test
    void charAtReturnsCorrectCharWithOffset() {
        char[] chars = "abcdefghij".toCharArray();
        CharArraySegment seg = new CharArraySegment();
        seg.set(chars, 3, 4); // "defg"
        assertEquals('d', seg.charAt(0));
        assertEquals('e', seg.charAt(1));
        assertEquals('f', seg.charAt(2));
        assertEquals('g', seg.charAt(3));
    }

    @Test
    void toStringReturnsSlice() {
        char[] chars = "the quick brown fox".toCharArray();
        CharArraySegment seg = new CharArraySegment();
        seg.set(chars, 4, 5); // "quick"
        assertEquals("quick", seg.toString());
    }

    @Test
    void subSequenceReturnsIndependentCopy() {
        char[] chars = "AKIAIOSFODNN7EXAMPLE".toCharArray();
        CharArraySegment seg = new CharArraySegment();
        seg.set(chars, 0, chars.length);
        CharSequence sub = seg.subSequence(0, 4);
        assertEquals("AKIA", sub.toString());
        // Modifying the original array shouldn't affect the subsequence
        chars[0] = 'X';
        assertEquals("AKIA", sub.toString());
    }

    @Test
    void setCanBeRepointedMultipleTimes() {
        CharArraySegment seg = new CharArraySegment();
        seg.set("first".toCharArray(), 0, 5);
        assertEquals("first", seg.toString());
        seg.set("second_value".toCharArray(), 7, 5);
        assertEquals("value", seg.toString());
    }

    @Test
    void emptySegmentHasZeroLength() {
        CharArraySegment seg = new CharArraySegment();
        seg.set("abc".toCharArray(), 1, 0);
        assertEquals(0, seg.length());
        assertEquals("", seg.toString());
    }

    @Test
    void charAtOutOfBoundsThrows() {
        CharArraySegment seg = new CharArraySegment();
        seg.set("abc".toCharArray(), 0, 3);
        assertThrows(ArrayIndexOutOfBoundsException.class, () -> seg.charAt(3));
    }

    @Test
    void setReturnsSelfForFluency() {
        CharArraySegment seg = new CharArraySegment();
        CharArraySegment returned = seg.set("x".toCharArray(), 0, 1);
        assertEquals(seg, returned);
    }
}
