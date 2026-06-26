package dev.jleak.util;

import org.junit.jupiter.api.Test;

import static org.junit.jupiter.api.Assertions.assertEquals;

class SequencesTest {

    @Test
    void indexOfFindsNeedleAtStart() {
        CharSequence hay = segment("AKIA1234567890ABCDEF");
        assertEquals(0, Sequences.indexOf(hay, "AKIA"));
    }

    @Test
    void indexOfFindsNeedleInMiddle() {
        CharSequence hay = segment("prefix_ghp_abcdefgh_suffix");
        assertEquals(7, Sequences.indexOf(hay, "ghp_"));
    }

    @Test
    void indexOfFindsNeedleAtEnd() {
        CharSequence hay = segment("some text AKIA");
        assertEquals(10, Sequences.indexOf(hay, "AKIA"));
    }

    @Test
    void indexOfReturnsMinusOneWhenAbsent() {
        CharSequence hay = segment("nothing here");
        assertEquals(-1, Sequences.indexOf(hay, "AKIA"));
    }

    @Test
    void indexOfEmptyNeedleReturnsZero() {
        CharSequence hay = segment("anything");
        assertEquals(0, Sequences.indexOf(hay, ""));
    }

    @Test
    void indexOfNeedleLongerThanHayReturnsMinusOne() {
        CharSequence hay = segment("ab");
        assertEquals(-1, Sequences.indexOf(hay, "abcde"));
    }

    @Test
    void indexOfIgnoreCaseLowerNeedleMatchesMixedCase() {
        CharSequence hay = segment("Some AWS_KEY here");
        assertEquals(5, Sequences.indexOfIgnoreCaseLowerNeedle(hay, "aws"));
    }

    @Test
    void indexOfIgnoreCaseLowerNeedleMatchesAllCaps() {
        CharSequence hay = segment("JLEAK:IGNORE this line");
        assertEquals(0, Sequences.indexOfIgnoreCaseLowerNeedle(hay, "jleak:ignore"));
    }

    @Test
    void indexOfIgnoreCaseLowerNeedleReturnsMinusOneWhenAbsent() {
        CharSequence hay = segment("no match here");
        assertEquals(-1, Sequences.indexOfIgnoreCaseLowerNeedle(hay, "akia"));
    }

    @Test
    void indexOfIgnoreCaseWrapsLowerNeedle() {
        CharSequence hay = segment("Look: BEGIN PRIVATE KEY block");
        assertEquals(6, Sequences.indexOfIgnoreCase(hay, "BEGIN"));
    }

    @Test
    void indexOfWorksWithCharArraySegment() {
        char[] chars = "padding_ghp_token_end".toCharArray();
        CharArraySegment seg = new CharArraySegment();
        seg.set(chars, 8, 9); // "ghp_token"
        assertEquals(0, Sequences.indexOf(seg, "ghp_"));
    }

    @Test
    void indexOfIgnoreCaseEmptyNeedleReturnsZero() {
        CharSequence hay = segment("text");
        assertEquals(0, Sequences.indexOfIgnoreCaseLowerNeedle(hay, ""));
    }

    private static CharArraySegment segment(String s) {
        CharArraySegment seg = new CharArraySegment();
        seg.set(s.toCharArray(), 0, s.length());
        return seg;
    }
}
