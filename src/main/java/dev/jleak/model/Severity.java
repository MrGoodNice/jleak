package dev.jleak.model;

/**
 * How alarming a finding is, lowest to highest. The declaration order is the
 * ranking: {@link Finding} relies on natural enum ordering to sort the worst
 * findings to the top, so don't reshuffle these.
 */
public enum Severity {
    INFO, LOW, MEDIUM, HIGH, CRITICAL
}
