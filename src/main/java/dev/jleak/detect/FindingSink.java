package dev.jleak.detect;

import dev.jleak.model.Finding;

/**
 * Callback a {@link Detector} uses to hand off a confirmed finding. Kept as a
 * single-method functional interface so call sites can pass a lambda and we can
 * wrap/filter the stream (e.g. overlap suppression) without extra plumbing.
 */
@FunctionalInterface
public interface FindingSink {
    void report(Finding finding);
}
