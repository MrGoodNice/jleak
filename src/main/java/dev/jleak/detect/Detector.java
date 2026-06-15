package dev.jleak.detect;

import dev.jleak.model.SecretType;

/**
 * One way of spotting a secret on a single line of input.
 *
 * <p>Implementations are invoked once per line and push any hits into the
 * supplied {@link FindingSink}. They're expected to be stateless with respect to
 * the line stream - all per-line scratch state lives on {@link LineContext} - so
 * the same instance can be shared across worker threads.
 */
public interface Detector {

    /** The kind of secret this detector is responsible for. */
    SecretType type();

    /**
     * Examines a single line and reports any matches to {@code sink}.
     *
     * @param ctx  the current line plus reusable per-thread scratch buffers
     * @param sink where findings are emitted
     */
    void detect(LineContext ctx, FindingSink sink);
}
