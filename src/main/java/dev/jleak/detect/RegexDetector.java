package dev.jleak.detect;

import dev.jleak.entropy.ShannonEntropy;
import dev.jleak.model.Finding;
import dev.jleak.model.SecretType;
import dev.jleak.util.Sequences;

import java.util.regex.Matcher;
import java.util.regex.Pattern;

/**
 * Detector backed by a single compiled {@link Pattern}.
 *
 * <p>Most lines never match, so before we wake the regex engine we run a plain
 * substring "anchor" check - if none of the literal anchors appear, we bail. The
 * compiled pattern is shared across threads; each thread keeps its own
 * {@link Matcher} in a {@link ThreadLocal} so matching stays lock-free and
 * allocation-free on the hot path.
 */
public final class RegexDetector implements Detector {
    private final SecretType type;
    private final ThreadLocal<Matcher> matcher;
    private final String[] anchors;
    private final boolean caseInsensitiveAnchors;
    private final double minEntropy;
    private final int captureGroup;

    public RegexDetector(SecretType type, Pattern pattern, String[] anchors,
                         boolean caseInsensitiveAnchors, double minEntropy, int captureGroup) {
        this.type = type;
        this.matcher = ThreadLocal.withInitial(() -> pattern.matcher(""));
        this.caseInsensitiveAnchors = caseInsensitiveAnchors;
        // For case-insensitive anchors we pre-lowercase once here so the per-line
        // prefilter can compare against an already-lowered needle.
        if (anchors != null && caseInsensitiveAnchors) {
            this.anchors = new String[anchors.length];
            for (int i = 0; i < anchors.length; i++) {
                this.anchors[i] = anchors[i].toLowerCase();
            }
        } else {
            this.anchors = anchors;
        }
        this.minEntropy = minEntropy;
        this.captureGroup = captureGroup;
    }

    @Override
    public SecretType type() {
        return type;
    }

    @Override
    public void detect(LineContext ctx, FindingSink sink) {
        CharSequence view = ctx.view;
        // Fast reject before touching the regex engine.
        if (!passesAnchorPrefilter(view)) return;
        Matcher m = matcher.get();
        m.reset(view);
        while (m.find()) {
            int start = m.start(captureGroup);
            int end = m.end(captureGroup);
            // Guard against an optional/empty capture group.
            if (start < 0 || end <= start) continue;
            double entropy = 0.0;
            // Some patterns (e.g. AWS secret) only count if the match also looks
            // random enough; skip the entropy math when no floor is configured.
            if (minEntropy > 0.0) {
                entropy = ShannonEntropy.of(view, start, end, ctx.entropyCounts, ctx.entropyTouched);
                if (entropy < minEntropy) continue;
            }
            String redacted = Finding.redact(view, start, end);
            sink.report(Finding.from(type, ctx, start, end - start, redacted, entropy));
        }
    }

    // True if any anchor occurs in the line (or there are no anchors to check).
    private boolean passesAnchorPrefilter(CharSequence view) {
        if (anchors == null || anchors.length == 0) return true;
        for (String anchor : anchors) {
            int idx = caseInsensitiveAnchors
                    ? Sequences.indexOfIgnoreCaseLowerNeedle(view, anchor)
                    : Sequences.indexOf(view, anchor);
            if (idx >= 0) return true;
        }
        return false;
    }
}
