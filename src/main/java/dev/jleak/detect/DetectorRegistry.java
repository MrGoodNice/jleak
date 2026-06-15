package dev.jleak.detect;

import dev.jleak.engine.ScannerConfig;
import dev.jleak.model.Finding;
import dev.jleak.model.SecretType;

import java.util.List;
import java.util.regex.Pattern;

/**
 * Holds the active detector set and decides the order they run in.
 *
 * <p>Specific (regex) detectors go first because a typed hit like an AWS key is
 * far more useful than a vague "high entropy here". The generic entropy detector
 * runs afterwards, and any of its hits that land on top of a specific match on
 * the same line are dropped so we don't double-report the same secret.
 */
public final class DetectorRegistry {
    private final Detector[] specific;
    private final EntropyDetector generic;

    public DetectorRegistry(Detector[] specific, EntropyDetector generic) {
        this.specific = specific;
        this.generic = generic;
    }

    public void scanLine(LineContext ctx, FindingSink sink) {
        // Reset the per-line record of specific hits; it doubles as the overlap
        // set for the entropy pass below.
        ctx.specificFindings.clear();
        FindingSink collector = f -> {
            ctx.specificFindings.add(f);
            sink.report(f);
        };
        for (Detector d : specific) d.detect(ctx, collector);
        if (generic != null) {
            // Generic hits only survive if they don't sit under a specific one.
            generic.detect(ctx, f -> {
                if (!overlapsSpecific(ctx.specificFindings, f)) sink.report(f);
            });
        }
    }

    // Plain index loop (no iterator/stream) - this runs for every entropy hit
    // on every line, so we keep it allocation-free. Half-open [col, col+len)
    // ranges overlap when each start is strictly before the other's end.
    private static boolean overlapsSpecific(List<Finding> specifics, Finding generic) {
        int gStart = generic.column();
        int gEnd = gStart + generic.length();
        for (int i = 0; i < specifics.size(); i++) {
            Finding sp = specifics.get(i);
            int sStart = sp.column();
            int sEnd = sStart + sp.length();
            if (gStart < sEnd && sStart < gEnd) return true;
        }
        return false;
    }

    public static DetectorRegistry defaults(ScannerConfig cfg) {
        // Built-in providers. The String[] prefixes are cheap literal pre-filters
        // so the regex only fires on lines that could plausibly match; a null
        // prefix list means "always try the pattern".
        Detector[] specific = new Detector[] {
            new RegexDetector(SecretType.AWS_ACCESS_KEY,
                    Pattern.compile("\\b(AKIA[0-9A-Z]{16})\\b"),
                    new String[]{"AKIA"}, false, 0.0, 1),
            // Secret key has no fixed prefix, so we gate it on entropy (>= 4.0).
            new RegexDetector(SecretType.AWS_SECRET_KEY,
                    Pattern.compile("(?i)aws.{0,20}?['\"]?([A-Za-z0-9/+]{40})['\"]?"),
                    new String[]{"aws"}, true, 4.0, 1),
            new RegexDetector(SecretType.GITHUB_TOKEN,
                    Pattern.compile("\\b((?:ghp|gho|ghu|ghs|ghr)_[A-Za-z0-9]{36}|github_pat_[A-Za-z0-9_]{82})\\b"),
                    new String[]{"ghp_", "gho_", "ghu_", "ghs_", "ghr_", "github_pat_"}, false, 0.0, 1),
            new RegexDetector(SecretType.GOOGLE_API_KEY,
                    Pattern.compile("\\b(AIza[0-9A-Za-z\\-_]{35})\\b"),
                    new String[]{"AIza"}, false, 0.0, 1),
            new RegexDetector(SecretType.SLACK_TOKEN,
                    Pattern.compile("\\b(xox[baprs]-[0-9A-Za-z-]{10,48})\\b"),
                    new String[]{"xox"}, false, 0.0, 1),
            // Telegram tokens carry no keyword to anchor on; lookarounds keep the
            // numeric id from bleeding into surrounding digits.
            new RegexDetector(SecretType.TELEGRAM_BOT_TOKEN,
                    Pattern.compile("(?<![0-9])([0-9]{8,10}:[A-Za-z0-9_-]{35})(?![A-Za-z0-9_-])"),
                    null, false, 0.0, 1)
        };
        EntropyDetector generic = new EntropyDetector(
                cfg.genericMinEntropy(), cfg.genericMinLen(), cfg.genericMaxLen());
        return new DetectorRegistry(specific, generic);
    }
}
