package dev.jleak.model;

/**
 * The catalogue of things we know how to flag. Each constant pairs a
 * human-readable label (used in reports) with the severity a hit defaults to.
 *
 * <p>Order matters a little: it's the final tiebreaker in {@link Finding}'s
 * sort, and {@code values().length} sizes the per-detector counters, so append
 * new types at the end rather than inserting in the middle.
 */
public enum SecretType {
    AWS_ACCESS_KEY("AWS Access Key ID", Severity.CRITICAL),
    AWS_SECRET_KEY("AWS Secret Access Key", Severity.CRITICAL),
    GITHUB_TOKEN("GitHub Token", Severity.HIGH),
    GOOGLE_API_KEY("Google API Key", Severity.HIGH),
    SLACK_TOKEN("Slack Token", Severity.HIGH),
    PEM_PRIVATE_KEY("PEM Private Key", Severity.CRITICAL),
    TELEGRAM_BOT_TOKEN("Telegram Bot Token", Severity.HIGH),
    // The fallback bucket for the entropy detector - deliberately only MEDIUM
    // since it's the most likely of the lot to be a false positive.
    GENERIC_HIGH_ENTROPY("Generic High-Entropy Secret", Severity.MEDIUM);

    private final String label;
    private final Severity defaultSeverity;

    SecretType(String label, Severity defaultSeverity) {
        this.label = label;
        this.defaultSeverity = defaultSeverity;
    }

    public String label() {
        return label;
    }

    public Severity defaultSeverity() {
        return defaultSeverity;
    }
}
