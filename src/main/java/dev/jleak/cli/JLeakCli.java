package dev.jleak.cli;

import dev.jleak.detect.DetectorRegistry;
import dev.jleak.engine.ScanReport;
import dev.jleak.engine.Scanner;
import dev.jleak.engine.ScannerConfig;

import java.io.IOException;
import java.io.PrintStream;
import java.nio.file.Path;
import java.util.Locale;

/**
 * Entry point for the binary. The argument parser here is hand-rolled and
 * deliberately tiny - there's no third-party CLI library, since the whole
 * point is to drop into CI with zero deps.
 *
 * <pre>
 *   jleak scan [path]      Recursively scan a directory or file (default: .)
 *   jleak pre-commit       Scan staged git content (for use as a hook)
 * </pre>
 *
 * Exit codes: 0 = clean, 1 = findings, 2 = usage error, 3 = internal error.
 */
public final class JLeakCli {

    public static void main(String[] args) {
        // Everything funnels through run(); the catch blocks just translate the
        // failure mode into the documented exit code.
        try {
            System.exit(run(args));
        } catch (UsageException e) {
            System.err.println("error: " + e.getMessage());
            printUsage(System.err);
            System.exit(2);
        } catch (Exception e) {
            System.err.println("jleak: internal error: " + e.getMessage());
            System.exit(3);
        }
    }

    static int run(String[] args) throws IOException, InterruptedException {
        if (args.length == 0) {
            printUsage(System.out);
            return 2;
        }
        String command = args[0];
        if (command.equals("-h") || command.equals("--help")) {
            printUsage(System.out);
            return 0;
        }

        ScannerConfig.Builder configBuilder = ScannerConfig.builder();
        Reporter.Format format = Reporter.Format.TEXT;
        String pathArg = null;

        // Walk the args after the command. Options consume the next token via
        // nextValue(); the lone non-option token is treated as the path.
        int i = 1;
        while (i < args.length) {
            String arg = args[i];
            switch (arg) {
                case "--threads" -> configBuilder.threads(parseInt(nextValue(args, ++i, arg)));
                case "--max-file-size" -> configBuilder.maxFileSizeBytes(parseLong(nextValue(args, ++i, arg)));
                case "--format" -> format = parseFormat(nextValue(args, ++i, arg));
                case "-h", "--help" -> {
                    printUsage(System.out);
                    return 0;
                }
                default -> {
                    if (arg.startsWith("-")) {
                        throw new UsageException("unknown option: " + arg);
                    }
                    if (pathArg != null) {
                        throw new UsageException("unexpected argument: " + arg);
                    }
                    pathArg = arg;
                }
            }
            i++;
        }

        ScannerConfig config = configBuilder.build();
        Scanner scanner = new Scanner(config, DetectorRegistry.defaults(config));

        return switch (command) {
            case "scan" -> {
                Path root = Path.of(pathArg == null ? "." : pathArg);
                ScanReport report = scanner.scan(root);
                Reporter.print(report, format, System.out);
                yield report.hasFindings() ? 1 : 0;
            }
            // Hook mode: any finding fails the commit, so collapse the count to 1/0.
            case "pre-commit" -> new GitPreCommit(scanner).run(format) > 0 ? 1 : 0;
            default -> throw new UsageException("unknown command: " + command);
        };
    }

    private static String nextValue(String[] args, int i, String option) {
        if (i >= args.length) {
            throw new UsageException("missing value for " + option);
        }
        return args[i];
    }

    private static int parseInt(String s) {
        try {
            return Integer.parseInt(s);
        } catch (NumberFormatException e) {
            throw new UsageException("not a number: " + s);
        }
    }

    private static long parseLong(String s) {
        try {
            return Long.parseLong(s);
        } catch (NumberFormatException e) {
            throw new UsageException("not a number: " + s);
        }
    }

    private static Reporter.Format parseFormat(String s) {
        return switch (s.toLowerCase(Locale.ROOT)) {
            case "text" -> Reporter.Format.TEXT;
            case "json" -> Reporter.Format.JSON;
            default -> throw new UsageException("unknown format: " + s);
        };
    }

    private static void printUsage(PrintStream out) {
        out.println("jleak - fast secret scanner");
        out.println();
        out.println("Exit codes: 0 = clean, 1 = secrets found, 2 = usage error, 3 = internal error.");
        out.println("Inline allowlist: add `jleak:ignore` on a line to suppress its findings.");
        out.println();
        out.println("Usage:");
        out.println("  jleak scan [path]      Recursively scan a directory (default: .)");
        out.println("  jleak pre-commit       Scan staged git content");
        out.println();
        out.println("Options:");
        out.println("  --threads N            Worker threads (default: CPU count)");
        out.println("  --max-file-size BYTES  Skip files larger than this (default: 5242880)");
        out.println("  --format text|json     Output format (default: text)");
        out.println("  -h, --help             Show this help");
    }

    private static final class UsageException extends RuntimeException {
        UsageException(String message) {
            super(message);
        }
    }
}
