package dev.jleak;

import dev.jleak.engine.ScanReport;
import dev.jleak.engine.Scanner;
import dev.jleak.model.Finding;
import dev.jleak.model.SecretType;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

class ScannerTest {

    private static boolean hasType(ScanReport report, SecretType type) {
        for (Finding f : report.findings()) {
            if (f.type() == type) return true;
        }
        return false;
    }

    @Test
    void findsAwsAndGithubSecrets(@TempDir Path dir) throws IOException {
        Path src = dir.resolve("config.txt");
        Files.writeString(src,
                "aws_access_key_id = AKIAIOSFODNN7EXAMPLE\n" +
                "github_token = ghp_0123456789abcdefghijklmnopqrstuvwxyz\n",
                StandardCharsets.UTF_8);

        ScanReport report = Scanner.withDefaults().scan(dir);

        assertTrue(hasType(report, SecretType.AWS_ACCESS_KEY), "should detect AWS access key");
        assertTrue(hasType(report, SecretType.GITHUB_TOKEN), "should detect GitHub token");
        assertEquals(1, report.filesScanned());
    }

    @Test
    void skipsBinaryFilesByExtension(@TempDir Path dir) throws IOException {
        Path png = dir.resolve("image.png");
        byte[] bytes = new byte[64];
        bytes[0] = (byte) 0x89;
        bytes[1] = 'P';
        bytes[2] = 'N';
        bytes[3] = 'G';
        Files.write(png, bytes);

        ScanReport report = Scanner.withDefaults().scan(dir);

        assertFalse(report.hasFindings(), "binary files must not be scanned");
        assertEquals(0, report.filesScanned());
    }

    @Test
    void skipsGitDirectory(@TempDir Path dir) throws IOException {
        Path gitDir = dir.resolve(".git");
        Files.createDirectories(gitDir);
        Files.writeString(gitDir.resolve("config"),
                "token = AKIAIOSFODNN7EXAMPLE\n", StandardCharsets.UTF_8);

        ScanReport report = Scanner.withDefaults().scan(dir);

        assertFalse(report.hasFindings(), ".git contents must be skipped");
    }

    @Test
    void findsTelegramToken(@TempDir Path dir) throws IOException {
        Path src = dir.resolve("bot.txt");
        Files.writeString(src,
                "token = 123456789:ABCdefGhIJKlmNoPQRsTUVwxyZ123456789\n",
                StandardCharsets.UTF_8);

        ScanReport report = Scanner.withDefaults().scan(dir);

        assertTrue(hasType(report, SecretType.TELEGRAM_BOT_TOKEN), "should detect Telegram token");
    }

    @Test
    void findsSecretAtEndOfLongLine(@TempDir Path dir) throws IOException {
        Path src = dir.resolve("bundle.js");
        StringBuilder sb = new StringBuilder();
        sb.append("var a = \"");
        for (int i = 0; i < 5000; i++) {
            sb.append("x");
        }
        sb.append(" AKIAIOSFODNN7EXAMPLE");
        sb.append("\";\n");
        Files.writeString(src, sb.toString(), StandardCharsets.UTF_8);

        ScanReport report = Scanner.withDefaults().scan(dir);

        assertTrue(hasType(report, SecretType.AWS_ACCESS_KEY), "should detect AWS access key at the end of a very long line");
    }
}
