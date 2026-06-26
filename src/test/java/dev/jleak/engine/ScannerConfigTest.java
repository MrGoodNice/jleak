package dev.jleak.engine;

import org.junit.jupiter.api.Test;

import java.nio.file.Path;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertEquals;

class ScannerConfigTest {

    @Test
    void shouldScanReturnsFalseForBinaryExtensions() {
        ScannerConfig cfg = ScannerConfig.defaults();
        assertFalse(cfg.shouldScan(Path.of("image.png")));
        assertFalse(cfg.shouldScan(Path.of("archive.zip")));
        assertFalse(cfg.shouldScan(Path.of("binary.exe")));
        assertFalse(cfg.shouldScan(Path.of("lib.dll")));
        assertFalse(cfg.shouldScan(Path.of("font.woff2")));
        assertFalse(cfg.shouldScan(Path.of("app.jar")));
        assertFalse(cfg.shouldScan(Path.of("packages.lock")));
    }

    @Test
    void shouldScanReturnsTrueForTextExtensions() {
        ScannerConfig cfg = ScannerConfig.defaults();
        assertTrue(cfg.shouldScan(Path.of("config.txt")));
        assertTrue(cfg.shouldScan(Path.of("script.py")));
        assertTrue(cfg.shouldScan(Path.of("Main.java")));
        assertTrue(cfg.shouldScan(Path.of("app.js")));
        assertTrue(cfg.shouldScan(Path.of("style.css")));
        assertTrue(cfg.shouldScan(Path.of(".env")));
        assertTrue(cfg.shouldScan(Path.of("Dockerfile")));
    }

    @Test
    void shouldScanReturnsTrueForExtensionlessFiles() {
        ScannerConfig cfg = ScannerConfig.defaults();
        assertTrue(cfg.shouldScan(Path.of("Makefile")));
        assertTrue(cfg.shouldScan(Path.of("Dockerfile")));
        assertTrue(cfg.shouldScan(Path.of("LICENSE")));
    }

    @Test
    void shouldScanReturnsTrueForTrailingDot() {
        ScannerConfig cfg = ScannerConfig.defaults();
        assertTrue(cfg.shouldScan(Path.of("file.")));
    }

    @Test
    void shouldScanIsCaseInsensitive() {
        ScannerConfig cfg = ScannerConfig.defaults();
        assertFalse(cfg.shouldScan(Path.of("IMAGE.PNG")));
        assertFalse(cfg.shouldScan(Path.of("archive.ZIP")));
        assertFalse(cfg.shouldScan(Path.of("photo.Jpg")));
    }

    @Test
    void shouldScanHandlesPathWithDirectories() {
        ScannerConfig cfg = ScannerConfig.defaults();
        assertTrue(cfg.shouldScan(Path.of("src/main/java/App.java")));
        assertFalse(cfg.shouldScan(Path.of("assets/logo.png")));
    }

    @Test
    void skipDirsContainsExpectedEntries() {
        assertTrue(ScannerConfig.SKIP_DIRS.contains(".git"));
        assertTrue(ScannerConfig.SKIP_DIRS.contains("node_modules"));
        assertTrue(ScannerConfig.SKIP_DIRS.contains("build"));
        assertTrue(ScannerConfig.SKIP_DIRS.contains("target"));
        assertTrue(ScannerConfig.SKIP_DIRS.contains(".idea"));
        assertTrue(ScannerConfig.SKIP_DIRS.contains("vendor"));
    }

    @Test
    void defaultsHaveSensibleValues() {
        ScannerConfig cfg = ScannerConfig.defaults();
        assertTrue(cfg.threads() >= 1);
        assertEquals(5L * 1024 * 1024, cfg.maxFileSizeBytes());
        assertEquals(4096, cfg.maxLineLength());
        assertEquals(4.0, cfg.genericMinEntropy(), 1e-9);
        assertEquals(20, cfg.genericMinLen());
        assertEquals(128, cfg.genericMaxLen());
        assertEquals(10_000, cfg.maxFindingsGlobal());
        assertEquals(1_000, cfg.maxFindingsPerFile());
        assertEquals(500, cfg.maxFindingsPerDetector());
    }

    @Test
    void builderOverridesDefaults() {
        ScannerConfig cfg = ScannerConfig.builder()
                .threads(4)
                .maxFileSizeBytes(1024)
                .maxLineLength(2048)
                .genericMinEntropy(3.5)
                .genericMinLen(10)
                .genericMaxLen(64)
                .maxFindingsGlobal(100)
                .maxFindingsPerFile(50)
                .maxFindingsPerDetector(25)
                .binarySniffBytes(4096)
                .binaryNonPrintableRatio(0.5)
                .build();
        assertEquals(4, cfg.threads());
        assertEquals(1024, cfg.maxFileSizeBytes());
        assertEquals(2048, cfg.maxLineLength());
        assertEquals(3.5, cfg.genericMinEntropy(), 1e-9);
        assertEquals(10, cfg.genericMinLen());
        assertEquals(64, cfg.genericMaxLen());
        assertEquals(100, cfg.maxFindingsGlobal());
        assertEquals(50, cfg.maxFindingsPerFile());
        assertEquals(25, cfg.maxFindingsPerDetector());
        assertEquals(4096, cfg.binarySniffBytes());
        assertEquals(0.5, cfg.binaryNonPrintableRatio(), 1e-9);
    }

    @Test
    void builderClampsThreadsToAtLeastOne() {
        ScannerConfig cfg = ScannerConfig.builder().threads(0).build();
        assertEquals(1, cfg.threads());
        cfg = ScannerConfig.builder().threads(-5).build();
        assertEquals(1, cfg.threads());
    }
}
