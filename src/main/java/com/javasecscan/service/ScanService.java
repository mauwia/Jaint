package com.javasecscan.service;

import com.javasecscan.analysis.Finding;
import com.javasecscan.analysis.SootAnalyzer;
import com.javasecscan.api.dto.FindingDto;
import com.javasecscan.domain.FindingEntity;
import com.javasecscan.domain.Scan;
import com.javasecscan.domain.ScanRepository;
import com.javasecscan.domain.ScanStatus;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.transaction.annotation.Transactional;
import org.springframework.web.multipart.MultipartFile;

import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.time.Instant;
import java.util.List;
import java.util.Set;
import java.util.UUID;
import java.util.stream.Collectors;

@Slf4j
@Service
public class ScanService {

    private final ScanRepository scanRepository;
    private final SootAnalyzer analyzer;
    private final Path workDir;

    public ScanService(ScanRepository scanRepository,
                       SootAnalyzer analyzer,
                       @Value("${javasecscan.work-dir}") String workDirPath) throws IOException {
        this.scanRepository = scanRepository;
        this.analyzer = analyzer;
        this.workDir = Paths.get(workDirPath);
        Files.createDirectories(this.workDir);
    }

    @Transactional
    public Scan submit(MultipartFile file) throws IOException {
        if (file == null || file.isEmpty()) {
            throw new IllegalArgumentException("Uploaded file is empty");
        }
        String originalName = file.getOriginalFilename();
        if (originalName == null || !originalName.toLowerCase().endsWith(".jar")) {
            throw new IllegalArgumentException("Only .jar files are accepted");
        }

        Path stored = workDir.resolve(UUID.randomUUID() + "-" + originalName);
        file.transferTo(stored.toFile());

        Scan scan = new Scan();
        scan.setJarName(originalName);
        scan.setJarSizeBytes(file.getSize());
        scan.setStatus(ScanStatus.PENDING);
        scan = scanRepository.save(scan);

        runAsync(scan.getId(), stored);
        return scan;
    }

    @Async("scanExecutor")
    public void runAsync(Long scanId, Path jarPath) {
        try {
            updateStatus(scanId, ScanStatus.RUNNING, null);
            List<Finding> findings = analyzer.analyze(jarPath);
            persistFindings(scanId, findings);
            updateStatus(scanId, ScanStatus.COMPLETED, null);
        } catch (Exception e) {
            log.error("Scan {} failed", scanId, e);
            updateStatus(scanId, ScanStatus.FAILED, e.getMessage());
        } finally {
            try { Files.deleteIfExists(jarPath); } catch (IOException ignored) {}
        }
    }

    @Transactional
    protected void updateStatus(Long scanId, ScanStatus status, String error) {
        scanRepository.findById(scanId).ifPresent(scan -> {
            scan.setStatus(status);
            scan.setErrorMessage(error);
            if (status == ScanStatus.COMPLETED || status == ScanStatus.FAILED) {
                scan.setCompletedAt(Instant.now());
            }
            scanRepository.save(scan);
        });
    }

    @Transactional
    protected void persistFindings(Long scanId, List<Finding> findings) {
        Scan scan = scanRepository.findById(scanId).orElseThrow();
        for (Finding f : findings) {
            FindingEntity entity = new FindingEntity();
            entity.setRuleId(f.getRuleId());
            entity.setRuleName(f.getRuleName());
            entity.setCwe(f.getCwe());
            entity.setSeverity(f.getSeverity());
            entity.setSourceSignature(f.getSourceSignature());
            entity.setSinkSignature(f.getSinkSignature());
            entity.setEnclosingClass(f.getEnclosingClass());
            entity.setEnclosingMethod(f.getEnclosingMethod());
            entity.setLineNumber(f.getLineNumber());
            entity.setMessage(f.getMessage());
            scan.addFinding(entity);
        }
        scanRepository.save(scan);
    }

    @Transactional(readOnly = true)
    public Scan get(Long id) {
        Scan scan = scanRepository.findById(id)
                .orElseThrow(() -> new IllegalArgumentException("Scan not found: " + id));
        scan.getFindings().size();
        return scan;
    }

    @Transactional(readOnly = true)
    public List<Scan> list() {
        return scanRepository.findAll();
    }

    /**
     * Returns findings present in {@code targetId} but absent from {@code baselineId}.
     * Match key: (ruleId, enclosingClass, enclosingMethod, lineNumber).
     */
    @Transactional(readOnly = true)
    public List<FindingDto> diff(Long baselineId, Long targetId) {
        Scan baseline = scanRepository.findById(baselineId)
                .orElseThrow(() -> new IllegalArgumentException("Scan not found: " + baselineId));
        Scan target = scanRepository.findById(targetId)
                .orElseThrow(() -> new IllegalArgumentException("Scan not found: " + targetId));

        Set<String> baselineKeys = baseline.getFindings().stream()
                .map(ScanService::matchKey)
                .collect(Collectors.toSet());

        return target.getFindings().stream()
                .filter(f -> !baselineKeys.contains(matchKey(f)))
                .map(FindingDto::from)
                .collect(Collectors.toList());
    }

    private static String matchKey(FindingEntity f) {
        // Intentionally excludes line number — a finding that moves due to a
        // cosmetic edit is the same finding, not a new one.
        return f.getRuleId() + "|" + f.getEnclosingClass() + "|" + f.getEnclosingMethod();
    }
}
