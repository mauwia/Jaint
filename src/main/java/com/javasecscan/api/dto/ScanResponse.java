package com.javasecscan.api.dto;

import com.javasecscan.domain.Scan;
import com.javasecscan.domain.ScanStatus;
import lombok.Builder;
import lombok.Data;

import java.time.Instant;
import java.util.List;
import java.util.stream.Collectors;

@Data
@Builder
public class ScanResponse {
    private Long id;
    private String jarName;
    private long jarSizeBytes;
    private ScanStatus status;
    private Instant createdAt;
    private Instant completedAt;
    private String errorMessage;
    private List<FindingDto> findings;

    public static ScanResponse from(Scan scan, boolean includeFindings) {
        return ScanResponse.builder()
                .id(scan.getId())
                .jarName(scan.getJarName())
                .jarSizeBytes(scan.getJarSizeBytes())
                .status(scan.getStatus())
                .createdAt(scan.getCreatedAt())
                .completedAt(scan.getCompletedAt())
                .errorMessage(scan.getErrorMessage())
                .findings(includeFindings
                        ? scan.getFindings().stream().map(FindingDto::from).collect(Collectors.toList())
                        : null)
                .build();
    }
}
