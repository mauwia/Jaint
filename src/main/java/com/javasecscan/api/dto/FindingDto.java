package com.javasecscan.api.dto;

import com.javasecscan.domain.FindingEntity;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
public class FindingDto {
    private String ruleId;
    private String ruleName;
    private String cwe;
    private String severity;
    private String sourceSignature;
    private String sinkSignature;
    private String enclosingClass;
    private String enclosingMethod;
    private int lineNumber;
    private String message;

    public static FindingDto from(FindingEntity e) {
        return FindingDto.builder()
                .ruleId(e.getRuleId())
                .ruleName(e.getRuleName())
                .cwe(e.getCwe())
                .severity(e.getSeverity())
                .sourceSignature(e.getSourceSignature())
                .sinkSignature(e.getSinkSignature())
                .enclosingClass(e.getEnclosingClass())
                .enclosingMethod(e.getEnclosingMethod())
                .lineNumber(e.getLineNumber())
                .message(e.getMessage())
                .build();
    }
}
