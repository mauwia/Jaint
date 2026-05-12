package com.javasecscan.analysis;

import lombok.AllArgsConstructor;
import lombok.Builder;
import lombok.Data;

@Data
@Builder
@AllArgsConstructor
public class Finding {
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
}
