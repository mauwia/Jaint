package com.javasecscan.analysis;

import lombok.Data;

import java.util.List;

@Data
public class Rule {
    private String id;
    private String name;
    private String cwe;
    private String severity;
    private List<String> sources;
    private List<String> sinks;
    private List<String> sanitizers = java.util.Collections.emptyList();
}
