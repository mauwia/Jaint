package com.javasecscan.analysis;

import com.javasecscan.domain.FindingEntity;
import com.javasecscan.domain.Scan;
import org.springframework.stereotype.Component;

import java.util.ArrayList;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

/**
 * Renders findings as SARIF 2.1.0 JSON-compatible maps. Output is suitable
 * for ingestion by GitHub Code Scanning, IDE viewers, and other SARIF
 * consumers. Format reference: https://docs.oasis-open.org/sarif/sarif/v2.1.0/sarif-v2.1.0.html
 */
@Component
public class SarifFormatter {

    private static final String SCHEMA = "https://json.schemastore.org/sarif-2.1.0.json";
    private static final String VERSION = "2.1.0";
    private static final String TOOL_NAME = "JavaSecScan";
    private static final String TOOL_VERSION = "0.1.0";
    private static final String TOOL_URI = "https://github.com/yourname/javasecscan";

    public Map<String, Object> fromFindings(List<Finding> findings) {
        return wrap(buildRules(findings), buildResultsFromFindings(findings));
    }

    public Map<String, Object> fromScan(Scan scan) {
        List<Finding> projected = scan.getFindings().stream().map(this::projectEntity).toList();
        return wrap(buildRules(projected), buildResultsFromFindings(projected));
    }

    private Finding projectEntity(FindingEntity e) {
        return Finding.builder()
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

    private Map<String, Object> wrap(List<Map<String, Object>> rules, List<Map<String, Object>> results) {
        Map<String, Object> driver = new LinkedHashMap<>();
        driver.put("name", TOOL_NAME);
        driver.put("version", TOOL_VERSION);
        driver.put("informationUri", TOOL_URI);
        driver.put("rules", rules);

        Map<String, Object> tool = new LinkedHashMap<>();
        tool.put("driver", driver);

        Map<String, Object> run = new LinkedHashMap<>();
        run.put("tool", tool);
        run.put("results", results);

        Map<String, Object> root = new LinkedHashMap<>();
        root.put("$schema", SCHEMA);
        root.put("version", VERSION);
        root.put("runs", List.of(run));
        return root;
    }

    private List<Map<String, Object>> buildRules(List<Finding> findings) {
        Map<String, Map<String, Object>> byId = new LinkedHashMap<>();
        for (Finding f : findings) {
            byId.computeIfAbsent(f.getRuleId(), id -> {
                Map<String, Object> rule = new LinkedHashMap<>();
                rule.put("id", id);
                rule.put("name", f.getRuleName());
                rule.put("shortDescription", Map.of("text", f.getRuleName()));
                rule.put("fullDescription", Map.of("text", f.getRuleName() + " (" + f.getCwe() + ")"));
                Map<String, Object> defaultCfg = new LinkedHashMap<>();
                defaultCfg.put("level", sarifLevel(f.getSeverity()));
                rule.put("defaultConfiguration", defaultCfg);
                Map<String, Object> props = new LinkedHashMap<>();
                props.put("tags", List.of("security", f.getCwe()));
                props.put("security-severity", securityScore(f.getSeverity()));
                rule.put("properties", props);
                return rule;
            });
        }
        return new ArrayList<>(byId.values());
    }

    private List<Map<String, Object>> buildResultsFromFindings(List<Finding> findings) {
        List<Map<String, Object>> out = new ArrayList<>(findings.size());
        for (Finding f : findings) {
            Map<String, Object> region = new LinkedHashMap<>();
            region.put("startLine", Math.max(1, f.getLineNumber()));

            Map<String, Object> artifact = new LinkedHashMap<>();
            artifact.put("uri", f.getEnclosingClass().replace('.', '/') + ".java");

            Map<String, Object> physical = new LinkedHashMap<>();
            physical.put("artifactLocation", artifact);
            physical.put("region", region);

            Map<String, Object> logical = new LinkedHashMap<>();
            logical.put("name", f.getEnclosingMethod());
            logical.put("fullyQualifiedName", f.getEnclosingClass() + "." + f.getEnclosingMethod());
            logical.put("kind", "function");

            Map<String, Object> location = new LinkedHashMap<>();
            location.put("physicalLocation", physical);
            location.put("logicalLocations", List.of(logical));

            Map<String, Object> result = new LinkedHashMap<>();
            result.put("ruleId", f.getRuleId());
            result.put("level", sarifLevel(f.getSeverity()));
            result.put("message", Map.of("text", f.getMessage()));
            result.put("locations", List.of(location));
            Map<String, Object> props = new LinkedHashMap<>();
            props.put("source", f.getSourceSignature());
            props.put("sink", f.getSinkSignature());
            props.put("cwe", f.getCwe());
            result.put("properties", props);
            out.add(result);
        }
        return out;
    }

    private String sarifLevel(String severity) {
        if (severity == null) return "warning";
        return switch (severity.toUpperCase()) {
            case "CRITICAL", "HIGH" -> "error";
            case "MEDIUM" -> "warning";
            case "LOW", "INFO" -> "note";
            default -> "warning";
        };
    }

    private String securityScore(String severity) {
        if (severity == null) return "5.0";
        return switch (severity.toUpperCase()) {
            case "CRITICAL" -> "9.5";
            case "HIGH" -> "7.5";
            case "MEDIUM" -> "5.0";
            case "LOW" -> "3.0";
            default -> "5.0";
        };
    }
}
