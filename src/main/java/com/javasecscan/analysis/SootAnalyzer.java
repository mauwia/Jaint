package com.javasecscan.analysis;

import lombok.extern.slf4j.Slf4j;
import org.springframework.stereotype.Component;
import soot.Body;
import soot.G;
import soot.Local;
import soot.PackManager;
import soot.Scene;
import soot.SootClass;
import soot.SootMethod;
import soot.Unit;
import soot.Value;
import soot.jimple.InvokeExpr;
import soot.jimple.Stmt;
import soot.options.Options;
import soot.tagkit.LineNumberTag;
import soot.toolkits.graph.BriefUnitGraph;
import soot.toolkits.scalar.FlowSet;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.Collections;
import java.util.HashSet;
import java.util.List;
import java.util.Set;
import java.util.stream.Collectors;

@Slf4j
@Component
public class SootAnalyzer {

    private final RuleLoader ruleLoader;

    public SootAnalyzer(RuleLoader ruleLoader) {
        this.ruleLoader = ruleLoader;
    }

    public synchronized List<Finding> analyze(Path jarPath) {
        log.info("Analyzing {}", jarPath);
        List<Rule> rules = ruleLoader.getRules();
        if (rules.isEmpty()) {
            log.warn("No rules loaded — analysis will produce no findings");
            return List.of();
        }

        Set<String> allSources = rules.stream()
                .flatMap(r -> r.getSources().stream())
                .collect(Collectors.toSet());
        Set<String> allSanitizers = rules.stream()
                .filter(r -> r.getSanitizers() != null)
                .flatMap(r -> r.getSanitizers().stream())
                .collect(Collectors.toSet());

        configureSoot(jarPath);
        try {
            Scene.v().loadNecessaryClasses();
            PackManager.v().runPacks();

            List<Finding> findings = new ArrayList<>();
            for (SootClass cls : new ArrayList<>(Scene.v().getApplicationClasses())) {
                for (SootMethod method : new ArrayList<>(cls.getMethods())) {
                    if (!method.isConcrete()) continue;
                    Body body;
                    try {
                        body = method.retrieveActiveBody();
                    } catch (Exception e) {
                        continue;
                    }
                    findings.addAll(scanMethod(cls, method, body, rules, allSources, allSanitizers));
                }
            }
            log.info("Analysis complete: {} finding(s)", findings.size());
            return findings;
        } finally {
            G.reset();
        }
    }

    private void configureSoot(Path jarPath) {
        G.reset();
        Options.v().set_prepend_classpath(true);
        Options.v().set_allow_phantom_refs(true);
        Options.v().set_whole_program(false);
        Options.v().set_no_bodies_for_excluded(true);
        Options.v().set_output_format(Options.output_format_none);
        Options.v().set_process_dir(Collections.singletonList(jarPath.toAbsolutePath().toString()));
        Options.v().set_keep_line_number(true);
        // Use the JRE on the current JDK for type resolution.
        String javaHome = System.getProperty("java.home");
        Options.v().set_soot_classpath(jarPath.toAbsolutePath() + java.io.File.pathSeparator + javaHome);
    }

    private List<Finding> scanMethod(SootClass cls, SootMethod method, Body body,
                                     List<Rule> rules, Set<String> allSources,
                                     Set<String> allSanitizers) {
        BriefUnitGraph cfg = new BriefUnitGraph(body);
        TaintFlowAnalysis analysis = new TaintFlowAnalysis(cfg, allSources, allSanitizers);

        Set<String> sourcesSeenInMethod = new HashSet<>();
        for (Unit unit : body.getUnits()) {
            if (unit instanceof Stmt s && s.containsInvokeExpr()) {
                String sig = s.getInvokeExpr().getMethodRef().getSignature();
                if (allSources.contains(sig)) sourcesSeenInMethod.add(sig);
            }
        }

        List<Finding> findings = new ArrayList<>();
        Set<String> seen = new HashSet<>();

        for (Unit unit : body.getUnits()) {
            if (!(unit instanceof Stmt stmt) || !stmt.containsInvokeExpr()) continue;
            InvokeExpr invoke = stmt.getInvokeExpr();
            String sig = invoke.getMethodRef().getSignature();

            for (Rule rule : rules) {
                if (!rule.getSinks().contains(sig)) continue;

                FlowSet<Local> taintedBefore = analysis.getFlowBefore(unit);
                for (Value arg : invoke.getArgs()) {
                    if (arg instanceof Local local && taintedBefore.contains(local)) {
                        String key = rule.getId() + "@" + cls.getName() + "#" + method.getName() + ":" + lineOf(unit);
                        if (seen.add(key)) {
                            findings.add(Finding.builder()
                                    .ruleId(rule.getId())
                                    .ruleName(rule.getName())
                                    .cwe(rule.getCwe())
                                    .severity(rule.getSeverity())
                                    .sourceSignature(matchingSource(rule, sourcesSeenInMethod))
                                    .sinkSignature(sig)
                                    .enclosingClass(cls.getName())
                                    .enclosingMethod(method.getSubSignature())
                                    .lineNumber(lineOf(unit))
                                    .message("Tainted value flows from user-controlled source into " + rule.getName())
                                    .build());
                        }
                        break;
                    }
                }
            }
        }
        return findings;
    }

    private String matchingSource(Rule rule, Set<String> sourcesSeenInMethod) {
        for (String s : rule.getSources()) {
            if (sourcesSeenInMethod.contains(s)) return s;
        }
        return rule.getSources().isEmpty() ? "" : rule.getSources().get(0);
    }

    private int lineOf(Unit unit) {
        LineNumberTag tag = (LineNumberTag) unit.getTag("LineNumberTag");
        return tag == null ? -1 : tag.getLineNumber();
    }
}
