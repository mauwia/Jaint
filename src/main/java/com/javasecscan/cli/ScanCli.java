package com.javasecscan.cli;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.databind.SerializationFeature;
import com.javasecscan.analysis.Finding;
import com.javasecscan.analysis.SarifFormatter;
import com.javasecscan.analysis.SootAnalyzer;
import lombok.extern.slf4j.Slf4j;
import org.springframework.boot.ApplicationArguments;
import org.springframework.boot.ApplicationRunner;
import org.springframework.context.ConfigurableApplicationContext;
import org.springframework.context.annotation.Profile;
import org.springframework.stereotype.Component;

import java.nio.file.Path;
import java.util.List;

@Slf4j
@Profile("cli")
@Component
public class ScanCli implements ApplicationRunner {

    private final SootAnalyzer analyzer;
    private final SarifFormatter sarif;
    private final ConfigurableApplicationContext ctx;

    public ScanCli(SootAnalyzer analyzer, SarifFormatter sarif, ConfigurableApplicationContext ctx) {
        this.analyzer = analyzer;
        this.sarif = sarif;
        this.ctx = ctx;
    }

    @Override
    public void run(ApplicationArguments args) throws Exception {
        List<String> jars = args.getNonOptionArgs();
        if (jars.isEmpty()) {
            System.err.println("Usage: java -jar javasecscan.jar --spring.profiles.active=cli "
                    + "[--format=json|sarif] <path-to-jar>");
            System.exit(2);
        }
        String format = firstOptionValue(args, "format", "json").toLowerCase();
        Path jar = Path.of(jars.get(0));
        List<Finding> findings = analyzer.analyze(jar);

        ObjectMapper mapper = new ObjectMapper().enable(SerializationFeature.INDENT_OUTPUT);
        Object payload = "sarif".equals(format) ? sarif.fromFindings(findings) : findings;
        System.out.println(mapper.writeValueAsString(payload));

        int exitCode = findings.isEmpty() ? 0 : 1;
        ctx.close();
        System.exit(exitCode);
    }

    private String firstOptionValue(ApplicationArguments args, String name, String fallback) {
        List<String> values = args.getOptionValues(name);
        return (values == null || values.isEmpty()) ? fallback : values.get(0);
    }
}
