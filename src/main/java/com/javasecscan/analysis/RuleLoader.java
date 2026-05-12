package com.javasecscan.analysis;

import com.fasterxml.jackson.databind.ObjectMapper;
import com.fasterxml.jackson.dataformat.yaml.YAMLFactory;
import jakarta.annotation.PostConstruct;
import lombok.extern.slf4j.Slf4j;
import org.springframework.beans.factory.annotation.Value;
import org.springframework.core.io.Resource;
import org.springframework.core.io.ResourceLoader;
import org.springframework.stereotype.Component;

import java.io.IOException;
import java.io.InputStream;
import java.util.Collections;
import java.util.List;

@Slf4j
@Component
public class RuleLoader {

    private final ResourceLoader resourceLoader;
    private final String rulesPath;
    private List<Rule> rules = Collections.emptyList();

    public RuleLoader(ResourceLoader resourceLoader,
                      @Value("${javasecscan.rules-path}") String rulesPath) {
        this.resourceLoader = resourceLoader;
        this.rulesPath = rulesPath;
    }

    @PostConstruct
    void load() throws IOException {
        Resource resource = resourceLoader.getResource(rulesPath);
        if (!resource.exists()) {
            throw new IllegalStateException("Rules file not found: " + rulesPath);
        }
        try (InputStream in = resource.getInputStream()) {
            ObjectMapper mapper = new ObjectMapper(new YAMLFactory());
            RuleSet ruleSet = mapper.readValue(in, RuleSet.class);
            List<Rule> loaded = ruleSet.getRules() == null ? List.of() : ruleSet.getRules();
            loaded.forEach(r -> {
                r.setSources(r.getSources().stream().map(this::canonical).toList());
                r.setSinks(r.getSinks().stream().map(this::canonical).toList());
                if (r.getSanitizers() != null) {
                    r.setSanitizers(r.getSanitizers().stream().map(this::canonical).toList());
                }
            });
            this.rules = loaded;
            log.info("Loaded {} rules from {}", rules.size(), rulesPath);
        }
    }

    public List<Rule> getRules() {
        return rules;
    }

    private String canonical(String sig) {
        String trimmed = sig.trim();
        if (trimmed.startsWith("<") && trimmed.endsWith(">")) return trimmed;
        return "<" + trimmed + ">";
    }
}
