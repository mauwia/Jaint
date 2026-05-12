package com.javasecscan.analysis;

import org.junit.jupiter.api.Test;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;

import static org.assertj.core.api.Assertions.assertThat;

@SpringBootTest
class RuleLoaderTest {

    @Autowired
    RuleLoader ruleLoader;

    @Test
    void loadsDefaultRules() {
        assertThat(ruleLoader.getRules()).isNotEmpty();
        assertThat(ruleLoader.getRules())
                .extracting(Rule::getId)
                .contains("SQLI-001", "CMDI-001", "PATH-001");
    }

    @Test
    void everyRuleHasSourcesAndSinks() {
        ruleLoader.getRules().forEach(r -> {
            assertThat(r.getSources()).isNotEmpty();
            assertThat(r.getSinks()).isNotEmpty();
            assertThat(r.getCwe()).startsWith("CWE-");
        });
    }
}
