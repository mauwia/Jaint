package com.javasecscan.config;

import io.swagger.v3.oas.models.OpenAPI;
import io.swagger.v3.oas.models.info.Contact;
import io.swagger.v3.oas.models.info.Info;
import io.swagger.v3.oas.models.info.License;
import org.springframework.context.annotation.Bean;
import org.springframework.context.annotation.Configuration;

@Configuration
public class OpenApiConfig {

    @Bean
    public OpenAPI javaSecScanOpenAPI() {
        return new OpenAPI().info(new Info()
                .title("JavaSecScan API")
                .version("0.1.0")
                .description("""
                        Static vulnerability scanner for Java bytecode.
                        Submit a `.jar` and retrieve findings as JSON or SARIF 2.1.0.

                        Detection: SQL injection (CWE-89), command injection (CWE-78),
                        path traversal (CWE-22). Powered by Soot intraprocedural
                        forward taint analysis with configurable sanitizers.""")
                .contact(new Contact().name("JavaSecScan").url("https://github.com/yourname/javasecscan"))
                .license(new License().name("MIT")));
    }
}
