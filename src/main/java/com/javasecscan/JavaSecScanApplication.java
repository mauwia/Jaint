package com.javasecscan;

import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import org.springframework.scheduling.annotation.EnableAsync;

@SpringBootApplication
@EnableAsync
public class JavaSecScanApplication {
    public static void main(String[] args) {
        SpringApplication.run(JavaSecScanApplication.class, args);
    }
}
