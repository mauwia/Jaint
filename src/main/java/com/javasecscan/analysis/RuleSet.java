package com.javasecscan.analysis;

import lombok.Data;

import java.util.List;

@Data
public class RuleSet {
    private List<Rule> rules;
}
