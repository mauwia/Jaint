package com.javasecscan.domain;

import jakarta.persistence.Column;
import jakarta.persistence.Entity;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.JoinColumn;
import jakarta.persistence.ManyToOne;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

@Entity
@Table(name = "finding")
@Getter
@Setter
public class FindingEntity {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    @ManyToOne(optional = false)
    @JoinColumn(name = "scan_id")
    private Scan scan;

    private String ruleId;
    private String ruleName;
    private String cwe;
    private String severity;

    @Column(length = 512)
    private String sourceSignature;

    @Column(length = 512)
    private String sinkSignature;

    @Column(length = 512)
    private String enclosingClass;

    @Column(length = 512)
    private String enclosingMethod;

    private int lineNumber;

    @Column(length = 2048)
    private String message;
}
