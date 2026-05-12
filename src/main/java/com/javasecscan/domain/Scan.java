package com.javasecscan.domain;

import jakarta.persistence.CascadeType;
import jakarta.persistence.Entity;
import jakarta.persistence.EnumType;
import jakarta.persistence.Enumerated;
import jakarta.persistence.FetchType;
import jakarta.persistence.GeneratedValue;
import jakarta.persistence.GenerationType;
import jakarta.persistence.Id;
import jakarta.persistence.OneToMany;
import jakarta.persistence.Table;
import lombok.Getter;
import lombok.Setter;

import java.time.Instant;
import java.util.ArrayList;
import java.util.List;

@Entity
@Table(name = "scan")
@Getter
@Setter
public class Scan {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id;

    private String jarName;

    private long jarSizeBytes;

    @Enumerated(EnumType.STRING)
    private ScanStatus status = ScanStatus.PENDING;

    private Instant createdAt = Instant.now();

    private Instant completedAt;

    private String errorMessage;

    @OneToMany(mappedBy = "scan", cascade = CascadeType.ALL, fetch = FetchType.LAZY, orphanRemoval = true)
    private List<FindingEntity> findings = new ArrayList<>();

    public void addFinding(FindingEntity f) {
        f.setScan(this);
        findings.add(f);
    }
}
