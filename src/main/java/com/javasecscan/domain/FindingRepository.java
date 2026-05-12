package com.javasecscan.domain;

import org.springframework.data.jpa.repository.JpaRepository;

import java.util.List;

public interface FindingRepository extends JpaRepository<FindingEntity, Long> {
    List<FindingEntity> findByScanId(Long scanId);
}
