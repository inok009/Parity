package com.parity.hunter.model;

import java.time.Instant;

/**
 * Immutable record representing a confirmed BOLA finding.
 * Captures the endpoint, HTTP method, extracted resource identifier,
 * response status codes from both sessions, similarity score, and discovery timestamp.
 */
public final class ParityFinding {

    private final String  endpoint;
    private final String  method;
    private final String  resourceIdentifier;
    private final int     baselineStatus;
    private final int     attackerStatus;
    private final double  similarity;
    private final Instant discoveredAt;

    public ParityFinding(String endpoint, String method, String resourceIdentifier,
                       int baselineStatus, int attackerStatus, double similarity) {
        this.endpoint           = endpoint;
        this.method             = method;
        this.resourceIdentifier = resourceIdentifier;
        this.baselineStatus     = baselineStatus;
        this.attackerStatus     = attackerStatus;
        this.similarity         = similarity;
        this.discoveredAt       = Instant.now();
    }

    public String  getEndpoint()           { return endpoint; }
    public String  getMethod()             { return method; }
    public String  getResourceIdentifier() { return resourceIdentifier; }
    public int     getBaselineStatus()     { return baselineStatus; }
    public int     getAttackerStatus()     { return attackerStatus; }
    public double  getSimilarity()         { return similarity; }
    public Instant getDiscoveredAt()       { return discoveredAt; }
}