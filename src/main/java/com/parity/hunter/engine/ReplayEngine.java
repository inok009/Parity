package com.parity.hunter.engine;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.http.message.responses.HttpResponse;

import com.parity.hunter.analysis.DiffEngine;
import com.parity.hunter.analysis.IdentifierExtractor;
import com.parity.hunter.analysis.SimilarityCalculator;
import com.parity.hunter.config.Profile;
import com.parity.hunter.config.SessionRegistry;
import com.parity.hunter.http.RequestCloner;
import com.parity.hunter.model.ParityFinding;
import com.parity.hunter.model.FindingsStore;

import java.util.Set;

/**
 * Core attack execution engine.
 *
 * For each intercepted Profile B request, ReplayEngine:
 *   1. Extracts resource identifiers from the request
 *   2. Clones the request with Profile A credentials
 *   3. Sends the cloned request out-of-band via Montoya
 *   4. Passes both responses to DiffEngine for BOLA determination
 *   5. Stores confirmed findings in FindingsStore
 */
public class ReplayEngine {

    private final MontoyaApi          montoya;
    private final SessionRegistry     registry;
    private final DiffEngine          diffEngine;
    private final IdentifierExtractor extractor;
    private final FindingsStore       findingsStore;

    public ReplayEngine(MontoyaApi montoya, SessionRegistry registry, FindingsStore findingsStore) {
        this.montoya       = montoya;
        this.registry      = registry;
        this.diffEngine    = new DiffEngine();
        this.extractor     = new IdentifierExtractor();
        this.findingsStore = findingsStore;
    }

    /**
     * Processes a victim request/response pair.
     * Replays the request using attacker credentials and diffs the result.
     */
    public void process(HttpRequest victimRequest, HttpResponse victimResponse) {

        Profile attacker = registry.getProfileA();
        Profile victim   = registry.getProfileB();
        if (attacker == null || victim == null) return;

        Set<String> identifiers = extractor.extract(victimRequest);
        String      resourceId  = identifiers.isEmpty() ? "unknown" : identifiers.iterator().next();

        HttpRequest attackerRequest = RequestCloner.cloneWithNewAuth(
                victimRequest, attacker.getAuthHeader()
        );

        HttpRequestResponse attackerRR;
        try {
            attackerRR = montoya.http().sendRequest(attackerRequest);
        } catch (Exception e) {
            montoya.logging().logToError("ReplayEngine: sendRequest failed — " + e.getMessage());
            return;
        }

        HttpResponse attackerResponse = attackerRR.response();
        if (attackerResponse == null) return;

        boolean vulnerable = diffEngine.isBolaVulnerable(victimResponse, attackerResponse);

        if (vulnerable) {
            double similarity = SimilarityCalculator.dice(
                    victimResponse.bodyToString(),
                    attackerResponse.bodyToString()
            );

            findingsStore.add(new ParityFinding(
                    victimRequest.url(),
                    victimRequest.method(),
                    resourceId,
                    victimResponse.statusCode(),
                    attackerResponse.statusCode(),
                    similarity
            ));

            montoya.logging().logToOutput(
                    "[BOLA Hunter] Vulnerability detected: " + victimRequest.url()
                    + " | Resource: " + resourceId
                    + " | Similarity: " + String.format("%.2f", similarity)
            );
        }
    }
}