package com.parity.hunter.analysis;

import burp.api.montoya.http.message.responses.HttpResponse;

import java.util.List;
import java.util.regex.Pattern;

/**
 * Compares baseline (victim) and attacker responses to determine
 * whether a BOLA vulnerability is present.
 *
 * Detection pipeline:
 *   Gate 1 — Attacker response must be HTTP 200
 *   Gate 2 — False-200 detection (API-level denial inside a 200 envelope)
 *   Gate 3 — Empty body guard (inconclusive, skip)
 *   Gate 4 — Structural similarity via Dice coefficient >= threshold
 *
 * Normalization strips dynamic fields (timestamps, UUIDs, nonces) before
 * comparison to reduce false negatives from rotating response values.
 */
public class DiffEngine {

    private static final double SIMILARITY_THRESHOLD = 0.85;

    private static final List<String> ERROR_SIGNALS = List.of(
            "unauthorized", "forbidden", "access denied", "access_denied",
            "not allowed", "permission denied", "invalid token",
            "\"error\"", "\"errors\"", "\"message\":\"error",
            "\"status\":\"error", "\"code\":403", "\"code\":401"
    );

    private static final List<Pattern> NOISE_PATTERNS = List.of(
            Pattern.compile("\\d{10,13}"),
            Pattern.compile("[0-9a-fA-F]{8}(?:-[0-9a-fA-F]{4}){3}-[0-9a-fA-F]{12}"),
            Pattern.compile("\"(nonce|requestId|traceId|x-request-id)\"\\s*:\\s*\"[^\"]+\""),
            Pattern.compile("\"iat\"\\s*:\\s*\\d+"),
            Pattern.compile("\"exp\"\\s*:\\s*\\d+")
    );

    /**
     * Returns true if the attacker response indicates unauthorized cross-tenant access.
     */
    public boolean isBolaVulnerable(HttpResponse baseline, HttpResponse attacker) {
        if (baseline == null || attacker == null) return false;

        if (attacker.statusCode() != 200) return false;

        String baselineBody = normalize(baseline.bodyToString());
        String attackerBody = normalize(attacker.bodyToString());

        if (isFalse200(attackerBody)) return false;
        if (attackerBody.isBlank())   return false;

        double similarity = SimilarityCalculator.dice(baselineBody, attackerBody);
        return similarity >= SIMILARITY_THRESHOLD;
    }

    /** Detects APIs that return HTTP 200 but embed an error at the application layer. */
    private boolean isFalse200(String body) {
        String lower = body.toLowerCase();
        for (String signal : ERROR_SIGNALS) {
            if (lower.contains(signal)) return true;
        }
        return false;
    }

    /** Strips dynamic fields to reduce false negatives during similarity comparison. */
    private String normalize(String input) {
        if (input == null) return "";
        String result = input;
        for (Pattern p : NOISE_PATTERNS) {
            result = p.matcher(result).replaceAll("");
        }
        return result.trim();
    }
}