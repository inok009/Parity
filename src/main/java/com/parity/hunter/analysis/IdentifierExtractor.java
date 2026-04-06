package com.parity.hunter.analysis;

import burp.api.montoya.http.message.requests.HttpRequest;

import java.util.*;
import java.util.regex.*;

/**
 * Extracts resource and tenant identifiers from HTTP requests.
 *
 * Detection covers three surfaces:
 *   1. UUID patterns in the URL path and query string
 *   2. Numeric IDs in URL path segments
 *   3. Known JSON key names in the request body
 *
 * Results are returned as a LinkedHashSet to preserve discovery order
 * while eliminating duplicates.
 */
public class IdentifierExtractor {

    private static final Pattern UUID_PATTERN =
            Pattern.compile("[0-9a-fA-F]{8}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{12}");

    private static final Pattern NUMERIC_ID_PATTERN =
            Pattern.compile("/([0-9]{2,})(?:/|\\?|$)");

    private static final List<String> KNOWN_ID_KEYS = List.of(
            "id", "userId", "user_id", "accountId", "account_id",
            "orgId", "org_id", "tenantId", "tenant_id", "resourceId"
    );

    /**
     * Returns all discovered identifiers from the request URL and body.
     * Returns an empty set if none are found.
     */
    public Set<String> extract(HttpRequest request) {
        Set<String> identifiers = new LinkedHashSet<>();

        String url  = request.url();
        String body = request.bodyToString();
        if (url == null) url = "";

        // 1. UUID matches in URL
        Matcher uuidMatcher = UUID_PATTERN.matcher(url);
        while (uuidMatcher.find()) identifiers.add(uuidMatcher.group());

        // 2. Numeric IDs in URL path segments
        Matcher numMatcher = NUMERIC_ID_PATTERN.matcher(url);
        while (numMatcher.find()) identifiers.add(numMatcher.group(1));

        // 3. Known keys in JSON body
        if (body != null && !body.isBlank()) {
            for (String key : KNOWN_ID_KEYS) {
                Pattern keyPattern = Pattern.compile(
                        "\"" + key + "\"\\s*:\\s*\"?([\\w\\-]+)\"?"
                );
                Matcher km = keyPattern.matcher(body);
                if (km.find()) identifiers.add(km.group(1));
            }

            // Also extract UUIDs embedded directly in body
            Matcher bodyUuid = UUID_PATTERN.matcher(body);
            while (bodyUuid.find()) identifiers.add(bodyUuid.group());
        }

        return Collections.unmodifiableSet(identifiers);
    }
}