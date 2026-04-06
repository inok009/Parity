package com.parity.hunter.http;

import burp.api.montoya.http.message.requests.HttpRequest;

/**
 * Utility class for cloning HTTP requests with modified credentials.
 * All other headers, query parameters, and body content are preserved exactly.
 */
public final class RequestCloner {

    private RequestCloner() {}

    /**
     * Returns a clone of the original request with the Authorization header
     * replaced by the attacker's (Profile A) token.
     *
     * @param original   The victim's (Profile B) request
     * @param authHeader The attacker's full Authorization header value
     *                   e.g. "Bearer eyJhbGciOiJIUzI1NiJ9..."
     */
    public static HttpRequest cloneWithNewAuth(HttpRequest original, String authHeader) {
        return original
                .withRemovedHeader("Authorization")
                .withAddedHeader("Authorization", authHeader);
    }
}