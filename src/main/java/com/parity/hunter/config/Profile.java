package com.parity.hunter.config;

/**
 * Immutable data object representing a session profile (attacker or victim).
 * Stores the Authorization header value and tenant identifier used to
 * distinguish cross-tenant traffic during interception.
 */
public final class Profile {

    private final String authHeader;
    private final String tenantIdentifier;

    public Profile(String authHeader, String tenantIdentifier) {
        if (authHeader == null || authHeader.isBlank())
            throw new IllegalArgumentException("Auth header must not be blank.");
        if (tenantIdentifier == null || tenantIdentifier.isBlank())
            throw new IllegalArgumentException("Tenant identifier must not be blank.");

        this.authHeader       = authHeader.trim();
        this.tenantIdentifier = tenantIdentifier.trim();
    }

    public String getAuthHeader()       { return authHeader; }
    public String getTenantIdentifier() { return tenantIdentifier; }

    @Override
    public String toString() {
        return "Profile{tenant='" + tenantIdentifier + "'}";
    }
}