package com.parity.hunter.config;

import java.util.concurrent.atomic.AtomicReference;

/**
 * Thread-safe registry holding Profile A (attacker) and Profile B (victim).
 * Uses AtomicReference to ensure safe concurrent reads from the HTTP handler thread.
 */
public class SessionRegistry {

    private final AtomicReference<Profile> profileA = new AtomicReference<>();
    private final AtomicReference<Profile> profileB = new AtomicReference<>();

    public void setProfileA(Profile p) { profileA.set(p); }
    public void setProfileB(Profile p) { profileB.set(p); }

    public Profile getProfileA() { return profileA.get(); }
    public Profile getProfileB() { return profileB.get(); }

    /** Returns true only when both profiles are configured and interception can begin. */
    public boolean isConfigured() {
        return profileA.get() != null && profileB.get() != null;
    }
}