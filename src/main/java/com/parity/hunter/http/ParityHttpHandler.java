package com.parity.hunter.http;

import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.handler.*;
import burp.api.montoya.http.message.requests.HttpRequest;

import com.parity.hunter.config.Profile;
import com.parity.hunter.config.SessionRegistry;
import com.parity.hunter.engine.ReplayEngine;
import com.parity.hunter.model.FindingsStore;

import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

/**
 * Montoya-compliant HTTP handler. Intercepts responses at the response stage
 * so both the initiating request and response are available simultaneously.
 *
 * Traffic is filtered to Profile B (victim) requests only. Matched requests
 * are dispatched asynchronously to the ReplayEngine to avoid blocking
 * Burp's internal handler thread.
 */
public class ParityHttpHandler implements HttpHandler {

    private final MontoyaApi montoya;
    private final SessionRegistry registry;
    private final ReplayEngine replayEngine;
    private final ExecutorService executor;

    public ParityHttpHandler(MontoyaApi montoya, SessionRegistry registry, FindingsStore findingsStore) {
        
        this.montoya      = montoya;
        this.registry     = registry;
        this.replayEngine = new ReplayEngine(montoya, registry, findingsStore);
        this.executor     = Executors.newFixedThreadPool(5);
    }

    /** Passthrough — outbound requests are not modified. */
    @Override
    public RequestToBeSentAction handleHttpRequestToBeSent(HttpRequestToBeSent request) {
        return RequestToBeSentAction.continueWith(request);
    }

    /** Core interception logic — filters and dispatches Profile B traffic. */
    @Override
    public ResponseReceivedAction handleHttpResponseReceived(HttpResponseReceived responseReceived) {

        if (!registry.isConfigured()) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        Profile     profileB = registry.getProfileB();
        HttpRequest req      = responseReceived.initiatingRequest();
        if (req == null) return ResponseReceivedAction.continueWith(responseReceived);

        // Filter: only process requests containing Profile B's tenant identifier
        if (!req.toString().contains(profileB.getTenantIdentifier())) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        // Filter: only replay successful 2xx responses
        int status = responseReceived.statusCode();
        if (status < 200 || status >= 300) {
            return ResponseReceivedAction.continueWith(responseReceived);
        }

        // Async dispatch — never block Burp's handler thread
        executor.submit(() -> {
    try {
        replayEngine.process(req, responseReceived);
    } catch (Exception e) {
        montoya.logging().logToError(
            "[Parity] Background thread error: " + e.getMessage()
        );
    }
});

        return ResponseReceivedAction.continueWith(responseReceived);
    }

    /** Called on extension unload — terminates the thread pool cleanly. */
    public void shutdown() {
        executor.shutdown();
    }
}