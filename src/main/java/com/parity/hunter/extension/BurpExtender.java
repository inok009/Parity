package com.parity.hunter.extension;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;

import com.parity.hunter.config.SessionRegistry;
import com.parity.hunter.http.ParityHttpHandler;
import com.parity.hunter.model.FindingsStore;
import com.parity.hunter.ui.MainTab;

/**
 * Extension entry point. Registered via META-INF/services or pom.xml manifest.
 *
 * Wires together:
 *   SessionRegistry  — shared profile store
 *   FindingsStore    — shared findings store
 *   BolaHttpHandler  — Montoya HTTP handler (traffic interception)
 *   MainTab          — Burp UI tab (profiles + findings table)
 */
public class BurpExtender implements BurpExtension {

    @Override
    public void initialize(MontoyaApi api) {

        api.extension().setName("Cross-Tenant BOLA Hunter");

        SessionRegistry registry      = new SessionRegistry();
        FindingsStore   findingsStore  = new FindingsStore();

        ParityHttpHandler handler = new ParityHttpHandler(api, registry, findingsStore);
        api.http().registerHttpHandler(handler);

        MainTab tab = new MainTab(registry, findingsStore, api.userInterface());
        api.userInterface().registerSuiteTab(tab.getTabCaption(), tab.getUiComponent());

        api.logging().logToOutput("[Parity Hunter] Extension loaded successfully.");

        api.extension().registerUnloadingHandler(() -> {
            handler.shutdown();
            api.logging().logToOutput("[Parity Hunter] Extension unloaded.");
        });
    }
}