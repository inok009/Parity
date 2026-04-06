package com.parity.hunter.model;

import java.util.List;
import java.util.concurrent.CopyOnWriteArrayList;

/**
 * Thread-safe store for confirmed BOLA findings.
 *
 * Uses CopyOnWriteArrayList to allow safe concurrent writes from the
 * ReplayEngine thread pool while the UI reads for display.
 */
public class FindingsStore {

    private final CopyOnWriteArrayList<ParityFinding> findings = new CopyOnWriteArrayList<>();

    public void add(ParityFinding finding) { findings.add(finding); }
    public List<ParityFinding> getAll()    { return List.copyOf(findings); }
    public int size()                    { return findings.size(); }
    public void clear()                  { findings.clear(); }
}