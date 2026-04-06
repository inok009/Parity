package com.parity.hunter.ui;

import com.parity.hunter.model.ParityFinding;
import com.parity.hunter.model.FindingsStore;

import javax.swing.table.AbstractTableModel;
import java.util.List;

/**
 * Swing table model backed by FindingsStore.
 * Call refresh() after new findings are added to trigger UI repaint.
 */
public class FindingsTableModel extends AbstractTableModel {

    private static final String[] COLUMNS = {
            "Endpoint", "Method", "Resource ID",
            "Baseline Status", "Attacker Status", "Similarity", "Discovered At"
    };

    private final FindingsStore store;

    public FindingsTableModel(FindingsStore store) {
        this.store = store;
    }

    public void refresh() {
        fireTableDataChanged();
    }

    @Override public int    getRowCount()              { return store.size(); }
    @Override public int    getColumnCount()           { return COLUMNS.length; }
    @Override public String getColumnName(int col)     { return COLUMNS[col]; }

    @Override
    public Object getValueAt(int row, int col) {
        List<ParityFinding> findings = store.getAll();
        if (row >= findings.size()) return null;
        ParityFinding f = findings.get(row);
        return switch (col) {
            case 0 -> f.getEndpoint();
            case 1 -> f.getMethod();
            case 2 -> f.getResourceIdentifier();
            case 3 -> f.getBaselineStatus();
            case 4 -> f.getAttackerStatus();
            case 5 -> String.format("%.0f%%", f.getSimilarity() * 100);
            case 6 -> f.getDiscoveredAt().toString();
            default -> null;
        };
    }
}