package com.parity.hunter.ui;

import burp.api.montoya.ui.UserInterface;
import com.parity.hunter.config.SessionRegistry;
import com.parity.hunter.model.FindingsStore;

import javax.swing.*;
import java.awt.*;

/**
 * Root UI component registered as a Burp Suite tab.
 * Contains two sub-tabs: Profiles (configuration) and Findings (results table).
 */
public class MainTab extends JPanel {

    public MainTab(SessionRegistry registry, FindingsStore store, UserInterface ui) {

        setLayout(new BorderLayout());

        FindingsTableModel tableModel = new FindingsTableModel(store);
        JTable             table      = new JTable(tableModel);
        JScrollPane        scrollPane = new JScrollPane(table);

        JButton refreshButton = new JButton("Refresh Findings");
        refreshButton.addActionListener(e -> tableModel.refresh());

        JButton clearButton = new JButton("Clear");
        clearButton.addActionListener(e -> {
            store.clear();
            tableModel.refresh();
        });

        JPanel topBar = new JPanel(new FlowLayout(FlowLayout.LEFT));
        topBar.add(refreshButton);
        topBar.add(clearButton);

        JTabbedPane tabs = new JTabbedPane();
        tabs.addTab("Profiles", new ProfilePanel(registry));
        tabs.addTab("Findings", scrollPane);

        add(topBar, BorderLayout.NORTH);
        add(tabs,   BorderLayout.CENTER);
    }

    public String    getTabCaption()   { return "BOLA Hunter"; }
    public Component getUiComponent()  { return this; }
}