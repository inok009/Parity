package com.parity.hunter.ui;

import com.parity.hunter.config.Profile;
import com.parity.hunter.config.SessionRegistry;

import javax.swing.*;
import java.awt.*;

/**
 * UI panel for configuring Profile A (attacker) and Profile B (victim).
 *
 * Uses GridBagLayout for reliable field alignment. Each profile form
 * provides an Authorization Header field, a Tenant Identifier field,
 * a Save button, and an inline status label with validation feedback.
 */
public class ProfilePanel extends JPanel {

    public ProfilePanel(SessionRegistry registry) {
        setLayout(new GridLayout(2, 1, 0, 10));
        setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        add(buildProfileForm("Profile A — Attacker", registry, true));
        add(buildProfileForm("Profile B — Victim",   registry, false));
    }

    private JPanel buildProfileForm(String title, SessionRegistry registry, boolean isA) {

        JPanel panel = new JPanel(new GridBagLayout());
        panel.setBorder(BorderFactory.createTitledBorder(title));

        GridBagConstraints gbc = new GridBagConstraints();
        gbc.insets = new Insets(4, 6, 4, 6);
        gbc.fill   = GridBagConstraints.HORIZONTAL;

        JTextField authField   = new JTextField(30);
        JTextField tenantField = new JTextField(30);
        JLabel     statusLabel = new JLabel(" ");
        JButton    saveButton  = new JButton("Save Profile");

        gbc.gridx = 0; gbc.gridy = 0; gbc.weightx = 0;
        panel.add(new JLabel("Authorization Header:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        panel.add(authField, gbc);

        gbc.gridx = 0; gbc.gridy = 1; gbc.weightx = 0;
        panel.add(new JLabel("Tenant Identifier:"), gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        panel.add(tenantField, gbc);

        gbc.gridx = 0; gbc.gridy = 2; gbc.weightx = 0;
        panel.add(saveButton, gbc);
        gbc.gridx = 1; gbc.weightx = 1.0;
        panel.add(statusLabel, gbc);

        saveButton.addActionListener(e -> {
            try {
                Profile profile = new Profile(authField.getText(), tenantField.getText());
                if (isA) registry.setProfileA(profile);
                else     registry.setProfileB(profile);
                statusLabel.setForeground(new Color(0, 140, 0));
                statusLabel.setText("✔ Saved — " + profile.getTenantIdentifier());
            } catch (IllegalArgumentException ex) {
                statusLabel.setForeground(Color.RED);
                statusLabel.setText("✘ " + ex.getMessage());
            }
        });

        return panel;
    }
}