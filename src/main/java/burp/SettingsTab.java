package burp;

import com.google.gson.Gson;
import com.intellij.uiDesigner.core.GridConstraints;
import com.intellij.uiDesigner.core.GridLayoutManager;
import com.intellij.uiDesigner.core.Spacer;

import javax.swing.*;
import java.awt.*;
import java.awt.event.ActionEvent;
import java.awt.event.ActionListener;
import java.io.PrintWriter;

public class SettingsTab implements ITab {
    private JComboBox comboBoxFingerprint;
    private JPanel panelMain;
    private JLabel labelFingerprint;
    private JTextField textFieldSpoofProxyAddress;
    private JTextField textFieldInterceptProxyAddress;
    private JTextField textFieldBurpProxyAddress;
    private JLabel labelSpoofProxyAddress;
    private JButton buttonSave;
    private JLabel labelTimeout;
    private JSpinner spinnerHttpTimout;
    private JSpinner spinnerKeepAlive;
    private JLabel labelKeepAlive;
    private JLabel labelIdleConnTimeout;
    private JSpinner spinnerIdleConnTimeout;
    private JLabel labelTlsHandshakeTimeout;
    private JSpinner spinnerTlsHandshakeTimeout;
    private JLabel labelInterceptProxyAddress;
    private JLabel labelBurpProxyAddress;
    private JCheckBox checkBoxButtonUseInterceptedFingerprint;
    private JTabbedPane tabbedPaneTab;
    private JPanel panelSettings;
    private JPanel panelAdvanced;
    private JButton buttonSaveAdvanced;

    private Gson gson;
    private PrintWriter stdout;
    private PrintWriter stderr;

    @Override
    public String getTabCaption() {
        return "Awesome TLS";
    }

    @Override
    public Component getUiComponent() {
        return panelMain;
    }

    public SettingsTab(Settings settings, IBurpExtenderCallbacks callbacks) {
        gson = new Gson();
        this.stdout = new PrintWriter(callbacks.getStdout(), true);
        this.stderr = new PrintWriter(callbacks.getStderr(), true);

        textFieldInterceptProxyAddress.setText(settings.getInterceptProxyAddress());
        textFieldBurpProxyAddress.setText(settings.getBurpProxyAddress());
        textFieldSpoofProxyAddress.setText(settings.getSpoofProxyAddress());

        spinnerHttpTimout.setValue(settings.getHttpTimeout());
        spinnerKeepAlive.setValue(settings.getHttpKeepAliveInterval());
        spinnerIdleConnTimeout.setValue(settings.getIdleConnTimeout());
        spinnerTlsHandshakeTimeout.setValue(settings.getTlsHandshakeTimeout());

        for (var item : settings.getFingerprints()) {
            comboBoxFingerprint.addItem(item);
        }
        comboBoxFingerprint.setSelectedItem(settings.getFingerprint());

        buttonSave.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                var err = SaveSettings(settings);
                if (!err.equals("")) {
                    JOptionPane.showMessageDialog(panelSettings,
                            err,
                            "Error",
                            JOptionPane.ERROR_MESSAGE);
                }
            }
        });

        buttonSaveAdvanced.addActionListener(new ActionListener() {
            @Override
            public void actionPerformed(ActionEvent e) {
                var err = SaveSettings(settings);
                if (!err.equals("")) {
                    JOptionPane.showMessageDialog(panelAdvanced,
                            err,
                            "Error",
                            JOptionPane.ERROR_MESSAGE);
                }
            }
        });
    }

    private String SaveSettings(Settings settings) {
        settings.setSpoofProxyAddress(textFieldSpoofProxyAddress.getText());
        settings.setFingerprint((String) comboBoxFingerprint.getSelectedItem());
        settings.setHttpTimeout((int) spinnerHttpTimout.getValue());
        settings.setIdleConnTimeout((int) spinnerIdleConnTimeout.getValue());
        settings.setHttpKeepAliveInterval((int) spinnerKeepAlive.getValue());
        settings.setTlsHandshakeTimeout((int) spinnerTlsHandshakeTimeout.getValue());
        settings.setInterceptProxyAddress(textFieldInterceptProxyAddress.getText());
        settings.setBurpProxyAddress(textFieldBurpProxyAddress.getText());
        settings.setUseInterceptedFingerprint(checkBoxButtonUseInterceptedFingerprint.isSelected());

        var transportConfig = new TransportConfig();
        transportConfig.InterceptProxyAddr = settings.getInterceptProxyAddress();
        transportConfig.BurpAddr = settings.getBurpProxyAddress();
        transportConfig.Fingerprint = settings.getFingerprint();
        transportConfig.HttpTimeout = settings.getHttpTimeout();
        transportConfig.HttpKeepAliveInterval = settings.getHttpKeepAliveInterval();
        transportConfig.IdleConnTimeout = settings.getIdleConnTimeout();
        transportConfig.TlsHandshakeTimeout = settings.getTlsHandshakeTimeout();
        transportConfig.UseInterceptedFingerprint = settings.getUseInterceptedFingerprint();
        var goConfigJSON = this.gson.toJson(transportConfig);

        this.stdout.println("Using config: " + goConfigJSON);

        return ServerLibrary.INSTANCE.SaveSettings(goConfigJSON);
    }

    {
// GUI initializer generated by IntelliJ IDEA GUI Designer
// >>> IMPORTANT!! <<<
// DO NOT EDIT OR ADD ANY CODE HERE!
        $$$setupUI$$$();
    }

    /**
     * Method generated by IntelliJ IDEA GUI Designer
     * >>> IMPORTANT!! <<<
     * DO NOT edit this method OR call it in your code!
     *
     * @noinspection ALL
     */
    private void $$$setupUI$$$() {
        panelMain = new JPanel();
        panelMain.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(3, 5, new Insets(0, 0, 0, 0), -1, -1));
        tabbedPaneTab = new JTabbedPane();
        panelMain.add(tabbedPaneTab, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, new Dimension(200, 200), null, 0, false));
        panelSettings = new JPanel();
        panelSettings.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(14, 1, new Insets(0, 0, 0, 0), -1, -1));
        tabbedPaneTab.addTab("settings", panelSettings);
        labelSpoofProxyAddress = new JLabel();
        labelSpoofProxyAddress.setRequestFocusEnabled(false);
        labelSpoofProxyAddress.setText("Listen address:");
        labelSpoofProxyAddress.setToolTipText("");
        panelSettings.add(labelSpoofProxyAddress, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        textFieldSpoofProxyAddress = new JTextField();
        textFieldSpoofProxyAddress.setToolTipText("Local address the  proxy server should listen on. Requires extension reload.");
        panelSettings.add(textFieldSpoofProxyAddress, new com.intellij.uiDesigner.core.GridConstraints(1, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        labelFingerprint = new JLabel();
        labelFingerprint.setEnabled(true);
        labelFingerprint.setHorizontalAlignment(10);
        labelFingerprint.setText("Fingerprint:");
        labelFingerprint.setVerticalAlignment(0);
        labelFingerprint.setVerticalTextPosition(0);
        panelSettings.add(labelFingerprint, new com.intellij.uiDesigner.core.GridConstraints(2, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_NORTHWEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        comboBoxFingerprint = new JComboBox();
        panelSettings.add(comboBoxFingerprint, new com.intellij.uiDesigner.core.GridConstraints(3, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_NORTHWEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        labelTimeout = new JLabel();
        labelTimeout.setText("Http connection timeout (seconds)");
        panelSettings.add(labelTimeout, new com.intellij.uiDesigner.core.GridConstraints(4, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        spinnerHttpTimout = new JSpinner();
        spinnerHttpTimout.setToolTipText("The maximum amount of time a dial will wait for a connect to complete.");
        panelSettings.add(spinnerHttpTimout, new com.intellij.uiDesigner.core.GridConstraints(5, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        labelKeepAlive = new JLabel();
        labelKeepAlive.setText("Http keep alive interval");
        panelSettings.add(labelKeepAlive, new com.intellij.uiDesigner.core.GridConstraints(6, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        spinnerKeepAlive = new JSpinner();
        spinnerKeepAlive.setToolTipText("Specifies the interval between keep-alive probes for an active network connection.");
        panelSettings.add(spinnerKeepAlive, new com.intellij.uiDesigner.core.GridConstraints(7, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        labelIdleConnTimeout = new JLabel();
        labelIdleConnTimeout.setText("Idle connection timeout");
        panelSettings.add(labelIdleConnTimeout, new com.intellij.uiDesigner.core.GridConstraints(8, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        spinnerIdleConnTimeout = new JSpinner();
        spinnerIdleConnTimeout.setToolTipText("The maximum amount of time an idle (keep-alive) connection will remain idle before closing itself.");
        panelSettings.add(spinnerIdleConnTimeout, new com.intellij.uiDesigner.core.GridConstraints(9, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        labelTlsHandshakeTimeout = new JLabel();
        labelTlsHandshakeTimeout.setText("TLS handshake timeout");
        panelSettings.add(labelTlsHandshakeTimeout, new com.intellij.uiDesigner.core.GridConstraints(10, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        spinnerTlsHandshakeTimeout = new JSpinner();
        spinnerTlsHandshakeTimeout.setToolTipText("The maximum amount of time to wait for a TLS handshake.");
        panelSettings.add(spinnerTlsHandshakeTimeout, new com.intellij.uiDesigner.core.GridConstraints(11, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        buttonSave = new JButton();
        buttonSave.setText("Save all settings");
        panelSettings.add(buttonSave, new com.intellij.uiDesigner.core.GridConstraints(12, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel1 = new JPanel();
        panel1.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(1, 1, new Insets(0, 0, 0, 0), -1, -1));
        panelSettings.add(panel1, new com.intellij.uiDesigner.core.GridConstraints(13, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        panelAdvanced = new JPanel();
        panelAdvanced.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(7, 1, new Insets(0, 0, 0, 0), -1, -1));
        panelAdvanced.setToolTipText("");
        tabbedPaneTab.addTab("advanced", panelAdvanced);
        labelInterceptProxyAddress = new JLabel();
        labelInterceptProxyAddress.setEnabled(true);
        labelInterceptProxyAddress.setText("Intercept proxy address:");
        panelAdvanced.add(labelInterceptProxyAddress, new com.intellij.uiDesigner.core.GridConstraints(1, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        textFieldInterceptProxyAddress = new JTextField();
        textFieldInterceptProxyAddress.setToolTipText("Local address the intercept proxy server should listen on. Use it to configure proxy on your client. Requires extension reload.");
        panelAdvanced.add(textFieldInterceptProxyAddress, new com.intellij.uiDesigner.core.GridConstraints(2, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        labelBurpProxyAddress = new JLabel();
        labelBurpProxyAddress.setText("Burp proxy address:");
        panelAdvanced.add(labelBurpProxyAddress, new com.intellij.uiDesigner.core.GridConstraints(3, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        textFieldBurpProxyAddress = new JTextField();
        textFieldBurpProxyAddress.setText("");
        panelAdvanced.add(textFieldBurpProxyAddress, new com.intellij.uiDesigner.core.GridConstraints(4, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_HORIZONTAL, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, new Dimension(150, -1), null, 0, false));
        buttonSaveAdvanced = new JButton();
        buttonSaveAdvanced.setHideActionText(false);
        buttonSaveAdvanced.setText("Save all settings");
        panelAdvanced.add(buttonSaveAdvanced, new com.intellij.uiDesigner.core.GridConstraints(5, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
        final JPanel panel2 = new JPanel();
        panel2.setLayout(new com.intellij.uiDesigner.core.GridLayoutManager(1, 1, new Insets(0, 0, 0, 0), -1, -1));
        panelAdvanced.add(panel2, new com.intellij.uiDesigner.core.GridConstraints(6, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_BOTH, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, null, null, null, 0, false));
        final com.intellij.uiDesigner.core.Spacer spacer1 = new com.intellij.uiDesigner.core.Spacer();
        panel2.add(spacer1, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_CENTER, com.intellij.uiDesigner.core.GridConstraints.FILL_VERTICAL, 1, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_WANT_GROW, null, null, null, 0, false));
        checkBoxButtonUseInterceptedFingerprint = new JCheckBox();
        checkBoxButtonUseInterceptedFingerprint.setText("Use intercepted tls fingerprint");
        panelAdvanced.add(checkBoxButtonUseInterceptedFingerprint, new com.intellij.uiDesigner.core.GridConstraints(0, 0, 1, 1, com.intellij.uiDesigner.core.GridConstraints.ANCHOR_WEST, com.intellij.uiDesigner.core.GridConstraints.FILL_NONE, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_SHRINK | com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_CAN_GROW, com.intellij.uiDesigner.core.GridConstraints.SIZEPOLICY_FIXED, null, null, null, 0, false));
    }

    /**
     * @noinspection ALL
     */
    public JComponent $$$getRootComponent$$$() {
        return panelMain;
    }

}
