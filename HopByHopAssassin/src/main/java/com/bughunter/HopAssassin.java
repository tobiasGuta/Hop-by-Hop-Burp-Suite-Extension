package com.bughunter;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.http.message.HttpHeader;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.http.message.requests.HttpRequest;
import burp.api.montoya.ui.UserInterface;
import burp.api.montoya.ui.contextmenu.ContextMenuEvent;
import burp.api.montoya.ui.contextmenu.ContextMenuItemsProvider;
import burp.api.montoya.ui.contextmenu.MessageEditorHttpRequestResponse;
import burp.api.montoya.ui.editor.EditorOptions;
import burp.api.montoya.ui.editor.HttpRequestEditor;
import burp.api.montoya.ui.editor.HttpResponseEditor;

import javax.swing.*;
import javax.swing.table.AbstractTableModel;
import java.awt.*;
import java.awt.event.MouseAdapter;
import java.awt.event.MouseEvent;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.List;
import java.util.concurrent.ExecutorService;
import java.util.concurrent.Executors;

public class HopAssassin implements BurpExtension, ContextMenuItemsProvider {

    private MontoyaApi api;
    private final AssassinTableModel tableModel = new AssassinTableModel();
    private final ExecutorService executor = Executors.newFixedThreadPool(5);
    private HttpRequestEditor requestViewer;
    private HttpResponseEditor responseViewer;

    // Standard headers to always try dropping
    private static final List<String> COMMON_HEADERS = Arrays.asList(
            "Cookie", "Authorization", "X-Forwarded-For", "X-Real-IP",
            "User-Agent", "Referer", "Origin", "X-Originating-IP",
            "X-Remote-IP", "CF-Connecting-IP", "True-Client-IP"
    );

    @Override
    public void initialize(MontoyaApi api) {
        this.api = api;
        api.extension().setName("Hop-by-Hop Assassin");

        SwingUtilities.invokeLater(() -> {
            JTable table = new JTable(tableModel);
            table.setFont(new Font("SansSerif", Font.PLAIN, 12));
            table.setSelectionMode(ListSelectionModel.SINGLE_SELECTION);

            UserInterface ui = api.userInterface();
            requestViewer = ui.createHttpRequestEditor(EditorOptions.READ_ONLY);
            responseViewer = ui.createHttpResponseEditor(EditorOptions.READ_ONLY);

            // Viewer Updater
            table.getSelectionModel().addListSelectionListener(e -> {
                if (!e.getValueIsAdjusting()) {
                    int selectedRow = table.getSelectedRow();
                    if (selectedRow != -1) {
                        AssassinResult result = tableModel.getResult(selectedRow);
                        requestViewer.setRequest(result.requestResponse.request());
                        responseViewer.setResponse(result.requestResponse.response());
                    }
                }
            });

            // Context Menu (Clear/Delete)
            JPopupMenu popupMenu = new JPopupMenu();
            JMenuItem deleteItem = new JMenuItem("Delete Item");
            JMenuItem clearItem = new JMenuItem("Clear History");

            deleteItem.addActionListener(e -> {
                int selectedRow = table.getSelectedRow();
                if (selectedRow != -1) tableModel.removeRow(selectedRow);
            });
            clearItem.addActionListener(e -> tableModel.clear());
            popupMenu.add(deleteItem);
            popupMenu.addSeparator();
            popupMenu.add(clearItem);

            table.addMouseListener(new MouseAdapter() {
                @Override
                public void mouseReleased(MouseEvent e) { handleContextMenu(e); }
                @Override
                public void mousePressed(MouseEvent e) { handleContextMenu(e); }
                private void handleContextMenu(MouseEvent e) {
                    if (e.isPopupTrigger()) {
                        int row = table.rowAtPoint(e.getPoint());
                        if (row != -1 && !table.isRowSelected(row)) {
                            table.setRowSelectionInterval(row, row);
                        }
                        popupMenu.show(e.getComponent(), e.getX(), e.getY());
                    }
                }
            });

            // Layout
            JScrollPane tableScroll = new JScrollPane(table);
            JSplitPane bottomSplit = new JSplitPane(JSplitPane.HORIZONTAL_SPLIT, requestViewer.uiComponent(), responseViewer.uiComponent());
            bottomSplit.setResizeWeight(0.5);
            JSplitPane mainSplit = new JSplitPane(JSplitPane.VERTICAL_SPLIT, tableScroll, bottomSplit);
            mainSplit.setResizeWeight(0.4);

            api.userInterface().registerSuiteTab("Hop Assassin", mainSplit);
        });

        api.userInterface().registerContextMenuItemsProvider(this);
        api.logging().logToOutput("Hop-by-Hop Assassin Loaded. Right-click to probe headers.");
    }

    @Override
    public List<Component> provideMenuItems(ContextMenuEvent event) {
        if (event.messageEditorRequestResponse().isEmpty()) return null;
        JMenuItem probeItem = new JMenuItem("Probe Hop-by-Hop Headers");
        MessageEditorHttpRequestResponse editor = event.messageEditorRequestResponse().get();
        probeItem.addActionListener(l -> executor.submit(() -> startAttack(editor.requestResponse())));
        List<Component> menuList = new ArrayList<>();
        menuList.add(probeItem);
        return menuList;
    }

    private void startAttack(HttpRequestResponse baseRequestResponse) {
        HttpRequest originalRequest = baseRequestResponse.request();
        api.logging().logToOutput("[-] Starting probe on: " + originalRequest.url());

        try {
            // 1. Establish Baseline
            HttpRequestResponse baselineResp = api.http().sendRequest(originalRequest);
            int baselineStatus = baselineResp.response().statusCode();
            int baselineLen = baselineResp.response().bodyToString().length();

            // 2. Build Candidate List (Existing Headers + Common List)
            List<String> candidates = new ArrayList<>(COMMON_HEADERS);
            for (HttpHeader h : originalRequest.headers()) {
                if (!candidates.contains(h.name()) && !h.name().equalsIgnoreCase("Connection")) {
                    candidates.add(h.name());
                }
            }

            // 3. The Attack Loop
            for (String headerToDrop : candidates) {
                // Construct the "Assassin" Header
                // Connection: close, Header-Name
                String connectionValue = "close, " + headerToDrop;

                HttpRequest attackRequest;
                if (originalRequest.hasHeader("Connection")) {
                    attackRequest = originalRequest.withUpdatedHeader("Connection", connectionValue);
                } else {
                    attackRequest = originalRequest.withAddedHeader("Connection", connectionValue);
                }

                HttpRequestResponse attackResp = api.http().sendRequest(attackRequest);
                int status = attackResp.response().statusCode();
                int len = attackResp.response().bodyToString().length();

                // 4. Differential Analysis
                // We only care if the response CHANGED significantly
                boolean interesting = false;
                if (status != baselineStatus) interesting = true;
                if (Math.abs(len - baselineLen) > 100) interesting = true; // Size changed > 100 bytes

                if (interesting) {
                    SwingUtilities.invokeLater(() -> tableModel.addResult(new AssassinResult(
                            headerToDrop,
                            String.valueOf(status),
                            len + " (Diff: " + (len - baselineLen) + ")",
                            attackResp
                    )));
                    api.logging().logToOutput("[!] Anomaly detected dropping: " + headerToDrop);
                }
            }

        } catch (Exception e) {
            api.logging().logToError("Attack Error: " + e.getMessage());
        }
    }

    // --- TABLE MODEL ---
    static class AssassinTableModel extends AbstractTableModel {
        private final List<AssassinResult> results = new ArrayList<>();
        private final String[] columns = {"Header Dropped", "Status", "Length (Delta)"};

        public void addResult(AssassinResult result) { results.add(result); fireTableRowsInserted(results.size()-1, results.size()-1); }
        public void clear() { results.clear(); fireTableDataChanged(); }
        public void removeRow(int row) { if (row >= 0 && row < results.size()) { results.remove(row); fireTableRowsDeleted(row, row); } }

        public AssassinResult getResult(int row) { return results.get(row); }
        @Override public int getRowCount() { return results.size(); }
        @Override public int getColumnCount() { return columns.length; }
        @Override public String getColumnName(int col) { return columns[col]; }
        @Override public Object getValueAt(int row, int col) {
            AssassinResult r = results.get(row);
            return switch (col) { case 0 -> r.header; case 1 -> r.status; case 2 -> r.length; default -> ""; };
        }
    }

    static class AssassinResult {
        String header, status, length;
        HttpRequestResponse requestResponse;
        public AssassinResult(String h, String s, String l, HttpRequestResponse rr) {
            this.header = h; this.status = s; this.length = l; this.requestResponse = rr;
        }
    }
}