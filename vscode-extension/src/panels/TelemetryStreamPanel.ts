/**
 * TelemetryStreamPanel.ts — Live enforcement event monitor.
 *
 * Subscribes to WebSocket /ws/telemetry and renders events in real time.
 * Event types mirror RuntimeEventType in control-plane/api/runtime_contract.py:
 *   agent_detected, policy_verdict, network_verdict, component_health, authz_failure
 *
 * Verdict colours mirror RuntimeVerdict:
 *   ALLOW → green, DENY → red, AUDIT → yellow, INFO → blue, DEGRADED → orange
 */

import * as vscode from 'vscode';
import { TelemetrySocket } from '../api/TelemetrySocket';
import { RuntimeEventEnvelope } from '../api/types';

export class TelemetryStreamPanel {
  static currentPanel: TelemetryStreamPanel | undefined;
  private readonly panel: vscode.WebviewPanel;
  private disposables: vscode.Disposable[] = [];

  static createOrShow(extensionUri: vscode.Uri, socket: TelemetrySocket): void {
    if (TelemetryStreamPanel.currentPanel) {
      TelemetryStreamPanel.currentPanel.panel.reveal(vscode.ViewColumn.Two);
      return;
    }
    const panel = vscode.window.createWebviewPanel(
      'gavelTelemetry',
      'Gavel: Live Monitor',
      vscode.ViewColumn.Two,
      {
        enableScripts: true,
        retainContextWhenHidden: true,
      }
    );
    TelemetryStreamPanel.currentPanel = new TelemetryStreamPanel(panel, socket);
  }

  private constructor(panel: vscode.WebviewPanel, socket: TelemetrySocket) {
    this.panel = panel;
    this.panel.webview.html = this.getHtml();

    // Forward telemetry events to the webview
    const eventSub = socket.onEvent((event: RuntimeEventEnvelope) => {
      void this.panel.webview.postMessage({ command: 'event', data: event });
    });
    this.disposables.push(eventSub);

    // Forward connection status
    const statusSub = socket.onStatusChange((connected: boolean) => {
      void this.panel.webview.postMessage({ command: 'status', connected });
    });
    this.disposables.push(statusSub);

    this.panel.onDidDispose(() => {
      TelemetryStreamPanel.currentPanel = undefined;
      this.dispose();
    }, null, this.disposables);
  }

  private getHtml(): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <title>Gavel: Live Monitor</title>
  <style>
    * { box-sizing: border-box; margin: 0; padding: 0; }
    body {
      font-family: var(--vscode-font-family);
      font-size: 12px;
      color: var(--vscode-foreground);
      background: var(--vscode-editor-background);
      display: flex;
      flex-direction: column;
      height: 100vh;
    }
    header {
      padding: 10px 14px;
      border-bottom: 1px solid var(--vscode-panel-border, #333);
      display: flex;
      align-items: center;
      gap: 10px;
    }
    header h2 { font-size: 13px; font-weight: 600; flex: 1; }
    #status-dot {
      width: 8px; height: 8px; border-radius: 50%;
      background: #888;
    }
    #status-dot.connected { background: #4caf50; }
    #status-dot.disconnected { background: #f44336; }
    #status-label { font-size: 11px; opacity: 0.7; }
    #controls { display: flex; gap: 8px; }
    button {
      padding: 3px 10px;
      background: var(--vscode-button-secondaryBackground, #3a3a3a);
      color: var(--vscode-button-secondaryForeground, #ccc);
      border: none; border-radius: 3px; cursor: pointer; font-size: 11px;
    }
    button:hover { opacity: 0.8; }
    #event-list {
      flex: 1;
      overflow-y: auto;
      padding: 8px 0;
    }
    .event-row {
      display: grid;
      grid-template-columns: 60px 90px 80px 1fr 120px;
      gap: 8px;
      padding: 5px 14px;
      border-bottom: 1px solid var(--vscode-panel-border, #2a2a2a);
      align-items: center;
      font-size: 11px;
    }
    .event-row:hover { background: var(--vscode-list-hoverBackground, #2a2a2a); }
    .verdict {
      font-weight: 700;
      font-size: 10px;
      padding: 2px 6px;
      border-radius: 3px;
      text-align: center;
    }
    .ALLOW  { background: rgba(76,175,80,0.2);  color: #4caf50; }
    .DENY   { background: rgba(244,67,54,0.2);  color: #f44336; }
    .AUDIT  { background: rgba(255,193,7,0.2);  color: #ffc107; }
    .INFO   { background: rgba(33,150,243,0.2); color: #2196f3; }
    .DEGRADED { background: rgba(255,152,0,0.2); color: #ff9800; }
    .target { font-family: var(--vscode-editor-font-family, monospace); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
    .reason-code { opacity: 0.6; font-size: 10px; }
    .time { opacity: 0.5; font-size: 10px; }
    #empty { padding: 40px; text-align: center; opacity: 0.4; }
  </style>
</head>
<body>
  <header>
    <h2>$(pulse) Gavel Live Monitor</h2>
    <div id="status-dot" class="disconnected"></div>
    <span id="status-label">Connecting...</span>
    <div id="controls">
      <button onclick="clearEvents()">Clear</button>
      <button onclick="togglePause()" id="pause-btn">Pause</button>
    </div>
  </header>

  <div id="event-list">
    <div id="empty">Waiting for enforcement events...</div>
  </div>

  <script>
    let paused = false;
    let eventCount = 0;
    const MAX_EVENTS = 500;

    const list = document.getElementById('event-list');
    const empty = document.getElementById('empty');
    const dot = document.getElementById('status-dot');
    const statusLabel = document.getElementById('status-label');

    function togglePause() {
      paused = !paused;
      document.getElementById('pause-btn').textContent = paused ? 'Resume' : 'Pause';
    }

    function clearEvents() {
      list.innerHTML = '';
      list.appendChild(empty);
      empty.style.display = 'block';
      eventCount = 0;
    }

    function formatTime(iso) {
      try {
        return new Date(iso).toLocaleTimeString();
      } catch { return iso; }
    }

    window.addEventListener('message', event => {
      const msg = event.data;

      if (msg.command === 'status') {
        dot.className = msg.connected ? 'connected' : 'disconnected';
        statusLabel.textContent = msg.connected ? 'Connected' : 'Reconnecting...';
        return;
      }

      if (msg.command === 'event' && !paused) {
        const e = msg.data;
        empty.style.display = 'none';

        const row = document.createElement('div');
        row.className = 'event-row';
        row.innerHTML =
          '<span class="verdict ' + e.verdict + '">' + e.verdict + '</span>' +
          '<span class="reason-code">' + (e.reason_code || '') + '</span>' +
          '<span>' + (e.runtime_os || '') + '/' + (e.runtime_arch || '') + '</span>' +
          '<span class="target" title="' + e.target + '">' + e.target + '</span>' +
          '<span class="time">' + formatTime(e.event_time) + '</span>';

        list.insertBefore(row, list.firstChild);
        eventCount++;

        // Cap at MAX_EVENTS to prevent memory growth
        if (eventCount > MAX_EVENTS) {
          const rows = list.querySelectorAll('.event-row');
          if (rows.length > MAX_EVENTS) {
            rows[rows.length - 1].remove();
          }
        }
      }
    });
  </script>
</body>
</html>`;
  }

  dispose(): void {
    this.disposables.forEach(d => d.dispose());
    this.disposables = [];
  }
}
