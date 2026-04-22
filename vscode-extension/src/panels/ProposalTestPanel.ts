/**
 * ProposalTestPanel.ts — Webview panel for testing policy proposals.
 *
 * The form maps exactly to ValidateRequest in external.py.
 * The result shows is_allowed (green/red badge) and the reason string.
 * Opened via "Gavel: Test Policy Proposal" command or editor context menu.
 */

import * as vscode from 'vscode';
import { GavelClient } from '../api/GavelClient';

export class ProposalTestPanel {
  static currentPanel: ProposalTestPanel | undefined;
  private readonly panel: vscode.WebviewPanel;
  private disposables: vscode.Disposable[] = [];

  static createOrShow(extensionUri: vscode.Uri, client: GavelClient): void {
    if (ProposalTestPanel.currentPanel) {
      ProposalTestPanel.currentPanel.panel.reveal(vscode.ViewColumn.Beside);
      return;
    }
    const panel = vscode.window.createWebviewPanel(
      'gavelProposalTest',
      'Gavel: Test Proposal',
      vscode.ViewColumn.Beside,
      {
        enableScripts: true,
        localResourceRoots: [vscode.Uri.joinPath(extensionUri, 'media')],
        retainContextWhenHidden: true,
      }
    );
    ProposalTestPanel.currentPanel = new ProposalTestPanel(panel, client);
  }

  private constructor(panel: vscode.WebviewPanel, private readonly client: GavelClient) {
    this.panel = panel;
    this.panel.webview.html = this.getHtml();

    this.panel.webview.onDidReceiveMessage(
      async (msg: { command: string; action?: string; method?: string; clearance?: number }) => {
        if (msg.command === 'validate') {
          try {
            // Ensure we have a token
            await this.client.mintToken({ role: 'customer', clearance_level: msg.clearance ?? 1 });
            const result = await this.client.validate({
              action: msg.action ?? '',
              method: msg.method ?? 'EXECUTE',
              required_clearance: msg.clearance ?? 1,
            });
            await this.panel.webview.postMessage({ command: 'result', data: result });
          } catch (err) {
            await this.panel.webview.postMessage({
              command: 'error',
              message: err instanceof Error ? err.message : String(err),
            });
          }
        }
      },
      null,
      this.disposables
    );

    this.panel.onDidDispose(() => {
      ProposalTestPanel.currentPanel = undefined;
      this.dispose();
    }, null, this.disposables);
  }

  private getHtml(): string {
    return `<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8">
  <meta name="viewport" content="width=device-width, initial-scale=1.0">
  <title>Gavel: Test Proposal</title>
  <style>
    body {
      font-family: var(--vscode-font-family);
      font-size: var(--vscode-font-size);
      color: var(--vscode-foreground);
      background: var(--vscode-editor-background);
      padding: 20px;
      max-width: 600px;
    }
    h2 { margin-top: 0; font-weight: 600; }
    label { display: block; margin-bottom: 4px; font-size: 12px; opacity: 0.8; }
    input, select {
      width: 100%;
      padding: 6px 8px;
      margin-bottom: 14px;
      background: var(--vscode-input-background);
      color: var(--vscode-input-foreground);
      border: 1px solid var(--vscode-input-border, #555);
      border-radius: 3px;
      font-family: var(--vscode-font-family);
      font-size: var(--vscode-font-size);
      box-sizing: border-box;
    }
    button {
      padding: 8px 20px;
      background: var(--vscode-button-background);
      color: var(--vscode-button-foreground);
      border: none;
      border-radius: 3px;
      cursor: pointer;
      font-size: 13px;
    }
    button:hover { background: var(--vscode-button-hoverBackground); }
    #result {
      margin-top: 20px;
      padding: 14px;
      border-radius: 4px;
      display: none;
    }
    #result.allow {
      background: rgba(0, 180, 0, 0.12);
      border: 1px solid rgba(0, 180, 0, 0.4);
    }
    #result.deny {
      background: rgba(220, 50, 50, 0.12);
      border: 1px solid rgba(220, 50, 50, 0.4);
    }
    #result.error {
      background: rgba(220, 150, 0, 0.12);
      border: 1px solid rgba(220, 150, 0, 0.4);
    }
    .verdict-badge {
      font-size: 16px;
      font-weight: 700;
      margin-bottom: 6px;
    }
    .reason { font-size: 12px; opacity: 0.85; }
    .hint { font-size: 11px; opacity: 0.6; margin-top: 16px; }
  </style>
</head>
<body>
  <h2>$(beaker) Test Policy Proposal</h2>
  <p style="opacity:0.7;font-size:12px;">
    Calls <code>POST /external/validate</code> against the running control plane.
    Maps to <code>ValidateRequest</code> in <code>external.py</code>.
  </p>

  <label for="action">Action</label>
  <input id="action" type="text" placeholder="e.g. read.data  or  data.delete  or  api.example.com" value="read.data">

  <label for="method">Method</label>
  <select id="method">
    <option value="EXECUTE">EXECUTE</option>
    <option value="GET">GET</option>
    <option value="POST">POST</option>
    <option value="CONNECT">CONNECT</option>
  </select>

  <label for="clearance">Required Clearance Level (1–5)</label>
  <input id="clearance" type="number" min="1" max="5" value="1">

  <button onclick="runValidate()">Run Validation</button>

  <div id="result">
    <div class="verdict-badge" id="verdict-text"></div>
    <div class="reason" id="reason-text"></div>
  </div>

  <p class="hint">
    Tip: try <code>data.delete</code> (blocked by default policy) vs <code>read.data</code> (allowed).
  </p>

  <script>
    const vscode = acquireVsCodeApi();

    function runValidate() {
      const action = document.getElementById('action').value.trim();
      const method = document.getElementById('method').value;
      const clearance = parseInt(document.getElementById('clearance').value, 10);

      if (!action) {
        showError('Action is required');
        return;
      }

      vscode.postMessage({ command: 'validate', action, method, clearance });
    }

    window.addEventListener('message', event => {
      const msg = event.data;
      const resultEl = document.getElementById('result');
      const verdictEl = document.getElementById('verdict-text');
      const reasonEl = document.getElementById('reason-text');

      if (msg.command === 'result') {
        resultEl.style.display = 'block';
        resultEl.className = msg.data.is_allowed ? 'allow' : 'deny';
        verdictEl.textContent = msg.data.is_allowed ? '✓ ALLOW' : '✗ DENY';
        reasonEl.textContent = msg.data.reason;
      } else if (msg.command === 'error') {
        showError(msg.message);
      }
    });

    function showError(message) {
      const resultEl = document.getElementById('result');
      const verdictEl = document.getElementById('verdict-text');
      const reasonEl = document.getElementById('reason-text');
      resultEl.style.display = 'block';
      resultEl.className = 'error';
      verdictEl.textContent = '⚠ Error';
      reasonEl.textContent = message;
    }
  </script>
</body>
</html>`;
  }

  dispose(): void {
    this.disposables.forEach(d => d.dispose());
    this.disposables = [];
  }
}
