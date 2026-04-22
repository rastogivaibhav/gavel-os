/**
 * extension.ts — Gavel VS Code Extension entry point.
 *
 * Activates on startup (onStartupFinished) so the Gavel icon always
 * appears in the Activity Bar. Policy validation works immediately
 * without any configuration. The sidebar shows a welcome view with
 * one-click setup until the control plane is reachable.
 */

import * as vscode from 'vscode';
import { GavelClient } from './api/GavelClient';
import { TelemetrySocket } from './api/TelemetrySocket';
import { PolicyDiagnosticsProvider } from './validation/PolicyDiagnosticsProvider';
import { PolicyCodeActionProvider } from './validation/PolicyCodeActionProvider';
import { AuditLedgerProvider } from './providers/AuditLedgerProvider';
import { EnforcerStatusBar } from './providers/EnforcerStatusBar';
import { ProposalTestPanel } from './panels/ProposalTestPanel';
import { TelemetryStreamPanel } from './panels/TelemetryStreamPanel';
import { getConfig, toWebSocketUrl } from './config';
import { AuditEntry } from './api/types';

// Context key that drives which views are visible in the sidebar.
// When false: welcome view with setup instructions.
// When true: enforcer status + audit ledger.
const CTX_CONNECTED = 'gavel.connected';

export function activate(context: vscode.ExtensionContext): void {
  const config = getConfig();

  // ── Core services ─────────────────────────────────────────────────────────
  const client = new GavelClient(config.controlPlaneUrl);

  const socket = new TelemetrySocket(
    toWebSocketUrl(config.controlPlaneUrl),
    config.apiKey
  );

  // ── Policy validation — always active, no config needed ──────────────────
  const diagnosticsProvider = new PolicyDiagnosticsProvider();
  context.subscriptions.push(diagnosticsProvider);

  const codeActionProvider = vscode.languages.registerCodeActionsProvider(
    { language: 'yaml', scheme: 'file' },
    new PolicyCodeActionProvider(),
    { providedCodeActionKinds: PolicyCodeActionProvider.providedCodeActionKinds }
  );
  context.subscriptions.push(codeActionProvider);

  // Validate all already-open documents
  vscode.workspace.textDocuments.forEach(doc => diagnosticsProvider.validate(doc));

  context.subscriptions.push(
    vscode.workspace.onDidSaveTextDocument(doc => {
      if (getConfig().validateOnSave) diagnosticsProvider.validate(doc);
    }),
    vscode.workspace.onDidOpenTextDocument(doc => diagnosticsProvider.validate(doc)),
    vscode.workspace.onDidCloseTextDocument(doc => diagnosticsProvider.clear(doc))
  );

  // ── Audit ledger tree view ────────────────────────────────────────────────
  const auditProvider = new AuditLedgerProvider(client);
  const auditTree = vscode.window.createTreeView('gavelAuditLedger', {
    treeDataProvider: auditProvider,
    showCollapseAll: false,
  });
  context.subscriptions.push(auditTree);

  // ── Enforcer status tree view (simple placeholder provider) ───────────────
  const enforcerProvider = new EnforcerStatusTreeProvider();
  vscode.window.createTreeView('gavelEnforcerStatus', {
    treeDataProvider: enforcerProvider,
  });

  // ── Status bar ────────────────────────────────────────────────────────────
  const statusBar = new EnforcerStatusBar(client);
  context.subscriptions.push(statusBar);

  // ── Virtual document provider for audit entries ───────────────────────────
  context.subscriptions.push(
    vscode.workspace.registerTextDocumentContentProvider('gavel-audit', {
      provideTextDocumentContent(uri: vscode.Uri): string {
        try {
          return JSON.stringify(
            JSON.parse(decodeURIComponent(uri.query)) as AuditEntry,
            null, 2
          );
        } catch { return '{}'; }
      },
    })
  );

  // ── Connection management ─────────────────────────────────────────────────

  async function tryConnect(showMessages = false): Promise<boolean> {
    try {
      const health = await client.health();
      const ok = health.status === 'healthy' || health.status === 'degraded';

      await vscode.commands.executeCommand('setContext', CTX_CONNECTED, ok);

      if (ok) {
        statusBar.start();
        auditProvider.refresh().catch(() => {});
        if (getConfig().telemetryEnabled) socket.connect();
        enforcerProvider.setHealth(health);

        // Auto-mint a token if apiKey is set
        if (getConfig().apiKey) {
          client.mintToken({ role: 'customer', clearance_level: 1 }).catch(() => {});
        }

        if (showMessages) {
          vscode.window.showInformationMessage(
            `Gavel connected — control plane is ${health.status}`
          );
        }
      }
      return ok;
    } catch {
      await vscode.commands.executeCommand('setContext', CTX_CONNECTED, false);
      return false;
    }
  }

  // Try connecting silently on startup
  if (config.autoConnect) {
    tryConnect(false);
  } else {
    vscode.commands.executeCommand('setContext', CTX_CONNECTED, false);
  }

  // ── Commands ──────────────────────────────────────────────────────────────

  // Connect to control plane (shown in welcome view)
  context.subscriptions.push(
    vscode.commands.registerCommand('gavel.connect', async () => {
      const connected = await tryConnect(true);
      if (!connected) {
        const action = await vscode.window.showErrorMessage(
          'Cannot reach Gavel control plane at ' + getConfig().controlPlaneUrl,
          'Open Settings',
          'Start with Docker Compose'
        );
        if (action === 'Open Settings') {
          vscode.commands.executeCommand('workbench.action.openSettings', 'gavel');
        } else if (action === 'Start with Docker Compose') {
          vscode.commands.executeCommand('gavel.startDockerCompose');
        }
      }
    })
  );

  // Start Docker Compose (shown in welcome view)
  context.subscriptions.push(
    vscode.commands.registerCommand('gavel.startDockerCompose', () => {
      const terminal = vscode.window.createTerminal('Gavel Setup');
      terminal.show();
      // Find the repo root relative to the workspace
      const workspaceRoot = vscode.workspace.workspaceFolders?.[0]?.uri?.fsPath ?? '.';
      terminal.sendText(`cd "${workspaceRoot}" ; docker compose up -d`);
      // Poll for the control plane to come up
      let attempts = 0;
      const poll = setInterval(async () => {
        attempts++;
        const connected = await tryConnect(false);
        if (connected || attempts >= 24) {  // give up after 2 minutes
          clearInterval(poll);
          if (connected) {
            vscode.window.showInformationMessage('Gavel control plane is ready ✓');
          }
        }
      }, 5000);
    })
  );

  // Open Live Monitor
  context.subscriptions.push(
    vscode.commands.registerCommand('gavel.openMonitor', () => {
      if (!socket.connected) socket.connect();
      TelemetryStreamPanel.createOrShow(context.extensionUri, socket);
    })
  );

  // Test Policy Proposal
  context.subscriptions.push(
    vscode.commands.registerCommand('gavel.testProposal', () => {
      ProposalTestPanel.createOrShow(context.extensionUri, client);
    })
  );

  // Validate Policy File
  context.subscriptions.push(
    vscode.commands.registerCommand('gavel.validatePolicy', () => {
      const editor = vscode.window.activeTextEditor;
      if (!editor) {
        vscode.window.showWarningMessage('Open a policy YAML file first');
        return;
      }
      const passed = diagnosticsProvider.validate(editor.document);
      if (passed) {
        vscode.window.showInformationMessage('Gavel: Policy validation passed ✓');
      } else {
        vscode.window.showWarningMessage('Gavel: Errors found — see the Problems panel (Ctrl+Shift+M)');
      }
    })
  );

  // Refresh Audit Ledger
  context.subscriptions.push(
    vscode.commands.registerCommand('gavel.refreshAuditLedger', () => {
      auditProvider.refresh().catch(err => {
        vscode.window.showErrorMessage(
          `Refresh failed: ${err instanceof Error ? err.message : String(err)}`
        );
      });
    })
  );

  // Verify Audit Chain
  context.subscriptions.push(
    vscode.commands.registerCommand('gavel.verifyChain', () => {
      auditProvider.verifyAndRefresh().catch(err => {
        vscode.window.showErrorMessage(
          `Verification failed: ${err instanceof Error ? err.message : String(err)}`
        );
      });
    })
  );

  // Mint JWT Token
  context.subscriptions.push(
    vscode.commands.registerCommand('gavel.mintToken', async () => {
      const role = await vscode.window.showQuickPick(['customer', 'admin'], {
        placeHolder: 'Select token role',
      });
      if (!role) return;
      try {
        const token = await client.mintToken({ role, clearance_level: 2 });
        await vscode.env.clipboard.writeText(token);
        vscode.window.showInformationMessage(`JWT token (${role}) copied to clipboard`);
      } catch (err) {
        vscode.window.showErrorMessage(
          `Token minting failed: ${err instanceof Error ? err.message : String(err)}`
        );
      }
    })
  );

  // Run Enforcer Preflight
  context.subscriptions.push(
    vscode.commands.registerCommand('gavel.runPreflight', () => {
      const terminal = vscode.window.createTerminal('Gavel Preflight');
      terminal.show();
      terminal.sendText(
        'gavel-enforcer -preflight 2>&1 ; if ($LASTEXITCODE -ne 0) { .\\enforcer\\gavel-enforcer -preflight 2>&1 }'
      );
    })
  );

  // Open audit entry as virtual document
  context.subscriptions.push(
    vscode.commands.registerCommand('gavel.openAuditEntry', async (entry: AuditEntry) => {
      const uri = vscode.Uri.parse(
        `gavel-audit:audit-entry-${entry.id}.json?${encodeURIComponent(JSON.stringify(entry))}`
      );
      const doc = await vscode.workspace.openTextDocument(uri);
      await vscode.window.showTextDocument(doc, {
        preview: true,
        viewColumn: vscode.ViewColumn.Beside,
      });
    })
  );

  // Re-connect when settings change
  context.subscriptions.push(
    vscode.workspace.onDidChangeConfiguration(e => {
      if (e.affectsConfiguration('gavel.controlPlaneUrl') || e.affectsConfiguration('gavel.apiKey')) {
        socket.disconnect();
        tryConnect(false);
      }
    })
  );

  context.subscriptions.push(socket);
}

export function deactivate(): void {}

// ── Simple tree provider for the Enforcer Status view ────────────────────────

class EnforcerStatusTreeProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
  private items: vscode.TreeItem[] = [];
  private readonly _onChange = new vscode.EventEmitter<void>();
  readonly onDidChangeTreeData = this._onChange.event;

  setHealth(health: { status: string; version: string; components: Record<string, string> }): void {
    this.items = [
      this.item(`Status: ${health.status}`, health.status === 'healthy' ? 'check' : 'warning'),
      this.item(`Version: ${health.version}`, 'tag'),
      ...Object.entries(health.components).map(([k, v]) =>
        this.item(`${k}: ${v}`, v === 'connected' || v === 'ready' || v === 'loaded' || v === 'configured' ? 'circle-filled' : 'circle-outline')
      ),
    ];
    this._onChange.fire();
  }

  private item(label: string, icon: string): vscode.TreeItem {
    const t = new vscode.TreeItem(label, vscode.TreeItemCollapsibleState.None);
    t.iconPath = new vscode.ThemeIcon(icon);
    return t;
  }

  getTreeItem(e: vscode.TreeItem): vscode.TreeItem { return e; }
  getChildren(): vscode.TreeItem[] { return this.items; }
}
