/**
 * AuditLedgerProvider.ts — TreeDataProvider for the Gavel Audit Ledger view.
 *
 * Calls POST /audit/ledger for the last 24 hours and renders entries as a tree.
 * Each entry shows outcome icon, action, actor, and truncated hash.
 * Clicking an entry opens the full JSON in a read-only virtual document.
 */

import * as vscode from 'vscode';
import { GavelClient } from '../api/GavelClient';
import { AuditEntry } from '../api/types';

export class AuditLedgerProvider implements vscode.TreeDataProvider<vscode.TreeItem> {
  private readonly _onDidChangeTreeData = new vscode.EventEmitter<vscode.TreeItem | undefined>();
  readonly onDidChangeTreeData = this._onDidChangeTreeData.event;

  private entries: AuditEntry[] = [];
  private chainValid: boolean | null = null;

  constructor(private readonly client: GavelClient) {}

  async refresh(): Promise<void> {
    const now = new Date();
    const start = new Date(now.getTime() - 24 * 60 * 60 * 1000);

    try {
      const result = await this.client.queryLedger({
        start_date: start.toISOString(),
        end_date: now.toISOString(),
      });
      // Most recent first
      this.entries = [...result.entries].reverse();
    } catch {
      this.entries = [];
    }

    this._onDidChangeTreeData.fire(undefined);
  }

  async verifyAndRefresh(): Promise<void> {
    try {
      const report = await this.client.verifyChain();
      this.chainValid = report.is_valid;
      if (!report.is_valid) {
        vscode.window.showWarningMessage(
          `Gavel audit chain integrity check failed. Corrupted entries: ${report.corrupted_entries.join(', ')}`
        );
      } else {
        vscode.window.showInformationMessage('Gavel audit chain integrity verified ✓');
      }
    } catch (err) {
      vscode.window.showErrorMessage(`Chain verification failed: ${err instanceof Error ? err.message : String(err)}`);
    }
    await this.refresh();
  }

  getTreeItem(element: vscode.TreeItem): vscode.TreeItem {
    return element;
  }

  getChildren(element?: vscode.TreeItem): vscode.TreeItem[] {
    if (element) return [];
    if (this.entries.length === 0) {
      return [new PlaceholderItem('No audit entries in the last 24 hours')];
    }
    return this.entries.map(e => new AuditTreeItem(e));
  }
}

class AuditTreeItem extends vscode.TreeItem {
  constructor(readonly entry: AuditEntry) {
    super(entry.event.action, vscode.TreeItemCollapsibleState.None);

    const isSuccess = entry.event.outcome === 'SUCCESS';
    this.description = `${entry.event.actor} · ${entry.current_hash.slice(0, 12)}`;
    this.tooltip = new vscode.MarkdownString(
      `**Action:** \`${entry.event.action}\`\n\n` +
      `**Actor:** ${entry.event.actor}\n\n` +
      `**Target:** ${entry.event.target_system}\n\n` +
      `**Outcome:** ${entry.event.outcome}\n\n` +
      `**Time:** ${entry.event.timestamp}\n\n` +
      `**Hash:** \`${entry.current_hash}\`\n\n` +
      `**Previous:** \`${entry.previous_hash}\``
    );
    this.iconPath = isSuccess
      ? new vscode.ThemeIcon('check', new vscode.ThemeColor('testing.iconPassed'))
      : new vscode.ThemeIcon('x', new vscode.ThemeColor('testing.iconFailed'));

    this.command = {
      command: 'gavel.openAuditEntry',
      title: 'Open Entry',
      arguments: [entry],
    };
  }
}

class PlaceholderItem extends vscode.TreeItem {
  constructor(message: string) {
    super(message, vscode.TreeItemCollapsibleState.None);
    this.iconPath = new vscode.ThemeIcon('info');
  }
}
