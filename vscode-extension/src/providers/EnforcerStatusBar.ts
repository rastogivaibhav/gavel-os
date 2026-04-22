/**
 * EnforcerStatusBar.ts — Status bar item showing control plane health.
 *
 * Polls GET /health every 30 seconds (matching the enforcer heartbeat interval
 * defined in enforcer/main.go and enforcer/windows_enforcer.go).
 * Clicking the item opens the live monitor panel.
 */

import * as vscode from 'vscode';
import { GavelClient } from '../api/GavelClient';

export class EnforcerStatusBar {
  private readonly item: vscode.StatusBarItem;
  private timer: ReturnType<typeof setInterval> | null = null;

  constructor(private readonly client: GavelClient) {
    this.item = vscode.window.createStatusBarItem(
      vscode.StatusBarAlignment.Right,
      100
    );
    this.item.command = 'gavel.openMonitor';
    this.item.show();
    this.setOffline();
  }

  start(): void {
    this.poll();
    // 30s matches linuxHeartbeatInterval / heartbeatInterval in the enforcer
    this.timer = setInterval(() => this.poll(), 30_000);
  }

  stop(): void {
    if (this.timer) {
      clearInterval(this.timer);
      this.timer = null;
    }
  }

  private async poll(): Promise<void> {
    try {
      const health = await this.client.health();

      if (health.status === 'healthy') {
        this.item.text = '$(shield) Gavel: enforce';
        this.item.backgroundColor = undefined;
        this.item.tooltip = new vscode.MarkdownString(
          `**Gavel Control Plane** — healthy\n\nVersion: ${health.version}\n\nClick to open live monitor`
        );
      } else {
        const degraded = Object.entries(health.components)
          .filter(([, v]) => !['connected', 'loaded', 'ready', 'configured'].includes(v as string))
          .map(([k]) => k)
          .join(', ');
        this.item.text = '$(warning) Gavel: degraded';
        this.item.backgroundColor = new vscode.ThemeColor('statusBarItem.warningBackground');
        this.item.tooltip = new vscode.MarkdownString(
          `**Gavel Control Plane** — degraded\n\nDegraded: ${degraded}\n\nClick to open live monitor`
        );
      }
    } catch {
      this.setOffline();
    }
  }

  private setOffline(): void {
    this.item.text = '$(circle-slash) Gavel: offline';
    this.item.backgroundColor = new vscode.ThemeColor('statusBarItem.errorBackground');
    this.item.tooltip = 'Cannot reach Gavel control plane. Check gavel.controlPlaneUrl setting.';
  }

  dispose(): void {
    this.stop();
    this.item.dispose();
  }
}
