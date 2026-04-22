/**
 * config.ts — Extension settings reader.
 * All settings are declared in package.json contributes.configuration.
 */

import * as vscode from 'vscode';

export interface GavelConfig {
  controlPlaneUrl: string;
  apiKey: string;
  autoConnect: boolean;
  telemetryEnabled: boolean;
  validateOnSave: boolean;
}

export function getConfig(): GavelConfig {
  const cfg = vscode.workspace.getConfiguration('gavel');
  return {
    controlPlaneUrl: cfg.get<string>('controlPlaneUrl', 'http://localhost:18000'),
    apiKey: cfg.get<string>('apiKey', ''),
    autoConnect: cfg.get<boolean>('autoConnect', true),
    telemetryEnabled: cfg.get<boolean>('telemetryEnabled', true),
    validateOnSave: cfg.get<boolean>('validateOnSave', true),
  };
}

/** Convert http:// control plane URL to ws:// for the telemetry socket */
export function toWebSocketUrl(httpUrl: string): string {
  return httpUrl
    .replace(/^http:\/\//, 'ws://')
    .replace(/^https:\/\//, 'wss://')
    .replace(/\/$/, '') + '/ws/telemetry';
}
