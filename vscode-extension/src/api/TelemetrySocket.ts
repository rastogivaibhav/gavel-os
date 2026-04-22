/**
 * TelemetrySocket.ts — WebSocket client for /ws/telemetry
 *
 * The control plane broadcasts RuntimeEventEnvelope objects over this socket.
 * Every ALLOW, DENY, AUDIT, agent_detected, and component_health event
 * from every connected enforcer appears here in real time.
 *
 * Authentication: X-API-Key header (API_SECRET_KEY on the control plane).
 * Reconnects automatically on close — mirrors the enforcer heartbeat pattern.
 */

import * as vscode from 'vscode';
import WebSocket from 'ws';
import { RuntimeEventEnvelope } from './types';

export class TelemetrySocket {
  private ws: WebSocket | null = null;
  private reconnectTimer: ReturnType<typeof setTimeout> | null = null;
  private _connected = false;

  private readonly _onEvent = new vscode.EventEmitter<RuntimeEventEnvelope>();
  private readonly _onStatusChange = new vscode.EventEmitter<boolean>();

  /** Fires for every RuntimeEventEnvelope received from the control plane */
  readonly onEvent = this._onEvent.event;

  /** Fires true when connected, false when disconnected */
  readonly onStatusChange = this._onStatusChange.event;

  get connected(): boolean {
    return this._connected;
  }

  constructor(
    private readonly wsUrl: string,   // e.g. ws://localhost:8000/ws/telemetry
    private readonly apiKey: string
  ) {}

  connect(): void {
    if (this.ws?.readyState === WebSocket.OPEN) return;

    try {
      this.ws = new WebSocket(this.wsUrl, {
        headers: { 'X-API-Key': this.apiKey },
        handshakeTimeout: 5000,
      });
    } catch (err) {
      this.scheduleReconnect();
      return;
    }

    this.ws.on('open', () => {
      this._connected = true;
      this._onStatusChange.fire(true);
    });

    this.ws.on('message', (raw: WebSocket.RawData) => {
      try {
        const text = raw.toString();
        const msg = JSON.parse(text) as { type: string; payload: RuntimeEventEnvelope };
        if (msg.payload) {
          this._onEvent.fire(msg.payload);
        }
      } catch {
        // Malformed message — ignore silently
      }
    });

    this.ws.on('close', () => {
      this._connected = false;
      this._onStatusChange.fire(false);
      this.scheduleReconnect();
    });

    this.ws.on('error', () => {
      // error is always followed by close — let close handler reconnect
      this._connected = false;
    });
  }

  disconnect(): void {
    if (this.reconnectTimer) {
      clearTimeout(this.reconnectTimer);
      this.reconnectTimer = null;
    }
    this.ws?.close();
    this.ws = null;
    this._connected = false;
  }

  private scheduleReconnect(): void {
    if (this.reconnectTimer) return;
    // 5 second reconnect — matches the enforcer heartbeat interval
    this.reconnectTimer = setTimeout(() => {
      this.reconnectTimer = null;
      this.connect();
    }, 5000);
  }

  dispose(): void {
    this.disconnect();
    this._onEvent.dispose();
    this._onStatusChange.dispose();
  }
}
