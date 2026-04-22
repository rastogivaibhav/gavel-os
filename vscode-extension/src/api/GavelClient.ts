/**
 * GavelClient.ts — Typed HTTP client for the Gavel control plane REST API.
 *
 * All methods map 1:1 to actual endpoints in the control plane.
 * Uses Node's built-in http/https — no fetch polyfill needed in the extension host.
 */

import * as http from 'http';
import * as https from 'https';
import {
  GavelHealthResponse,
  TokenRequest,
  TokenResponse,
  ValidateRequest,
  ValidateResponse,
  LedgerQueryParams,
  LedgerQueryResponse,
  ChainVerifyResponse,
} from './types';

export class GavelClient {
  private token: string | null = null;

  constructor(private readonly baseUrl: string) {
    // Strip trailing slash — mirrors how the enforcer normalises GAVEL_ENGINE_URL
    this.baseUrl = baseUrl.replace(/\/$/, '');
  }

  // ── Auth ──────────────────────────────────────────────────────────────────

  /**
   * POST /auth/token
   * Mints a JWT for the given role and clearance level.
   * Stores the token internally for subsequent requests.
   */
  async mintToken(params: TokenRequest = {}): Promise<string> {
    const body: TokenRequest = {
      role: params.role ?? 'customer',
      clearance_level: params.clearance_level ?? 1,
      tenant_id: params.tenant_id ?? 'default',
      department: params.department ?? 'external',
    };
    const resp = await this.post<TokenResponse>('/auth/token', body);
    this.token = resp.access_token;
    return this.token;
  }

  setToken(token: string): void {
    this.token = token;
  }

  clearToken(): void {
    this.token = null;
  }

  // ── Health ────────────────────────────────────────────────────────────────

  /** GET /health — component health check */
  async health(): Promise<GavelHealthResponse> {
    return this.get<GavelHealthResponse>('/health');
  }

  // ── Policy validation ─────────────────────────────────────────────────────

  /**
   * POST /external/validate
   * Evaluates an action against OPA policy.
   * Requires a valid Bearer token (call mintToken first).
   */
  async validate(req: ValidateRequest): Promise<ValidateResponse> {
    return this.post<ValidateResponse>('/external/validate', req);
  }

  // ── Audit ledger ──────────────────────────────────────────────────────────

  /** POST /audit/ledger — query entries by date range and optional actor */
  async queryLedger(params: LedgerQueryParams): Promise<LedgerQueryResponse> {
    return this.post<LedgerQueryResponse>('/audit/ledger', params);
  }

  /** POST /audit/verify — verify SHA-256 chain integrity */
  async verifyChain(): Promise<ChainVerifyResponse> {
    return this.post<ChainVerifyResponse>('/audit/verify', {});
  }

  // ── HTTP helpers ──────────────────────────────────────────────────────────

  private get<T>(path: string): Promise<T> {
    return this.request<T>('GET', path, undefined);
  }

  private post<T>(path: string, body: unknown): Promise<T> {
    return this.request<T>('POST', path, body);
  }

  private request<T>(method: string, path: string, body: unknown): Promise<T> {
    return new Promise((resolve, reject) => {
      const url = new URL(this.baseUrl + path);
      const isHttps = url.protocol === 'https:';
      const lib = isHttps ? https : http;

      const payload = body !== undefined ? JSON.stringify(body) : undefined;
      const headers: Record<string, string> = {
        'Content-Type': 'application/json',
        'Accept': 'application/json',
      };
      if (this.token) {
        headers['Authorization'] = `Bearer ${this.token}`;
      }
      if (payload) {
        headers['Content-Length'] = Buffer.byteLength(payload).toString();
      }

      const options: http.RequestOptions = {
        hostname: url.hostname,
        port: url.port || (isHttps ? 443 : 80),
        path: url.pathname + url.search,
        method,
        headers,
        timeout: 8000,
      };

      const req = lib.request(options, (res) => {
        let data = '';
        res.on('data', (chunk: string) => (data += chunk));
        res.on('end', () => {
          if (res.statusCode && res.statusCode >= 400) {
            let detail = data;
            try {
              const parsed = JSON.parse(data) as { detail?: string };
              detail = parsed.detail ?? data;
            } catch { /* use raw */ }
            reject(new Error(`HTTP ${res.statusCode} from ${path}: ${detail}`));
            return;
          }
          try {
            resolve(JSON.parse(data) as T);
          } catch {
            reject(new Error(`Invalid JSON from ${path}: ${data.slice(0, 200)}`));
          }
        });
      });

      req.on('error', (err) => reject(new Error(`Request to ${path} failed: ${err.message}`)));
      req.on('timeout', () => {
        req.destroy();
        reject(new Error(`Request to ${path} timed out`));
      });

      if (payload) req.write(payload);
      req.end();
    });
  }
}
