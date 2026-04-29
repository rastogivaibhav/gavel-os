/**
 * API Client — Wrapper around Gavel OS Control Plane endpoints
 */

const apiClient = {
  baseUrl: '/api',
  token: null,

  async init() {
    this.token = await getAuthToken();
  },

  async request(endpoint, options = {}) {
    const headers = { 'Content-Type': 'application/json', ...options.headers };
    if (this.token) headers['Authorization'] = `Bearer ${this.token}`;

    const response = await fetch(`${this.baseUrl}${endpoint}`, { ...options, headers });
    if (!response.ok) {
      if (response.status === 401) window.location.href = '/auth/login';
      throw new Error(`HTTP ${response.status}`);
    }
    return response.json();
  },

  async getHealth() {
    try { return await fetch('/health').then(r => r.json()); }
    catch { return { status: 'unknown', components: {} }; }
  },

  async getAuditEvents(filters = {}) {
    const query = new URLSearchParams(filters);
    return this.request(`/audit/ledger?${query}`);
  },

  async getPolicies() {
    return this.request('/policies');
  },

  async validatePolicy(rego_code) {
    return this.request('/policies/validate', { method: 'POST', body: JSON.stringify({ code: rego_code }) });
  },

  async testPolicy(proposal) {
    return this.request('/external/tool/verdict', { method: 'POST', body: JSON.stringify(proposal) });
  },

  connectWebSocket(onMessage, onError) {
    const protocol = window.location.protocol === 'https:' ? 'wss' : 'ws';
    const ws = new WebSocket(`${protocol}://${window.location.host}/ws/events`);
    ws.onmessage = (event) => {
      try { onMessage(JSON.parse(event.data)); }
      catch (e) { console.error('WebSocket parse error:', e); }
    };
    ws.onerror = (error) => { console.error('WebSocket error:', error); if (onError) onError(error); };
    return ws;
  }
};

(async () => { try { await apiClient.init(); } catch (e) { console.warn('API client init failed:', e); } })();
