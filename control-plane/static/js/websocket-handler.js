/**
 * WebSocket event stream handler for real-time Live Monitor
 */

const wsHandler = {
  ws: null,
  listeners: new Set(),
  reconnectAttempts: 0,
  maxReconnectAttempts: 5,
  reconnectDelay: 3000,

  async connect() {
    try {
      const protocol = window.location.protocol === 'https:' ? 'wss:' : 'ws:';
      const url = `${protocol}//${window.location.host}/ws/events`;
      this.ws = new WebSocket(url);

      this.ws.onopen = () => {
        console.log('WebSocket connected');
        this.reconnectAttempts = 0;
        this.broadcast({ type: 'connected' });
      };

      this.ws.onmessage = (event) => {
        try { this.broadcast({ type: 'event', data: JSON.parse(event.data) }); }
        catch (e) { console.error('WebSocket parse error:', e); }
      };

      this.ws.onerror = (error) => {
        console.error('WebSocket error:', error);
        this.broadcast({ type: 'error', error });
      };

      this.ws.onclose = () => {
        console.log('WebSocket disconnected');
        this.broadcast({ type: 'disconnected' });
        this.attemptReconnect();
      };
      return true;
    } catch (error) {
      console.error('WebSocket connection failed:', error);
      return false;
    }
  },

  attemptReconnect() {
    if (this.reconnectAttempts >= this.maxReconnectAttempts) {
      console.error('Max reconnection attempts reached');
      return;
    }
    this.reconnectAttempts++;
    const delay = this.reconnectDelay * Math.pow(2, this.reconnectAttempts - 1);
    console.log(`Reconnecting in ${delay}ms...`);
    setTimeout(() => this.connect(), delay);
  },

  onEvent(callback) {
    this.listeners.add(callback);
    return () => this.listeners.delete(callback);
  },

  broadcast(message) {
    this.listeners.forEach(callback => {
      try { callback(message); }
      catch (e) { console.error('Event listener error:', e); }
    });
  },

  send(message) {
    if (this.ws && this.ws.readyState === WebSocket.OPEN) {
      this.ws.send(JSON.stringify(message));
    }
  },

  close() {
    if (this.ws) this.ws.close();
  }
};

document.addEventListener('DOMContentLoaded', () => {
  wsHandler.connect().catch(e => console.error('Initial WS connection failed:', e));
});
