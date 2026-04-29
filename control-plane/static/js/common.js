/**
 * Common utilities — formatting, helpers
 */

function formatTimestamp(isoString) {
  return new Date(isoString).toLocaleString();
}

function formatTimestampRelative(isoString) {
  const date = new Date(isoString), now = new Date(), diff = Math.floor((now - date) / 1000);
  if (diff < 60) return `${diff}s ago`;
  if (diff < 3600) return `${Math.floor(diff / 60)}m ago`;
  if (diff < 86400) return `${Math.floor(diff / 3600)}h ago`;
  return `${Math.floor(diff / 86400)}d ago`;
}

function escapeHtml(unsafe) {
  return unsafe.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#039;');
}

function showNotification(message, type = 'info') {
  const notification = document.createElement('div');
  const bgColor = type === 'error' ? 'bg-error' : type === 'success' ? 'bg-primary' : 'bg-surface-container';
  notification.className = `fixed bottom-4 right-4 px-4 py-2 rounded-lg ${bgColor} text-white text-body-sm shadow-lg z-50`;
  notification.textContent = message;
  document.body.appendChild(notification);
  setTimeout(() => notification.remove(), 3000);
}

function downloadJSON(data, filename) {
  const json = JSON.stringify(data, null, 2);
  const blob = new Blob([json], { type: 'application/json' });
  const url = URL.createObjectURL(blob);
  const a = document.createElement('a');
  a.href = url;
  a.download = filename || 'export.json';
  a.click();
  URL.revokeObjectURL(url);
}
