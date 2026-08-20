/* Shared helpers for every dashboard page.
 *
 * Rule that shapes all of this: nothing is rendered unless the backend actually
 * reported it. Missing telemetry renders as an em dash, never as a plausible
 * looking number.
 */

const SOTA = {
  async get(url) {
    const r = await fetch(url, { headers: { 'Accept': 'application/json' } });
    const body = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(body.error || `HTTP ${r.status}`);
    return body;
  },

  async post(url, payload) {
    const r = await fetch(url, {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify(payload || {}),
    });
    const body = await r.json().catch(() => ({}));
    if (!r.ok) throw new Error(body.error || `HTTP ${r.status}`);
    return body;
  },

  /* A value that was never reported must look absent, not zero. */
  val(v, suffix = '') {
    if (v === null || v === undefined || v === '') return '&mdash;';
    return `${SOTA.esc(v)}${suffix}`;
  },

  esc(s) {
    return String(s).replace(/[&<>"']/g, c => ({
      '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;',
    }[c]));
  },

  bytes(n) {
    if (n === null || n === undefined || n === '') return '&mdash;';
    n = Number(n);
    if (n < 1024) return `${n} B`;
    if (n < 1024 * 1024) return `${(n / 1024).toFixed(1)} KB`;
    return `${(n / 1048576).toFixed(2)} MB`;
  },

  duration(seconds) {
    if (seconds === null || seconds === undefined) return '&mdash;';
    seconds = Math.floor(Number(seconds));
    const d = Math.floor(seconds / 86400);
    const h = Math.floor((seconds % 86400) / 3600);
    const m = Math.floor((seconds % 3600) / 60);
    const s = seconds % 60;
    if (d) return `${d}d ${h}h ${m}m`;
    if (h) return `${h}h ${m}m ${s}s`;
    if (m) return `${m}m ${s}s`;
    return `${s}s`;
  },

  time(ts) {
    if (!ts) return '&mdash;';
    return new Date(ts * 1000).toLocaleTimeString();
  },

  datetime(ts) {
    if (!ts) return '&mdash;';
    const d = new Date(ts * 1000);
    return d.toLocaleDateString(undefined, {
      day: '2-digit', month: 'short', year: 'numeric',
    }) + ' ' + d.toLocaleTimeString();
  },

  ago(seconds) {
    if (seconds === null || seconds === undefined) return 'never';
    if (seconds < 2) return 'just now';
    if (seconds < 60) return `${Math.floor(seconds)} seconds ago`;
    if (seconds < 3600) return `${Math.floor(seconds / 60)} minutes ago`;
    return `${Math.floor(seconds / 3600)} hours ago`;
  },

  statusClass(status) {
    return { ONLINE: 'ok', REBOOTING: 'warn', OFFLINE: 'alert' }[status] || '';
  },

  toast(message, kind = '') {
    const host = document.getElementById('toast-host');
    if (!host) return;
    const el = document.createElement('div');
    el.className = `toast ${kind}`;
    el.innerHTML = message;
    host.appendChild(el);
    setTimeout(() => {
      el.style.transition = 'opacity .3s';
      el.style.opacity = '0';
      setTimeout(() => el.remove(), 320);
    }, kind === 'alert' ? 9000 : 5200);
  },

  modal(title, innerHtml) {
    const host = document.getElementById('modal-host');
    host.innerHTML = `
      <div class="modal-backdrop" data-close="1">
        <div class="modal">
          <div class="card-head">
            <div class="card-title">${SOTA.esc(title)}</div>
            <button class="btn sm ghost" data-close="1">Close</button>
          </div>
          ${innerHtml}
        </div>
      </div>`;
    host.querySelectorAll('[data-close]').forEach(el => {
      el.addEventListener('click', ev => {
        if (ev.target === el) host.innerHTML = '';
      });
    });
  },

  closeModal() { document.getElementById('modal-host').innerHTML = ''; },

  /* Header status chips, shared by every page. */
  paintHeader(summary) {
    const sDot = document.getElementById('hdr-server-dot');
    const sTxt = document.getElementById('hdr-server');
    const dDot = document.getElementById('hdr-device-dot');
    const dTxt = document.getElementById('hdr-device');
    if (sTxt) {
      sTxt.textContent = 'OTA SERVER ONLINE';
      sDot.className = 'dot ok live';
    }
    if (!dTxt) return;
    const dev = summary && summary.device;
    if (!dev) {
      dTxt.textContent = 'NO ESP32 REGISTERED';
      dDot.className = 'dot';
      return;
    }
    dTxt.textContent = `ESP32 ${dev.status}`;
    dDot.className = `dot ${SOTA.statusClass(dev.status)}${dev.status === 'ONLINE' ? ' live' : ''}`;
  },

  markOffline() {
    const sDot = document.getElementById('hdr-server-dot');
    const sTxt = document.getElementById('hdr-server');
    if (sTxt) { sTxt.textContent = 'OTA SERVER UNREACHABLE'; sDot.className = 'dot alert'; }
  },

  poll(fn, intervalMs) {
    const tick = async () => {
      try { await fn(); } catch (e) { /* handled by the caller's own UI */ }
    };
    tick();
    return setInterval(tick, intervalMs);
  },
};

setInterval(() => {
  const el = document.getElementById('foot-clock');
  if (el) el.textContent = new Date().toLocaleTimeString();
}, 1000);
