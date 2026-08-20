/* OTA history table. */

function resultPill(result) {
  const cls = { SUCCESS: 'ok', OK: 'ok', STARTED: 'info', REJECTED: 'alert',
                FAILED: 'alert', NO_PACKAGE: 'warn' }[result] || '';
  return `<span class="pill ${cls}">${SOTA.esc(result || '-')}</span>`;
}

async function loadHistory() {
  const data = await SOTA.get('/api/ota/history?limit=300');
  const rows = data.events;

  document.getElementById('h-total').textContent = rows.length;
  document.getElementById('h-ok').textContent =
    rows.filter(r => r.result === 'SUCCESS').length;
  document.getElementById('h-rej').textContent =
    rows.filter(r => r.result === 'REJECTED' || r.result === 'FAILED').length;
  document.getElementById('h-checks').textContent =
    rows.filter(r => r.event === 'CHECK').length;

  document.getElementById('hist-body').innerHTML = rows.length
    ? rows.map(r => `<tr>
        <td class="nowrap">${SOTA.datetime(r.ts)}</td>
        <td class="mono">${SOTA.val(r.device_id)}</td>
        <td><b>${SOTA.val(r.event)}</b></td>
        <td class="mono">${SOTA.val(r.stage)}</td>
        <td class="mono nowrap">${(r.from_version || r.to_version)
          ? `${SOTA.esc(r.from_version || '?')} &rarr; ${SOTA.esc(r.to_version || '?')}`
          : '&mdash;'}</td>
        <td>${SOTA.val(r.security_version)}</td>
        <td>${resultPill(r.result)}</td>
        <td>${SOTA.val(r.reason)}</td>
        <td class="nowrap">${r.duration_ms ? r.duration_ms + ' ms' : '&mdash;'}</td>
      </tr>`).join('')
    : `<tr><td colspan="9" class="empty">No OTA activity recorded yet.</td></tr>`;
}

SOTA.get('/api/dashboard/summary').then(SOTA.paintHeader).catch(() => SOTA.markOffline());
SOTA.poll(loadHistory, 4000);
