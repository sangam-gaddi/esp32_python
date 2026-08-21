/* Overview page: polls /api/dashboard/summary and paints what the device
 * actually reported. When a value is absent it stays an em dash -- there is no
 * placeholder telemetry anywhere in this file.
 */

let currentDeviceId = null;

function renderDevice(dev) {
  const kv = document.getElementById('d-kv');
  const pill = document.getElementById('d-pill');

  if (!dev) {
    pill.className = 'pill';
    pill.textContent = 'NO DEVICE';
    kv.innerHTML = `<dt>Status</dt><dd>No ESP32 has ever sent a heartbeat.</dd>
      <dt>Expected</dt><dd class="mono">POST /api/device/heartbeat</dd>`;
    document.querySelectorAll('[data-cmd]').forEach(b => { b.disabled = true; });
    return;
  }

  currentDeviceId = dev.device_id;
  const cls = SOTA.statusClass(dev.status);
  pill.className = `pill ${cls}`;
  pill.textContent = dev.status;

  const rows = [
    ['Device ID', SOTA.val(dev.device_id)],
    ['IP address', SOTA.val(dev.ip)],
    ['Wi-Fi', dev.wifi_ssid ? `${SOTA.esc(dev.wifi_ssid)} &nbsp;<span class="hint">RSSI ${SOTA.val(dev.wifi_rssi)} dBm</span>` : SOTA.val(dev.wifi_rssi, ' dBm')],
    ['Firmware', SOTA.val(dev.firmware_version)],
    ['Security version', SOTA.val(dev.security_version)],
    ['Partition', dev.partition ? `${SOTA.esc(dev.partition)} <span class="hint">${SOTA.val(dev.partition_addr)}</span>` : '&mdash;'],
    ['Free heap', SOTA.bytes(dev.free_heap)],
    ['Min free heap', SOTA.bytes(dev.min_free_heap)],
    ['Uptime', SOTA.duration(dev.uptime_s)],
    ['Chip', dev.chip_model ? `${SOTA.esc(dev.chip_model)} rev ${SOTA.val(dev.chip_revision)}, ${SOTA.val(dev.chip_cores)} core(s)` : '&mdash;'],
    ['Flash', SOTA.bytes(dev.flash_size)],
    ['MAC', SOTA.val(dev.mac)],
    ['ESP-IDF', SOTA.val(dev.idf_version)],
    ['Build', SOTA.val(dev.build_time)],
    ['App id', SOTA.val(dev.app_version)],
    ['OTA state', SOTA.val(dev.ota_state)],
    ['OTA checks', `${SOTA.val(dev.ota_checks)} <span class="hint">rejections ${SOTA.val(dev.ota_rejections)}</span>`],
    ['Last heartbeat', dev.status === 'ONLINE'
      ? `${SOTA.ago(dev.seconds_since_heartbeat)}`
      : `<span style="color:var(--warn)">${SOTA.ago(dev.seconds_since_heartbeat)}</span>`],
    ['Queued commands', SOTA.val(dev.pending_commands)],
  ];
  if (dev.last_error) rows.push(['Last error', SOTA.val(dev.last_error)]);

  kv.innerHTML = rows.map(([k, v]) => `<dt>${k}</dt><dd>${v}</dd>`).join('');
  document.querySelectorAll('[data-cmd]').forEach(b => { b.disabled = false; });
}

function renderFirmware(data) {
  const pill = document.getElementById('f-pill');
  const body = document.getElementById('f-body');
  const dev = data.device;
  const up = data.update;

  if (!data.server.latest_version) {
    pill.className = 'pill';
    pill.textContent = 'NONE';
    body.innerHTML = `<div class="empty">No package is published.<br>
      Build one on the <a href="/firmware">Firmware</a> page.</div>`;
    return;
  }

  if (up) {
    pill.className = 'pill info';
    pill.textContent = 'UPDATE AVAILABLE';
    body.innerHTML = `
      <dl class="kv">
        <dt>Current</dt><dd>${SOTA.val(up.current)}</dd>
        <dt>Available</dt><dd style="color:var(--accent)">${SOTA.val(up.available)}</dd>
        <dt>Security</dt><dd>${SOTA.val(up.security_version)}</dd>
        <dt>Package</dt><dd>${SOTA.bytes(up.package_size)}</dd>
        <dt>Firmware</dt><dd>${SOTA.bytes(up.firmware_size)}</dd>
        <dt>Built</dt><dd>${SOTA.val(up.built)}</dd>
      </dl>
      <div class="btn-row" style="margin-top:16px;">
        <button class="btn sm" id="btn-details">View details</button>
        <button class="btn sm primary" data-cmd="START_OTA">Trigger OTA</button>
      </div>`;
    document.getElementById('btn-details').addEventListener('click', () => {
      SOTA.modal(`Package ${up.file}`, `
        <dl class="kv">
          <dt>File</dt><dd>${SOTA.val(up.file)}</dd>
          <dt>Firmware version</dt><dd>${SOTA.val(up.available)}</dd>
          <dt>Security version</dt><dd>${SOTA.val(up.security_version)}</dd>
          <dt>Package size</dt><dd>${SOTA.bytes(up.package_size)}</dd>
          <dt>Firmware size</dt><dd>${SOTA.bytes(up.firmware_size)}</dd>
          <dt>Ascon-Hash256</dt><dd>${SOTA.val(up.firmware_hash)}</dd>
          <dt>Built</dt><dd>${SOTA.val(up.built)}</dd>
        </dl>
        <p class="hint" style="margin-top:14px;">
          The header shown here is the untrusted server-side view. Every value
          that matters is re-read from the signed header on the device, where
          the Ed25519 signature, the Ascon-AEAD128 tag and the Ascon-Hash256
          digest are enforced before the boot partition is switched.
        </p>`);
    });
    wireCommandButtons();
    return;
  }

  pill.className = 'pill ok';
  pill.textContent = dev ? 'UP TO DATE' : 'PUBLISHED';
  body.innerHTML = `
    <dl class="kv">
      <dt>Device</dt><dd>${dev ? SOTA.val(dev.firmware_version) : '&mdash;'}</dd>
      <dt>Published</dt><dd>${SOTA.val(data.server.latest_version)}</dd>
      <dt>Packages</dt><dd>${SOTA.val(data.server.published_packages)} published,
        ${SOTA.val(data.server.staged_packages)} staged</dd>
    </dl>
    <div class="hint" style="margin-top:14px;">
      ${dev ? 'The device is running the newest published firmware version.'
            : 'Waiting for a device to report its version.'}
    </div>`;
}

function renderCrypto(items) {
  document.getElementById('c-body').innerHTML = items.map(it => {
    const cls = { ACTIVE: 'ok', ENFORCED: 'ok', PRESENT: 'ok',
                  REPORTED: 'info', MISSING: 'alert' }[it.state] || '';
    return `<div class="event">
      <div class="body" style="flex:1">
        <b>${SOTA.esc(it.name)}</b>
        <div class="detail">${SOTA.esc(it.detail)}</div>
      </div>
      <span class="pill ${cls}" style="align-self:center">${SOTA.esc(it.state)}</span>
    </div>`;
  }).join('');
}

function renderProgress(data) {
  const dev = data.device;
  const body = document.getElementById('p-body');
  const state = document.getElementById('p-state');

  if (!dev) {
    state.textContent = 'no device';
    body.innerHTML = `<div class="empty">No telemetry. An OTA cycle is shown
      here only while the device is actually reporting one.</div>`;
    return;
  }

  state.textContent = `state: ${dev.ota_state || 'unknown'}`;

  if (!dev.ota_active) {
    body.innerHTML = `<div class="empty">
      No OTA update is running.<br>
      <span class="hint">Device state: ${SOTA.esc(dev.ota_state || 'unknown')}
      &middot; last heartbeat ${SOTA.ago(dev.seconds_since_heartbeat)}</span>
    </div>`;
    return;
  }

  const pct = dev.ota_percent;
  const hasBytes = dev.ota_total > 0;
  body.innerHTML = `
    <div style="display:flex; justify-content:space-between; align-items:baseline; margin-bottom:8px;">
      <div class="stat-value">${hasBytes ? pct + '%' : '&mdash;'}</div>
      <div class="hint">${hasBytes
        ? SOTA.bytes(dev.ota_done) + ' / ' + SOTA.bytes(dev.ota_total)
        : 'byte counters not reported for this stage'}</div>
    </div>
    <div class="bar"><i style="width:${hasBytes ? pct : 0}%"></i></div>
    <div class="grid cols-3" style="margin-top:16px; gap:12px;">
      <div><div class="stat-label">Current state</div>
           <div style="font-family:var(--mono)">${SOTA.val(dev.ota_state)}</div></div>
      <div><div class="stat-label">Free heap</div>
           <div style="font-family:var(--mono)">${SOTA.bytes(dev.free_heap)}</div></div>
      <div><div class="stat-label">Target</div>
           <div style="font-family:var(--mono)">${data.update ? SOTA.val(data.update.available) : SOTA.val(data.server.latest_version)}</div></div>
    </div>`;
}

function renderPipeline(stages) {
  const glyph = { done: '&#10003;', active: '&#9679;', pending: '&#9675;',
                  failed: '&#10007;' };
  document.getElementById('pipe-body').innerHTML = stages.map(s =>
    `<div class="stage ${s.state}">
       <span class="mark">${glyph[s.state]}</span>
       <span>${SOTA.esc(s.label)}</span>
     </div>`).join('');
}

function renderHistory(events) {
  const body = document.getElementById('h-body');
  if (!events.length) {
    body.innerHTML = `<div class="empty">Nothing yet. Activity appears as soon
      as the device checks for an update.</div>`;
    return;
  }
  body.innerHTML = events.map(e => {
    const cls = { SUCCESS: 'ok', OK: 'ok', REJECTED: 'alert', FAILED: 'alert',
                  STARTED: 'info' }[e.result] || '';
    const versions = (e.from_version || e.to_version)
      ? `${SOTA.esc(e.from_version || '?')} &rarr; ${SOTA.esc(e.to_version || '?')}`
      : '';
    return `<div class="event">
      <div class="when">${SOTA.time(e.ts)}</div>
      <div class="body" style="flex:1">
        <b>${SOTA.esc(e.event)}</b> ${versions}
        ${e.reason ? `<div class="detail">${SOTA.esc(e.reason)}</div>` : ''}
      </div>
      <span class="pill ${cls}" style="align-self:center">${SOTA.esc(e.result || '')}</span>
    </div>`;
  }).join('');
}

function renderSecurityEvents(events) {
  const body = document.getElementById('e-body');
  if (!events.length) {
    body.innerHTML = `<div class="empty">No security events recorded.</div>`;
    return;
  }
  const icon = { ok: '&#10003;', warn: '&#9888;', alert: '&#10007;' };
  body.innerHTML = events.map(e => `
    <div class="event">
      <div class="when">${SOTA.time(e.ts)}</div>
      <div class="body">
        <b style="color:var(--${e.severity === 'ok' ? 'ok' : e.severity === 'warn' ? 'warn' : 'alert'})">
          ${icon[e.severity] || ''}</b>
        <b>${SOTA.esc(e.title)}</b>
        <div class="detail">${SOTA.esc(e.kind)}</div>
      </div>
    </div>`).join('');
}

function renderAlerts(data) {
  const zone = document.getElementById('alert-zone');
  const items = [];

  if (data.version_mismatch) {
    const m = data.version_mismatch;
    items.push(`<div class="banner warn">
      <span style="font-size:18px">&#9888;</span>
      <div><b>VERSION MISMATCH</b>
      The installed package declared firmware <b>${SOTA.esc(m.installed_version)}</b>,
      but the device reports <b>${SOTA.esc(m.running_version)}</b> after rebooting.
      <div class="muted" style="margin-top:6px;">${SOTA.esc(m.explanation)}</div></div>
    </div>`);
  }

  if (data.reinstall_loop) {
    const r = data.reinstall_loop;
    items.push(`<div class="banner warn">
      <span style="font-size:18px">&#8635;</span>
      <div><b>STALE PACKAGE &mdash; DEVICE IS REINSTALLING ${SOTA.esc(r.version)}</b>
      Installed once, then downloaded ${r.downloads_since_install} more times
      with no boot report in between.
      <div class="muted" style="margin-top:6px;">${SOTA.esc(r.explanation)}</div></div>
    </div>`);
  }

  const dev = data.device;
  if (dev && dev.status === 'REBOOTING') {
    items.push(`<div class="banner warn">
      <span style="font-size:18px">&#8635;</span>
      <div><b>DEVICE REBOOTING</b>
      Last state was ${SOTA.esc(dev.ota_state)}; the heartbeat stopped
      ${SOTA.ago(dev.seconds_since_heartbeat)}. This is expected right after an
      install.</div></div>`);
  } else if (dev && dev.status === 'OFFLINE') {
    const http = data.device_http_activity;
    const alive = http
      ? `<div class="muted" style="margin-top:6px;">But the OTA endpoints have
         served ${http.requests} request(s) in the last
         ${Math.round(http.window_s / 60)} minute(s), most recently
         ${SOTA.time(http.last)} &mdash; so a device <b>is</b> alive and checking
         for updates. It is running an image without the reporting task, which is
         what an older build looks like.</div>`
      : '';
    items.push(`<div class="banner alert">
      <span style="font-size:18px">&#9679;</span>
      <div><b>ESP32 OFFLINE</b>
      Last seen ${SOTA.ago(dev.seconds_since_heartbeat)} at
      ${SOTA.val(dev.ip)}. Telemetry below is the last reported state, not live.
      ${alive}</div></div>`);
  }

  if (data.server.invalid_packages) {
    items.push(`<div class="banner alert">
      <span style="font-size:18px">&#10007;</span>
      <div><b>${data.server.invalid_packages} UNPARSABLE PACKAGE(S)</b>
      They are never offered to a device. See the
      <a href="/firmware">Firmware</a> page.</div></div>`);
  }

  zone.innerHTML = items.join('');
}

function renderStats(data) {
  const dev = data.device;
  const st = document.getElementById('s-device-status');
  st.textContent = dev ? dev.status : 'NO DEVICE';
  st.style.color = dev
    ? { ONLINE: 'var(--ok)', REBOOTING: 'var(--warn)', OFFLINE: 'var(--alert)' }[dev.status] || ''
    : 'var(--text-faint)';
  document.getElementById('s-device-sub').innerHTML = dev
    ? `${SOTA.esc(dev.device_id)} &middot; ${SOTA.val(dev.ip)} &middot; ${SOTA.ago(dev.seconds_since_heartbeat)}`
    : 'waiting for a heartbeat';

  document.getElementById('s-firmware').innerHTML = dev ? SOTA.val(dev.firmware_version) : '&mdash;';
  document.getElementById('s-firmware-sub').innerHTML = dev
    ? `security version ${SOTA.val(dev.security_version)} &middot; ${SOTA.val(dev.partition)}`
    : 'no device telemetry';

  document.getElementById('s-latest').innerHTML = SOTA.val(data.server.latest_version);
  document.getElementById('s-latest-sub').innerHTML =
    `${data.server.published_packages} published &middot; ${data.server.staged_packages} staged`;

  const bad = (data.security_events || []).filter(e => e.severity === 'alert').length;
  const warn = (data.security_events || []).filter(e => e.severity === 'warn').length;
  const sec = document.getElementById('s-security');
  sec.textContent = bad ? 'ATTENTION' : (warn ? 'EVENTS' : 'SECURE');
  sec.style.color = bad ? 'var(--alert)' : (warn ? 'var(--warn)' : 'var(--ok)');
  document.getElementById('s-security-sub').textContent = bad || warn
    ? `${warn} warning(s), ${bad} alert(s) recorded`
    : 'signature · AEAD · hash · rollback enforced';
}

async function refreshLogs() {
  const data = await SOTA.get('/api/logs');
  const box = document.getElementById('log-body');
  if (!box) return;
  const lines = data.lines.slice(-120);
  box.innerHTML = lines.map(l => `
    <div class="line lv-${SOTA.esc(l.level)}">
      <span class="t">[${new Date(l.ts * 1000).toLocaleTimeString()}]</span>
      <span class="s">${SOTA.esc(l.source)}</span>
      <span class="m">${SOTA.esc(l.message)}</span>
    </div>`).join('') || '<div class="hint">No log lines yet.</div>';
  box.scrollTop = box.scrollHeight;
}

function wireCommandButtons() {
  document.querySelectorAll('[data-cmd]').forEach(btn => {
    if (btn.dataset.wired) return;
    btn.dataset.wired = '1';
    btn.addEventListener('click', async () => {
      if (!currentDeviceId) {
        SOTA.toast('No device has registered yet.', 'warn');
        return;
      }
      const cmd = btn.dataset.cmd;
      if (cmd === 'REBOOT' &&
          !confirm('Queue a REBOOT for ' + currentDeviceId + '?')) return;
      btn.disabled = true;
      try {
        const r = await SOTA.post(`/api/devices/${currentDeviceId}/command`,
                                  { command: cmd });
        SOTA.toast(`<b>${cmd}</b> queued.<br><span class="hint">${SOTA.esc(r.note)}</span>`,
                   'ok');
      } catch (e) {
        SOTA.toast(`Could not queue ${cmd}: ${SOTA.esc(e.message)}`, 'alert');
      } finally {
        btn.disabled = false;
        refresh();
      }
    });
  });
}

async function refresh() {
  try {
    const data = await SOTA.get('/api/dashboard/summary');
    SOTA.paintHeader(data);
    renderAlerts(data);
    renderStats(data);
    renderDevice(data.device);
    renderFirmware(data);
    renderCrypto(data.crypto);
    renderProgress(data);
    renderPipeline(data.pipeline);
    renderHistory(data.history);
    renderSecurityEvents(data.security_events);
    wireCommandButtons();
  } catch (e) {
    SOTA.markOffline();
  }
}

document.getElementById('btn-refresh').addEventListener('click', refresh);
wireCommandButtons();
SOTA.poll(refresh, 2000);
SOTA.poll(refreshLogs, 3000);
