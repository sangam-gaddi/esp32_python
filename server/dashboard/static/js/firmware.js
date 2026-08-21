/* Firmware page: upload -> package -> publish.
 *
 * The browser sends a .bin, a version and a security version. It never sends,
 * receives or stores key material: the packaging tool reads keys/ server-side.
 */

const PKG_STAGES = [
  ['load', 'Firmware loaded'],
  ['hash', 'Ascon-Hash256 generated'],
  ['encrypt', 'Ascon-AEAD128 encryption'],
  ['sign', 'Ed25519 signature generated'],
  ['write', 'OTA package generated'],
  ['verify', 'Self-verification (signature + tag + hash)'],
];

function stageList(states, note) {
  const glyph = { done: '&#10003;', active: '&#9679;', pending: '&#9675;',
                  failed: '&#10007;' };
  return `<div class="pipeline">` + PKG_STAGES.map(([k, label]) => {
    const st = states[k] || 'pending';
    return `<div class="stage ${st}"><span class="mark">${glyph[st]}</span>
            <span>${label}</span></div>`;
  }).join('') + `</div>` + (note ? `<div style="margin-top:10px">${note}</div>` : '');
}

async function loadInventory() {
  const data = await SOTA.get('/api/firmware');

  const pill = document.getElementById('keys-pill');
  pill.className = `pill ${data.keys_present ? 'ok' : 'alert'}`;
  pill.textContent = data.keys_present ? 'SIGNING KEYS PRESENT' : 'KEYS MISSING';
  document.getElementById('btn-package').disabled = !data.keys_present;

  // uploads
  const sel = document.getElementById('pkg-source');
  const chosen = sel.value;
  sel.innerHTML = data.uploads.length
    ? data.uploads.map(u => `<option value="${SOTA.esc(u.file)}">${SOTA.esc(u.file)} (${SOTA.bytes(u.size)})</option>`).join('')
    : '<option value="">no image uploaded yet</option>';
  if (chosen) sel.value = chosen;

  document.getElementById('up-body').innerHTML = data.uploads.length
    ? data.uploads.map(u => `<tr>
        <td class="mono">${SOTA.esc(u.file)}</td>
        <td>${SOTA.bytes(u.size)}</td>
        <td>${SOTA.datetime(u.modified)}</td></tr>`).join('')
    : '<tr><td colspan="3" class="empty">No images uploaded.</td></tr>';

  // packages
  const rows = data.packages;
  document.getElementById('rel-body').innerHTML = rows.length
    ? rows.map(p => {
        if (!p.valid) {
          return `<tr>
            <td class="mono">${SOTA.esc(p.file)}</td>
            <td colspan="6" style="color:var(--alert)">unparsable: ${SOTA.esc(p.error)}</td>
            <td><span class="pill alert">REJECTED</span></td><td></td></tr>`;
        }
        const status = p.published
          ? '<span class="pill ok">PUBLISHED</span>'
          : '<span class="pill warn">STAGED</span>';
        const action = p.published
          ? `<button class="btn sm ghost" data-unpublish="${SOTA.esc(p.file)}">Unpublish</button>`
          : `<button class="btn sm primary" data-publish="${SOTA.esc(p.file)}">Publish update</button>`;
        return `<tr>
          <td class="mono">${SOTA.esc(p.file)}</td>
          <td><b>${SOTA.esc(p.firmware_version)}</b></td>
          <td>${SOTA.esc(p.security_version)}</td>
          <td>${SOTA.bytes(p.firmware_size)}</td>
          <td>${SOTA.bytes(p.package_size)}</td>
          <td class="nowrap">${SOTA.esc(p.built)}</td>
          <td class="mono">${SOTA.esc(p.firmware_hash.slice(0, 16))}&hellip;</td>
          <td>${status}</td>
          <td class="nowrap">
            <button class="btn sm" data-details="${SOTA.esc(p.file)}">Details</button>
            ${action}
          </td></tr>`;
      }).join('')
    : '<tr><td colspan="9" class="empty">No packages yet.</td></tr>';

  wireRowButtons(rows);
}

function wireRowButtons(rows) {
  document.querySelectorAll('[data-publish]').forEach(b => {
    b.addEventListener('click', async () => {
      const file = b.dataset.publish;
      b.disabled = true;
      try {
        await SOTA.post(`/api/firmware/${encodeURIComponent(file)}/publish`);
        SOTA.toast(`<b>${SOTA.esc(file)}</b> published &mdash; devices are now offered it.`, 'ok');
      } catch (e) {
        SOTA.toast(`Publish failed: ${SOTA.esc(e.message)}`, 'alert');
      } finally { loadInventory(); }
    });
  });

  document.querySelectorAll('[data-unpublish]').forEach(b => {
    b.addEventListener('click', async () => {
      const file = b.dataset.unpublish;
      if (!confirm(`Withdraw ${file} from the OTA server?`)) return;
      b.disabled = true;
      try {
        await SOTA.post(`/api/firmware/${encodeURIComponent(file)}/unpublish`);
        SOTA.toast(`<b>${SOTA.esc(file)}</b> withdrawn (kept in staging).`, 'warn');
      } catch (e) {
        SOTA.toast(`Unpublish failed: ${SOTA.esc(e.message)}`, 'alert');
      } finally { loadInventory(); }
    });
  });

  document.querySelectorAll('[data-details]').forEach(b => {
    b.addEventListener('click', () => {
      const p = rows.find(r => r.file === b.dataset.details);
      if (!p) return;
      SOTA.modal(p.file, p.valid ? `
        <dl class="kv">
          <dt>Format version</dt><dd>${SOTA.val(p.format_version)}</dd>
          <dt>Firmware version</dt><dd>${SOTA.val(p.firmware_version)}</dd>
          <dt>Security version</dt><dd>${SOTA.val(p.security_version)}</dd>
          <dt>Firmware size</dt><dd>${SOTA.bytes(p.firmware_size)}</dd>
          <dt>Package size</dt><dd>${SOTA.bytes(p.package_size)}</dd>
          <dt>Built</dt><dd>${SOTA.val(p.built)}</dd>
          <dt>Ascon-Hash256</dt><dd>${SOTA.val(p.firmware_hash)}</dd>
          <dt>Ascon nonce</dt><dd>${SOTA.val(p.nonce)}</dd>
          <dt>Ascon-AEAD128 tag</dt><dd>${SOTA.val(p.auth_tag)}</dd>
          <dt>Ed25519 signature</dt><dd>${SOTA.val(p.signature_head)}&hellip;</dd>
          <dt>Structure</dt><dd>parsed OK &middot; signature field present:
            ${p.has_signature ? 'yes' : 'no'} &middot; tag present:
            ${p.has_auth_tag ? 'yes' : 'no'}</dd>
          <dt>Status</dt><dd>${p.published ? 'published' : 'staged (not offered to devices)'}</dd>
        </dl>
        <p class="hint" style="margin-top:14px;">
          This server holds no keys, so it can only parse the header &mdash; it
          deliberately cannot verify the signature. The ESP32 does that, against
          a public key compiled into its own image.
        </p>` : `<p style="color:var(--alert)">${SOTA.esc(p.error)}</p>`);
    });
  });
}

document.getElementById('upload-form').addEventListener('submit', async ev => {
  ev.preventDefault();
  const input = document.getElementById('bin-file');
  const btn = document.getElementById('btn-upload');
  const out = document.getElementById('upload-result');
  if (!input.files.length) return;

  const fd = new FormData();
  fd.append('file', input.files[0]);
  btn.disabled = true;
  out.innerHTML = '<span class="hint">Uploading&hellip;</span>';
  try {
    const r = await fetch('/api/firmware/upload', { method: 'POST', body: fd });
    const body = await r.json();
    if (!r.ok) throw new Error(body.error || `HTTP ${r.status}`);
    out.innerHTML = `<div class="banner ok"><span>&#10003;</span><div>
      <b>UPLOAD SUCCESSFUL</b>${SOTA.esc(body.file)} &middot; ${SOTA.bytes(body.size)}
      ${body.looks_like_esp32_image ? '' :
        '<div class="muted">Warning: this file does not start with 0xE9, so it may not be an ESP32 application image. The device will reject a non-bootable image at install time.</div>'}
      </div></div>`;
    SOTA.toast('Firmware uploaded.', 'ok');
    input.value = '';
    loadInventory();
  } catch (e) {
    out.innerHTML = `<div class="banner alert"><span>&#10007;</span><div>
      <b>UPLOAD FAILED</b>${SOTA.esc(e.message)}</div></div>`;
  } finally { btn.disabled = false; }
});

document.getElementById('pkg-form').addEventListener('submit', async ev => {
  ev.preventDefault();
  const source = document.getElementById('pkg-source').value;
  const version = document.getElementById('pkg-version').value.trim();
  const security = document.getElementById('pkg-security').value;
  const btn = document.getElementById('btn-package');
  const out = document.getElementById('pkg-stages');

  if (!source) { SOTA.toast('Upload a .bin first.', 'warn'); return; }

  btn.disabled = true;
  out.innerHTML = stageList({ load: 'active' },
    '<span class="hint">Running tools/create_ota_package.py&hellip;</span>');

  try {
    const r = await SOTA.post('/api/firmware/package',
      { file: source, version, security_version: Number(security) });
    const states = {};
    r.stages.forEach(s => { states[s.key] = s.ok ? 'done' : 'failed'; });
    out.innerHTML = stageList(states, `
      <div class="banner ok" style="margin-top:12px"><span>&#10003;</span><div>
        <b>PACKAGE READY</b>
        <span class="mono">${SOTA.esc(r.filename)}</span><br>
        <span class="muted">Version ${SOTA.esc(r.version)} &middot;
        security ${SOTA.esc(r.security_version)} &middot;
        package valid &#10003; &middot; built in ${r.duration_ms} ms</span>
        <div class="muted mono" style="margin-top:6px; word-break:break-all">
          Ascon-Hash256 ${SOTA.esc(r.firmware_hash)}</div>
        <div style="margin-top:10px">
          <button class="btn sm primary" data-publish="${SOTA.esc(r.filename)}">Publish update</button>
        </div>
      </div></div>`);
    SOTA.toast('Package created and self-verified.', 'ok');
    document.querySelectorAll('[data-publish]').forEach(b =>
      b.addEventListener('click', async () => {
        try {
          await SOTA.post(`/api/firmware/${encodeURIComponent(b.dataset.publish)}/publish`);
          SOTA.toast('Published.', 'ok');
        } catch (e) { SOTA.toast(`Publish failed: ${SOTA.esc(e.message)}`, 'alert'); }
        loadInventory();
      }));
    loadInventory();
  } catch (e) {
    out.innerHTML = `<div class="banner alert"><span>&#10007;</span><div>
      <b>PACKAGE CREATION FAILED</b>${SOTA.esc(e.message)}</div></div>`;
  } finally { btn.disabled = false; }
});

SOTA.get('/api/dashboard/summary').then(SOTA.paintHeader).catch(() => SOTA.markOffline());
SOTA.poll(loadInventory, 5000);
