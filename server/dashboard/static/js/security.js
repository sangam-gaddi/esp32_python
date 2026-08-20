/* Security page: crypto status, the attack lab, and the event log. */

const labResults = {};
let labTests = [];

function labCard(t) {
  const r = labResults[t.key];
  let cls = '', pill = '<span class="pill">NOT RUN</span>', detail = '';

  if (r === 'running') {
    cls = 'running';
    pill = '<span class="pill info"><span class="spin">&#9696;</span> RUNNING</span>';
  } else if (r) {
    if (r.status === 'PROTECTED' || r.status === 'VERIFIED') {
      cls = 'protected';
      pill = `<span class="pill ok">&#9679; ${SOTA.esc(r.status)}</span>`;
    } else {
      cls = 'vulnerable';
      pill = `<span class="pill alert">&#9679; ${SOTA.esc(r.status)}</span>`;
    }
    detail = `<div class="hint">${SOTA.esc(r.headline)}</div>
      <div class="hint mono">${SOTA.esc(r.result_line)}</div>`;
  }

  return `<div class="lab-card ${cls}">
    <div style="display:flex; justify-content:space-between; gap:10px; align-items:flex-start;">
      <div class="name">${SOTA.esc(t.label)}</div>${pill}
    </div>
    <div class="why">Defended by: ${SOTA.esc(t.defended_by)}<br>
      <span class="mono">mode ${SOTA.esc(t.mode)}</span></div>
    ${detail}
    <div class="btn-row">
      <button class="btn sm" data-run="${SOTA.esc(t.key)}">Run test</button>
      ${r && r !== 'running' ? `<button class="btn sm ghost" data-out="${SOTA.esc(t.key)}">Output</button>` : ''}
    </div>
  </div>`;
}

function paintLab() {
  document.getElementById('lab-grid').innerHTML = labTests.map(labCard).join('');
  document.querySelectorAll('[data-run]').forEach(b =>
    b.addEventListener('click', () => runTest(b.dataset.run)));
  document.querySelectorAll('[data-out]').forEach(b =>
    b.addEventListener('click', () => {
      const r = labResults[b.dataset.out];
      SOTA.modal(`${r.label} -- ${r.status}`, `
        <div class="banner ${r.passed ? 'ok' : 'alert'}" style="margin-bottom:14px">
          <span>${r.passed ? '&#10003;' : '&#10007;'}</span>
          <div><b>TEST RESULT: ${SOTA.esc(r.verdict)}</b>${SOTA.esc(r.headline)}
          <div class="muted">${SOTA.esc(r.base_note)} &middot; ${SOTA.esc(r.tamper_note)}</div></div>
        </div>
        <pre>${SOTA.esc(r.output)}</pre>`);
    }));
  paintProtection();
}

function paintProtection() {
  const done = labTests.filter(t => labResults[t.key] && labResults[t.key] !== 'running');
  const body = document.getElementById('prot-body');
  if (!done.length) {
    body.innerHTML = `<div class="empty">No lab test has been run in this
      session. Run one below to see live results.</div>`;
    return;
  }
  body.innerHTML = `<div class="event-list">` + done.map(t => {
    const r = labResults[t.key];
    const ok = r.status === 'PROTECTED' || r.status === 'VERIFIED';
    return `<div class="event">
      <div class="body" style="flex:1"><b>${SOTA.esc(t.label)}</b>
        <div class="detail">${SOTA.esc(r.defended_by)} &middot; ${r.duration_ms} ms</div>
      </div>
      <span class="pill ${ok ? 'ok' : 'alert'}" style="align-self:center">
        &#9679; ${SOTA.esc(r.status)}</span>
    </div>`;
  }).join('') + `</div>`;
}

async function runTest(key) {
  labResults[key] = 'running';
  paintLab();
  try {
    const r = await SOTA.post(`/api/security/lab/${key}`);
    labResults[key] = r;
    SOTA.toast(`<b>${SOTA.esc(r.label)}</b>: ${SOTA.esc(r.status)}<br>
      <span class="hint">${SOTA.esc(r.headline)}</span>`,
      r.passed ? 'ok' : 'alert');
  } catch (e) {
    delete labResults[key];
    SOTA.toast(`Test failed to run: ${SOTA.esc(e.message)}`, 'alert');
  }
  paintLab();
  loadEvents();
}

async function runAll() {
  const btn = document.getElementById('btn-run-all');
  btn.disabled = true;
  for (const t of labTests) {
    await runTest(t.key);
  }
  btn.disabled = false;
}

async function loadLab() {
  const data = await SOTA.get('/api/security/lab');
  labTests = data.tests;
  const pill = document.getElementById('lab-keys');
  pill.className = `pill ${data.keys_present ? 'ok' : 'alert'}`;
  pill.textContent = data.keys_present ? 'KEYS AVAILABLE' : 'KEYS MISSING -- LAB DISABLED';
  document.getElementById('btn-run-all').disabled = !data.keys_present;
  paintLab();
}

async function loadEvents() {
  const data = await SOTA.get('/api/security/events?limit=200');

  document.getElementById('c-body').innerHTML = data.crypto.map(it => {
    const cls = { ACTIVE: 'ok', ENFORCED: 'ok', PRESENT: 'ok',
                  REPORTED: 'info', MISSING: 'alert' }[it.state] || '';
    return `<div class="event"><div class="body" style="flex:1">
      <b>${SOTA.esc(it.name)}</b><div class="detail">${SOTA.esc(it.detail)}</div></div>
      <span class="pill ${cls}" style="align-self:center">${SOTA.esc(it.state)}</span>
    </div>`;
  }).join('');

  const sev = { ok: 'ok', warn: 'warn', alert: 'alert' };
  document.getElementById('ev-body').innerHTML = data.events.length
    ? data.events.map(e => `<tr>
        <td class="nowrap">${SOTA.datetime(e.ts)}</td>
        <td><span class="pill ${sev[e.severity] || ''}">${SOTA.esc(e.severity)}</span></td>
        <td class="mono">${SOTA.esc(e.kind)}</td>
        <td>${SOTA.esc(e.title)}</td>
        <td class="hint">${SOTA.esc(e.detail)}</td>
        <td class="mono">${SOTA.esc(e.source)}</td>
      </tr>`).join('')
    : `<tr><td colspan="6" class="empty">No security events recorded yet.</td></tr>`;
}

document.getElementById('btn-run-all').addEventListener('click', runAll);
SOTA.get('/api/dashboard/summary').then(SOTA.paintHeader).catch(() => SOTA.markOffline());
loadLab();
SOTA.poll(loadEvents, 5000);
