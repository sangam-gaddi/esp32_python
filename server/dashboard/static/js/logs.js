/* Live log viewer over Server-Sent Events, with a polling fallback. */

let filter = 'ALL';
let lines = [];
let lastId = 0;

function paint() {
  const term = document.getElementById('term');
  const shown = filter === 'ALL' ? lines : lines.filter(l => l.source === filter);
  term.innerHTML = shown.slice(-800).map(l => `
    <div class="line lv-${SOTA.esc(l.level)}">
      <span class="t">[${new Date(l.ts * 1000).toLocaleTimeString()}]</span>
      <span class="s">${SOTA.esc(l.source)}</span>
      <span class="m">${SOTA.esc(l.message)}</span>
    </div>`).join('') || '<div class="hint">No lines match this filter.</div>';
  if (document.getElementById('auto-scroll').checked) {
    term.scrollTop = term.scrollHeight;
  }
}

function append(newLines) {
  if (!newLines.length) return;
  lines = lines.concat(newLines).slice(-1000);
  lastId = lines[lines.length - 1].id;
  paint();
}

function status(text, cls) {
  const el = document.getElementById('log-status');
  el.textContent = text;
  el.style.color = cls === 'ok' ? 'var(--ok)'
    : cls === 'alert' ? 'var(--alert)' : '';
}

async function start() {
  const initial = await SOTA.get('/api/logs');
  lines = initial.lines;
  lastId = initial.last_id;
  paint();

  if (!window.EventSource) {
    status('polling (no SSE support)', '');
    SOTA.poll(async () => {
      const d = await SOTA.get(`/api/logs?after=${lastId}`);
      append(d.lines);
    }, 2000);
    return;
  }

  const connect = () => {
    const es = new EventSource(`/api/logs/stream?after=${lastId}`);
    es.onopen = () => status('streaming (SSE)', 'ok');
    es.onmessage = ev => {
      try { append(JSON.parse(ev.data)); } catch (e) { /* ignore a bad frame */ }
    };
    es.onerror = () => {
      status('reconnecting…', 'alert');
      es.close();
      setTimeout(connect, 2500);
    };
  };
  connect();
}

document.querySelectorAll('[data-filter]').forEach(b => {
  b.addEventListener('click', () => {
    filter = b.dataset.filter;
    document.querySelectorAll('[data-filter]').forEach(x =>
      x.classList.toggle('primary', x === b));
    paint();
  });
});

document.getElementById('btn-clear').addEventListener('click', () => {
  lines = [];
  paint();
});

SOTA.get('/api/dashboard/summary').then(SOTA.paintHeader).catch(() => SOTA.markOffline());
start();
