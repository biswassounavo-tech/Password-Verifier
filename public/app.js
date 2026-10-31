(() => {
  'use strict';

  const $ = (s) => document.querySelector(s);
  const input = $('#pw');
  const toggle = $('#toggle');
  const validateBtn = $('#validate');
  const terminal = $('#terminal');
  const conn = $('#conn');
  const checksEl = $('#checks');
  const passedCount = $('#passedCount');
  const meter = $('#meter');
  const meterFill = $('#meterFill');
  const meterLabel = $('#meterLabel');
  const meterScore = $('#meterScore');
  const suggestCard = $('#suggestCard');
  const suggestList = $('#suggestions');
  const statusEl = $('#status');
  const sumPassed = $('#sumPassed');
  const sumStrength = $('#sumStrength');
  const sumFailed = $('#sumFailed');
  const username = $('#username');
  const email = $('#email');
  const generateBtn = $('#generate');
  const entropyEl = $('#entropy');
  const crackTimeEl = $('#crackTime');
  const pauseBtn = $('#pauseLog');
  const clearBtn = $('#clearLog');
  const copyBtn = $('#copyLog');
  const logModeBtn = $('#logMode');
  const termCard = document.querySelector('.term-card');
  const themeBtn = $('#themeToggle');

  const DEBOUNCE_MS = 400;
  const MAX_LINES = 300;

  let rules = [];
  let controller = null;
  let timer = null;
  let runId = 0;
  let logPaused = false;

  /* ---------- terminal ---------- */
  function fmtTime(iso) {
    const d = iso ? new Date(iso) : new Date();
    const p = (n, l = 2) => String(n).padStart(l, '0');
    return `${p(d.getHours())}:${p(d.getMinutes())}:${p(d.getSeconds())}.${p(d.getMilliseconds(), 3)}`;
  }

  function addLine(level, message, ts, extraClass) {
    if (logPaused) return;
    terminal.querySelector('.cursor')?.classList.remove('cursor');
    const line = document.createElement('div');
    line.className = 'line' + (extraClass ? ' ' + extraClass : '');

    const t = document.createElement('span');
    t.className = 'ts';
    t.textContent = fmtTime(ts);

    const tag = document.createElement('span');
    tag.className = 'tag ' + level;
    tag.textContent = `[${level}]`;

    const msg = document.createElement('span');
    msg.className = 'msg';
    const m = /^(.*): (PASS|FAIL)$/.exec(message);
    if (level === 'CHECK' && m) {
      msg.append(document.createTextNode(m[1] + ': '));
      const r = document.createElement('span');
      r.className = m[2] === 'PASS' ? 'ok' : 'bad';
      r.textContent = m[2];
      msg.append(r);
    } else {
      msg.textContent = message;
    }

    line.append(t, tag, msg);
    terminal.append(line);
    while (terminal.childElementCount > MAX_LINES) terminal.firstElementChild.remove();
    terminal.scrollTop = terminal.scrollHeight;
    return line;
  }

  function sysLine(text) {
    const l = document.createElement('div');
    l.className = 'line sys';
    const t = document.createElement('span');
    t.className = 'ts';
    t.textContent = fmtTime();
    const m = document.createElement('span');
    m.className = 'msg';
    m.textContent = text;
    l.append(t, m);
    terminal.append(l);
    terminal.scrollTop = terminal.scrollHeight;
  }

  function resetTerminal() {
    terminal.replaceChildren();
    sysLine('Waiting for input… type a password to begin.');
  }

  /* ---------- checklist ---------- */
  function renderChecks() {
    checksEl.replaceChildren();
    for (const r of rules) {
      const li = document.createElement('li');
      li.dataset.id = r.id;
      li.dataset.state = 'idle';
      const name = document.createElement('span');
      name.textContent = r.name;
      const badge = document.createElement('span');
      badge.className = 'badge';
      badge.textContent = '—';
      li.append(name, badge);
      checksEl.append(li);
    }
    passedCount.textContent = `0 / ${rules.length}`;
  }

  function setCheck(id, state) {
    const li = checksEl.querySelector(`li[data-id="${CSS.escape(id)}"]`);
    if (!li) return;
    li.dataset.state = state;
    li.querySelector('.badge').textContent = state === 'pass' ? 'PASS' : state === 'fail' ? 'FAIL' : '—';
  }

  function resetChecks() {
    checksEl.querySelectorAll('li').forEach((li) => {
      li.dataset.state = 'idle';
      li.querySelector('.badge').textContent = '—';
    });
    passedCount.textContent = `0 / ${rules.length}`;
  }

  /* ---------- meter / summary ---------- */
  function setMeter(score, label) {
    const level = score === 0 ? 0 : score < 25 ? 1 : score < 50 ? 2 : score < 70 ? 3 : score < 90 ? 4 : 5;
    meterFill.style.width = score + '%';
    meterFill.dataset.level = String(level);
    meterLabel.textContent = label || '—';
    meterScore.textContent = `${score}/100`;
    meter.setAttribute('aria-valuenow', String(score));
  }

  function setStatus(state, text) {
    statusEl.dataset.state = state;
    statusEl.textContent = text;
  }

  function resetSummary() {
    setMeter(0, '—');
    setStatus('idle', 'AWAITING INPUT');
    sumPassed.textContent = sumStrength.textContent = sumFailed.textContent = '—';
    entropyEl.textContent = crackTimeEl.textContent = '—';
    suggestCard.hidden = true;
    suggestList.replaceChildren();
    resetChecks();
  }

  function setConn(state, text) {
    conn.dataset.state = state;
    conn.textContent = text;
  }

  /* ---------- event handling ---------- */
  let passedSoFar = 0;

  function handleEvent(ev) {
    switch (ev.type) {
      case 'log': {
        const cls = ev.level === 'RESULT' ? (/accepted/.test(ev.message) ? 'result-ok' : 'result-bad') : '';
        addLine(ev.level, ev.message, ev.ts, cls);
        break;
      }
      case 'check':
        setCheck(ev.id, ev.pass ? 'pass' : 'fail');
        if (ev.pass) passedSoFar += 1;
        passedCount.textContent = `${passedSoFar} / ${rules.length}`;
        break;
      case 'summary': {
        setMeter(ev.score, ev.label);
        entropyEl.textContent = `${ev.entropy} bits`;
        crackTimeEl.textContent = ev.crackTime;
        setStatus(ev.status === 'ACCEPTED' ? 'accepted' : 'rejected', ev.status);
        sumPassed.textContent = `${ev.passed} / ${ev.total}`;
        sumStrength.textContent = `${ev.label} (${ev.score})`;
        const names = ev.failed.map((id) => (rules.find((r) => r.id === id) || {}).name || id);
        sumFailed.textContent = names.length ? names.join(', ') : 'None';
        suggestList.replaceChildren();
        ev.suggestions.forEach((s) => {
          const li = document.createElement('li');
          li.textContent = s;
          suggestList.append(li);
        });
        suggestCard.hidden = ev.suggestions.length === 0;
        break;
      }
      default:
        break;
    }
  }

  /* ---------- validation request (streamed NDJSON) ---------- */
  async function validate() {
    clearTimeout(timer);
    const password = input.value;

    if (controller) controller.abort();
    if (!password) {
      resetSummary();
      resetTerminal();
      setConn('idle', 'idle');
      return;
    }

    controller = new AbortController();
    const myRun = ++runId;
    passedSoFar = 0;

    resetChecks();
    setStatus('running', 'VALIDATING…');
    sumPassed.textContent = sumStrength.textContent = sumFailed.textContent = '…';
    suggestCard.hidden = true;
    terminal.replaceChildren();
    setConn('live', 'streaming');

    try {
      const res = await fetch('/api/validate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        cache: 'no-store',
        credentials: 'omit',
        body: JSON.stringify({ password, username: username.value.trim(), email: email.value.trim() }),
        signal: controller.signal
      });

      if (!res.ok) {
        let msg = `Request failed (${res.status})`;
        try { msg = (await res.json()).error || msg; } catch (_) { /* ignore */ }
        throw new Error(msg);
      }

      const reader = res.body.getReader();
      const decoder = new TextDecoder();
      let buf = '';
      for (;;) {
        const { value, done } = await reader.read();
        if (done) break;
        if (myRun !== runId) return;
        buf += decoder.decode(value, { stream: true });
        let idx;
        while ((idx = buf.indexOf('\n')) >= 0) {
          const raw = buf.slice(0, idx).trim();
          buf = buf.slice(idx + 1);
          if (raw) handleEvent(JSON.parse(raw));
        }
      }
      if (myRun === runId) {
        setConn('idle', 'done');
        terminal.lastElementChild?.classList.add('cursor');
      }
    } catch (err) {
      if (err.name === 'AbortError') return; // superseded by newer input
      if (myRun !== runId) return;
      addLine('ERROR', err.message || 'Connection lost');
      setStatus('idle', 'ERROR');
      setConn('idle', 'error');
    }
  }

  function schedule() {
    clearTimeout(timer);
    timer = setTimeout(validate, DEBOUNCE_MS);
  }

  /* ---------- wiring ---------- */
  input.addEventListener('input', schedule);
  input.addEventListener('keydown', (e) => { if (e.key === 'Enter') validate(); });
  validateBtn.addEventListener('click', validate);
  username.addEventListener('input', schedule);
  email.addEventListener('input', schedule);
  toggle.addEventListener('click', () => {
    const show = input.type === 'password';
    input.type = show ? 'text' : 'password';
    toggle.textContent = show ? 'Hide' : 'Show';
    toggle.setAttribute('aria-pressed', String(show));
    input.focus();
  });

  generateBtn.addEventListener('click', async () => {
    try {
      const res = await fetch('/api/generate', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({ length: Math.max(20, Number($('#minLength').value) || 20) })
      });
      const data = await res.json();
      input.value = data.password;
      input.type = 'text';
      toggle.textContent = 'Hide';
      toggle.setAttribute('aria-pressed', 'true');
      schedule();
    } catch (_) {
      addLine('ERROR', 'Could not generate a password');
    }
  });

  pauseBtn.addEventListener('click', () => {
    logPaused = !logPaused;
    pauseBtn.textContent = logPaused ? 'Resume' : 'Pause';
    pauseBtn.setAttribute('aria-pressed', String(logPaused));
  });
  clearBtn.addEventListener('click', () => { terminal.replaceChildren(); });
  copyBtn.addEventListener('click', async () => {
    await navigator.clipboard.writeText(terminal.innerText);
    copyBtn.textContent = 'Copied';
    setTimeout(() => { copyBtn.textContent = 'Copy'; }, 1200);
  });
  logModeBtn.addEventListener('click', () => {
    const compact = !termCard.classList.contains('compact');
    termCard.classList.toggle('compact', compact);
    logModeBtn.textContent = compact ? 'Verbose' : 'Compact';
    logModeBtn.setAttribute('aria-pressed', String(compact));
  });
  themeBtn.addEventListener('click', () => {
    const light = document.body.classList.toggle('light');
    themeBtn.textContent = light ? 'Dark theme' : 'Light theme';
    localStorage.setItem('theme', light ? 'light' : 'dark');
  });
  if (localStorage.getItem('theme') === 'light') {
    document.body.classList.add('light');
    themeBtn.textContent = 'Dark theme';
  }

  async function refreshStats() {
    try {
      const res = await fetch('/api/stats', { cache: 'no-store' });
      const data = await res.json();
      $('#statTotal').textContent = data.total;
      $('#statAccepted').textContent = data.accepted;
      $('#statRejected').textContent = data.rejected;
      const entries = Object.entries(data.failed);
      $('#failedRules').textContent = entries.length
        ? entries.map(([id, count]) => `${rules.find((rule) => rule.id === id)?.name || id}: ${count}`).join('  •  ')
        : 'No failed rules recorded.';
    } catch (_) {}
  }

  async function loadPolicy() {
    try {
      const res = await fetch('/api/policy');
      const data = await res.json();
      $('#minLength').value = data.minLength;
      const allRules = await (await fetch('/api/rules')).json();
      const container = $('#requiredRules');
      container.replaceChildren();
      for (const rule of allRules) {
        const label = document.createElement('label');
        const input = document.createElement('input');
        input.type = 'checkbox';
        input.value = rule.id;
        input.checked = data.required.includes(rule.id);
        label.append(input, document.createTextNode(' ' + rule.name));
        container.append(label);
      }
    } catch (_) {}
  }

  $('#savePolicy').addEventListener('click', async () => {
    const required = [...$('#requiredRules').querySelectorAll('input:checked')].map((input) => input.value);
    const res = await fetch('/api/policy', {
      method: 'POST',
      headers: { 'Content-Type': 'application/json' },
      body: JSON.stringify({ minLength: Number($('#minLength').value), required })
    });
    if (res.ok) {
      rules = await (await fetch('/api/rules')).json();
      renderChecks();
      resetSummary();
      refreshStats();
    } else {
      addLine('ERROR', (await res.json()).error || 'Could not save policy');
    }
  });

  (async function init() {
    try {
      const res = await fetch('/api/rules', { cache: 'no-store' });
      rules = await res.json();
    } catch (_) {
      rules = [];
    }
    renderChecks();
    resetSummary();
    resetTerminal();
    await refreshStats();
    await loadPolicy();
    setInterval(refreshStats, 3000);
    input.focus();
  })();
})();