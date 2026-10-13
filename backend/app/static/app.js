'use strict';

const $ = (sel) => document.querySelector(sel);
const state = { networks: [], services: [], rules: [] };

// ------------------------------------------------------------ helpers
async function api(method, path, body) {
  const res = await fetch('/api' + path, {
    method,
    headers: body ? { 'Content-Type': 'application/json' } : {},
    body: body ? JSON.stringify(body) : undefined,
  });
  const text = await res.text();
  let data = text;
  try { data = text ? JSON.parse(text) : null; } catch { /* plain text */ }
  if (!res.ok) throw new Error(errorText(data) || res.statusText);
  return data;
}

function errorText(d) {
  if (!d) return '';
  if (typeof d === 'string') return d;
  if (typeof d.detail === 'string') return d.detail;
  if (Array.isArray(d.detail)) {
    return d.detail.map((e) => `${e.loc.slice(1).join('.') || 'input'}: ${e.msg.replace(/^Value error, /, '')}`).join('; ');
  }
  return JSON.stringify(d);
}

const esc = (s) => String(s ?? '').replace(/[&<>"']/g, (c) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' }[c]));

let toastTimer;
function toast(msg, isError = false) {
  const el = $('#toast');
  el.textContent = msg;
  el.className = 'toast' + (isError ? ' error' : '');
  clearTimeout(toastTimer);
  toastTimer = setTimeout(() => el.classList.add('hidden'), isError ? 7000 : 3000);
}

async function run(fn, okMsg) {
  try {
    const r = await fn();
    if (okMsg) toast(okMsg);
    return r;
  } catch (e) {
    toast(e.message, true);
  }
}

function readForm(form) {
  const out = {};
  for (const el of form.elements) {
    if (!el.name || el.name === 'id') continue;
    if (el.type === 'checkbox') out[el.name] = el.checked;
    else if (el.dataset.type === 'int') out[el.name] = el.value === '' ? null : Number(el.value);
    else out[el.name] = el.value;
  }
  return out;
}

function fillForm(form, item) {
  for (const el of form.elements) {
    if (!el.name) continue;
    if (el.type === 'checkbox') el.checked = !!item[el.name];
    else el.value = item[el.name] ?? '';
  }
}

// ------------------------------------------------------------ tabs
document.querySelectorAll('#tabs button').forEach((btn) => {
  btn.addEventListener('click', () => {
    document.querySelectorAll('#tabs button').forEach((b) => b.classList.toggle('active', b === btn));
    document.querySelectorAll('main > section').forEach((s) => s.classList.toggle('hidden', s.id !== 'tab-' + btn.dataset.tab));
    if (btn.dataset.tab === 'apply') loadApply();
    if (btn.dataset.tab === 'history') loadHistory();
  });
});

// ------------------------------------------------------------ entities
const netName = (id) => {
  const n = state.networks.find((x) => x.id === id);
  return n ? esc(n.name) : '<span class="muted">any</span>';
};
const svcLabel = (s) => (s.ports ? `${s.protocol}/${s.ports}` : s.protocol);
const svcName = (id) => {
  const s = state.services.find((x) => x.id === id);
  return s ? `${esc(s.name)} <span class="muted">${esc(svcLabel(s))}</span>` : '<span class="muted">any</span>';
};

const renderers = {
  networks: (n) => `<td>${esc(n.name)}</td><td><code>${esc(n.cidr || '')}</code></td><td><code>${esc(n.interface || '')}</code></td><td>${esc(n.description)}</td>`,
  services: (s) => `<td>${esc(s.name)}</td><td>${esc(s.protocol)}</td><td><code>${esc(s.ports)}</code></td><td>${esc(s.description)}</td>`,
  rules: (r, i) => `<td>${i + 1}</td>
    <td>${esc(r.name)}${r.log ? ' <span class="muted">(log)</span>' : ''}${r.comment ? `<br><span class="muted">${esc(r.comment)}</span>` : ''}</td>
    <td>${r.chain === 'input' ? 'to host' : 'forward'}</td>
    <td>${netName(r.src_network_id)}</td><td>${netName(r.dst_network_id)}</td><td>${svcName(r.service_id)}</td>
    <td><span class="tag ${r.action}">${r.action}</span></td>`,
};

function renderList(entity) {
  const rows = state[entity].map((item, i) => {
    const move = entity === 'rules'
      ? `<button data-move="-1" title="Move up">&uarr;</button><button data-move="1" title="Move down">&darr;</button>`
      : '';
    const toggle = entity === 'rules' ? `<button data-toggle>${item.enabled ? 'Disable' : 'Enable'}</button>` : '';
    const cls = entity === 'rules' && !item.enabled ? ' class="disabled"' : '';
    return `<tr data-id="${item.id}"${cls}>${renderers[entity](item, i)}
      <td class="nowrap">${move}${toggle}<button data-edit>Edit</button><button data-delete class="danger">Delete</button></td></tr>`;
  });
  const cols = entity === 'rules' ? 8 : 5;
  $('#list-' + entity).innerHTML = rows.join('') || `<tr><td colspan="${cols}" class="muted">Nothing yet.</td></tr>`;
}

function fillSelects() {
  const nets = '<option value="">any</option>' + state.networks.map((n) =>
    `<option value="${n.id}">${esc(n.name)} (${esc([n.cidr, n.interface].filter(Boolean).join(' @ '))})</option>`).join('');
  const svcs = '<option value="">any</option>' + state.services.map((s) =>
    `<option value="${s.id}">${esc(s.name)} (${esc(svcLabel(s))})</option>`).join('');
  document.querySelectorAll('.net-select').forEach((sel) => { const v = sel.value; sel.innerHTML = nets; sel.value = v; });
  document.querySelectorAll('.svc-select').forEach((sel) => { const v = sel.value; sel.innerHTML = svcs; sel.value = v; });
}

async function loadAll() {
  const [networks, services, rules] = await Promise.all([api('GET', '/networks'), api('GET', '/services'), api('GET', '/rules')]);
  Object.assign(state, { networks, services, rules });
  fillSelects();
  ['networks', 'services', 'rules'].forEach(renderList);
  refreshStatus();
}

for (const entity of ['networks', 'services', 'rules']) {
  const form = $('#form-' + entity);

  form.addEventListener('submit', async (ev) => {
    ev.preventDefault();
    const id = form.elements.id.value;
    const ok = await run(() => api(id ? 'PUT' : 'POST', `/${entity}${id ? '/' + id : ''}`, readForm(form)), 'Saved');
    if (ok) {
      form.reset();
      await loadAll();
    }
  });
  form.addEventListener('reset', () => { form.elements.id.value = ''; });

  $('#list-' + entity).addEventListener('click', async (ev) => {
    const btn = ev.target.closest('button');
    if (!btn) return;
    const id = Number(btn.closest('tr').dataset.id);
    const item = state[entity].find((x) => x.id === id);

    if ('edit' in btn.dataset) {
      fillForm(form, item);
      form.scrollIntoView({ behavior: 'smooth' });
      form.elements.name.focus();
    } else if ('delete' in btn.dataset) {
      if (!confirm(`Delete "${item.name}"?`)) return;
      await run(() => api('DELETE', `/${entity}/${id}`), 'Deleted');
      await loadAll();
    } else if ('toggle' in btn.dataset) {
      await run(() => api('PUT', `/rules/${id}`, { ...item, enabled: !item.enabled }));
      await loadAll();
    } else if (btn.dataset.move) {
      const ids = state.rules.map((r) => r.id);
      const i = ids.indexOf(id);
      const j = i + Number(btn.dataset.move);
      if (j < 0 || j >= ids.length) return;
      [ids[i], ids[j]] = [ids[j], ids[i]];
      await run(() => api('POST', '/rules/reorder', { ids }));
      await loadAll();
    }
  });
}

// ------------------------------------------------------------ settings / apply
const settingsForm = $('#form-settings');

async function loadApply() {
  await run(async () => {
    const [settings, preview] = await Promise.all([api('GET', '/settings'), api('GET', '/preview')]);
    fillForm(settingsForm, settings);
    $('#preview').textContent = preview.script;
    $('#warnings').innerHTML = preview.warnings.map((w) => `<div class="warning">${esc(w)}</div>`).join('');
  });
}

settingsForm.addEventListener('submit', async (ev) => {
  ev.preventDefault();
  if (await run(() => api('PUT', '/settings', readForm(settingsForm)), 'Settings saved')) {
    loadApply();
    refreshStatus();
  }
});

$('#btn-apply').addEventListener('click', async () => {
  if (!confirm('Apply the generated ruleset to the host firewall?')) return;
  const r = await run(() => api('POST', '/apply'));
  if (r) toast(r.status === 'pending' ? 'Applied: confirm to keep it' : `Applied. ${r.message || ''}`);
  refreshStatus();
});

$('#btn-confirm').addEventListener('click', async () => {
  const r = await run(() => api('POST', '/confirm'));
  if (r) toast(`Confirmed. ${r.message || ''}`);
  refreshStatus();
});

$('#btn-rollback').addEventListener('click', async () => {
  await run(() => api('POST', '/rollback'), 'Rolled back');
  refreshStatus();
});

$('#btn-live').addEventListener('click', () => run(async () => {
  $('#live').textContent = await api('GET', '/live');
}));

// ------------------------------------------------------------ history
async function loadHistory() {
  await run(async () => {
    const items = await api('GET', '/history');
    $('#list-history').innerHTML = items.map((h) => `<tr>
      <td>${esc(h.ts.replace('T', ' ').replace('Z', ''))}</td><td>${esc(h.user)}</td>
      <td><span class="tag ${h.status === 'applied' ? 'ACCEPT' : h.status === 'rolled_back' ? 'DROP' : ''}">${esc(h.status)}</span></td>
      <td>${esc(h.message)}</td>
      <td><details><summary>view</summary><pre>${esc(h.script)}</pre></details></td></tr>`).join('')
      || '<tr><td colspan="5" class="muted">No changes applied yet.</td></tr>';
  });
}

// ------------------------------------------------------------ status
let statusTimer;
async function refreshStatus() {
  clearTimeout(statusTimer);
  let next = 10000;
  try {
    const s = await api('GET', '/status');
    const pills = [`<span class="pill">backend: ${esc(s.backend)}</span>`];
    if (s.dry_run) pills.push('<span class="pill warn">DRY RUN</span>');
    if (s.pending) pills.push('<span class="pill warn">awaiting confirmation</span>');
    else if (s.dirty) pills.push('<span class="pill danger">unapplied changes</span>');
    else pills.push('<span class="pill ok">in sync</span>');
    $('#status').innerHTML = pills.join('');

    $('#pending').classList.toggle('hidden', !s.pending);
    if (s.pending) {
      $('#countdown').textContent = s.pending.remaining;
      next = 1000;
    }
  } catch (e) {
    $('#status').innerHTML = `<span class="pill danger">${esc(e.message)}</span>`;
  }
  statusTimer = setTimeout(refreshStatus, next);
}

run(loadAll);
