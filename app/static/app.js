function detailMessage(detail) {
  if (!detail) return 'Ошибка запроса';
  if (typeof detail === 'string') return detail;
  if (Array.isArray(detail)) return detail.map((x) => x.msg || JSON.stringify(x)).join('; ');
  return JSON.stringify(detail);
}

async function api(path, method, body) {
  const opts = { method: method || 'GET', headers: {}, credentials: 'same-origin' };
  if (body !== undefined) {
    opts.headers['Content-Type'] = 'application/json';
    opts.body = JSON.stringify(body);
  }
  const res = await fetch(path, opts);
  const data = await res.json().catch(() => ({}));
  if (res.status === 401) {
    window.location.href = '/login';
    throw new Error('Нужно войти заново');
  }
  if (!res.ok) {
    const error = new Error(data.detail ? detailMessage(data.detail) : ('HTTP ' + res.status + ' · ' + (res.statusText || 'сбой запроса')));
    error.detail = data.detail;
    throw error;
  }
  return data;
}

async function submitInstall(path, payload) {
  try {
    return await api(path, 'POST', payload);
  } catch (error) {
    const key = error.detail;
    if (key?.code !== 'confirm_ssh_host_key') throw error;
    const message = ['Первое подключение SSH к ' + key.address,
      key.algorithm + '  ' + key.fingerprint,
      'Сверьте отпечаток с ключом сервера в консоли хостинга. Отпечатки совпадают?'].join('\n\n');
    if (!window.confirm(message)) return null;
    return api(path, 'POST', { ...payload, ssh_fingerprint: key.fingerprint });
  }
}

function toast(text, kind) {
  let wrap = document.querySelector('.toast-wrap');
  if (!wrap) {
    wrap = document.createElement('div');
    wrap.className = 'toast-wrap';
    document.body.appendChild(wrap);
  }
  const el = document.createElement('div');
  el.className = 'toast' + (kind === 'err' ? ' err' : '');
  el.textContent = text;
  wrap.appendChild(el);
  setTimeout(() => el.remove(), kind === 'err' ? 12000 : 4200);
}

function showLog(el, lines) {
  if (!el) return;
  el.textContent = Array.isArray(lines) ? lines.join('\n') : String(lines || '');
  el.classList.add('show');
}

function copyViaTextarea(text) {
  const area = document.createElement('textarea');
  area.value = text;
  area.setAttribute('readonly', '');
  area.style.position = 'fixed';
  area.style.top = '0';
  area.style.left = '0';
  area.style.opacity = '0';
  document.body.appendChild(area);
  area.focus();
  area.select();
  let ok = false;
  try {
    ok = document.execCommand('copy');
  } catch (err) {
    ok = false;
  }
  area.remove();
  return ok;
}

function copyText(text) {
  const value = String(text || '');
  if (!value) {
    toast('Нечего копировать', 'err');
    return;
  }
  const done = () => toast('Ссылка скопирована');
  const fail = () => toast('Не удалось скопировать', 'err');
  if (navigator.clipboard && window.isSecureContext) {
    navigator.clipboard.writeText(value).then(done).catch(() => {
      if (copyViaTextarea(value)) done();
      else fail();
    });
    return;
  }
  if (copyViaTextarea(value)) done();
  else fail();
}

function busy(btn, on) {
  if (!btn) return;
  btn.disabled = !!on;
  if (on) {
    btn.dataset.busyLabel = btn.textContent;
    btn.textContent = 'Секунду…';
  } else if (btn.dataset.busyLabel) {
    btn.textContent = btn.dataset.busyLabel;
    delete btn.dataset.busyLabel;
  }
}

async function withBusy(btn, fn) {
  busy(btn, true);
  try {
    return await fn();
  } catch (err) {
    toast(err.message || String(err), 'err');
    throw err;
  } finally {
    busy(btn, false);
  }
}

function openModal(id) {
  document.getElementById(id)?.classList.add('open');
}
function closeModal(id) {
  document.getElementById(id)?.classList.remove('open');
}

let overlayPressId = '';
document.addEventListener('pointerdown', (e) => {
  const node = e.target;
  overlayPressId = node && node.classList && node.classList.contains('overlay') && node.id ? node.id : '';
}, true);

document.addEventListener('click', (e) => {
  const pressed = overlayPressId;
  overlayPressId = '';
  const copyBtn = e.target.closest && e.target.closest('[data-copy]');
  if (copyBtn) {
    e.preventDefault();
    copyText(copyBtn.dataset.copy || copyBtn.getAttribute('data-copy') || '');
    return;
  }
  const closeBtn = e.target.closest && e.target.closest('[data-close]');
  if (closeBtn) {
    closeModal(closeBtn.dataset.close);
    return;
  }
  if (pressed && e.target.classList && e.target.classList.contains('overlay') && e.target.id === pressed) {
    closeModal(pressed);
  }
}, true);

const FLAG_NAMES = JSON.parse(document.getElementById('flag-names')?.textContent || '{}');
const FLAGS = Object.keys(FLAG_NAMES);

function flagCodes(value) {
  const seen = [];
  String(value || '').split(',').forEach((part) => {
    const code = part.trim().toUpperCase();
    if (code && seen.indexOf(code) === -1) seen.push(code);
  });
  return seen;
}

function paintFlagBox(box) {
  const input = box.parentElement && box.parentElement.querySelector(`[name="${box.dataset.flags}"]`);
  if (!input) return;
  const selected = flagCodes(input.value);
  box.innerHTML = FLAGS.map((code) => {
    const on = selected.indexOf(code) !== -1 ? ' on' : '';
    const src = '/static/flags/' + code.toLowerCase() + '.png';
    const title = FLAG_NAMES[code] || code;
    return `<button type="button" class="flag${on}" data-flag="${code}" title="${title}"><img src="${src}" alt="${title}"></button>`;
  }).join('');
}

function bindFlagPicker(root) {
  root.querySelectorAll('[data-flags]').forEach((box) => {
    const input = box.parentElement && box.parentElement.querySelector(`[name="${box.dataset.flags}"]`);
    if (!input) return;
    paintFlagBox(box);
    if (box.dataset.bound) return;
    box.dataset.bound = '1';
    box.addEventListener('click', (e) => {
      const btn = e.target.closest('[data-flag]');
      if (!btn || !box.contains(btn)) return;
      const code = btn.dataset.flag;
      if (box.dataset.multi === '1') {
        const selected = flagCodes(input.value);
        const next = selected.indexOf(code) === -1
          ? selected.concat(code)
          : selected.filter((item) => item !== code);
        input.value = next.join(',');
      } else {
        input.value = code;
      }
      paintFlagBox(box);
    });
  });
}

async function pullDestSni(dest, btn) {
  return withBusy(btn, () => api('/api/dest-sni', 'POST', { dest }));
}

function applyDestSni(input, meta, data, opts) {
  const names = data.names || [];
  input.value = names.join(', ');
  const bits = [];
  bits.push('С сертификата ' + data.dest + ': ' + names.length + ' имён.');
  if (data.wildcards && data.wildcards.length) {
    bits.push('Wildcard ' + data.wildcards.join(', ') + ' в список не раскрывается — допишите нужные поддомены вручную.');
  }
  if (meta) meta.textContent = bits.join(' ');
  if (!opts || opts.toast !== false) toast('Подставили ' + names.length + ' SNI с цели');
}

document.addEventListener('DOMContentLoaded', () => {
  bindFlagPicker(document);
  document.querySelectorAll('tbody[data-sortable]').forEach((body) => bindSort(body));
  bindReportFilters();
  mountSitePage();
});

function sortValue(row, key) {
  const raw = row.dataset[key] ?? '';
  if (raw === '∞') return Number.POSITIVE_INFINITY;
  if (raw !== '' && Number.isFinite(Number(raw))) return Number(raw);
  return raw.toLocaleLowerCase();
}

function bindSort(list) {
  const scope = list.closest('.fold, .card') || list.parentElement;
  const buttons = scope.querySelectorAll('[data-sort]');
  let key = '';
  let dir = 1;
  function marks() {
    buttons.forEach((btn) => {
      const on = btn.dataset.sort === key;
      btn.classList.toggle('on', on);
      btn.classList.toggle('asc', on && dir > 0);
      btn.classList.toggle('desc', on && dir < 0);
    });
  }
  function resort() {
    if (!key) return;
    const rows = [...list.children].filter((el) => el.matches('article, tr'));
    rows.sort((a, b) => {
      const av = sortValue(a, key);
      const bv = sortValue(b, key);
      const cmp = typeof av === 'number' && typeof bv === 'number'
        ? av - bv
        // numeric: версии вроде 25.11.1 и 25.9.8 сравниваются по числам, а не по буквам
        : String(av).localeCompare(String(bv), 'ru', { numeric: true });
      return cmp * dir;
    });
    rows.forEach((row) => list.appendChild(row));
  }
  const textSort = { name: true, host: true, tunnel: true, platform: true, version: true, status: true };
  buttons.forEach((btn) => btn.addEventListener('click', (event) => {
    event.preventDefault();
    event.stopPropagation();
    const next = btn.dataset.sort;
    if (key === next) dir *= -1;
    else {
      key = next;
      dir = textSort[next] ? 1 : -1;
    }
    marks();
    resort();
  }));
  return { resort };
}

function bindReportFilters() {
  const chips = document.querySelectorAll('[data-status-filter]');
  if (!chips.length) return;
  const rows = document.querySelectorAll('[data-status-row]');
  chips.forEach((chip) => chip.addEventListener('click', () => {
    const key = chip.dataset.statusFilter || 'all';
    chips.forEach((item) => {
      const on = item === chip;
      item.classList.toggle('on', on);
      item.setAttribute('aria-pressed', on ? 'true' : 'false');
    });
    rows.forEach((row) => {
      row.hidden = key !== 'all' && row.dataset.key !== key;
    });
  }));
}

function applyClientPresence(clients) {
  (clients || []).forEach((client) => {
    const row = document.querySelector('[data-client="' + client.id + '"]');
    if (!row) return;
    const online = Number(client.online_nodes || 0);
    row.dataset.online = String(online);
    const seen = Math.max(Number(row.dataset.seen || 0), Number(client.last_online || 0));
    const seenLabel = row.querySelector('[data-last-online]');
    if (seenLabel && seen) {
      row.dataset.seen = String(seen);
      seenLabel.textContent = new Date(seen * 1000).toLocaleString('ru-RU', {
        timeZone: 'Europe/Moscow', day: '2-digit', month: '2-digit', year: 'numeric',
        hour: '2-digit', minute: '2-digit'
      });
    }
    row.classList.toggle('is-online', online > 0);
    const label = row.querySelector('[data-online]');
    if (label) {
      label.textContent = online ? ('в сети на ' + online) : 'не в сети';
      label.classList.toggle('live-tag', online > 0);
    }
    if (client.used_label) {
      row.dataset.used = String(client.used || 0);
      const traffic = row.querySelector('[data-traffic]');
      if (traffic) traffic.textContent = client.used_label + ' / ' + (client.limit_label || 'без лимита');
    }
  });
  applyUserStats();
}

// Метрика блока «Клиенты»: всего / в сети / не в сети. Считаем по строкам таблицы,
// поэтому цифры всегда совпадают с тем, что человек видит списком ниже.
function applyUserStats() {
  const box = document.getElementById('user-stats');
  if (!box) return;
  let total = 0;
  let online = 0;
  document.querySelectorAll('[data-client]').forEach((row) => {
    total += 1;
    if (Number(row.dataset.online || 0) > 0) online += 1;
  });
  const put = (key, value) => {
    const el = box.querySelector('[data-stat-' + key + ']');
    if (el) el.textContent = String(value);
  };
  put('total', total);
  put('online', online);
  put('offline', total - online);
}

function sinceLabel(iso) {
  if (!iso) return '';
  const then = Date.parse(iso);
  if (!Number.isFinite(then)) return '';
  const mins = Math.round((Date.now() - then) / 60000);
  if (mins < 1) return 'только что';
  if (mins < 60) return mins + ' мин назад';
  const hours = Math.round(mins / 60);
  if (hours < 48) return hours + ' ч назад';
  return Math.round(hours / 24) + ' дн назад';
}

function applyNodeRf(row, node) {
  if (!row || !node || node.install_kind === 'grafana') return;
  const label = row.querySelector('[data-rf-label]');
  if (node.enabled === false) {
    row.dataset.rf = '-1';
    if (!label) return;
    label.textContent = '—';
    label.classList.toggle('rf-tag', true);
    label.classList.toggle('on', false);
    label.classList.toggle('bad', false);
    label.setAttribute('title', 'Нода выключена, в подписку не входит');
    return;
  }
  const checked = Boolean(node.rf_checked_at);
  const ok = Boolean(node.rf_ok);
  // -1 = ещё не проверяли, 0 = из России не достучаться, 1 = достучаться.
  row.dataset.rf = checked ? (ok ? '1' : '0') : '-1';
  if (!label) return;
  label.textContent = ok ? 'есть' : (checked ? 'нет' : '—');
  label.classList.toggle('rf-tag', true);
  label.classList.toggle('on', ok);
  label.classList.toggle('bad', checked && !ok);
  const parts = [];
  if (node.rf_note) parts.push(node.rf_note);
  if (checked) parts.push('проверено ' + sinceLabel(node.rf_checked_at));
  label.setAttribute('title', parts.join(' · ') || 'Проверки из России ещё не было');
}

function versionTuple(value) {
  return String(value || '').split(/[^0-9]+/).filter(Boolean).map(Number);
}

// Строго новее ли candidate, чем base (с учётом '3.11' == '3.11.0').
function versionNewer(candidate, base) {
  const a = versionTuple(candidate);
  const b = versionTuple(base);
  if (!a.length || !b.length) return Boolean(candidate) && candidate !== base;
  const size = Math.max(a.length, b.length);
  while (a.length < size) a.push(0);
  while (b.length < size) b.push(0);
  for (let i = 0; i < size; i++) {
    if (a[i] !== b[i]) return a[i] > b[i];
  }
  return false;
}

function versionEqual(a, b) {
  return !versionNewer(a, b) && !versionNewer(b, a);
}

// Перерисовывает иконку против версии: спиннер (идёт обновление), красный «!»
// (сбой — некликабелен, «проверьте ноду вручную»), жёлтая ↑ (есть новее = обновить).
function renderVerIcon(el, node, kind, current, latest, state) {
  const old = el.querySelector('.ver-up,.ver-spin,.ver-fail');
  if (old) old.remove();
  el.classList.toggle('is-running', state === 'running');
  el.classList.toggle('is-failed', state === 'failed');
  if (state === 'running') {
    const s = document.createElement('span');
    s.className = 'ver-spin';
    s.title = 'обновление выполняется…';
    s.textContent = '…';
    el.appendChild(s);
    return;
  }
  if (state === 'failed') {
    const b = document.createElement('span');
    b.className = 'ver-fail';
    b.title = 'обновление не завершилось — проверьте ноду вручную';
    b.textContent = '!';
    el.appendChild(b);
    return;
  }
  if (node.enabled && current && versionNewer(latest, current)) {
    const b = document.createElement('button');
    b.type = 'button';
    b.className = 'ver-up';
    b.dataset.nodeId = String(node.id);
    b.dataset.updateKind = kind;
    b.dataset.cur = current || '';
    b.dataset.latest = latest || '';
    b.title = 'обновить ' + (kind === 'panel' ? 'панель' : 'ядро') + ' до ' + latest;
    b.textContent = '↑';
    el.appendChild(b);
  }
}

// Versions are read by the same /server/status call that powers CPU/RAM, so the
// two columns refresh on every overview poll. Empty means "this panel release
// does not report it" — we keep the last known value in the DB instead of blanking.
function applyNodeVersions(row, node) {
  if (!row || !node || node.install_kind === 'grafana') return;
  const put = (key, value, latest, checkedAt, label, kind) => {
    row.dataset[key] = String(value || '');
    const el = row.querySelector('[data-' + key + '-ver]');
    if (!el) return;
    const num = el.querySelector('.ver-num');
    if (num) num.textContent = value || '—';
    else el.textContent = value || '—';
    el.classList.toggle('is-empty', !value);
    const state = (node.update_kind === kind) ? (node.update_state || '') : '';
    const canUpdate = node.enabled && value && versionNewer(latest, value);
    const isCurrent = Boolean(latest) && Boolean(value) && versionEqual(latest, value);
    el.classList.toggle('has-update', canUpdate && !state);
    el.classList.toggle('is-current', isCurrent && !state);
    renderVerIcon(el, node, kind, value, latest, state);
    const bits = [];
    if (value) bits.push(label);
    if (state === 'running') bits.push('обновление выполняется…');
    else if (state === 'failed') bits.push('обновление не завершилось');
    else if (canUpdate) bits.push('доступно обновление до ' + latest);
    else if (isCurrent) bits.push('актуальная версия');
    const error = node[kind + '_check_error'];
    if (error) {
      bits.push(error);
      el.classList.add('is-failed');
      if (!state) {
        const mark = document.createElement('span');
        mark.className = 'ver-fail';
        mark.textContent = '!';
        mark.tabIndex = 0;
        mark.title = error;
        mark.setAttribute('aria-label', error);
        el.appendChild(mark);
      }
    }
    if (checkedAt) bits.push('установленная версия · ' + sinceLabel(checkedAt));
    if (node.update_checked_at) bits.push('проверка релизов · ' + sinceLabel(node.update_checked_at));
    el.setAttribute('title', bits.join(' · ') || 'Панель не отдаёт версию');
  };
  put('xui', node.xui_version || '', node.panel_latest_version || '', node.version_checked_at, 'Панель 3x-ui на сервере', 'panel');
  put('xray', node.xray_version || '', node.xray_latest_version || '', node.version_checked_at, 'Ядро Xray на сервере', 'xray');
}

function formatRps(value) {
  const number = Number(value || 0);
  if (number <= 0) return '0';
  if (number >= 10) return number.toFixed(1);
  if (number >= 1) return number.toFixed(2);
  return number.toFixed(3);
}

function moscowParts(epoch) {
  const shifted = new Date((Number(epoch) + 3 * 3600) * 1000);
  const pad = (n) => String(n).padStart(2, '0');
  return {
    dd: pad(shifted.getUTCDate()),
    mo: pad(shifted.getUTCMonth() + 1),
    hh: pad(shifted.getUTCHours()),
    mm: pad(shifted.getUTCMinutes()),
  };
}

function axisTime(epoch, span) {
  const part = moscowParts(epoch);
  if (span === '7d') return part.dd + '.' + part.mo;
  return part.hh + ':' + part.mm;
}

function tipTime(epoch) {
  const part = moscowParts(epoch);
  return part.dd + '.' + part.mo + ' ' + part.hh + ':' + part.mm;
}

function niceCeiling(value, integer) {
  if (value <= 0) return 1;
  if (integer) return Math.max(1, Math.ceil(value * 1.25));
  const padded = value * 1.15;
  const pow = Math.pow(10, Math.floor(Math.log10(padded)));
  const scaled = padded / pow;
  const step = scaled <= 1 ? 1 : scaled <= 2 ? 2 : scaled <= 5 ? 5 : 10;
  return step * pow;
}

function drawGraf(panel, model) {
  const plot = panel.querySelector('[data-graf-plot]');
  const legend = panel.querySelector('[data-graf-legend]');
  const empty = panel.querySelector('[data-graf-empty]');
  const now = panel.querySelector('[data-graf-now]');
  const avg = panel.querySelector('[data-graf-avg]');
  if (now) now.textContent = model.now;
  if (avg) avg.textContent = model.avg;
  if (!plot) return;
  plot.querySelectorAll('svg, .graf-tip').forEach((node) => node.remove());
  if (empty) empty.hidden = !model.empty;
  legend.innerHTML = '';
  if (model.empty || !model.times.length) {
    model.series.forEach((series) => {
      const key = document.createElement('span');
      key.className = 'graf-key';
      key.innerHTML = '<i class="graf-swatch" style="background:' + series.color + '"></i>' + series.name;
      legend.appendChild(key);
    });
    return;
  }
  const width = Math.max(280, Math.round(plot.clientWidth || 640));
  const height = 240;
  const pad = { l: 52, r: 12, t: 10, b: 26 };
  const max = niceCeiling(Math.max(...model.series.flatMap((series) => series.values), 0), model.integer);
  const innerW = width - pad.l - pad.r;
  const innerH = height - pad.t - pad.b;
  const xOf = (index) => {
    if (model.times.length <= 1) return pad.l + innerW / 2;
    return pad.l + (innerW * index) / (model.times.length - 1);
  };
  const yOf = (value) => pad.t + innerH - (Number(value) / max) * innerH;
  const svg = document.createElementNS('http://www.w3.org/2000/svg', 'svg');
  svg.setAttribute('viewBox', '0 0 ' + width + ' ' + height);
  svg.setAttribute('width', String(width));
  svg.setAttribute('height', String(height));
  const defs = document.createElementNS('http://www.w3.org/2000/svg', 'defs');
  svg.appendChild(defs);
  for (let tick = 0; tick <= 4; tick += 1) {
    const value = (max * tick) / 4;
    const y = yOf(value);
    const grid = document.createElementNS('http://www.w3.org/2000/svg', 'line');
    grid.setAttribute('x1', String(pad.l));
    grid.setAttribute('x2', String(width - pad.r));
    grid.setAttribute('y1', String(y));
    grid.setAttribute('y2', String(y));
    grid.setAttribute('stroke', 'rgba(204,204,220,0.15)');
    grid.setAttribute('stroke-dasharray', '4 4');
    svg.appendChild(grid);
    const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    label.setAttribute('x', String(pad.l - 8));
    label.setAttribute('y', String(y + 4));
    label.setAttribute('text-anchor', 'end');
    label.setAttribute('fill', '#8e8ea0');
    label.setAttribute('font-size', '11');
    label.textContent = model.integer ? String(Math.round(value)) : formatRps(value);
    svg.appendChild(label);
  }
  const labelStep = Math.max(1, Math.ceil(model.times.length / (width < 520 ? 4 : 6)));
  model.times.forEach((epoch, index) => {
    if (index % labelStep !== 0 && index !== model.times.length - 1) return;
    const label = document.createElementNS('http://www.w3.org/2000/svg', 'text');
    label.setAttribute('x', String(xOf(index)));
    label.setAttribute('y', String(height - 6));
    label.setAttribute('text-anchor', index === 0 ? 'start' : 'middle');
    label.setAttribute('fill', '#8e8ea0');
    label.setAttribute('font-size', '11');
    label.textContent = axisTime(epoch, model.span);
    svg.appendChild(label);
  });
  model.series.forEach((series, seriesIndex) => {
    const grad = document.createElementNS('http://www.w3.org/2000/svg', 'linearGradient');
    const gradId = 'graf-' + model.key + '-' + seriesIndex;
    grad.setAttribute('id', gradId);
    grad.setAttribute('x1', '0');
    grad.setAttribute('y1', '0');
    grad.setAttribute('x2', '0');
    grad.setAttribute('y2', '1');
    [['0', '0.35'], ['1', '0']].forEach((pair) => {
      const stop = document.createElementNS('http://www.w3.org/2000/svg', 'stop');
      stop.setAttribute('offset', pair[0]);
      stop.setAttribute('stop-color', series.color);
      stop.setAttribute('stop-opacity', pair[1]);
      grad.appendChild(stop);
    });
    defs.appendChild(grad);
    const base = yOf(0);
    const line = series.values.map((value, index) => (index ? 'L' : 'M') + xOf(index).toFixed(1) + ' ' + yOf(value).toFixed(1)).join(' ');
    const area = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    area.setAttribute('d', line + ' L ' + xOf(series.values.length - 1).toFixed(1) + ' ' + base.toFixed(1) + ' L ' + xOf(0).toFixed(1) + ' ' + base.toFixed(1) + ' Z');
    area.setAttribute('fill', 'url(#' + gradId + ')');
    svg.appendChild(area);
    const stroke = document.createElementNS('http://www.w3.org/2000/svg', 'path');
    stroke.setAttribute('d', line);
    stroke.setAttribute('fill', 'none');
    stroke.setAttribute('stroke', series.color);
    stroke.setAttribute('stroke-width', '2');
    svg.appendChild(stroke);
  });
  const cross = document.createElementNS('http://www.w3.org/2000/svg', 'line');
  cross.setAttribute('y1', String(pad.t));
  cross.setAttribute('y2', String(height - pad.b));
  cross.setAttribute('stroke', 'rgba(204,204,220,0.45)');
  cross.setAttribute('visibility', 'hidden');
  svg.appendChild(cross);
  plot.appendChild(svg);
  const tip = document.createElement('div');
  tip.className = 'graf-tip';
  tip.hidden = true;
  plot.appendChild(tip);
  model.series.forEach((series) => {
    const key = document.createElement('span');
    key.className = 'graf-key';
    key.dataset.legend = series.name;
    key.innerHTML = '<i class="graf-swatch" style="background:' + series.color + '"></i><span></span>';
    legend.appendChild(key);
  });
  const paintLegend = (index) => {
    model.series.forEach((series) => {
      const key = legend.querySelector('[data-legend="' + series.name + '"] span');
      if (!key) return;
      const value = series.values[index];
      key.textContent = series.name + ' ' + (model.integer ? String(value) : formatRps(value));
    });
  };
  paintLegend(model.times.length - 1);
  const showAt = (clientX) => {
    const box = svg.getBoundingClientRect();
    const rel = (clientX - box.left) / box.width;
    let nearest = 0;
    let best = Infinity;
    model.times.forEach((_, index) => {
      const dist = Math.abs(xOf(index) / width - rel);
      if (dist < best) {
        best = dist;
        nearest = index;
      }
    });
    const x = xOf(nearest);
    cross.setAttribute('x1', String(x));
    cross.setAttribute('x2', String(x));
    cross.setAttribute('visibility', 'visible');
    const rows = model.series.map((series) => {
      const value = model.integer ? String(series.values[nearest]) : formatRps(series.values[nearest]);
      return '<div><i class="graf-swatch" style="background:' + series.color + '"></i> ' + series.name + ' ' + value + '</div>';
    }).join('');
    tip.innerHTML = '<strong>' + tipTime(model.times[nearest]) + '</strong>' + rows;
    tip.hidden = false;
    const local = clientX - plot.getBoundingClientRect().left;
    const tipWidth = tip.offsetWidth || 140;
    tip.style.left = Math.max(8, Math.min(local + 12, plot.clientWidth - tipWidth - 8)) + 'px';
    tip.style.top = '8px';
    paintLegend(nearest);
  };
  plot.onpointermove = (event) => showAt(event.clientX);
  plot.onpointerleave = () => {
    cross.setAttribute('visibility', 'hidden');
    tip.hidden = true;
    paintLegend(model.times.length - 1);
  };
  plot._graf = model;
}

function mountSitePage() {
  const node = document.getElementById('site-series');
  if (!node || node.dataset.bound) return;
  node.dataset.bound = '1';
  let payload = JSON.parse(node.textContent || '{}');
  const panels = {
    rps: document.querySelector('[data-graf="rps"]'),
    people: document.querySelector('[data-graf="people"]'),
  };
  const show = (data) => {
    payload = data;
    document.querySelectorAll('[data-span]').forEach((btn) => {
      btn.classList.toggle('on', btn.dataset.span === data.span);
    });
    const quiet = !data.collecting && !data.samples;
    drawGraf(panels.rps, {
      key: 'rps',
      integer: false,
      empty: quiet,
      now: data.rps.now_label,
      avg: 'среднее ' + data.rps.avg_label,
      span: data.span,
      times: (data.rps.points || []).map((point) => point.t),
      series: [
        { name: 'Все запросы', color: '#5794F2', values: (data.rps.points || []).map((point) => point.all) },
        { name: 'Без ботов', color: '#73BF69', values: (data.rps.points || []).map((point) => point.human) },
      ],
    });
    drawGraf(panels.people, {
      key: 'people',
      integer: true,
      empty: quiet,
      now: String(data.people.new),
      avg: 'на сайте ' + data.people.unique,
      span: data.span,
      times: (data.people.points || []).map((point) => point.t),
      series: [
        { name: 'На сайте', color: '#73BF69', values: (data.people.points || []).map((point) => point.active) },
        { name: 'Впервые', color: '#F2CC0C', values: (data.people.points || []).map((point) => point.new) },
      ],
    });
  };
  show(payload);
  document.querySelectorAll('[data-span]').forEach((btn) => {
    btn.addEventListener('click', async () => {
      try {
        show(await api('/api/site?span=' + btn.dataset.span));
      } catch (err) {
        toast(err.message, 'err');
      }
    });
  });
  window.addEventListener('resize', () => show(payload));
  setInterval(async () => {
    if (document.hidden) return;
    try {
      show(await api('/api/site?span=' + (payload.span || '24h')));
    } catch (err) {}
  }, 30000);
}

function watchPresence(after) {
  const everyMs = 10000;
  let timer = 0;
  let busy = false;

  async function tick() {
    if (document.hidden || busy) return;
    busy = true;
    try {
      const data = await api('/api/presence');
      applyClientPresence(data.clients);
      if (after) after();
    } catch (err) {
      // Последний статус остаётся на экране, страница не перезагружается.
    } finally {
      busy = false;
    }
  }

  document.addEventListener('visibilitychange', () => {
    if (!document.hidden) tick();
  });
  timer = setInterval(tick, everyMs);
  return { tick, stop() { clearInterval(timer); } };
}

function bindFolds(root) {
  root.querySelectorAll('details.fold[data-fold]').forEach((el) => {
    const store = 'fold-' + el.dataset.fold;
    if (localStorage.getItem(store) === '0') el.open = false;
    el.addEventListener('toggle', () => {
      localStorage.setItem(store, el.open ? '1' : '0');
    });
  });
}

// Пикер шаблонов входов на «Обзоре». Общие обработчики вешаются один раз.
let tplGlobalsBound = false;

function initTemplatePicker(scope) {
  const root = scope || document;
  const logTarget = () => document.getElementById('node-action-log');

  const esc = (value) => String(value).replace(/[&<>"]/g, (ch) => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;' }[ch]));

  function dropdownRoot(el) {
    const near = el.closest('.tpl-dropdown');
    if (near) return near;
    const host = el.closest('[data-node-id]');
    const id = host && host.dataset.nodeId;
    return id ? document.querySelector('.tpl-dropdown[data-node-id="' + id + '"]') : null;
  }
  function panelOf(nodeRoot) {
    if (!nodeRoot) return null;
    // Панель при открытии переезжает в body, поэтому ищем по всему документу.
    return document.querySelector('.tpl-dropdown__panel[data-node-id="' + nodeRoot.dataset.nodeId + '"]');
  }
  function boxOf(nodeRoot) {
    return panelOf(nodeRoot) || nodeRoot;
  }
  function placePanel(nodeRoot) {
    const trigger = nodeRoot.querySelector('.tpl-dropdown__trigger');
    const panel = panelOf(nodeRoot);
    if (!trigger || !panel) return;
    if (panel.parentElement !== document.body) document.body.appendChild(panel);
    panel.hidden = false;
    const rect = trigger.getBoundingClientRect();
    const margin = 8;
    const gap = 6;
    const width = Math.min(380, window.innerWidth - margin * 2);
    let left = rect.left;
    if (left + width > window.innerWidth - margin) left = window.innerWidth - margin - width;
    if (left < margin) left = margin;
    panel.style.left = left + 'px';
    panel.style.width = width + 'px';
    const height = panel.offsetHeight;
    const spaceBelow = window.innerHeight - rect.bottom - gap - margin;
    const spaceAbove = rect.top - gap - margin;
    let top = rect.bottom + gap;
    if (spaceBelow < height && spaceAbove > spaceBelow) top = rect.top - gap - height;
    if (top < margin) top = margin;
    if (top + height > window.innerHeight - margin) top = Math.max(margin, window.innerHeight - margin - height);
    panel.style.top = top + 'px';
  }
  function selectedIds(nodeRoot) {
    return [...boxOf(nodeRoot).querySelectorAll('.tpl-option input:checked')].map((i) => Number(i.value));
  }
  function refreshTrigger(nodeRoot) {
    const inner = nodeRoot.querySelector('.tpl-dropdown__trigger-inner');
    if (!inner) return;
    const checked = [...boxOf(nodeRoot).querySelectorAll('.tpl-option input:checked')];
    if (!checked.length) {
      inner.innerHTML = '<span class="tpl-dropdown__count">0</span><span class="tpl-dropdown__empty">Выберите входы</span>';
      syncClash(nodeRoot);
      return;
    }
    const pills = checked.map((input) => {
      const option = input.closest('.tpl-option');
      const name = option && option.querySelector('.tpl-option__name') ? option.querySelector('.tpl-option__name').textContent.trim() : '';
      const port = input.dataset.port || '';
      const flagsHost = option ? option.querySelector('.tpl-option__flags') : null;
      const flags = flagsHost ? flagsHost.innerHTML : '';
      const flagHtml = flags ? '<span class="tpl-pill__flags">' + flags + '</span>' : '';
      return '<span class="tpl-pill">' + flagHtml
        + '<span class="tpl-pill__name" title="' + esc(name) + '">' + esc(name) + '</span>'
        + '<span class="tpl-pill__port">' + esc(port || '—') + '</span></span>';
    }).join('');
    inner.innerHTML = '<span class="tpl-dropdown__count">' + checked.length + '</span><span class="tpl-dropdown__preview">' + pills + '</span>';
    syncClash(nodeRoot);
  }
  function clashesOf(nodeRoot) {
    const byPort = new Map();
    boxOf(nodeRoot).querySelectorAll('.tpl-option input:checked').forEach((input) => {
      const port = input.dataset.port || '';
      const option = input.closest('.tpl-option');
      const nameHost = option ? option.querySelector('.tpl-option__name') : null;
      const name = nameHost ? nameHost.textContent.trim() : port;
      if (!byPort.has(port)) byPort.set(port, []);
      byPort.get(port).push(name);
    });
    const clashes = [];
    byPort.forEach((names, port) => {
      if (names.length > 1) {
        const titled = names.map((item) => '«' + item + '»').join(' и ');
        clashes.push('Порт ' + port + ' уже занят входами ' + titled + '. Можно оставить только один.');
      }
    });
    return clashes;
  }
  function syncClash(nodeRoot) {
    if (!nodeRoot) return [];
    const clashes = clashesOf(nodeRoot);
    const blocked = clashes.length > 0;
    boxOf(nodeRoot).querySelectorAll('[data-save-templates], [data-refresh-templates]').forEach((btn) => {
      btn.disabled = blocked;
    });
    const panel = panelOf(nodeRoot);
    let hint = panel && panel.querySelector('.tpl-clash');
    if (!hint && panel) {
      hint = document.createElement('div');
      hint.className = 'hint tpl-clash';
      const foot = panel.querySelector('.tpl-dropdown__foot');
      if (foot) foot.before(hint);
    }
    if (!hint) return clashes;
    hint.hidden = !blocked;
    hint.textContent = clashes.join(' ');
    return clashes;
  }
  function closeAll(except) {
    document.querySelectorAll('.tpl-dropdown').forEach((nodeRoot) => {
      if (except && nodeRoot === except) return;
      const panel = panelOf(nodeRoot);
      const trigger = nodeRoot.querySelector('.tpl-dropdown__trigger');
      if (panel) panel.hidden = true;
      if (trigger) trigger.setAttribute('aria-expanded', 'false');
      nodeRoot.classList.remove('open');
    });
  }
  function repositionOpen() {
    const nodeRoot = document.querySelector('.tpl-dropdown.open');
    if (!nodeRoot) return;
    const trigger = nodeRoot.querySelector('.tpl-dropdown__trigger');
    const rect = trigger.getBoundingClientRect();
    if (rect.bottom < 0 || rect.top > window.innerHeight) {
      closeAll();
      return;
    }
    placePanel(nodeRoot);
  }
  async function saveTemplates(btn, nodeId, path) {
    const nodeRoot = document.querySelector('.tpl-dropdown[data-node-id="' + nodeId + '"]');
    if (!nodeRoot) return;
    const clashes = syncClash(nodeRoot);
    if (clashes.length) {
      const text = clashes.join('\n');
      showLog(logTarget(), text);
      toast(text, 'err');
      return;
    }
    const ids = selectedIds(nodeRoot);
    try {
      const res = await withBusy(btn, () => api(path, 'POST', { template_ids: ids }));
      const text = (res.logs || []).join('\n') || 'Готово';
      showLog(logTarget(), text);
      toast(text, res.ok ? undefined : 'err');
      closeAll();
      if (res.ok) setTimeout(() => location.reload(), 1200);
    } catch (e) { showLog(logTarget(), e.message); }
  }

  root.querySelectorAll('.tpl-dropdown__trigger').forEach((btn) => {
    if (btn.dataset.tplBound) return;
    btn.dataset.tplBound = '1';
    btn.addEventListener('click', (e) => {
      e.stopPropagation();
      const nodeRoot = dropdownRoot(btn);
      const open = nodeRoot.classList.contains('open');
      closeAll();
      if (!open) {
        nodeRoot.classList.add('open');
        btn.setAttribute('aria-expanded', 'true');
        placePanel(nodeRoot);
      }
    });
  });
  root.querySelectorAll('.tpl-dropdown__panel').forEach((panel) => {
    if (panel.dataset.tplBound) return;
    panel.dataset.tplBound = '1';
    panel.addEventListener('click', (e) => e.stopPropagation());
  });
  root.querySelectorAll('.tpl-option input').forEach((input) => {
    if (input.dataset.tplBound) return;
    input.dataset.tplBound = '1';
    input.addEventListener('change', () => {
      const nodeRoot = dropdownRoot(input);
      refreshTrigger(nodeRoot);
      syncClash(nodeRoot);
    });
  });
  root.querySelectorAll('[data-tpl-all], [data-tpl-none]').forEach((btn) => {
    if (btn.dataset.tplBound) return;
    btn.dataset.tplBound = '1';
    btn.addEventListener('click', () => {
      const nodeRoot = dropdownRoot(btn);
      boxOf(nodeRoot).querySelectorAll('.tpl-option input').forEach((i) => { i.checked = btn.hasAttribute('data-tpl-all'); });
      refreshTrigger(nodeRoot);
      syncClash(nodeRoot);
    });
  });
  root.querySelectorAll('[data-save-templates]').forEach((btn) => {
    if (btn.dataset.tplBound) return;
    btn.dataset.tplBound = '1';
    btn.addEventListener('click', () => saveTemplates(btn, btn.dataset.saveTemplates, '/api/nodes/' + btn.dataset.saveTemplates + '/templates'));
  });
  root.querySelectorAll('[data-refresh-templates]').forEach((btn) => {
    if (btn.dataset.tplBound) return;
    btn.dataset.tplBound = '1';
    btn.addEventListener('click', () => saveTemplates(btn, btn.dataset.refreshTemplates, '/api/nodes/' + btn.dataset.refreshTemplates + '/refresh-templates'));
  });
  root.querySelectorAll('[data-refresh-all]').forEach((btn) => {
    if (btn.dataset.tplBound) return;
    btn.dataset.tplBound = '1';
    btn.addEventListener('click', async () => {
      try {
        const res = await withBusy(btn, () => api('/api/nodes/refresh-templates', 'POST', {}));
        const text = (res.logs || []).join('\n') || 'Готово';
        showLog(logTarget(), text);
        toast(text, res.ok ? undefined : 'err');
        if (res.ok) setTimeout(() => location.reload(), 1200);
      } catch (e) { showLog(logTarget(), e.message); }
    });
  });
  if (!tplGlobalsBound) {
    tplGlobalsBound = true;
    window.addEventListener('resize', repositionOpen);
    document.addEventListener('scroll', repositionOpen, true);
    document.addEventListener('click', () => closeAll());
  }
  root.querySelectorAll('.tpl-dropdown').forEach((nodeRoot) => syncClash(nodeRoot));
}

// Кнопки клиентов (форма доступа, +30 дней, YAML, удалить, «Сверить с серверами»).
// Разметка модалок — _client_controls.html, logId — куда писать логи сверки и создания.
function initClientControls(scope, logId) {
  const root = scope || document;
  const form = document.getElementById('client-form');
  if (!form) return;
  const log = document.getElementById(logId || 'log');
  const enableWrap = document.getElementById('enable-wrap');
  const title = document.getElementById('client-title');
  const subtitle = document.getElementById('client-sub');
  const submit = document.getElementById('client-submit');

  function openClientForm(data) {
    form.reset();
    form.id.value = '';
    form.days.value = 30;
    form.traffic_gb.value = 0;
    form.limit_ip.value = 0;
    form.enable.checked = true;
    enableWrap.hidden = true;
    title.textContent = 'Новый доступ';
    subtitle.textContent = 'Срок 0 — без ограничения по дате. Трафик 0 — без лимита гигабайт.';
    submit.textContent = 'Создать и завести на серверах';
    if (data) {
      form.id.value = data.id;
      form.name.value = data.name || '';
      form.days.value = data.days ?? 0;
      form.traffic_gb.value = data.traffic_gb ?? 0;
      form.limit_ip.value = data.limit_ip ?? 0;
      form.note.value = data.note || '';
      form.enable.checked = data.enable !== false;
      enableWrap.hidden = false;
      title.textContent = 'Изменить доступ';
      subtitle.textContent = 'UUID и ссылка не меняются. После сохранения Master обновит панели.';
      submit.textContent = 'Сохранить';
    }
    openModal('add-client');
  }

  form.onsubmit = async (event) => {
    event.preventDefault();
    const fields = event.target;
    const btn = fields.querySelector('button[type=submit]');
    const id = fields.id.value;
    const payload = {
      name: fields.name.value,
      days: Number(fields.days.value),
      traffic_gb: Number(fields.traffic_gb.value),
      limit_ip: Number(fields.limit_ip.value),
      note: fields.note.value,
    };
    if (id) payload.enable = fields.enable.checked;
    try {
      const data = await withBusy(btn, () => id
        ? api('/api/clients/' + id, 'PATCH', payload)
        : api('/api/clients', 'POST', payload));
      if (!id && data.client && data.client.sub_url) {
        await copyText(data.client.sub_url);
      } else {
        toast(id ? 'Клиент сохранён' : 'Клиент создан');
      }
      showLog(log, data.logs);
      setTimeout(() => location.reload(), 450);
    } catch (err) {}
  };

  root.querySelectorAll('[data-new-client]').forEach((btn) => {
    if (btn.dataset.ccBound) return;
    btn.dataset.ccBound = '1';
    btn.addEventListener('click', () => openClientForm());
  });
  root.querySelectorAll('[data-edit]').forEach((btn) => {
    if (btn.dataset.ccBound) return;
    btn.dataset.ccBound = '1';
    btn.addEventListener('click', () => {
      try {
        openClientForm(JSON.parse(btn.dataset.edit));
      } catch (err) {
        toast('Не удалось открыть форму', 'err');
      }
    });
  });
  root.querySelectorAll('[data-add]').forEach((btn) => {
    if (btn.dataset.ccBound) return;
    btn.dataset.ccBound = '1';
    btn.addEventListener('click', async () => {
      try {
        await withBusy(btn, () => api('/api/clients/' + btn.dataset.add, 'PATCH', {add_days: 30}));
        toast('Продлено на 30 дней');
        location.reload();
      } catch (err) {
        toast(err.message, 'err');
      }
    });
  });
  root.querySelectorAll('[data-prev]').forEach((btn) => {
    if (btn.dataset.ccBound) return;
    btn.dataset.ccBound = '1';
    btn.addEventListener('click', async () => {
      try {
        const data = await withBusy(btn, () => api('/api/clients/' + btn.dataset.prev + '/preview'));
        document.getElementById('yaml-view').textContent = data.yaml;
        openModal('yaml-drawer');
      } catch (err) {
        toast(err.message, 'err');
      }
    });
  });
  root.querySelectorAll('[data-del]').forEach((btn) => {
    if (btn.dataset.ccBound) return;
    btn.dataset.ccBound = '1';
    btn.addEventListener('click', async () => {
      if (!confirm('Удалить человека с серверов и из Master? Ссылка сразу перестанет открываться.')) return;
      try {
        const result = await withBusy(btn, () => api('/api/clients/' + btn.dataset.del, 'DELETE'));
        if (!result.ok) {
          toast((result.logs || []).join(' · ') || 'Повторите удаление', 'err');
          return;
        }
        location.reload();
      } catch (err) {
        toast(err.message, 'err');
      }
    });
  });
  const reconcile = root.getElementById ? root.getElementById('reconcile') : document.getElementById('reconcile');
  if (reconcile && !reconcile.dataset.ccBound) {
    reconcile.dataset.ccBound = '1';
    reconcile.addEventListener('click', async (event) => {
      const btn = event.currentTarget;
      try {
        const data = await withBusy(btn, () => api('/api/clients/reconcile', 'POST', {}));
        toast('Сверка закончилась');
        showLog(log, data.logs);
      } catch (err) {}
    });
  }
}

function bindNodeRemoval() {
  document.querySelectorAll('[data-del-node]').forEach((btn) => {
    if (btn.dataset.nodeDelBound) return;
    btn.dataset.nodeDelBound = '1';
    btn.addEventListener('click', async () => {
      const name = btn.closest('[data-node]')?.dataset.name || ('№' + btn.dataset.delNode);
      if (!confirm('Убрать «' + name + '» из Master? Панель на сервере сохранится.')) return;
      try {
        await api('/api/nodes/' + btn.dataset.delNode, 'DELETE');
        location.reload();
      } catch (err) { toast('Удаление «' + name + '»: ' + err.message, 'err'); }
    });
  });
}

// Форма добавления сервера: переключатель «панель стоит / чистый VPS» и отправка.
// Разметка модалки — _node_controls.html.
function initNodeForm() {
  bindNodeRemoval();
  const nodeForm = document.getElementById('node-form');
  if (!nodeForm || nodeForm.dataset.nfBound) return;
  nodeForm.dataset.nfBound = '1';

  function installKind() {
    const picked = nodeForm.querySelector('input[name=install_kind]:checked');
    return picked ? picked.value : 'xui';
  }

  function applyNodeSource() {
    const install = nodeForm.source.value === 'install';
    const grafana = install && installKind() === 'grafana';
    document.getElementById('source-existing').hidden = install;
    document.getElementById('source-install').hidden = !install;
    nodeForm.panel_url.required = !install;
    nodeForm.api_token.required = !install;
    nodeForm.host.required = install;
    nodeForm.ssh_password.required = false;
    nodeForm.clash_name.required = !grafana;
    const flagBox = document.getElementById('node-flag');
    const clashField = document.getElementById('clash-field');
    const identity = document.getElementById('node-identity-label');
    if (flagBox) flagBox.hidden = grafana;
    if (clashField) clashField.hidden = grafana;
    if (identity) identity.textContent = grafana ? '1 · Название' : '1 · Флаг и имена';
    const hint = document.getElementById('install-hint');
    if (hint) {
      hint.textContent = grafana
        ? 'Пароль SSH нужен один раз, если ключа Master на сервере ещё нет. Ставятся Grafana, база метрик и сертификат Let’s Encrypt на IP. В подписку этот сервер не входит.'
        : 'Пусто, если публичный ключ Master уже добавлен у хостера. Иначе пароль нужен один раз: после проверки входа по ключу он стирается, парольный SSH выключается. Сертификат выпускается на IP, порт 80 открыт. Если на машине уже стоит x-ui, установка остановится и пароль панели не сменит.';
    }
    document.getElementById('node-submit').textContent = install
      ? (grafana ? 'Поставить Grafana' : 'Поставить 3x-ui')
      : 'Подключить';
  }

  nodeForm.querySelectorAll('input[name=source], input[name=install_kind]').forEach((input) => {
    input.addEventListener('change', applyNodeSource);
  });

  nodeForm.addEventListener('submit', async (event) => {
    event.preventDefault();
    const f = event.target;
    const install = f.source.value === 'install';
    const grafana = install && installKind() === 'grafana';
    if (!grafana && !f.flag.value) {
      toast('Выберите флаг', 'err');
      return;
    }
    const btn = f.querySelector('button[type=submit]');
    const payload = {
      flag: f.flag.value,
      name: f.name.value,
      clash_name: f.clash_name.value,
    };
    if (install) {
      payload.install = true;
      payload.install_kind = grafana ? 'grafana' : 'xui';
      payload.host = f.host.value.trim();
      payload.ssh_user = f.ssh_user.value.trim();
      payload.ssh_password = f.ssh_password.value;
    } else {
      payload.panel_url = f.panel_url.value;
      payload.api_token = f.api_token.value;
    }
    try {
      await withBusy(btn, async () => {
        const data = install ? await submitInstall('/api/nodes', payload) : await api('/api/nodes', 'POST', payload);
        if (!data) return;
        if (data.logs && data.logs.length) showLog(document.getElementById('node-log'), data.logs);
        toast(grafana ? 'Сервер в списке, Grafana ставится' : (install ? 'Сервер в списке, 3x-ui ставится' : 'Сервер добавлен'));
        setTimeout(() => location.reload(), install ? 700 : 400);
      });
    } catch (err) {}
  });
}

window.XUI = {
  api, submitInstall, toast, showLog, copyText, busy, withBusy, openModal, closeModal, bindFlagPicker,
  pullDestSni, applyDestSni, bindSort, bindFolds, applyClientPresence, applyUserStats, applyNodeRf,
  applyNodeVersions, watchPresence,
  initTemplatePicker, initClientControls, initNodeForm,
};
