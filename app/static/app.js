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
  if (!res.ok) throw new Error(detailMessage(data.detail) || res.statusText);
  return data;
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
    btn.dataset.prev = btn.textContent;
    btn.textContent = 'Секунду…';
  } else if (btn.dataset.prev) {
    btn.textContent = btn.dataset.prev;
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

document.addEventListener('click', (e) => {
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
  if (e.target.classList.contains('overlay') && e.target.id) closeModal(e.target.id);
}, true);

const FLAGS = [
  'FI', 'IT', 'DE', 'NL', 'FR', 'GB', 'US', 'ES', 'PL', 'CZ',
  'AT', 'CH', 'SE', 'NO', 'DK', 'EE', 'LV', 'LT', 'RU', 'UA',
  'TR', 'AE', 'SG', 'JP', 'KR', 'HK', 'TW', 'KZ', 'GE', 'CA',
];

function bindFlagPicker(root) {
  root.querySelectorAll('[data-flags]').forEach((box) => {
    const input = root.querySelector(`[name="${box.dataset.flags}"]`);
    if (!input) return;
    const current = (input.value || '').toUpperCase();
    box.innerHTML = FLAGS.map((code) => {
      const on = current === code ? ' on' : '';
      const src = '/static/flags/' + code.toLowerCase() + '.png';
      return `<button type="button" class="flag${on}" data-flag="${code}" title="${code}"><img src="${src}" alt="${code}"></button>`;
    }).join('');
    box.addEventListener('click', (e) => {
      const btn = e.target.closest('[data-flag]');
      if (!btn) return;
      input.value = btn.dataset.flag;
      box.querySelectorAll('.flag').forEach((el) => el.classList.toggle('on', el === btn));
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

document.addEventListener('DOMContentLoaded', () => bindFlagPicker(document));

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
        : String(av).localeCompare(String(bv), 'ru');
      return cmp * dir;
    });
    rows.forEach((row) => list.appendChild(row));
  }
  buttons.forEach((btn) => btn.addEventListener('click', (event) => {
    event.preventDefault();
    event.stopPropagation();
    const next = btn.dataset.sort;
    if (key === next) dir *= -1;
    else {
      key = next;
      dir = next === 'name' || next === 'host' ? 1 : -1;
    }
    marks();
    resort();
  }));
  return { resort };
}

function applyClientPresence(clients) {
  (clients || []).forEach((client) => {
    const row = document.querySelector('[data-client="' + client.id + '"]');
    if (!row) return;
    const online = Number(client.online_nodes || 0);
    row.dataset.online = String(online);
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
  if (!row || !node) return;
  const checked = Boolean(node.rf_checked_at);
  const ok = Boolean(node.rf_ok);
  // -1 = ещё не проверяли, 0 = из России не достучаться, 1 = достучаться.
  row.dataset.rf = checked ? (ok ? '1' : '0') : '-1';
  const label = row.querySelector('[data-rf-label]');
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

window.XUI = {
  api, toast, showLog, copyText, busy, withBusy, openModal, closeModal, bindFlagPicker,
  pullDestSni, applyDestSni, bindSort, bindFolds, applyClientPresence, applyNodeRf, watchPresence,
};
