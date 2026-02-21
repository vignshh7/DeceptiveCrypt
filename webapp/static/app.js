let selectedFile = null;
let lastLogId = 0;

const el = (id) => document.getElementById(id);

function setStatus(mode, ransomwareDetected) {
  const pill = el('statusPill');
  if (mode === 'HONEY' || ransomwareDetected) {
    pill.textContent = '🔴 Ransomware Detected (Honey Encryption)';
    pill.style.borderColor = 'rgba(251,113,133,0.35)';
    pill.style.background = 'rgba(251,113,133,0.14)';
  } else {
    pill.textContent = '🟢 Normal (AES)';
    pill.style.borderColor = 'rgba(45,212,191,0.35)';
    pill.style.background = 'rgba(45,212,191,0.15)';
  }
}

async function apiGet(path) {
  const res = await fetch(path);
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

async function apiPost(path, body) {
  const res = await fetch(path, {
    method: 'POST',
    headers: { 'Content-Type': 'application/json' },
    body: body ? JSON.stringify(body) : '{}'
  });
  if (!res.ok) throw new Error(await res.text());
  return res.json();
}

function showModal(file) {
  selectedFile = file;
  el('modalTitle').textContent = `Open ${file.display_name}`;
  el('contentBox').textContent = '(no content yet)';
  el('secretKey').value = '';
  el('modalBackdrop').classList.remove('hidden');
  setTimeout(() => el('secretKey').focus(), 50);
}

function hideModal() {
  selectedFile = null;
  el('modalBackdrop').classList.add('hidden');
}

function appendLogs(entries) {
  const panel = el('logPanel');
  for (const e of entries) {
    const line = document.createElement('div');
    line.className = 'logLine';

    const lvl = document.createElement('span');
    lvl.className = `lvl lvl-${e.level}`;
    lvl.textContent = `[${e.level}]`;

    const msg = document.createElement('span');
    msg.textContent = ' ' + e.message;

    line.appendChild(lvl);
    line.appendChild(msg);
    panel.appendChild(line);

    lastLogId = Math.max(lastLogId, e.id);
  }

  panel.scrollTop = panel.scrollHeight;
}

async function refreshStatus() {
  const s = await apiGet('/api/status');
  setStatus(s.mode, s.ransomware_detected);
}

async function loadFiles() {
  const data = await apiGet('/api/files');
  const list = el('fileList');
  list.innerHTML = '';

  for (const f of data) {
    const item = document.createElement('div');
    item.className = 'fileItem';

    const name = document.createElement('div');
    name.className = 'fileName';
    name.textContent = f.display_name;

    const btn = document.createElement('button');
    btn.className = 'btn primary';
    btn.textContent = 'Open';
    btn.addEventListener('click', () => showModal(f));

    item.appendChild(name);
    item.appendChild(btn);
    list.appendChild(item);
  }
}

async function pollLogs() {
  try {
    const data = await apiGet(`/api/logs?after_id=${lastLogId}`);
    if (data.entries && data.entries.length) appendLogs(data.entries);
  } catch (e) {
    // Ignore transient errors
  }
}

async function openSelectedFile() {
  if (!selectedFile) return;
  const secret_key = el('secretKey').value || '';
  const resp = await apiPost(`/api/files/${selectedFile.file_id}/open`, { secret_key });
  el('contentBox').textContent = resp.content;
  await refreshStatus();
}

async function simulateRansomware() {
  await apiPost('/api/simulate_ransomware');
  await refreshStatus();
}

async function resetSystem() {
  await apiPost('/api/reset');
  lastLogId = 0;
  el('logPanel').innerHTML = '';
  await refreshStatus();
}

function wireUI() {
  el('btnSim').addEventListener('click', async () => {
    try { await simulateRansomware(); } catch (e) { alert('Failed: ' + e); }
  });

  el('btnReset').addEventListener('click', async () => {
    try { await resetSystem(); } catch (e) { alert('Failed: ' + e); }
  });

  el('modalClose').addEventListener('click', hideModal);
  el('modalBackdrop').addEventListener('click', (ev) => {
    if (ev.target.id === 'modalBackdrop') hideModal();
  });

  el('btnOpen').addEventListener('click', async () => {
    try { await openSelectedFile(); } catch (e) { alert('Failed: ' + e); }
  });

  el('secretKey').addEventListener('keydown', async (ev) => {
    if (ev.key === 'Enter') {
      try { await openSelectedFile(); } catch (e) { alert('Failed: ' + e); }
    }
  });
}

async function boot() {
  wireUI();
  await refreshStatus();
  await loadFiles();
  await pollLogs();
  setInterval(pollLogs, 700);
  setInterval(refreshStatus, 1500);
}

boot();
