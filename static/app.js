const socket = io();
let scanResults = [];
let scanMeta = {};
let startTime = null;
let timerInterval = null;
let currentMode = 'clean';

window.addEventListener('load', () => {
    loadSavedTelegramSettings();
    setMode('clean');
});

function setMode(mode) {
    currentMode = mode;
    document.getElementById('modeCleanIP').classList.toggle('active', mode === 'clean');
    document.getElementById('modeVless').classList.toggle('active', mode === 'vless');
    document.getElementById('cleanModeSettings').style.display = mode === 'clean' ? 'block' : 'none';
    document.getElementById('vlessConfigGroup').style.display = mode === 'vless' ? 'block' : 'none';
    document.getElementById('startBtnText').textContent = mode === 'clean' ? 'شروع اسکن آی‌پی تمیز' : 'شروع اسکن با کانفیگ';
    if (scanResults.length > 0) {
        document.getElementById('btnCopyConfigs').style.display = mode === 'vless' ? 'inline-flex' : 'none';
        document.getElementById('btnDlVless').style.display = mode === 'vless' ? 'inline-flex' : 'none';
    }
}

function loadSavedTelegramSettings() {
    fetch('/api/telegram/load').then(r => r.json()).then(data => {
        if (data.token) {
            document.getElementById('botToken').value = data.token;
            document.getElementById('chatId').value = data.chat_id || '';
            document.getElementById('savedBadge').style.display = 'flex';
        }
    }).catch(() => {});
}

function toggleTokenVisibility() {
    const input = document.getElementById('botToken');
    const icon = document.getElementById('tokenEyeIcon');
    if (input.type === 'password') { input.type = 'text'; icon.className = 'fas fa-eye-slash'; }
    else { input.type = 'password'; icon.className = 'fas fa-eye'; }
}

function onOperatorChange() {
    document.getElementById('customRangeGroup').style.display =
        document.getElementById('operatorSelect').value === 'custom' ? 'block' : 'none';
}

function startScan() {
    const data = {
        mode: currentMode,
        ip_count: parseInt(document.getElementById('ipCount').value) || 300,
        concurrent: parseInt(document.getElementById('concurrent').value) || 50,
        top_count: parseInt(document.getElementById('topCount').value) || 20,
        sort_by: document.getElementById('sortBy').value,
        operator: document.getElementById('operatorSelect').value,
        custom_ranges: '',
    };
    if (data.operator === 'custom') data.custom_ranges = document.getElementById('customRanges').value.trim();

    if (currentMode === 'vless') {
        const config = document.getElementById('vlessConfig').value.trim();
        if (!config) { showToast('❌ کانفیگ را وارد کنید', 'error'); return; }
        if (!config.startsWith('vless://') && !config.startsWith('trojan://')) {
            showToast('❌ کانفیگ باید با vless:// یا trojan:// شروع شود', 'error'); return;
        }
        data.config = config;
    } else {
        data.config = '';
        data.scan_port = parseInt(document.getElementById('scanPort').value) || 443;
        data.scan_sni = document.getElementById('scanSNI').value.trim() || 'speed.cloudflare.com';
        data.test_tls = document.getElementById('testTLS').checked;
        data.test_speed = document.getElementById('testSpeed').checked;
    }

    scanResults = []; scanMeta = data;
    document.getElementById('startBtn').style.display = 'none';
    document.getElementById('stopBtn').style.display = 'inline-flex';
    document.getElementById('progressPanel').style.display = 'block';
    document.getElementById('resultsPanel').style.display = 'none';
    document.getElementById('progressBar').style.width = '0%';
    document.getElementById('progressText').textContent = '0%';
    document.getElementById('scannedCount').textContent = '0';
    document.getElementById('aliveCount').textContent = '0';
    document.getElementById('deadCount').textContent = '0';
    document.getElementById('liveLog').innerHTML = '';
    startTime = Date.now();
    timerInterval = setInterval(updateTimer, 1000);
    socket.emit('start_scan', data);
}

function stopScan() {
    socket.emit('stop_scan');
    document.getElementById('startBtn').style.display = 'inline-flex';
    document.getElementById('stopBtn').style.display = 'none';
    clearInterval(timerInterval);
}

function updateTimer() {
    if (!startTime) return;
    const s = Math.floor((Date.now() - startTime) / 1000);
    document.getElementById('elapsedTime').textContent = s >= 60 ? `${Math.floor(s/60)}m ${s%60}s` : `${s}s`;
}

socket.on('scan_progress', (d) => {
    const p = Math.round((d.scanned / d.total) * 100);
    document.getElementById('progressBar').style.width = p + '%';
    document.getElementById('progressText').textContent = p + '%';
    document.getElementById('scannedCount').textContent = d.scanned;
    document.getElementById('aliveCount').textContent = d.alive;
    document.getElementById('deadCount').textContent = d.scanned - d.alive;
    if (d.last_result) {
        const log = document.getElementById('liveLog');
        const e = document.createElement('div');
        e.className = 'log-entry';
        if (d.last_result.is_alive) {
            e.className += ' log-alive';
            e.textContent = `✅ ${d.last_result.ip}:${d.last_result.port} | Ping:${d.last_result.tcp_ping}ms | Speed:${d.last_result.download_speed}KB/s | Score:${d.last_result.score}`;
        } else {
            e.className += ' log-dead';
            e.textContent = `❌ ${d.last_result.ip} - ${d.last_result.error || 'Failed'}`;
        }
        log.appendChild(e); log.scrollTop = log.scrollHeight;
        while (log.children.length > 150) log.removeChild(log.firstChild);
    }
});

socket.on('scan_complete', (d) => {
    clearInterval(timerInterval);
    document.getElementById('startBtn').style.display = 'inline-flex';
    document.getElementById('stopBtn').style.display = 'none';
    scanResults = d.results;
    scanMeta.total_scanned = d.total_scanned;
    scanMeta.total_alive = d.total_alive;
    scanMeta.elapsed = d.elapsed;
    displayResults(d);
    showToast(`✅ اسکن تمام شد! ${d.total_alive} IP زنده`);
});

socket.on('scan_error', (d) => {
    clearInterval(timerInterval);
    document.getElementById('startBtn').style.display = 'inline-flex';
    document.getElementById('stopBtn').style.display = 'none';
    showToast('❌ ' + d.error, 'error');
});

function displayResults(data) {
    document.getElementById('resultsPanel').style.display = 'block';
    const hasConfig = currentMode === 'vless';
    document.getElementById('btnCopyConfigs').style.display = hasConfig ? 'inline-flex' : 'none';
    document.getElementById('btnDlVless').style.display = hasConfig ? 'inline-flex' : 'none';

    document.getElementById('resultsSummary').innerHTML = `
        <div class="summary-card green"><div class="number">${data.total_alive}</div><div class="label">IP زنده</div></div>
        <div class="summary-card blue"><div class="number">${data.total_scanned.toLocaleString()}</div><div class="label">کل اسکن</div></div>
        <div class="summary-card yellow"><div class="number">${data.elapsed}s</div><div class="label">زمان</div></div>`;

    const tbody = document.getElementById('resultsBody');
    tbody.innerHTML = '';
    data.results.forEach((r, i) => {
        const sc = r.score >= 60 ? 'score-high' : r.score >= 30 ? 'score-mid' : 'score-low';
        const m = i === 0 ? '🥇' : i === 1 ? '🥈' : i === 2 ? '🥉' : (i+1);
        let cb = '';
        if (hasConfig && r.vless_url) cb = `<button class="btn-copy-row" onclick="copyConfig(\`${escapeBacktick(r.vless_url)}\`)"><i class="fas fa-link"></i></button>`;
        const tr = document.createElement('tr');
        tr.innerHTML = `<td>${m}</td><td><code>${r.ip}</code></td><td>${r.port}</td><td>${r.tcp_ping}</td><td>${r.tls_handshake_time||'-'}</td><td>${r.http_status||'-'}</td><td>${r.download_speed||'-'}</td><td class="${sc}">${r.score}</td><td><button class="btn-copy-row" onclick="copySingleIP(this,'${r.ip}')"><i class="fas fa-copy"></i> IP</button>${cb}</td>`;
        tbody.appendChild(tr);
    });

    const ipList = document.getElementById('ipList');
    ipList.innerHTML = '';
    data.results.forEach((r, i) => {
        const m = i === 0 ? '🥇' : i === 1 ? '🥈' : i === 2 ? '🥉' : `${i+1}.`;
        const item = document.createElement('div');
        item.className = 'ip-item';
        item.innerHTML = `<span class="ip-item-rank">${m}</span><span class="ip-item-text">${r.ip}</span><button class="ip-item-copy" onclick="copySingleIP(this,'${r.ip}')"><i class="fas fa-copy"></i> کپی</button>`;
        ipList.appendChild(item);
    });
    document.getElementById('resultsPanel').scrollIntoView({behavior:'smooth'});
}

function copySingleIP(btn, ip) {
    navigator.clipboard.writeText(ip).then(() => {
        const o = btn.innerHTML; btn.innerHTML = '<i class="fas fa-check"></i> شد!'; btn.classList.add('copied');
        setTimeout(() => { btn.innerHTML = o; btn.classList.remove('copied'); }, 2000);
    }).catch(() => { fallbackCopy(ip); });
}
function copyConfig(url) { navigator.clipboard.writeText(url).then(() => showToast('✅ کانفیگ کپی شد')).catch(() => fallbackCopy(url)); }
function copyAllConfigs() { if (!scanResults.length) return; const a = scanResults.filter(r=>r.vless_url).map(r=>r.vless_url).join('\n'); navigator.clipboard.writeText(a).then(() => showToast(`✅ ${scanResults.length} کانفیگ کپی شد`)).catch(() => fallbackCopy(a)); }
function copyAllIPs() { if (!scanResults.length) return; const a = scanResults.map(r=>r.ip).join('\n'); navigator.clipboard.writeText(a).then(() => showToast(`✅ ${scanResults.length} IP کپی شد`)).catch(() => fallbackCopy(a)); }

function downloadResults(fmt) {
    if (!scanResults.length) return;
    let c, f, t;
    if (fmt === 'json') { c = JSON.stringify(scanResults,null,2); f = 'cf_results.json'; t = 'application/json'; }
    else if (fmt === 'ip') { c = scanResults.map(r=>r.ip).join('\n'); f = 'cf_clean_ips.txt'; t = 'text/plain'; }
    else { c = scanResults.filter(r=>r.vless_url).map(r=>r.vless_url).join('\n'); f = 'cf_configs.txt'; t = 'text/plain'; }
    const b = new Blob([c],{type:t}); const u = URL.createObjectURL(b);
    const a = document.createElement('a'); a.href = u; a.download = f; document.body.appendChild(a); a.click(); document.body.removeChild(a); URL.revokeObjectURL(u);
    showToast(`📥 ${f} دانلود شد`);
}

function testTelegram() {
    const token = document.getElementById('botToken').value.trim();
    const st = document.getElementById('telegramStatus');
    if (!token) { st.textContent = '❌ توکن خالی'; st.className = 'error'; return; }
    st.textContent = '⏳ تست...'; st.className = '';
    fetch('/api/telegram/test', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({token}) })
    .then(r=>r.json()).then(d => { if (d.success) { st.textContent = '✅ @' + (d.bot_name||''); st.className = 'success'; } else { st.textContent = '❌ ' + d.error; st.className = 'error'; } })
    .catch(() => { st.textContent = '❌ خطا'; st.className = 'error'; });
}

function saveTelegramSettings() {
    const token = document.getElementById('botToken').value.trim();
    const chatId = document.getElementById('chatId').value.trim();
    if (!token) { showToast('❌ توکن خالی','error'); return; }
    fetch('/api/telegram/save', { method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify({token,chat_id:chatId}) })
    .then(r=>r.json()).then(d => { if (d.success) { showToast('✅ ذخیره شد'); document.getElementById('savedBadge').style.display = 'flex'; } });
}

function deleteTelegramSettings() {
    fetch('/api/telegram/delete',{method:'POST'}).then(() => {
        document.getElementById('botToken').value = ''; document.getElementById('chatId').value = '';
        document.getElementById('savedBadge').style.display = 'none'; document.getElementById('telegramStatus').textContent = '';
        showToast('🗑️ حذف شد');
    });
}

function sendToTelegram() {
    const token = document.getElementById('botToken').value.trim();
    const chatId = document.getElementById('chatId').value.trim();
    if (!token || !chatId) { showToast('❌ توکن و Chat ID لازمه','error'); return; }
    if (!scanResults.length) { showToast('❌ نتایجی نیست','error'); return; }
    showToast('⏳ ارسال...');
    fetch('/api/telegram/send', { method:'POST', headers:{'Content-Type':'application/json'},
        body:JSON.stringify({ token, chat_id:chatId, results:scanResults, operator:scanMeta.operator||'all', total_scanned:scanMeta.total_scanned||0, total_found:scanMeta.total_alive||0 }) })
    .then(r=>r.json()).then(d => { if (d.success) showToast('✅ ارسال شد'); else showToast('❌ '+d.error,'error'); });
}

function showToast(msg, type='info') {
    const c = document.getElementById('toastContainer'); const t = document.createElement('div'); t.className = 'toast';
    if (type === 'error') { t.style.borderColor = 'var(--red)'; t.style.boxShadow = '0 5px 25px rgba(239,68,68,.3)'; }
    t.textContent = msg; c.appendChild(t); setTimeout(() => { if (t.parentNode) t.remove(); }, 3000);
}
function escapeBacktick(s) { return s ? s.replace(/`/g,'\\`') : ''; }
function fallbackCopy(text) {
    const ta = document.createElement('textarea'); ta.value = text; ta.style.cssText = 'position:fixed;left:-9999px';
    document.body.appendChild(ta); ta.select(); try { document.execCommand('copy'); } catch(e) {} document.body.removeChild(ta);
}
