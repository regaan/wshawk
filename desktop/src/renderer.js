/**
 * WSHawk Renderer - Premium Linear-style Aesthetic
 */

// Window Controls
document.getElementById('btn-minimize')?.addEventListener('click', () => window.api.send('window:minimize'));
document.getElementById('btn-maximize')?.addEventListener('click', () => window.api.send('window:maximize'));
document.getElementById('btn-close')?.addEventListener('click', () => window.api.send('window:close'));

const targetUrlInput = document.getElementById('target-url');
const scanBtn = document.getElementById('scan-btn');
const connPill = document.getElementById('conn-pill');
const connText = document.getElementById('conn-text');

const valVulns = document.getElementById('val-vulns');
const valMsgs = document.getElementById('val-msgs');
const valRisk = document.getElementById('val-risk');
const valProgress = document.getElementById('val-progress');
const findingsContainer = document.getElementById('findings-container');
const systemLog = document.getElementById('system-log');
const historyTbody = document.getElementById('history-tbody');
const historyCount = document.getElementById('history-count');

const LEGACY_BRIDGE_BASE = 'http://127.0.0.1:8080';
const API_URL = LEGACY_BRIDGE_BASE;
let bridgePort = 8080;
let bridgeReady = false;
let bridgeConnectRequested = false;

const rawFetch = window.fetch.bind(window);
const apiModule = window.WSHawkModules?.api;
const identitiesModule = window.WSHawkModules?.identities;
const trafficModule = window.WSHawkModules?.traffic;
const protocolModule = window.WSHawkModules?.protocol;
const attacksModule = window.WSHawkModules?.attacks;
const evidenceModule = window.WSHawkModules?.evidence;

function bridgeHttpBase() {
    return apiModule ? apiModule.bridgeHttpBase(bridgePort) : `http://127.0.0.1:${bridgePort}`;
}

function bridgeWebSocketUrl(path) {
    return apiModule
        ? apiModule.bridgeWebSocketUrl(bridgePort, path)
        : (() => {
            const normalized = path.startsWith('/') ? path : `/${path}`;
            return `ws://127.0.0.1:${bridgePort}${normalized}`;
        })();
}

function bridgeFetch(input, init = {}) {
    if (apiModule) {
        return apiModule.bridgeFetch(rawFetch, bridgePort, input, init, LEGACY_BRIDGE_BASE);
    }

    let url = input;
    if (typeof input === 'string') {
        if (input.startsWith(LEGACY_BRIDGE_BASE)) {
            url = `${bridgeHttpBase()}${input.slice(LEGACY_BRIDGE_BASE.length)}`;
        } else if (input.startsWith('/')) {
            url = `${bridgeHttpBase()}${input}`;
        }
    }
    return rawFetch(url, init);
}

window.fetch = bridgeFetch;

window.api.receive('bridge-port', (port) => {
    const parsed = parseInt(port, 10);
    if (!Number.isNaN(parsed)) {
        bridgePort = parsed;
    }

    if (bridgeConnectRequested && typeof connectBridge === 'function' && bridgeReady) {
        connectBridge(true);
    }
});

window.api.receive('bridge-ready', (ready) => {
    bridgeReady = Boolean(ready);

    if (bridgeConnectRequested && typeof connectBridge === 'function') {
        connectBridge(true);
    }
});

window.api.receive('sidecar-error', (msg) => {
    console.error('[Sidecar]', msg);
    if (typeof appendLog === 'function') {
        appendLog('vuln', `Sidecar: ${String(msg).trim()}`);
    }
});

// Navigation
const navItems = document.querySelectorAll('.nav-item');
const views = document.querySelectorAll('.view');
const toggleModeBtn = document.getElementById('toggle-mode-btn');
const advancedMenu = document.getElementById('advanced-menu');
const modeBadge = document.getElementById('mode-badge');
const btnModeText = document.getElementById('btn-mode-text');

let isAdvanced = false;

navItems.forEach(btn => {
    btn.addEventListener('click', () => {
        navItems.forEach(n => n.classList.remove('active'));
        views.forEach(v => {
            v.classList.remove('active', 'slide-up');
        });

        btn.classList.add('active');
        const target = btn.getAttribute('data-target');
        const view = document.getElementById(`view-${target}`);

        if (view) {
            view.classList.add('active');
            void view.offsetWidth; // trigger reflow
            view.classList.add('slide-up');
        }
    });
});

// Mode: 'standard' | 'advanced' | 'web'
let currentMode = 'standard';
const webMenu = document.getElementById('web-menu');

toggleModeBtn.addEventListener('click', () => {
    if (currentMode === 'standard') {
        currentMode = 'advanced';
        modeBadge.textContent = 'ADVANCED';
        modeBadge.className = 'badge advanced';
        btnModeText.textContent = 'Switch to Web';
        advancedMenu.style.display = 'block';
        webMenu.style.display = 'none';
    } else if (currentMode === 'advanced') {
        currentMode = 'web';
        modeBadge.textContent = 'WEB';
        modeBadge.className = 'badge web';
        btnModeText.textContent = 'Switch to Standard';
        advancedMenu.style.display = 'none';
        webMenu.style.display = 'block';
    } else {
        currentMode = 'standard';
        modeBadge.textContent = 'STANDARD';
        modeBadge.className = 'badge standard';
        btnModeText.textContent = 'Switch to Advanced';
        advancedMenu.style.display = 'none';
        webMenu.style.display = 'none';
        document.querySelector('.nav-item[data-target="dashboard"]').click();
    }
});

// Project Management State
let currentProject = {
    projectId: null,
    url: '',
    vulns: 0,
    msgs: 0,
    findings: [],
    logs: [],
    history: []
};
const platformState = {
    syncPromise: null,
    refreshTimer: null,
    refreshQueued: null,
    refreshing: false,
    reqforgeIdentityCache: [],
    lastAnnouncement: null
};

const welcomeModal = document.getElementById('welcome-modal');
const mainApp = document.getElementById('main-app');

targetUrlInput?.addEventListener('input', () => {
    currentProject.url = targetUrlInput.value.trim();
});

function setCurrentProject(nextProject) {
    currentProject = nextProject;
}

function getCurrentProject() {
    return currentProject;
}

function getCurrentMode() {
    return currentMode;
}

function getPlatformContext() {
    return {
        addFinding: (vuln, options) => addFinding(vuln, options),
        addHistoryRow: (dir, data, options) => addHistoryRow(dir, data, options),
        appendLog,
        clearFindingStore: () => clearFindingStore(),
        clearSystemLog: () => { systemLog.innerHTML = ''; },
        findingsContainer,
        globalVulns,
        getCurrentMode,
        getCurrentProject,
        getMsgCount: () => msgCount,
        historyCount,
        historyData,
        historyTbody,
        mainApp,
        platformState,
        queuePlatformProjectRefresh: (delay) => queuePlatformProjectRefresh(delay),
        renderAttackWorkspace: (attackRuns, findings) => renderAttackWorkspace(attackRuns, findings),
        renderEvidenceWorkspace: (evidenceList, notes, timeline) => renderEvidenceWorkspace(evidenceList, notes, timeline),
        refreshPlatformProjectSummary: (options) => refreshPlatformProjectSummary(options),
        refreshReqForgeIdentities: (options) => refreshReqForgeIdentities(options),
        renderPlatformEvidence: (evidenceList) => renderPlatformEvidence(evidenceList),
        renderPlatformTimeline: (events) => renderPlatformTimeline(events),
        renderReqForgeIdentities: (identities) => renderReqForgeIdentities(identities),
        resetFindingsView: (message) => resetFindingsView(message),
        resetHistoryView: (message) => resetHistoryView(message),
        setCurrentProject,
        setMsgCount: (value) => { msgCount = value; },
        setReqForgePlatformStatus: (message, tone) => setReqForgePlatformStatus(message, tone),
        startPlatformProjectAutoRefresh: () => startPlatformProjectAutoRefresh(),
        stopPlatformProjectAutoRefresh: () => stopPlatformProjectAutoRefresh(),
        systemLog,
        targetUrlInput,
        valMsgs,
        valProgress,
        valRisk,
        valVulns,
        welcomeModal
    };
}

function getAttackContext() {
    return {
        appendLog,
        bridgeWebSocketUrl,
        ensurePlatformProject: (reason, targetUrlOverride) => ensurePlatformProject(reason, targetUrlOverride),
        getCurrentProject,
        isIntercepting: () => isIntercepting,
        platformState,
        queuePlatformProjectRefresh: (delay) => queuePlatformProjectRefresh(delay),
        refreshReqForgeIdentities: (options) => refreshReqForgeIdentities(options),
        resetFindingsView: (message) => resetFindingsView(message),
        resetHistoryView: (message) => resetHistoryView(message),
        scanBtn,
        startScanTimer: () => startScanTimer(),
        targetUrlInput,
        valProgress,
        valRisk
    };
}

function applyProjectState(data) {
    if (apiModule?.applyProjectState) {
        apiModule.applyProjectState(getPlatformContext(), data);
        return;
    }
}

function gatherProjectState() {
    if (apiModule?.gatherProjectState) {
        return apiModule.gatherProjectState(getPlatformContext());
    }
    return {};
}

function derivePlatformProjectName(url) {
    return apiModule ? apiModule.derivePlatformProjectName(url) : `wshawk-${new Date().toISOString().replace(/[:.]/g, '-')}`;
}

function setReqForgePlatformStatus(message, tone = 'muted') {
    if (identitiesModule) {
        identitiesModule.setReqForgePlatformStatus(message, tone);
        return;
    }
    const status = document.getElementById('reqforge-platform-status');
    if (status) status.textContent = message;
}

function renderReqForgeIdentities(identities = []) {
    if (identitiesModule) {
        identitiesModule.renderReqForgeIdentities(identities);
        return;
    }
}

async function refreshReqForgeIdentities({ announceErrors = false } = {}) {
    if (identitiesModule?.refreshReqForgeIdentities) {
        return identitiesModule.refreshReqForgeIdentities(getPlatformContext(), { announceErrors });
    }
    return [];
}

async function ensurePlatformProject(reason = 'operation', targetUrlOverride = '') {
    if (apiModule?.ensurePlatformProject) {
        return apiModule.ensurePlatformProject(getPlatformContext(), reason, targetUrlOverride);
    }
    throw new Error('Platform API unavailable');
}

function stopPlatformProjectAutoRefresh() {
    if (apiModule?.stopPlatformProjectAutoRefresh) {
        apiModule.stopPlatformProjectAutoRefresh(getPlatformContext());
    }
}

function startPlatformProjectAutoRefresh() {
    if (apiModule?.startPlatformProjectAutoRefresh) {
        apiModule.startPlatformProjectAutoRefresh(getPlatformContext());
    }
}

function queuePlatformProjectRefresh(delay = 900) {
    if (apiModule?.queuePlatformProjectRefresh) {
        apiModule.queuePlatformProjectRefresh(getPlatformContext(), delay);
    }
}

async function refreshPlatformProjectSummary({ silent = true } = {}) {
    if (apiModule?.refreshPlatformProjectSummary) {
        return apiModule.refreshPlatformProjectSummary(getPlatformContext(), { silent });
    }
    return null;
}

navItems.forEach(btn => {
    const target = btn.getAttribute('data-target');
    if (['dashboard', 'history', 'reqforge'].includes(target)) {
        btn.addEventListener('click', () => {
            if (currentProject.projectId) {
                queuePlatformProjectRefresh(150);
            }
        });
    }
});

document.getElementById('btn-new-project').addEventListener('click', () => {
    platformState.forceNewProject = true;
    platformState.lastAnnouncement = null;
    platformState.reqforgeIdentityCache = [];
    applyProjectState(null); // empty state
    renderReqForgeIdentities([]);
    setReqForgePlatformStatus('Fresh project requested. The next operation will create a new project vault.', 'info');
});

document.getElementById('btn-open-project').addEventListener('click', async () => {
    const res = await window.api.invoke('dialog:openProject');
    if (res.success) {
        applyProjectState(res.data);
    } else if (!res.canceled) {
        alert('Failed to load project: ' + res.error);
    }
});

document.getElementById('btn-save-project').addEventListener('click', async () => {
    const data = gatherProjectState();
    const res = await window.api.invoke('dialog:saveProject', data);
    if (!res.success && !res.canceled) {
        alert('Failed to save project: ' + res.error);
    } else if (res.success) {
        appendLog('info', `Project saved successfully to ${res.path}`);
    }
});

document.getElementById('btn-export-report').addEventListener('click', async () => {
    if (currentProject.projectId && evidenceModule?.exportProjectBundle) {
        try {
            await evidenceModule.exportProjectBundle({
                projectId: currentProject.projectId,
                format: 'html',
                appendLog,
            });
            return;
        } catch (error) {
            appendLog('vuln', `Platform HTML export failed: ${error.message}`);
        }
    }

    const data = gatherProjectState();
    const findingsMarkup = renderReportFindings(data.findings);
    const logsMarkup = renderReportLogs(data.logs);
    const historyMarkup = renderReportHistoryRows(data.history);

    const htmlReport = `
    <!DOCTYPE html>
    <html lang="en">
    <head>
        <meta charset="UTF-8">
        <title>WSHawk Security Report</title>
        <style>
            body { font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif; background: #0f172a; color: #f8fafc; padding: 40px; }
            h1 { color: #ef4444; border-bottom: 1px solid #334155; padding-bottom: 10px; }
            .metric { display: inline-block; padding: 20px; background: #1e293b; margin-right: 20px; border-radius: 8px; border: 1px solid #334155; }
            .metric strong { display: block; font-size: 24px; color: #60a5fa; }
            h2 { margin-top: 40px; color: #38bdf8; }
            table { width: 100%; border-collapse: collapse; margin-top: 20px; }
            th, td { padding: 12px; text-align: left; border-bottom: 1px solid #334155; }
            th { background: #1e293b; }
            .finding-card { background: #1e293b; padding: 20px; margin-bottom: 20px; border-radius: 8px; border-left: 4px solid #ef4444; }
            .f-title { display: flex; justify-content: space-between; font-weight: bold; font-size: 18px; margin-bottom: 10px; }
            .f-desc { margin-bottom: 10px; color: #cbd5e1; }
            .f-payload { background: #0f172a; padding: 10px; font-family: monospace; color: #a78bfa; border-radius: 4px; }
            .sev-HIGH { color: #ef4444; }
            .sev-MEDIUM { color: #f59e0b; }
            .sev-LOW { color: #3b82f6; }
            .log-line { font-family: monospace; font-size: 12px; margin-bottom: 4px; border-bottom: 1px solid #1e293b; padding-bottom: 4px; }
        </style>
    </head>
    <body>
        <h1>WSHAWK Intelligence Report</h1>
        <p><strong>Target URL:</strong> ${escapeHtml(data.url || '')}</p>
        <p><strong>Date Generated:</strong> ${escapeHtml(new Date().toLocaleString())}</p>
        
        <div>
            <div class="metric">Threats Detected: <strong>${data.vulns}</strong></div>
            <div class="metric">Frames Analyzed: <strong>${data.msgs}</strong></div>
        </div>

        <h2>Vulnerabilities Confirmed</h2>
        <div>${findingsMarkup}</div>

        <h2>System Telemetry / Logs</h2>
        <div style="background: #1e293b; padding: 20px; border-radius: 8px; overflow-x: auto;">
            ${logsMarkup}
        </div>

        <h2>Activity History (First 100 Frames)</h2>
        <table>
            <thead><tr><th>ID</th><th>DIR</th><th>TIMING</th><th>SIZE</th><th>PAYLOAD</th></tr></thead>
            <tbody>${historyMarkup}</tbody>
        </table>
    </body>
    </html>
    `;

    const res = await window.api.invoke('dialog:exportReport', htmlReport);
    if (!res.success && !res.canceled) {
        alert('Failed to export report: ' + res.error);
    } else if (res.success) {
        appendLog('info', `HTML Report exported successfully to ${res.path}`);
    }
});

// Socket.IO Integration
let socket;
let msgCount = 0;

function connectBridge(forceReconnect = false) {
    bridgeConnectRequested = true;

    if (!bridgeReady) {
        connPill.className = 'connection-status reconnecting';
        connText.innerText = 'Awaiting Bridge';
        document.getElementById('status-conn').innerText = 'Awaiting bridge';
        return;
    }

    if (socket && !forceReconnect) {
        return;
    }

    if (socket) {
        try { socket.removeAllListeners(); } catch (_) { }
        try { socket.disconnect(); } catch (_) { }
    }

    socket = io(bridgeHttpBase(), {
        reconnectionAttempts: 5,
    });
    // Expose on window so Team Mode and other modules can reuse the connection
    window.socket = socket;

    socket.on('connect', () => {
        connPill.className = 'connection-status online';
        connText.innerText = 'Connected';
        document.getElementById('status-dot')?.classList.add('online');
        document.getElementById('status-conn').innerText = 'Connected';
        appendLog('in', 'Bridge linkage established. Engine ready.');
        if (currentProject.projectId) {
            queuePlatformProjectRefresh(200);
        }
    });

    socket.on('disconnect', () => {
        connPill.className = 'connection-status offline';
        connText.innerText = 'Disconnected';
        document.getElementById('status-dot')?.classList.remove('online');
        document.getElementById('status-conn').innerText = 'Disconnected';
        appendLog('vuln', 'Connection to core engine lost.');
    });

    socket.on('connect_error', (err) => {
        connPill.className = 'connection-status reconnecting';
        connText.innerText = 'Bridge Auth Pending';
        document.getElementById('status-conn').innerText = 'Auth pending';
        appendLog('vuln', `Bridge connect failed: ${err.message}`);
    });

    // Feature 14: Auto-Reconnect UI
    socket.io.on('reconnect_attempt', (attempt) => {
        connPill.className = 'connection-status reconnecting';
        connText.innerText = `Reconnecting (${attempt})...`;
        document.getElementById('status-dot')?.classList.add('reconnecting');
        document.getElementById('status-dot')?.classList.remove('online');
        document.getElementById('status-conn').innerText = `Reconnecting...`;
    });

    socket.io.on('reconnect', () => {
        connPill.className = 'connection-status online';
        connText.innerText = 'Connected';
        document.getElementById('status-dot')?.classList.remove('reconnecting');
        document.getElementById('status-dot')?.classList.add('online');
        document.getElementById('status-conn').innerText = 'Connected';
        appendLog('success', 'Reconnected to core engine.');
    });

    socket.io.on('reconnect_failed', () => {
        connPill.className = 'connection-status offline';
        connText.innerText = 'Connection Failed';
        document.getElementById('status-dot')?.classList.remove('reconnecting');
        document.getElementById('status-conn').innerText = 'Failed';
        appendLog('vuln', 'All reconnection attempts failed. Restart the bridge.');
    });

    socket.on('scan_update', (data) => {
        if (data.status === 'running') {
            appendLog('out', `Initializing heuristic scan targeting: ${targetUrlInput.value}`);
        } else if (data.status === 'completed') {
            valProgress.style.width = '100%';
            appendLog('in', `Analysis complete. Vulnerabilities confirmed: ${data.vulnerabilities_count}`);
            scanBtn.innerText = 'Run Analysis';
            scanBtn.disabled = false;
            document.getElementById('scan-stop-btn').style.display = 'none';
            stopScanTimer();
        }
    });

    socket.on('scan_progress', (data) => {
        valProgress.style.width = `${data.progress}%`;
        appendLog('info', `Executing module [${data.phase}] — Progress: ${data.progress}%`);
    });

    socket.on('message_sent', (data) => {
        if (data.msg) {
            updateMsgCount(1);
            appendLog('out', `⟶ ${truncate(data.msg)}`);
            addHistoryRow('OUT', data.msg);
        }
        if (data.response) {
            updateMsgCount(1);
            appendLog('in', `⟵ ${truncate(data.response)}`);
            addHistoryRow('IN', data.response);
        }
    });

    socket.on('vulnerability_found', (vuln) => {
        addFinding(vuln);
        incVulns();
        appendLog('vuln', `THREAT IDENTIFIED: ${vuln.severity} - ${vuln.type} `);
    });

    socket.on('scan_error', (data) => {
        appendLog('vuln', `ABORT FATAL ERR: ${data.error} `);
        scanBtn.innerText = 'Run Analysis';
        scanBtn.disabled = false;
        document.getElementById('scan-stop-btn').style.display = 'none';
        valProgress.style.background = 'var(--danger)';
    });

    socket.on('blaster_progress', (data) => {
        addBlasterResult(data.payload, data.status, '...');
    });

    socket.on('blaster_result', (data) => {
        updateBlasterResult(data.payload, data.status, data.length, data.response,
            data.dom_verified, data.dom_evidence);
    });

    socket.on('dom_xss_confirmed', (data) => {
        appendLog('vuln', `[DOM INVADER] CONFIRMED XSS: ${truncate(data.payload, 60)} — ${data.evidence}`);
    });

    socket.on('blaster_completed', () => {
        appendLog('success', 'Payload blasting sequence complete.');
        const blasterBtn = document.getElementById('blaster-start-btn');
        if (blasterBtn) {
            blasterBtn.disabled = false;
            blasterBtn.innerText = "COMMENCE FUZZING";
        }
        const stopBtn = document.getElementById('blaster-stop-btn');
        if (stopBtn) stopBtn.style.display = 'none';
    });

    socket.on('intercepted_frame', (frame) => {
        handleInterceptedFrame(frame);
    });

    socket.on('new_handshake', (data) => {
        addHandshakeRow(data);
        appendLog('success', `Extension captured new handshake: ${truncate(data.url, 40)}`);
    });

    socket.on('platform_event', (data) => {
        if (data?.project_id && data.project_id === currentProject.projectId) {
            queuePlatformProjectRefresh(400);
        }
    });

    socket.on('platform_evidence', (data) => {
        if (data?.project_id && data.project_id === currentProject.projectId) {
            queuePlatformProjectRefresh(400);
        }
    });
}

const _handshakeStore = new Map();
let _handshakeIdx = 0;

function addHandshakeRow(data) {
    const tbody = document.getElementById('handshake-tbody');
    if (!tbody) return;
    if (tbody.querySelector('.empty-tr')) tbody.innerHTML = '';

    const idx = _handshakeIdx++;
    _handshakeStore.set(idx, data);

    const time = new Date().toLocaleTimeString('en-US', { hour12: false });
    const row = document.createElement('tr');
    row.innerHTML = `
        <td>${esc(time)}</td>
        <td><span class="text-accent" title="${esc(data.url)}">${esc(truncate(data.url, 50))}</span></td>
        <td>
            <button class="btn secondary small" style="font-size: 10px; padding: 2px 6px;" data-hs-idx="${idx}">Use</button>
        </td>
    `;
    row.querySelector('button[data-hs-idx]').addEventListener('click', () => {
        const hsData = _handshakeStore.get(idx);
        if (hsData) useHandshake(hsData);
    });
    tbody.insertBefore(row, tbody.firstChild);
}

window.useHandshake = function (data) {
    if (targetUrlInput) targetUrlInput.value = data.url;
    const authInput = document.getElementById('auth-payload');
    if (authInput && data.headers) {
        // Simple heuristic: if there's an Authorization header or similar, try to use it
        const headersJson = JSON.stringify(data.headers, null, 2);
        authInput.value = headersJson;
        appendLog('info', 'Target URL and handshake headers synced to Interceptor.');
    }
    // Switch to Interceptor view
    document.querySelector('.nav-item[data-target="intercept"]')?.click();
};

let baselineLength = null;

function addBlasterResult(payload, status, resp) {
    const tableInfo = document.getElementById('blaster-tbody');
    if (tableInfo.querySelector('.empty-tr')) {
        tableInfo.innerHTML = '';
        baselineLength = null;
    }
    const domVerifying = document.getElementById('blaster-dom-verify')?.checked;
    const domCell = domVerifying
        ? `<td><span class="dom-verified-badge dom-badge-pending">Verifying...</span></td>`
        : `<td><span class="dom-verified-badge dom-badge-skipped">—</span></td>`;
    const html = `
        <tr id="fuzz-${hashString(payload)}">
            <td>${esc(truncate(payload, 30))}</td>
            <td class="status-cell">${esc(status)}</td>
            <td class="length-cell">-</td>
            ${domCell}
            <td class="diff-cell">-</td>
            <td class="resp-cell">${esc(resp)}</td>
        </tr>
        `;
    tableInfo.insertAdjacentHTML('afterbegin', html);
}

function updateBlasterResult(payload, status, length, resp, domVerified, domEvidence) {
    const row = document.getElementById(`fuzz-${hashString(payload)}`);
    if (row) {
        row.querySelector('.status-cell').innerText = status;
        row.querySelector('.status-cell').className = `status-cell sev-${status === 'success' ? 'LOW' : 'HIGH'}`;

        let diffHtml = '-';
        if (typeof length === 'number') {
            row.querySelector('.length-cell').innerText = length;
            if (baselineLength === null) {
                baselineLength = length;
                diffHtml = '<span style="color:var(--text-muted);">(baseline)</span>';
            } else {
                const diff = length - baselineLength;
                if (diff !== 0) {
                    const color = Math.abs(diff) > 20 ? 'var(--danger)' : 'var(--warning)';
                    diffHtml = `<span style="color:${color}; font-weight:bold;">${diff > 0 ? '+' : ''}${diff}</span>`;
                } else {
                    diffHtml = '<span style="color:var(--text-muted);">0</span>';
                }
            }
        }
        row.querySelector('.diff-cell').innerHTML = diffHtml;
        row.querySelector('.resp-cell').innerText = truncate(resp, 50);

        // DOM Verified badge
        const domCell = row.querySelector('.dom-verified-badge')?.parentElement;
        if (domCell && domVerified !== undefined) {
            if (domVerified === true) {
                domCell.innerHTML = `<span class="dom-verified-badge dom-badge-confirmed" title="${esc(domEvidence || '')}">CONFIRMED XSS</span>`;
            } else if (domVerified === false) {
                domCell.innerHTML = `<span class="dom-verified-badge dom-badge-unverified" title="${esc(domEvidence || 'No execution')}">Unverified</span>`;
            }
        }
    }
}

// We can't rely just on integer hashes for DOM IDs since some payloads might collide 
// or the ID selector might break if it starts with a number. Use a hex string.
// Prefixed to ensure it starts with a letter (for selector safety)
function hashString(str) {
    let hash = 0;
    for (let i = 0; i < str.length; i++) {
        hash = (hash << 5) - hash + str.charCodeAt(i);
        hash |= 0;
    }
    return 'f' + Math.abs(hash).toString(16) + str.length;
}

function truncate(str, len = 70) {
    if (!str) return '';
    const s = typeof str === 'string' ? str : JSON.stringify(str);
    return s.length > len ? s.substring(0, len) + '...' : s;
}

function escapeHtml(value) {
    if (value === null || value === undefined) return '';
    return String(value)
        .replace(/&/g, '&amp;')
        .replace(/</g, '&lt;')
        .replace(/>/g, '&gt;')
        .replace(/"/g, '&quot;')
        .replace(/'/g, '&#39;');
}

function renderReportFindings(findings = []) {
    if (!Array.isArray(findings) || findings.length === 0) {
        return '<p>No vulnerabilities detected.</p>';
    }

    return findings.map((finding, index) => {
        const type = escapeHtml(finding?.type || `Finding ${index + 1}`);
        const severity = String(finding?.severity || 'LOW').trim().toUpperCase();
        const severityLabel = escapeHtml(severity);
        const description = escapeHtml(finding?.description || '');
        const payload = escapeHtml(finding?.payload || '');
        return `
            <div class="finding-card">
                <div class="f-title">
                    <span>${type}</span>
                    <span class="sev-${severityLabel}">${severityLabel}</span>
                </div>
                <div class="f-desc">${description || 'No description recorded.'}</div>
                <div class="f-payload">${payload || 'No payload recorded.'}</div>
            </div>
        `;
    }).join('');
}

function renderReportLogs(logs = []) {
    if (!Array.isArray(logs) || logs.length === 0) {
        return '<div class="log-line">No telemetry recorded.</div>';
    }

    return logs.map((entry) => {
        const type = escapeHtml(entry?.type || 'info');
        const text = escapeHtml(entry?.text || '');
        return `<div class="log-line ${type}">${text}</div>`;
    }).join('');
}

function renderReportHistoryRows(history = []) {
    if (!Array.isArray(history) || history.length === 0) {
        return '<tr><td colspan="5">No traffic recorded.</td></tr>';
    }

    return history.slice(0, 100).map((entry, index) => `
        <tr>
            <td>${escapeHtml(entry?.rowNumber || index + 1)}</td>
            <td>${escapeHtml(entry?.dir || 'INFO')}</td>
            <td>${escapeHtml(entry?.time || '')}</td>
            <td>${escapeHtml(entry?.size || 0)}</td>
            <td>${escapeHtml(truncate(entry?.payload || '', 160))}</td>
        </tr>
    `).join('');
}

function appendLog(type, msg) {
    const div = document.createElement('div');
    div.className = `log-line ${type}`;
    div.innerText = `[${new Date().toLocaleTimeString('en-US', { hour12: false })}] ${msg}`;
    systemLog.appendChild(div);
    systemLog.scrollTop = systemLog.scrollHeight;
}

window.truncate = truncate;
window.appendLog = appendLog;

document.addEventListener('click', async (event) => {
    const actionEl = event.target.closest('[data-action]');
    if (!actionEl) return;

    const action = actionEl.dataset.action || '';
    const closeGlobalSearch = () => {
        const modal = document.getElementById('global-search-modal');
        if (modal) {
            modal.style.display = 'none';
        }
    };

    if (action === 'copy-finding' && typeof window.copyFinding === 'function') {
        event.preventDefault();
        window.copyFinding(actionEl.dataset.findingId || '');
        return;
    }

    if (action === 'export-poc' && typeof window.exportPoC === 'function') {
        event.preventDefault();
        await window.exportPoC(actionEl.dataset.findingId || '');
        return;
    }

    if (action === 'send-to-forge' && typeof window.sendToForge === 'function') {
        event.preventDefault();
        window.sendToForge(actionEl.dataset.rowId || '');
        return;
    }

    if (action === 'close-profile-picker') {
        event.preventDefault();
        actionEl.closest('#profile-name-picker')?.remove();
        return;
    }

    if (action === 'copy-mutation') {
        event.preventDefault();
        const payload = actionEl.parentElement?.querySelector('.mut-payload')?.innerText || '';
        await navigator.clipboard.writeText(payload);
        appendLog('info', 'Mutation copied.');
        return;
    }

    if (action === 'gsearch-nav') {
        event.preventDefault();
        const target = actionEl.dataset.target || '';
        document.querySelector(`.nav-item[data-target="${target}"]`)?.click();
        closeGlobalSearch();
        return;
    }

    if (action === 'gsearch-history' && typeof window.sendToForge === 'function') {
        event.preventDefault();
        window.sendToForge(actionEl.dataset.rowId || '');
        closeGlobalSearch();
    }
});

function updateMsgCount(inc) {
    msgCount += inc;
    valMsgs.innerText = msgCount;
    historyCount.innerText = `${msgCount} frames`;
}

function incVulns() {
    valVulns.innerText = (parseInt(valVulns.innerText) || 0) + 1;
    valRisk.innerText = 'COMPROMISED';
    valRisk.className = 'metric-value text-danger';
}

const globalVulns = {};

function clearFindingStore() {
    if (evidenceModule) {
        evidenceModule.clearFindingStore(globalVulns);
        return;
    }
    Object.keys(globalVulns).forEach(key => delete globalVulns[key]);
}

function resetFindingsView(message = 'No vulnerabilities detected on the target.') {
    if (evidenceModule) {
        evidenceModule.resetFindingsView({ findingsContainer, globalVulns, message });
    } else {
        clearFindingStore();
        findingsContainer.innerHTML = `<div class="empty-state">${esc(message)}</div>`;
    }
    valVulns.innerText = '0';
    valRisk.innerText = 'SECURE';
    valRisk.className = 'metric-value text-safe';
}

function normalizeSeverity(value) {
    return evidenceModule ? evidenceModule.normalizeSeverity(value) : String(value || 'LOW').trim().toUpperCase();
}

function severityScore(value) {
    return evidenceModule ? evidenceModule.severityScore(value) : 1;
}

function summarizeEvidencePayload(payload = {}) {
    if (evidenceModule) {
        return evidenceModule.evidenceToFinding({ payload }).payload;
    }
    return truncate(payload, 140);
}

function evidenceToFinding(evidence) {
    return evidenceModule ? evidenceModule.evidenceToFinding(evidence) : evidence;
}

function updateRiskFromEvidence(evidenceList = []) {
    if (evidenceModule) {
        evidenceModule.updateRiskFromEvidence(valRisk, evidenceList);
        return;
    }
}

window.exportPoC = async function (id) {
    if (evidenceModule?.exportPoC) {
        await evidenceModule.exportPoC({
            globalVulns,
            findingId: id,
            targetUrl: targetUrlInput.value.trim(),
            authPayload: document.getElementById('auth-payload') ? document.getElementById('auth-payload').value.trim() : '',
            invoke: (...args) => window.api.invoke(...args),
            appendLog
        });
    }
};

function addFinding(vuln, options = {}) {
    const vId = evidenceModule
        ? evidenceModule.addFinding({ findingsContainer, globalVulns, vuln, options })
        : (options.findingId || Math.random().toString(36).substr(2, 9));
    updateSeverityChart();
    return vId;
}

let hIndex = 1;
const historyData = {};

function clearHistoryStore() {
    if (trafficModule) {
        trafficModule.clearHistoryStore(historyData);
    } else {
        Object.keys(historyData).forEach(key => delete historyData[key]);
    }
    hIndex = 1;
}

function resetHistoryView(message = 'Awaiting traffic capture...') {
    clearHistoryStore();
    if (trafficModule) {
        trafficModule.resetHistoryView({ historyTbody, historyData, message });
    } else {
        historyTbody.innerHTML = `<tr class="empty-tr"><td colspan="6">${esc(message)}</td></tr>`;
    }
    msgCount = 0;
    valMsgs.innerText = '0';
    historyCount.innerText = '0 frames';
}

function addHistoryRow(dir, data, options = {}) {
    const rowId = trafficModule
        ? trafficModule.addHistoryRow({ historyTbody, historyData, dir, data, options })
        : (options.rowId || ('h' + hIndex));
    const rowNumber = options.rowNumber || hIndex;
    hIndex = Math.max(hIndex + 1, rowNumber + 1);
    return rowId;
}

function eventToHistoryMessage(event) {
    return trafficModule ? trafficModule.eventToHistoryMessage(event) : JSON.stringify(event.payload || {});
}

function renderPlatformTimeline(events = []) {
    const count = trafficModule
        ? trafficModule.renderPlatformTimeline({ historyTbody, historyData, events })
        : 0;
    msgCount = count;
    valMsgs.innerText = String(msgCount);
    historyCount.innerText = `${msgCount} frames`;
}

function renderPlatformEvidence(evidenceList = []) {
    const rendered = evidenceModule
        ? evidenceModule.renderPlatformEvidence({ findingsContainer, globalVulns, evidenceList })
        : { count: 0, evidence: [] };
    valVulns.innerText = String(rendered.count);
    updateRiskFromEvidence(rendered.evidence);
    updateSeverityChart();
}

function renderAttackWorkspace(attackRuns = [], findings = []) {
    attacksModule?.renderAttackWorkspace?.({ attackRuns, findings });
}

function renderEvidenceWorkspace(evidenceList = [], notes = [], timeline = {}) {
    evidenceModule?.renderWorkspace?.({ evidenceList, notes, timeline });
}


// Handlers
// History search filter
const historyFilterInput = document.getElementById('history-filter');
if (historyFilterInput) {
    historyFilterInput.addEventListener('input', (e) => {
        const term = e.target.value.toLowerCase();
        const rows = document.querySelectorAll('#history-tbody tr');
        rows.forEach(r => {
            if (r.classList.contains('empty-tr')) return;
            const text = r.innerText.toLowerCase();
            r.style.display = text.includes(term) ? '' : 'none';
        });
    });
}
scanBtn.addEventListener('click', async () => {
    if (attacksModule?.runScan) {
        await attacksModule.runScan(getAttackContext());
    }
});

const scanStopBtn = document.getElementById('scan-stop-btn');
if (scanStopBtn) {
    scanStopBtn.addEventListener('click', async () => {
        if (attacksModule?.stopScan) {
            await attacksModule.stopScan(getAttackContext());
        }
    });
}

document.getElementById('send-reqforge').addEventListener('click', async () => {
    if (attacksModule?.runRequestForge) {
        await attacksModule.runRequestForge(getAttackContext());
    }
});

document.getElementById('reqforge-refresh-identities')?.addEventListener('click', async () => {
    try {
        await ensurePlatformProject('identity_refresh');
        const identities = await refreshReqForgeIdentities({ announceErrors: true });
        appendLog('info', `[Platform] Loaded ${identities.length} identity${identities.length === 1 ? '' : 'ies'} into Request Forge.`);
    } catch (error) {
        appendLog('vuln', `[Platform] Unable to refresh identities: ${error.message}`);
    }
});

document.getElementById('reqforge-store-dom-identity')?.addEventListener('click', async () => {
    if (!window._domInvaderAuthFlow) {
        setReqForgePlatformStatus('Record a DOM auth flow first, then store it here.', 'danger');
        appendLog('vuln', '[Platform] Record a DOM auth flow first, then store it as a project identity.');
        return;
    }

    const flow = window._domInvaderAuthFlow || {};
    const storage = flow.local_storage || {};
    const normalized = (value) => String(value || '')
        .trim()
        .toLowerCase()
        .replace(/[^a-z0-9]+/g, '-')
        .replace(/^-+|-+$/g, '');
    const inferredAlias = (() => {
        const username = normalized(
            storage['wshawk.validation.username']
            || storage.username
            || flow.extracted_tokens?.username
        );
        const tenant = normalized(
            storage['wshawk.validation.tenant']
            || storage.tenant
            || flow.extracted_tokens?.tenant
        );
        const role = normalized(
            storage['wshawk.validation.role']
            || storage.role
            || flow.extracted_tokens?.role
        );
        return [username, tenant, role].filter(Boolean).join('-')
            || [tenant, role].filter(Boolean).join('-')
            || 'captured-user';
    })();

    const fallbackAlias = inferredAlias === 'captured-user'
        ? `captured-user-${new Date().toISOString().replace(/[:.]/g, '-').slice(0, 19)}`
        : inferredAlias;
    let alias = fallbackAlias;
    try {
        if (typeof window.prompt === 'function') {
            const prompted = window.prompt(
                'Store the current DOM auth flow as which identity alias?',
                fallbackAlias
            );
            if (prompted && prompted.trim()) {
                alias = prompted.trim();
            }
        }
    } catch (_) {
        // Dialogs can be unavailable in this shell; fall back to inferred alias.
    }

    if (!alias || !alias.trim()) return;

    try {
        setReqForgePlatformStatus('Saving captured DOM identity into the current project...', 'info');
        const project = await ensurePlatformProject('dom_identity_store', targetUrlInput.value.trim());
        const flow = window._domInvaderAuthFlow || {};
        const extractedTokens = flow.extracted_tokens || {};
        const localStorageData = flow.local_storage || {};
        const cookieList = Array.isArray(flow.cookies) ? flow.cookies : [];
        const res = await fetch(`/platform/projects/${project.id}/identities`, {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                alias: alias.trim(),
                source: 'dom_recording',
                cookies: cookieList,
                headers: flow.ws_headers || {},
                tokens: extractedTokens,
                storage: localStorageData,
                notes: 'Captured from DOM auth recorder',
            })
        });
        const data = await res.json();
        if (!res.ok || data.status !== 'success') {
            throw new Error(data.detail || data.msg || 'DOM identity save failed');
        }
        if (!data.identity?.id) {
            throw new Error('DOM identity save completed, but no project identity was persisted');
        }

        const nextCache = [data.identity, ...(platformState.reqforgeIdentityCache || []).filter(item => item.id !== data.identity.id)];
        platformState.reqforgeIdentityCache = nextCache;
        renderReqForgeIdentities(nextCache);
        const select = document.getElementById('reqforge-identity-select');
        if (select && data.identity?.id) {
            select.value = data.identity.id;
        }
        setReqForgePlatformStatus(`Stored identity ${alias.trim()} in project ${project.id}. Refreshing vault...`, 'success');
        const refreshed = await refreshReqForgeIdentities({ announceErrors: true });
        if (!refreshed.length && data.identity?.id) {
            renderReqForgeIdentities(nextCache);
            if (select) {
                select.value = data.identity.id;
            }
            setReqForgePlatformStatus(
                `Saved ${alias.trim()}, but the project vault refresh still returned 0 identities. Project: ${project.id}`,
                'danger'
            );
        }
        queuePlatformProjectRefresh(150);
        appendLog('success', `[Platform] Stored fresh browser-backed identity as ${alias.trim()}.`);
    } catch (error) {
        setReqForgePlatformStatus(`Identity save failed: ${error.message}`, 'danger');
        appendLog('vuln', `[Platform] Failed to store DOM identity: ${error.message}`);
    }
});

document.getElementById('reqforge-authz-diff-btn')?.addEventListener('click', async () => {
    if (attacksModule?.runAuthzDiff) {
        await attacksModule.runAuthzDiff(getAttackContext());
    }
});

document.getElementById('reqforge-subscription-btn')?.addEventListener('click', async () => {
    if (attacksModule?.runSubscriptionAbuse) {
        await attacksModule.runSubscriptionAbuse(getAttackContext());
    }
});

document.getElementById('reqforge-race-btn')?.addEventListener('click', async () => {
    if (attacksModule?.runRaceAttack) {
        await attacksModule.runRaceAttack(getAttackContext());
    }
});

attacksModule?.initWorkspace?.(getPlatformContext());
evidenceModule?.initWorkspace?.(getPlatformContext());

// ── Highlight-to-Hack: AI Exploit Context Menu ─────────────────
