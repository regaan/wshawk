(function HighlightToHack() {
    'use strict';

    const reqforgeEditor = document.getElementById('reqforge-req');
    const ctxMenu = document.getElementById('ai-exploit-menu');
    if (!reqforgeEditor || !ctxMenu) return;

    // ── Show context menu on right-click when text is selected ───
    reqforgeEditor.addEventListener('contextmenu', (e) => {
        const selection = reqforgeEditor.value.substring(
            reqforgeEditor.selectionStart,
            reqforgeEditor.selectionEnd
        );

        if (!selection || selection.trim().length === 0) return; // No selection → use native menu

        e.preventDefault();

        // Position the menu at cursor
        const menuW = 240, menuH = 400;
        let x = e.clientX;
        let y = e.clientY;
        if (x + menuW > window.innerWidth) x = window.innerWidth - menuW - 8;
        if (y + menuH > window.innerHeight) y = window.innerHeight - menuH - 8;

        ctxMenu.style.left = x + 'px';
        ctxMenu.style.top = y + 'px';
        ctxMenu.style.display = 'block';
    });

    // ── Hide menu on click elsewhere ────────────────────────────
    document.addEventListener('click', (e) => {
        if (!ctxMenu.contains(e.target)) {
            ctxMenu.style.display = 'none';
        }
    });

    document.addEventListener('keydown', (e) => {
        if (e.key === 'Escape') ctxMenu.style.display = 'none';
    });

    // ── Handle vuln type selection ──────────────────────────────
    ctxMenu.querySelectorAll('.ai-ctx-item').forEach(item => {
        item.addEventListener('click', async () => {
            const vulnType = item.getAttribute('data-vuln');
            ctxMenu.style.display = 'none';

            const fullText = reqforgeEditor.value;
            const selStart = reqforgeEditor.selectionStart;
            const selEnd = reqforgeEditor.selectionEnd;
            const selection = fullText.substring(selStart, selEnd);

            if (!selection.trim()) return;

            // Build request
            const payload = {
                full_text: fullText,
                selection: selection,
                cursor_pos: selStart,
                count: 12,
            };

            // "auto" means let the engine decide; otherwise send specific type
            if (vulnType !== 'auto') {
                payload.vuln_types = [vulnType];
            }

            // Show loading overlay on the ReqForge editor
            const editorParent = reqforgeEditor.closest('.panel') || reqforgeEditor.parentElement;
            const loader = document.createElement('div');
            loader.className = 'reqforge-ai-loading';
            loader.innerHTML = `
                <div class="ai-spinner"></div>
                <div class="ai-loading-text">Generating exploit payloads...</div>
            `;
            editorParent.style.position = 'relative';
            editorParent.appendChild(loader);

            try {
                const res = await fetch('/ai/context-exploit', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload),
                });
                const data = await res.json();

                if (data.status !== 'success' || !data.payloads || data.payloads.length === 0) {
                    throw new Error(data.msg || 'No payloads generated');
                }

                // Populate Payload Blaster
                populateBlaster(data.blaster_template, data.payloads);

                // Log context info
                const ctx = data.context || {};
                const logMsg = `[AI Exploit] Detected ${ctx.format?.toUpperCase() || 'RAW'} context — ` +
                    `key: "${ctx.key || '?'}", type: ${ctx.data_type || '?'} — ` +
                    `Generated ${data.payloads.length} payloads for: ${(data.vuln_labels || []).join(', ')}`;
                if (typeof appendLog === 'function') appendLog('info', logMsg);

            } catch (err) {
                if (typeof appendLog === 'function') {
                    appendLog('vuln', `[AI Exploit] ${err.message}`);
                }
            } finally {
                loader.remove();
            }
        });
    });

    // ── Auto-navigate to Blaster and populate fields ────────────
    function populateBlaster(template, payloads) {
        // Set the template
        const templateEl = document.getElementById('blaster-template');
        if (templateEl) templateEl.value = template || '';

        // Set the payloads (one per line)
        const payloadsEl = document.getElementById('blaster-payloads');
        if (payloadsEl) payloadsEl.value = (payloads || []).join('\n');

        // Update payload count
        const countEl = document.getElementById('blaster-payload-count');
        if (countEl) {
            countEl.textContent = `${payloads.length} payloads`;
            countEl.style.display = 'inline';
        }

        // Navigate to the Blaster tab
        const blasterNav = document.querySelector('.nav-item[data-target="blaster"]');
        if (blasterNav) {
            blasterNav.click();
        }
    }
})();

let isIntercepting = false;
const interceptBtn = document.getElementById('toggle-intercept-btn');
const interceptOrb = document.getElementById('intercept-orb');
const interceptTitle = document.getElementById('intercept-title');
const queueTbody = document.getElementById('intercept-queue-tbody');
const editorPanel = document.getElementById('intercept-editor-panel');
const frameEditor = document.getElementById('intercept-editor');
const btnForward = document.getElementById('btn-intercept-forward');
const btnDrop = document.getElementById('btn-intercept-drop');

let interceptQueue = [];
let activeFrameId = null;

async function toggleInterceptor(enabled) {
    try {
        await fetch('/interceptor/toggle', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ enabled })
        });
        isIntercepting = enabled;

        if (isIntercepting) {
            interceptOrb.classList.add('intercept-active');
            interceptTitle.innerText = "Interceptor: ENGAGED";
            interceptTitle.style.color = "var(--danger)";
            interceptBtn.innerText = "Disengage Hook";
            interceptBtn.className = "btn secondary small";
            queueTbody.innerHTML = '<tr class="empty-tr"><td colspan="3">Waiting for traffic...</td></tr>';
            appendLog('vuln', 'Local Interceptor Hook Activated.');
        } else {
            interceptOrb.classList.remove('intercept-active');
            interceptTitle.innerText = "Interceptor: Idle";
            interceptTitle.style.color = "var(--text-secondary)";
            interceptBtn.innerText = "Engage Interceptor";
            interceptBtn.className = "btn primary small";
            queueTbody.innerHTML = '<tr class="empty-tr"><td colspan="3">Interceptor is currently idle.</td></tr>';
            interceptQueue = [];
            loadNextFrame();
            appendLog('info', 'Interceptor hook removed.');
        }
    } catch (e) {
        appendLog('vuln', 'Failed to toggle interceptor: ' + e.message);
    }
}

interceptBtn.addEventListener('click', () => {
    const u = targetUrlInput.value.trim();
    if (!u && !isIntercepting) {
        appendLog('vuln', 'Input Error: Cannot engage interceptor without Target URL.');
        return;
    }
    toggleInterceptor(!isIntercepting);
});

// Handle incoming intercepted frames from socket
function handleInterceptedFrame(frame) {
    interceptQueue.push(frame);
    renderQueue();
    if (!activeFrameId) loadNextFrame();
}

function renderQueue() {
    if (interceptQueue.length === 0 && !activeFrameId) {
        queueTbody.innerHTML = '<tr class="empty-tr"><td colspan="3">Waiting for traffic...</td></tr>';
        return;
    }

    let html = '';
    interceptQueue.forEach((f, idx) => {
        html += `
            <tr style="cursor: pointer; opacity: 0.7;">
                <td class="dir-${f.direction.toLowerCase()}">${f.direction}</td>
                <td>${esc(truncate(f.url, 20))}</td>
                <td>${esc(truncate(f.payload, 30))}</td>
            </tr>
        `;
    });

    // Add active frame at top
    if (activeFrameId) {
        const activeHtml = `
            <tr style="background: rgba(59, 130, 246, 0.2);">
                <td class="dir-${activeFrame.direction.toLowerCase()}">${activeFrame.direction}</td>
                <td>${esc(truncate(activeFrame.url, 20))}</td>
                <td>${esc(truncate(activeFrame.payload, 30))}</td>
            </tr>
        `;
        queueTbody.innerHTML = activeHtml + html;
    } else {
        queueTbody.innerHTML = html;
    }
}

let activeFrame = null;

function loadNextFrame() {
    if (interceptQueue.length > 0) {
        activeFrame = interceptQueue.shift();
        activeFrameId = activeFrame.id;
        frameEditor.value = activeFrame.payload;

        editorPanel.style.opacity = '1';
        editorPanel.style.pointerEvents = 'auto';
        renderQueue();
    } else {
        activeFrame = null;
        activeFrameId = null;
        frameEditor.value = '';
        editorPanel.style.opacity = '0.5';
        editorPanel.style.pointerEvents = 'none';
        renderQueue();
    }
}

async function sendFrameAction(action) {
    if (!activeFrameId) return;
    const payload = frameEditor.value;
    const id = activeFrameId;

    try {
        await fetch('/interceptor/action', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({ id, action, payload })
        });
        appendLog('info', `Frame ${action}ed`);
        loadNextFrame();
    } catch (e) {
        appendLog('vuln', `Action failed: ${e.message}`);
    }
}

btnForward.addEventListener('click', () => sendFrameAction('forward'));
btnDrop.addEventListener('click', () => sendFrameAction('drop'));

const payloadSelect = document.getElementById('blaster-payload-select');
if (payloadSelect) {
    payloadSelect.addEventListener('change', async (e) => {
        const category = e.target.value;
        const countSpan = document.getElementById('blaster-payload-count');
        if (!category) {
            countSpan.style.display = 'none';
            return;
        }

        try {
            const res = await fetch(`/blaster/payloads/${category}`);
            const data = await res.json();

            if (data.payloads) {
                const payloadsBox = document.getElementById('blaster-payloads');
                payloadsBox.value = data.payloads.join('\n');
                countSpan.innerText = `(~${data.count} payloads)`;
                countSpan.style.display = 'inline';
                appendLog('info', `Loaded ${data.count} elite payloads for ${category}`);
            }
        } catch (e) {
            appendLog('vuln', 'Failed to load payload list: ' + e.message);
        }
    });
}

const payloadsBox = document.getElementById('blaster-payloads');
if (payloadsBox) {
    payloadsBox.addEventListener('input', () => {
        const countSpan = document.getElementById('blaster-payload-count');
        const count = payloadsBox.value.split('\n').filter(p => p.trim() !== '').length;
        countSpan.innerText = `(~${count} payloads)`;
        countSpan.style.display = 'inline';
    });
}

const blasterBtn = document.getElementById('blaster-start-btn');
blasterBtn.addEventListener('click', async () => {
    const u = targetUrlInput.value.trim();
    const authPayload = document.getElementById('auth-payload').value.trim();
    if (!u) {
        appendLog('vuln', 'Input Error: Cannot start fuzzing without Target URL.');
        return;
    }

    const template = document.getElementById('blaster-template').value;
    const payloads = document.getElementById('blaster-payloads').value.split('\n');
    const speChecked = document.getElementById('blaster-spe-checkbox').checked;
    const domVerify = document.getElementById('blaster-dom-verify')?.checked || false;

    // Include saved auth flow if recorded
    const authFlow = window._domInvaderAuthFlow || null;

    document.getElementById('blaster-tbody').innerHTML = '<tr class="empty-tr"><td colspan="6">Fuzzing...</td></tr>';
    blasterBtn.disabled = true;
    blasterBtn.innerText = "BLASTING...";
    document.getElementById('blaster-stop-btn').style.display = 'block';

    if (domVerify) appendLog('info', '[DOM Invader] Headless XSS verification enabled for sandboxed execution evidence.');
    if (authFlow) appendLog('info', '[DOM Invader] Auth flow active — will auto-replay on session expiry.');

    try {
        await fetch('/blaster/start', {
            method: 'POST',
            headers: { 'Content-Type': 'application/json' },
            body: JSON.stringify({
                url: u,
                payloads: payloads,
                template: template,
                spe: speChecked,
                auth_payload: authPayload,
                dom_verify: domVerify,
                auth_flow: authFlow,
            })
        });
    } catch (e) {
        appendLog('vuln', '[ERR] Payload Blast Failed');
        blasterBtn.disabled = false;
        blasterBtn.innerText = "COMMENCE FUZZING";
        document.getElementById('blaster-stop-btn').style.display = 'none';
    }
});

const blasterStopBtn = document.getElementById('blaster-stop-btn');
if (blasterStopBtn) {
    blasterStopBtn.addEventListener('click', async () => {
        try {
            await fetch('/blaster/stop', { method: 'POST' });
            appendLog('info', 'Commanded Blaster to HALT.');
            blasterBtn.disabled = false;
            blasterBtn.innerText = "COMMENCE FUZZING";
            blasterStopBtn.style.display = 'none';
        } catch (e) {
            appendLog('vuln', 'Failed to stop blaster: ' + e.message);
        }
    });
}

// ── DOM Invader Frontend Module ──────────────────────────────────
(function DOMInvaderUI() {
    'use strict';

    const statusPill = document.getElementById('dom-invader-status');
    const recordBtn = document.getElementById('dom-record-auth-btn');
    const replayBtn = document.getElementById('dom-replay-auth-btn');
    const authStatus = document.getElementById('dom-auth-status');

    function inferLoginUrl(targetWs) {
        if (!targetWs) return '';
        try {
            const parsed = new URL(targetWs);
            parsed.protocol = parsed.protocol === 'wss:' ? 'https:' : 'http:';
            parsed.pathname = '/login';
            parsed.search = '';
            parsed.hash = '';
            return parsed.toString();
        } catch (_) {
            return '';
        }
    }

    // ── Check Playwright availability on load ────────────────────
    async function checkStatus() {
        try {
            const res = await fetch('/dom/status');
            const data = await res.json();
            if (!statusPill) return;
            if (data.playwright_installed) {
                statusPill.className = 'dom-status-pill dom-status-available';
                statusPill.textContent = 'Playwright Ready';
            } else {
                statusPill.className = 'dom-status-pill dom-status-unavailable';
                statusPill.textContent = 'Not Installed';
                statusPill.title = 'Run: pip install playwright && playwright install chromium';
            }
        } catch (_) {
            if (statusPill) {
                statusPill.className = 'dom-status-pill dom-status-unknown';
                statusPill.textContent = 'Offline';
            }
        }
    }

    // Check status when Blaster tab opens
    document.querySelectorAll('.nav-item').forEach(item => {
        if (item.dataset.target === 'blaster') {
            item.addEventListener('click', () => setTimeout(checkStatus, 300));
        }
    });
    checkStatus();

    // ── Record Auth Flow ─────────────────────────────────────────
    if (recordBtn) {
        recordBtn.addEventListener('click', async () => {
            const targetWs = targetUrlInput?.value.trim() || '';
            const suggestedLoginUrl = inferLoginUrl(targetWs) || 'https://';
            let loginUrl = suggestedLoginUrl;

            try {
                if (typeof window.prompt === 'function') {
                    const prompted = window.prompt(
                        'Enter the login URL to record auth flow:\n(e.g. https://app.example.com/login)',
                        suggestedLoginUrl
                    );
                    if (prompted && prompted.startsWith('http')) {
                        loginUrl = prompted;
                    } else if (prompted === null && suggestedLoginUrl === 'https://') {
                        return;
                    }
                }
            } catch (_) {
                // Fall back to inferred URL when dialogs are unavailable in the shell.
            }

            if (!loginUrl || !loginUrl.startsWith('http')) return;

            recordBtn.disabled = true;
            recordBtn.textContent = 'Recording...';
            if (authStatus) {
                authStatus.style.display = 'block';
                authStatus.textContent = `Visible browser opened for ${loginUrl} — complete your login. Auto-closes after 2 minutes.`;
            }
            appendLog('info', `[DOM Invader] Recording auth flow at ${loginUrl}...`);

            try {
                const project = targetWs ? await ensurePlatformProject('dom_auth_record', targetWs) : null;
                const res = await fetch('/dom/auth/record', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        login_url: loginUrl,
                        target_ws_url: targetWs,
                        timeout_s: 120,
                        project_id: project?.id || currentProject.projectId || null,
                    }),
                });
                const data = await res.json();
                if (data.status === 'success' && data.flow) {
                    window._domInvaderAuthFlow = data.flow;
                    const cookieCount = (data.flow.cookies || []).length;
                    const tokenCount = Object.keys(data.flow.extracted_tokens || {}).length;
                    recordBtn.textContent = 'Re-Record Auth';
                    recordBtn.disabled = false;
                    if (replayBtn) {
                        replayBtn.style.display = 'inline-flex';
                        replayBtn.textContent = `Auth Saved (${cookieCount} cookies, ${tokenCount} tokens)`;
                    }
                    if (authStatus) {
                        authStatus.textContent = `Captured: ${cookieCount} cookies, ${tokenCount} tokens. Active for this session.`;
                    }
                    appendLog('success', `[DOM Invader] Auth flow recorded: ${cookieCount} cookies, ${tokenCount} tokens`);
                    queuePlatformProjectRefresh(150);
                } else {
                    throw new Error(data.msg || 'Recording failed');
                }
            } catch (err) {
                appendLog('vuln', `[DOM Invader] Auth recording failed: ${err.message}`);
                recordBtn.disabled = false;
                recordBtn.textContent = 'Record Auth Flow';
                if (authStatus) authStatus.style.display = 'none';
            }
        });
    }

    // ── Discard saved auth flow ──────────────────────────────────
    if (replayBtn) {
        replayBtn.addEventListener('click', () => {
            if (confirm('Discard the saved auth flow?')) {
                window._domInvaderAuthFlow = null;
                replayBtn.style.display = 'none';
                if (authStatus) {
                    authStatus.textContent = 'Auth flow cleared.';
                    setTimeout(() => { authStatus.style.display = 'none'; }, 2000);
                }
                appendLog('info', '[DOM Invader] Auth flow discarded.');
            }
        });
    }
})();

// --- Settings Modal Logic ---
const btnSettings = document.getElementById('btn-settings');
const settingsModal = document.getElementById('settings-modal');
const btnSettingsClose = document.getElementById('btn-settings-close');
const btnSettingsSave = document.getElementById('btn-settings-save');

console.log('[UI] Initializing Modals...', { btnSettings: !!btnSettings, settingsModal: !!settingsModal });

if (btnSettings && settingsModal) {
    const secretFieldConfig = {
        'cfg-jira-token': { configuredKey: 'jiraTokenConfigured', placeholder: 'Configured. Leave blank to keep current token.' },
        'cfg-dd-key': { configuredKey: 'ddKeyConfigured', placeholder: 'Configured. Leave blank to keep current API key.' },
        'cfg-ai-key': { configuredKey: 'aiApiKeyConfigured', placeholder: 'Configured. Leave blank to keep current API key.' }
    };

    btnSettings.addEventListener('click', async () => {
        console.log('[UI] Opening Settings Modal');
        settingsModal.style.display = 'flex';
        try {
            const res = await fetch('/config/get');
            const data = await res.json();
            if (data.status === 'success') {
                const fields = {
                    'cfg-jira-url': data.jiraUrl,
                    'cfg-jira-email': data.jiraEmail,
                    'cfg-jira-project': data.jiraProject,
                    'cfg-dd-url': data.ddUrl,
                    // AI Settings
                    'cfg-ai-provider': data.ai_provider,
                    'cfg-ai-model': data.ai_model,
                    'cfg-ai-url': data.ai_base_url
                };
                for (const [id, val] of Object.entries(fields)) {
                    const el = document.getElementById(id);
                    if (el) el.value = val || '';
                }
                Object.entries(secretFieldConfig).forEach(([id, config]) => {
                    const el = document.getElementById(id);
                    if (!el) return;
                    el.value = '';
                    el.placeholder = data[config.configuredKey] ? config.placeholder : '';
                });
            }
        } catch (e) {
            console.error('[UI] Fetch config failed:', e);
            if (typeof appendLog === 'function') appendLog('vuln', 'Bridge error: Failed to fetch integration config.');
        }
    });

    if (btnSettingsClose) {
        btnSettingsClose.addEventListener('click', () => {
            console.log('[UI] Closing Settings Modal');
            settingsModal.style.display = 'none';
        });
    }

    if (btnSettingsSave) {
        btnSettingsSave.addEventListener('click', async () => {
            const getVal = (id) => {
                const el = document.getElementById(id);
                return el ? el.value.trim() : '';
            };

            const payload = {
                jiraUrl: getVal('cfg-jira-url'),
                jiraEmail: getVal('cfg-jira-email'),
                jiraToken: getVal('cfg-jira-token'),
                jiraProject: getVal('cfg-jira-project'),
                ddUrl: getVal('cfg-dd-url'),
                ddKey: getVal('cfg-dd-key'),
                // AI Settings
                ai_provider: getVal('cfg-ai-provider'),
                ai_model: getVal('cfg-ai-model'),
                ai_base_url: getVal('cfg-ai-url'),
                ai_api_key: getVal('cfg-ai-key')
            };

            try {
                const res = await fetch('/config/save', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });
                const data = await res.json();
                if (data.status === 'success') {
                    if (typeof appendLog === 'function') appendLog('success', 'Enterprise settings saved correctly.');
                    settingsModal.style.display = 'none';
                } else {
                    if (typeof appendLog === 'function') appendLog('vuln', 'Save failed: ' + data.msg);
                }
            } catch (e) {
                console.error('[UI] Save config failed:', e);
                if (typeof appendLog === 'function') appendLog('vuln', 'Bridge error: Failed to save settings.');
            }
        });
    }
}

// Settings modal click outside to close
window.addEventListener('click', (e) => {
    if (e.target === settingsModal) {
        settingsModal.style.display = 'none';
    }
});

function showToS() {
    const agreed = localStorage.getItem('wshawk_tos_agreed');
    console.log('[UI] Checking ToS status:', agreed);
    if (!agreed) {
        const tosModal = document.getElementById('tos-modal');
        if (tosModal) {
            console.log('[UI] Displaying Legal Terms of Service');
            tosModal.style.display = 'flex';
        }
    }
}

const btnAgreeToS = document.getElementById('btn-agree-tos');
if (btnAgreeToS) {
    btnAgreeToS.addEventListener('click', () => {
        console.log('[UI] User agreed to terms');
        safeStore('wshawk_tos_agreed', 'true');
        const modal = document.getElementById('tos-modal');
        if (modal) modal.style.display = 'none';
    });
}

// Clear Blaster Button
const btnClearBlaster = document.getElementById('blaster-clear-btn');
if (btnClearBlaster) {
    btnClearBlaster.addEventListener('click', () => {
        const tbody = document.getElementById('blaster-tbody');
        if (tbody) tbody.innerHTML = '<tr class="empty-tr"><td colspan="5">Awaiting execution...</td></tr>';
        baselineLength = null;
    });
}

// ═══════════════════════════════════════════════════════════════
// SHARED UTILITIES
// ═══════════════════════════════════════════════════════════════

// Global sanitizer for innerHTML rendering — prevents XSS in dynamic content
function esc(s) {
    if (!s) return '';
    return String(s).replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

// Safe localStorage write — catches QuotaExceededError gracefully
function safeStore(key, value) {
    try {
        localStorage.setItem(key, typeof value === 'string' ? value : JSON.stringify(value));
        return true;
    } catch (e) {
        if (e.name === 'QuotaExceededError' || e.code === 22) {
            appendLog('vuln', `Storage quota exceeded. Cannot save ${key}. Clear old data to free space.`);
        } else {
            appendLog('vuln', `Storage error for ${key}: ${e.message}`);
        }
        return false;
    }
}

// ═══════════════════════════════════════════════════════════════
// GLOBAL KEYBOARD SHORTCUTS
// ═══════════════════════════════════════════════════════════════
document.addEventListener('keydown', (e) => {
    // Ctrl+S — Save project
    if ((e.ctrlKey || e.metaKey) && e.key === 's') {
        e.preventDefault();
        document.getElementById('btn-save-project')?.click();
        return;
    }

    // Ctrl+Enter — Execute active action based on current view
    if ((e.ctrlKey || e.metaKey) && e.key === 'Enter') {
        e.preventDefault();
        const activeView = document.querySelector('.view.active');
        if (!activeView) return;

        const viewId = activeView.id;
        switch (viewId) {
            case 'view-dashboard':
                scanBtn?.click();
                break;
            case 'view-reqforge':
                document.getElementById('send-reqforge')?.click();
                break;
            case 'view-comparer':
                document.getElementById('comparer-run-btn')?.click();
                break;
            case 'view-codec':
                document.getElementById('codec-smart-btn')?.click();
                break;
            case 'view-authbuilder':
                document.getElementById('auth-test-btn')?.click();
                break;
            case 'view-wsmap':
                document.getElementById('wsmap-scan-btn')?.click();
                break;
            case 'view-blaster':
                document.getElementById('blaster-start-btn')?.click();
                break;
            case 'view-mutationlab':
                document.getElementById('mutation-run-btn')?.click();
                break;
        }
        return;
    }

    // Ctrl+Shift+N — New note
    if ((e.ctrlKey || e.metaKey) && e.shiftKey && e.key === 'N') {
        e.preventDefault();
        document.getElementById('notes-add-btn')?.click();
        // Switch to notes view
        document.querySelector('.nav-item[data-target="notes"]')?.click();
        return;
    }
    // Ctrl+K — Global search
    if ((e.ctrlKey || e.metaKey) && e.key === 'k') {
        e.preventDefault();
        toggleGlobalSearch();
        return;
    }

    // Escape — Close modals
    if (e.key === 'Escape') {
        const gsModal = document.getElementById('global-search-modal');
        if (gsModal && gsModal.style.display === 'flex') {
            gsModal.style.display = 'none';
            return;
        }

        const picker = document.getElementById('sched-interval-picker');
        if (picker) { picker.remove(); return; }

        if (settingsModal && settingsModal.style.display === 'flex') {
            settingsModal.style.display = 'none';
            return;
        }
    }
});

// ═══════════════════════════════════════════════════════════════
// CODEC
// ═══════════════════════════════════════════════════════════════
