const DEFAULT_PORTS = Array.from({ length: 10 }, (_, index) => 8080 + index);
const STATUS_PATH = '/api/extension/status';
const PAIR_PATH = '/api/extension/pair';
const HANDSHAKE_PATH = '/api/extension/ingest/handshake';
const LOCAL_STORAGE_KEYS = [
    'bridgeUrl',
    'projectId',
    'capturingEnabled',
    'autoDetectBridge',
    'lastDetectedBridgeUrl',
    'lastBridgeStatus',
    'captureScopes',
];
const SESSION_STORAGE_KEYS = [
    'extensionAccessToken',
    'extensionAccessTokenExpiresAt',
    'pairedOrigin',
];
const CAPTURE_HEADER_ALLOWLIST = new Set([
    'authorization',
    'cookie',
    'host',
    'origin',
    'referer',
    'sec-websocket-extensions',
    'sec-websocket-protocol',
    'sec-websocket-version',
    'user-agent',
    'x-csrf-token',
    'x-xsrf-token',
]);

const state = {
    bridgeUrl: '',
    projectId: '',
    capturingEnabled: true,
    autoDetectBridge: true,
    lastDetectedBridgeUrl: '',
    lastBridgeStatus: null,
    captureScopes: '',
    extensionAccessToken: '',
    extensionAccessTokenExpiresAt: '',
    pairedOrigin: '',
};

const sessionStorageArea = chrome.storage.session || chrome.storage.local;

function storageGet(area, keys) {
    return new Promise((resolve) => area.get(keys, resolve));
}

function storageSet(area, values) {
    return new Promise((resolve) => area.set(values, resolve));
}

function storageRemove(area, keys) {
    return new Promise((resolve) => area.remove(keys, resolve));
}

function normalizeBridgeUrl(rawValue) {
    const raw = String(rawValue || '').trim();
    if (!raw) return '';

    let candidate = raw;
    if (!/^https?:\/\//i.test(candidate)) {
        candidate = `http://${candidate}`;
    }

    try {
        const parsed = new URL(candidate);
        if (!parsed.pathname || parsed.pathname === '/') {
            parsed.pathname = HANDSHAKE_PATH;
        }
        return `${parsed.origin}${parsed.pathname}`;
    } catch (_) {
        return '';
    }
}

function bridgeBaseFromUrl(rawValue) {
    const normalized = normalizeBridgeUrl(rawValue);
    if (!normalized) return '';
    try {
        return new URL(normalized).origin;
    } catch (_) {
        return '';
    }
}

function normalizeCaptureScopes(rawValue) {
    return String(rawValue || '')
        .split(/[\n,]/)
        .map((item) => item.trim().toLowerCase())
        .filter(Boolean)
        .map((item) => item.replace(/^\*\./, '.'))
        .join(', ');
}

function parseCaptureScopes() {
    return normalizeCaptureScopes(state.captureScopes)
        .split(',')
        .map((item) => item.trim())
        .filter(Boolean);
}

function hostMatchesScope(hostname, scope) {
    const host = String(hostname || '').trim().toLowerCase();
    const candidate = String(scope || '').trim().toLowerCase();
    if (!host || !candidate) return false;
    if (host === candidate) return true;
    if (candidate.startsWith('.')) {
        return host.endsWith(candidate);
    }
    return host === candidate || host.endsWith(`.${candidate}`);
}

function requestWithinCaptureScope(details) {
    const scopes = parseCaptureScopes();
    if (scopes.length === 0) {
        return false;
    }

    const urls = [details.url, details.documentUrl, details.initiator]
        .filter(Boolean)
        .map((value) => {
            try {
                return new URL(value);
            } catch (_) {
                return null;
            }
        })
        .filter(Boolean);

    return urls.some((parsed) => scopes.some((scope) => hostMatchesScope(parsed.hostname, scope)));
}

function sessionTokenValid() {
    if (!state.extensionAccessToken || !state.extensionAccessTokenExpiresAt) {
        return false;
    }
    const expiresAt = Date.parse(state.extensionAccessTokenExpiresAt);
    if (!Number.isFinite(expiresAt)) {
        return false;
    }
    return expiresAt - Date.now() > 30_000;
}

async function loadState() {
    const [storedLocal, storedSession] = await Promise.all([
        storageGet(chrome.storage.local, LOCAL_STORAGE_KEYS),
        storageGet(sessionStorageArea, SESSION_STORAGE_KEYS),
    ]);

    state.bridgeUrl = normalizeBridgeUrl(storedLocal.bridgeUrl);
    state.projectId = String(storedLocal.projectId || '').trim();
    state.capturingEnabled = storedLocal.capturingEnabled !== false;
    state.autoDetectBridge = storedLocal.autoDetectBridge !== false;
    state.lastDetectedBridgeUrl = normalizeBridgeUrl(storedLocal.lastDetectedBridgeUrl);
    state.lastBridgeStatus = storedLocal.lastBridgeStatus || null;
    state.captureScopes = normalizeCaptureScopes(storedLocal.captureScopes);

    state.extensionAccessToken = String(storedSession.extensionAccessToken || '').trim();
    state.extensionAccessTokenExpiresAt = String(storedSession.extensionAccessTokenExpiresAt || '').trim();
    state.pairedOrigin = String(storedSession.pairedOrigin || '').trim();
}

async function fetchJson(url, options = {}, timeoutMs = 1500) {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), timeoutMs);
    try {
        const response = await fetch(url, { ...options, signal: controller.signal });
        const payload = await response.json().catch(() => ({}));
        return { ok: response.ok, status: response.status, payload };
    } finally {
        clearTimeout(timer);
    }
}

function candidateBridgeBases() {
    const bases = [];
    const configuredBase = bridgeBaseFromUrl(state.bridgeUrl);
    const detectedBase = bridgeBaseFromUrl(state.lastDetectedBridgeUrl);

    if (configuredBase) bases.push(configuredBase);
    if (detectedBase && detectedBase !== configuredBase) bases.push(detectedBase);

    DEFAULT_PORTS.forEach((port) => {
        bases.push(`http://127.0.0.1:${port}`);
    });

    return [...new Set(bases)];
}

async function probeBridgeBase(baseUrl) {
    const headers = {
        'X-WSHawk-Extension-Id': chrome.runtime.id,
    };
    const result = await fetchJson(`${baseUrl}${STATUS_PATH}`, { headers }, 1200);
    if (!result.ok || result.payload.status !== 'online') {
        return null;
    }

    const handshakePath = result.payload.handshake_path || HANDSHAKE_PATH;
    return {
        baseUrl,
        handshakeUrl: `${baseUrl}${handshakePath}`,
        pairPath: `${baseUrl}${result.payload.pair_path || PAIR_PATH}`,
        info: result.payload,
    };
}

async function discoverBridge(force = false) {
    if (!force && state.lastDetectedBridgeUrl && !state.autoDetectBridge) {
        return {
            handshakeUrl: state.lastDetectedBridgeUrl,
            info: state.lastBridgeStatus,
            pairPath: `${bridgeBaseFromUrl(state.lastDetectedBridgeUrl)}${PAIR_PATH}`,
        };
    }

    for (const baseUrl of candidateBridgeBases()) {
        try {
            const detected = await probeBridgeBase(baseUrl);
            if (!detected) continue;

            state.lastDetectedBridgeUrl = normalizeBridgeUrl(detected.handshakeUrl);
            state.lastBridgeStatus = detected.info;
            await storageSet(chrome.storage.local, {
                lastDetectedBridgeUrl: state.lastDetectedBridgeUrl,
                lastBridgeStatus: state.lastBridgeStatus,
            });
            return detected;
        } catch (_) {
            // Try the next candidate bridge port.
        }
    }

    state.lastBridgeStatus = { status: 'offline' };
    await storageSet(chrome.storage.local, { lastBridgeStatus: state.lastBridgeStatus });
    return null;
}

async function resolveBridgeTarget(forceDetect = false) {
    if (!forceDetect && state.bridgeUrl) {
        const baseUrl = bridgeBaseFromUrl(state.bridgeUrl);
        return {
            handshakeUrl: state.bridgeUrl,
            pairPath: `${baseUrl}${PAIR_PATH}`,
            info: state.lastBridgeStatus,
        };
    }

    if (!state.autoDetectBridge && state.lastDetectedBridgeUrl) {
        const baseUrl = bridgeBaseFromUrl(state.lastDetectedBridgeUrl);
        return {
            handshakeUrl: state.lastDetectedBridgeUrl,
            pairPath: `${baseUrl}${PAIR_PATH}`,
            info: state.lastBridgeStatus,
        };
    }

    return discoverBridge(forceDetect);
}

async function persistSession(session) {
    state.extensionAccessToken = String(session?.token || '').trim();
    state.extensionAccessTokenExpiresAt = String(session?.expires_at || '').trim();
    state.pairedOrigin = String(session?.paired_origin || '').trim();
    await storageSet(sessionStorageArea, {
        extensionAccessToken: state.extensionAccessToken,
        extensionAccessTokenExpiresAt: state.extensionAccessTokenExpiresAt,
        pairedOrigin: state.pairedOrigin,
    });
}

async function clearSession() {
    state.extensionAccessToken = '';
    state.extensionAccessTokenExpiresAt = '';
    state.pairedOrigin = '';
    await storageRemove(sessionStorageArea, SESSION_STORAGE_KEYS);
}

async function ensurePaired(forceDetect = false) {
    if (sessionTokenValid()) {
        return true;
    }

    const target = await resolveBridgeTarget(forceDetect);
    if (!target?.pairPath) {
        await clearSession();
        return false;
    }

    const result = await fetchJson(target.pairPath, {
        method: 'POST',
        headers: {
            'Content-Type': 'application/json',
            'X-WSHawk-Extension-Id': chrome.runtime.id,
        },
        body: JSON.stringify({
            extension_id: chrome.runtime.id,
            extension_version: chrome.runtime.getManifest().version,
        }),
    }, 1800);

    if (!result.ok || result.payload.status !== 'success') {
        await clearSession();
        return false;
    }

    await persistSession(result.payload.pairing || {});
    state.lastBridgeStatus = target.info || state.lastBridgeStatus;
    return true;
}

function isWebSocketUpgrade(requestHeaders) {
    return (requestHeaders || []).some((header) => {
        return header.name && header.value
            && header.name.toLowerCase() === 'upgrade'
            && header.value.toLowerCase() === 'websocket';
    });
}

function buildHandshake(details) {
    const handshake = {
        url: details.url,
        method: details.method,
        headers: {},
        timestamp: new Date().toISOString(),
        initiator: details.initiator || '',
        documentUrl: details.documentUrl || '',
        tabId: details.tabId,
        frameId: details.frameId,
        source: 'browser_extension',
        extension_version: chrome.runtime.getManifest().version,
        extension_id: chrome.runtime.id,
    };

    if (state.projectId) {
        handshake.project_id = state.projectId;
    }

    (details.requestHeaders || []).forEach((header) => {
        const key = String(header.name || '').trim();
        if (!key) return;
        if (!CAPTURE_HEADER_ALLOWLIST.has(key.toLowerCase())) return;
        handshake.headers[key] = header.value;
    });

    return handshake;
}

async function sendHandshake(handshake, retryOnDetect = true) {
    if (!requestWithinCaptureScope({ url: handshake.url, documentUrl: handshake.documentUrl, initiator: handshake.initiator })) {
        return false;
    }

    const ready = await ensurePaired(false);
    if (!ready) {
        if (state.autoDetectBridge && retryOnDetect) {
            const refreshed = await ensurePaired(true);
            if (refreshed) {
                return sendHandshake(handshake, false);
            }
        }
        console.warn('[WSHawk] Bridge pairing unavailable.');
        return false;
    }

    const target = await resolveBridgeTarget(false);
    const bridgeUrl = target?.handshakeUrl;
    if (!bridgeUrl) {
        return false;
    }

    try {
        const result = await fetchJson(bridgeUrl, {
            method: 'POST',
            headers: {
                'Content-Type': 'application/json',
                'X-WSHawk-Extension-Id': chrome.runtime.id,
                'X-WSHawk-Extension-Token': state.extensionAccessToken,
            },
            body: JSON.stringify(handshake),
        }, 1800);

        if (result.status === 401) {
            await clearSession();
        }

        if (!result.ok && retryOnDetect && state.autoDetectBridge) {
            const refreshed = await ensurePaired(true);
            if (refreshed) {
                return sendHandshake(handshake, false);
            }
        }

        return result.ok;
    } catch (error) {
        if (retryOnDetect && state.autoDetectBridge) {
            const refreshed = await ensurePaired(true);
            if (refreshed) {
                return sendHandshake(handshake, false);
            }
        }
        console.error('[WSHawk] Handshake sync failed:', error);
        return false;
    }
}

chrome.runtime.onInstalled.addListener(() => {
    chrome.storage.local.set({
        capturingEnabled: true,
        autoDetectBridge: true,
        captureScopes: '',
    });
});

chrome.storage.onChanged.addListener((changes, areaName) => {
    if (areaName === 'local') {
        if (changes.bridgeUrl) state.bridgeUrl = normalizeBridgeUrl(changes.bridgeUrl.newValue);
        if (changes.projectId) state.projectId = String(changes.projectId.newValue || '').trim();
        if (changes.capturingEnabled) state.capturingEnabled = changes.capturingEnabled.newValue !== false;
        if (changes.autoDetectBridge) state.autoDetectBridge = changes.autoDetectBridge.newValue !== false;
        if (changes.lastDetectedBridgeUrl) state.lastDetectedBridgeUrl = normalizeBridgeUrl(changes.lastDetectedBridgeUrl.newValue);
        if (changes.lastBridgeStatus) state.lastBridgeStatus = changes.lastBridgeStatus.newValue || null;
        if (changes.captureScopes) state.captureScopes = normalizeCaptureScopes(changes.captureScopes.newValue);
    }

    if (areaName === 'session' || areaName === 'local') {
        if (changes.extensionAccessToken) state.extensionAccessToken = String(changes.extensionAccessToken.newValue || '').trim();
        if (changes.extensionAccessTokenExpiresAt) state.extensionAccessTokenExpiresAt = String(changes.extensionAccessTokenExpiresAt.newValue || '').trim();
        if (changes.pairedOrigin) state.pairedOrigin = String(changes.pairedOrigin.newValue || '').trim();
    }
});

chrome.runtime.onMessage.addListener((message, _sender, sendResponse) => {
    if (!message || !message.type) return undefined;

    if (message.type === 'wshawk:get-config') {
        loadState().then(() => {
            sendResponse({
                ok: true,
                config: {
                    ...state,
                    hasPairedSession: sessionTokenValid(),
                },
            });
        });
        return true;
    }

    if (message.type === 'wshawk:save-config') {
        const nextValues = {
            bridgeUrl: normalizeBridgeUrl(message.bridgeUrl),
            projectId: String(message.projectId || '').trim(),
            capturingEnabled: message.capturingEnabled !== false,
            autoDetectBridge: message.autoDetectBridge !== false,
            captureScopes: normalizeCaptureScopes(message.captureScopes),
        };
        storageSet(chrome.storage.local, nextValues).then(async () => {
            await loadState();
            sendResponse({
                ok: true,
                config: {
                    ...state,
                    hasPairedSession: sessionTokenValid(),
                },
            });
        });
        return true;
    }

    if (message.type === 'wshawk:discover-bridge') {
        loadState().then(async () => {
            const detected = await discoverBridge(true);
            const paired = detected ? await ensurePaired(false) : false;
            sendResponse({
                ok: Boolean(detected),
                paired,
                bridgeUrl: detected?.handshakeUrl || '',
                bridgeInfo: detected?.info || state.lastBridgeStatus || null,
                pairedOrigin: state.pairedOrigin,
            });
        });
        return true;
    }

    if (message.type === 'wshawk:clear-session') {
        clearSession().then(() => sendResponse({ ok: true }));
        return true;
    }

    return undefined;
});

chrome.webRequest.onBeforeSendHeaders.addListener(
    (details) => {
        if (!state.capturingEnabled || !isWebSocketUpgrade(details.requestHeaders)) {
            return;
        }

        if (!requestWithinCaptureScope(details)) {
            return;
        }

        const handshake = buildHandshake(details);
        void sendHandshake(handshake);
    },
    { urls: ['<all_urls>'] },
    ['requestHeaders', 'extraHeaders']
);

void loadState();
