const { app, BrowserWindow, ipcMain, dialog, shell } = require('electron');
const path = require('path');
const { spawn, execSync } = require('child_process');
const fs = require('fs');

let mainWindow;
let pythonProcess;
let bridgeInfo = { port: null, token: null };
const sidecarState = {
    stdout: [],
    stderr: [],
    exited: false,
    exitCode: null,
    exitSignal: null,
};

const WSHAWK_E2E = process.env.WSHAWK_E2E === '1' || process.env.BASILISK_E2E === '1';
const WSHAWK_E2E_AUTOEXIT = process.env.WSHAWK_E2E_AUTOEXIT === '1' || process.env.BASILISK_E2E_AUTOEXIT === '1';
const WSHAWK_E2E_OUT = process.env.WSHAWK_E2E_OUT || process.env.BASILISK_E2E_OUT || '/tmp/wshawk-e2e.json';
const WSHAWK_E2E_NO_SANDBOX = process.env.WSHAWK_E2E_NO_SANDBOX === '1';
const WSHAWK_DESKTOP_SMOKE = process.env.WSHAWK_DESKTOP_SMOKE === '1';
const WSHAWK_DESKTOP_SMOKE_OUT = process.env.WSHAWK_DESKTOP_SMOKE_OUT || '/tmp/wshawk-desktop-smoke.json';
const WSHAWK_DESKTOP_SMOKE_TIMEOUT_MS = Number.parseInt(process.env.WSHAWK_DESKTOP_SMOKE_TIMEOUT_MS || '12000', 10);
let e2eSnapshotTimer = null;
let e2eSnapshotWritten = false;
let desktopSmokeSnapshotWritten = false;
let desktopSmokeTimer = null;
const desktopSmokeState = {
    didFinishLoad: false,
    bridgePort: false,
    bridgeReady: false,
};

if (process.env.BASILISK_E2E && !process.env.WSHAWK_E2E) {
    console.warn('[E2E] BASILISK_E2E is deprecated; use WSHAWK_E2E instead.');
}

if (WSHAWK_E2E) {
    process.env.LIBGL_ALWAYS_SOFTWARE = '1';
    app.disableHardwareAcceleration();
    app.commandLine.appendSwitch('headless');
    app.commandLine.appendSwitch('disable-gpu');
    app.commandLine.appendSwitch('disable-gpu-compositing');
    app.commandLine.appendSwitch('disable-gpu-rasterization');
    app.commandLine.appendSwitch('disable-software-rasterizer');
    app.commandLine.appendSwitch('disable-dev-shm-usage');
    app.commandLine.appendSwitch('ozone-platform', 'headless');
    app.commandLine.appendSwitch('use-gl', 'disabled');
    app.commandLine.appendSwitch('disable-features', 'VizDisplayCompositor,UseSkiaRenderer');
    app.commandLine.appendSwitch('in-process-gpu');
    app.commandLine.appendSwitch('single-process');
    if (WSHAWK_E2E_NO_SANDBOX) {
        app.commandLine.appendSwitch('no-sandbox');
    }
}

if (!WSHAWK_E2E_NO_SANDBOX) {
    app.enableSandbox();
}

function writeDesktopSmokeSnapshot(snapshot) {
    if (!WSHAWK_DESKTOP_SMOKE || desktopSmokeSnapshotWritten) {
        return;
    }
    desktopSmokeSnapshotWritten = true;
    try {
        fs.writeFileSync(WSHAWK_DESKTOP_SMOKE_OUT, JSON.stringify(snapshot, null, 2), 'utf-8');
        console.log(`[SMOKE] Snapshot written to ${WSHAWK_DESKTOP_SMOKE_OUT}`);
    } catch (error) {
        console.error(`[SMOKE] Failed to write snapshot: ${error.message}`);
    }
    setTimeout(() => app.quit(), 200);
}

async function captureDesktopSmokeSnapshot(reason, ok = false) {
    if (!WSHAWK_DESKTOP_SMOKE || desktopSmokeSnapshotWritten) {
        return;
    }

    const snapshot = {
        ok,
        reason,
        timestamp: new Date().toISOString(),
        bridgeInfo: {
            port: bridgeInfo.port,
            tokenPresent: Boolean(bridgeInfo.token),
        },
        sidecar: {
            stdout: sidecarState.stdout.slice(-10),
            stderr: sidecarState.stderr.slice(-10),
            exited: sidecarState.exited,
            exitCode: sidecarState.exitCode,
            exitSignal: sidecarState.exitSignal,
        },
        smokeState: {
            ...desktopSmokeState,
        },
    };

    try {
        if (mainWindow && !mainWindow.isDestroyed()) {
            snapshot.window = {
                visible: mainWindow.isVisible(),
                destroyed: mainWindow.isDestroyed(),
                title: mainWindow.getTitle(),
                url: mainWindow.webContents.getURL(),
            };
            snapshot.renderer = await mainWindow.webContents.executeJavaScript(`
                ({
                    title: document.title,
                    readyState: document.readyState,
                    hasApiBridge: Boolean(window.api),
                    hasReceiveBridge: typeof window.api?.receive === 'function',
                    hasTargetUrlInput: Boolean(document.getElementById('target-url')),
                    navCount: document.querySelectorAll('.nav-item').length
                })
            `, true);
        } else {
            snapshot.window = { destroyed: true };
        }
    } catch (error) {
        snapshot.rendererError = error.message;
    }

    writeDesktopSmokeSnapshot(snapshot);
}

function maybeCompleteDesktopSmoke(reason) {
    if (!WSHAWK_DESKTOP_SMOKE || desktopSmokeSnapshotWritten) {
        return;
    }
    if (desktopSmokeState.didFinishLoad && desktopSmokeState.bridgePort && desktopSmokeState.bridgeReady) {
        captureDesktopSmokeSnapshot(reason, true).catch((error) => {
            writeDesktopSmokeSnapshot({
                ok: false,
                reason,
                error: error.message,
                timestamp: new Date().toISOString(),
                smokeState: { ...desktopSmokeState },
                bridgeInfo: { port: bridgeInfo.port, tokenPresent: Boolean(bridgeInfo.token) },
                sidecar: sidecarState,
            });
        });
    }
}

function scheduleDesktopSmokeTimeout() {
    if (!WSHAWK_DESKTOP_SMOKE || desktopSmokeSnapshotWritten) {
        return;
    }
    if (desktopSmokeTimer) {
        clearTimeout(desktopSmokeTimer);
    }
    desktopSmokeTimer = setTimeout(() => {
        captureDesktopSmokeSnapshot('timeout', false).catch((error) => {
            writeDesktopSmokeSnapshot({
                ok: false,
                reason: 'timeout',
                error: error.message,
                timestamp: new Date().toISOString(),
                smokeState: { ...desktopSmokeState },
                bridgeInfo: { port: bridgeInfo.port, tokenPresent: Boolean(bridgeInfo.token) },
                sidecar: sidecarState,
            });
        });
    }, Math.max(2000, WSHAWK_DESKTOP_SMOKE_TIMEOUT_MS || 12000));
}

function rememberSidecarLog(kind, message) {
    if (!message) return;
    const bucket = kind === 'stderr' ? sidecarState.stderr : sidecarState.stdout;
    bucket.push(String(message).trim());
    if (bucket.length > 40) {
        bucket.shift();
    }
}

function writeE2ESnapshot(snapshot) {
    if (!WSHAWK_E2E || e2eSnapshotWritten) {
        return;
    }
    e2eSnapshotWritten = true;
    try {
        fs.writeFileSync(WSHAWK_E2E_OUT, JSON.stringify(snapshot, null, 2), 'utf-8');
        console.log(`[E2E] Snapshot written to ${WSHAWK_E2E_OUT}`);
    } catch (error) {
        console.error(`[E2E] Failed to write snapshot: ${error.message}`);
    }
    if (WSHAWK_E2E_AUTOEXIT) {
        setTimeout(() => app.quit(), 250);
    }
}

async function captureE2ESnapshot(reason) {
    if (!WSHAWK_E2E || e2eSnapshotWritten) {
        return;
    }

    const snapshot = {
        reason,
        timestamp: new Date().toISOString(),
        bridgeInfo: {
            port: bridgeInfo.port,
            tokenPresent: Boolean(bridgeInfo.token),
        },
        sidecar: {
            stdout: sidecarState.stdout.slice(-20),
            stderr: sidecarState.stderr.slice(-20),
            exited: sidecarState.exited,
            exitCode: sidecarState.exitCode,
            exitSignal: sidecarState.exitSignal,
        },
    };

    try {
        if (mainWindow && !mainWindow.isDestroyed()) {
            snapshot.window = {
                visible: mainWindow.isVisible(),
                destroyed: mainWindow.isDestroyed(),
                title: mainWindow.getTitle(),
                url: mainWindow.webContents.getURL(),
            };
            snapshot.renderer = await mainWindow.webContents.executeJavaScript(`
                ({
                    title: document.title,
                    navCount: document.querySelectorAll('.nav-item').length,
                    viewCount: document.querySelectorAll('.view').length,
                    activeView: document.querySelector('.view.active')?.id || null,
                    hasTargetUrlInput: Boolean(document.getElementById('target-url')),
                    hasProtocolMapButton: Boolean(document.getElementById('wsmap-live-btn')),
                    hasAttackWorkspace: Boolean(document.getElementById('view-attacks')),
                    hasEvidenceWorkspace: Boolean(document.getElementById('view-evidence')),
                    bodyClassList: Array.from(document.body.classList || []),
                    readyState: document.readyState
                })
            `, true);
        } else {
            snapshot.window = { destroyed: true };
        }
    } catch (error) {
        snapshot.rendererError = error.message;
    }

    writeE2ESnapshot(snapshot);
}

function scheduleE2ESnapshot(reason, delayMs = 3500) {
    if (!WSHAWK_E2E || e2eSnapshotWritten) {
        return;
    }
    if (e2eSnapshotTimer) {
        clearTimeout(e2eSnapshotTimer);
    }
    e2eSnapshotTimer = setTimeout(() => {
        captureE2ESnapshot(reason).catch((error) => {
            writeE2ESnapshot({
                reason,
                timestamp: new Date().toISOString(),
                fatal: error.message,
                bridgeInfo: { port: bridgeInfo.port, tokenPresent: Boolean(bridgeInfo.token) },
                sidecar: sidecarState,
            });
        });
    }, delayMs);
}

function resolveDevPythonExecutable() {
    const repoRoot = path.join(__dirname, '..');
    const candidates = process.platform === 'win32'
        ? [
            path.join(repoRoot, 'venv', 'Scripts', 'python.exe'),
            'python',
        ]
        : [
            path.join(repoRoot, 'venv', 'bin', 'python'),
            'python3',
            'python',
        ];

    for (const candidate of candidates) {
        if (candidate.includes(path.sep)) {
            if (fs.existsSync(candidate)) {
                return candidate;
            }
            continue;
        }
        try {
            execSync(`${candidate} --version`, { stdio: 'ignore' });
            return candidate;
        } catch (_) {
            // try next candidate
        }
    }

    return process.platform === 'win32' ? 'python' : 'python3';
}

function isLoopbackBridgeRequest(rawUrl) {
    if (!rawUrl) {
        return false;
    }
    try {
        const parsed = new URL(rawUrl);
        const hostname = String(parsed.hostname || '').toLowerCase();
        const protocol = String(parsed.protocol || '').toLowerCase();
        const port = parsed.port ? parseInt(parsed.port, 10) : null;
        if (!['http:', 'https:', 'ws:', 'wss:'].includes(protocol)) {
            return false;
        }
        if (!['127.0.0.1', 'localhost', '::1', '[::1]'].includes(hostname)) {
            return false;
        }
        return bridgeInfo.port ? port === bridgeInfo.port : true;
    } catch (_) {
        return false;
    }
}

function attachBridgeAuth(session) {
    if (!session || session.__wshawkBridgeAuthAttached) {
        return;
    }

    session.__wshawkBridgeAuthAttached = true;
    session.webRequest.onBeforeSendHeaders((details, callback) => {
        if (bridgeInfo.token && isLoopbackBridgeRequest(details.url)) {
            details.requestHeaders = details.requestHeaders || {};
            details.requestHeaders['X-WSHawk-Token'] = bridgeInfo.token;
        }
        callback({ requestHeaders: details.requestHeaders });
    });
}

function safeString(value, maxLength = 8192) {
    if (value === null || value === undefined) {
        return '';
    }
    return String(value).slice(0, maxLength);
}

function safeInteger(value, fallback = 0) {
    const parsed = parseInt(value, 10);
    return Number.isFinite(parsed) ? parsed : fallback;
}

function sanitizeProjectState(raw) {
    const source = raw && typeof raw === 'object' ? raw : {};
    const findings = Array.isArray(source.findings) ? source.findings : [];
    const logs = Array.isArray(source.logs) ? source.logs : [];
    const history = Array.isArray(source.history) ? source.history : [];

    return {
        version: safeString(source.version || '4.0.0', 32),
        projectId: safeString(source.projectId, 128),
        projectName: safeString(source.projectName, 256),
        url: safeString(source.url, 4096),
        vulns: Math.max(0, safeInteger(source.vulns, 0)),
        msgs: Math.max(0, safeInteger(source.msgs, 0)),
        findings: findings.slice(0, 500).map((item) => ({
            id: safeString(item?.id, 128),
            type: safeString(item?.type, 256),
            severity: safeString(item?.severity || 'LOW', 32),
            description: safeString(item?.description, 4096),
            payload: safeString(item?.payload, 4096),
        })),
        logs: logs.slice(0, 1000).map((item) => ({
            type: safeString(item?.type || 'info', 32),
            text: safeString(item?.text, 4096),
        })),
        history: history.slice(0, 1000).map((item, index) => ({
            rowId: safeString(item?.rowId, 128),
            rowNumber: Math.max(1, safeInteger(item?.rowNumber, index + 1)),
            dir: safeString(item?.dir || 'INFO', 32),
            time: safeString(item?.time, 64),
            payload: safeString(item?.payload, 65536),
            size: Math.max(0, safeInteger(item?.size, safeString(item?.payload).length)),
        })),
    };
}

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1280,
        height: 800,
        show: !(WSHAWK_E2E || WSHAWK_DESKTOP_SMOKE),
        paintWhenInitiallyHidden: WSHAWK_E2E || WSHAWK_DESKTOP_SMOKE,
        icon: path.join(__dirname, 'build', 'icon.png'),
        titleBarStyle: 'hidden',
        backgroundColor: '#0f172a',
        webPreferences: {
            preload: path.join(__dirname, 'preload.js'),
            nodeIntegration: false,
            contextIsolation: true,
            sandbox: !WSHAWK_E2E_NO_SANDBOX,
        },
    });

    const rendererSession = mainWindow.webContents.session;
    attachBridgeAuth(rendererSession);
    rendererSession.setPermissionRequestHandler((_webContents, _permission, callback) => {
        callback(false);
    });

    // Inject Content-Security-Policy header to harden the renderer
    rendererSession.webRequest.onHeadersReceived((details, callback) => {
        const csp = [
            "default-src 'self'",
            "script-src 'self'",
            "style-src 'self' 'unsafe-inline'",
            "img-src 'self' data: blob:",
            `connect-src 'self' http://127.0.0.1:* ws://127.0.0.1:*`,
            "font-src 'self' data:",
            "object-src 'none'",
            "base-uri 'self'",
            "frame-ancestors 'none'",
            "form-action 'self'",
        ].join('; ');
        callback({
            responseHeaders: {
                ...details.responseHeaders,
                'Content-Security-Policy': [csp],
            },
        });
    });

    mainWindow.loadFile(path.join(__dirname, 'src', 'index.html'));
    mainWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
    mainWindow.webContents.on('will-navigate', (event, url) => {
        const currentUrl = mainWindow?.webContents?.getURL?.() || '';
        if (url !== currentUrl) {
            event.preventDefault();
        }
    });


    mainWindow.webContents.on('did-finish-load', () => {
        desktopSmokeState.didFinishLoad = true;
        if (bridgeInfo.port) {
            mainWindow.webContents.send('bridge-port', bridgeInfo.port);
        }
        if (bridgeInfo.token) {
            mainWindow.webContents.send('bridge-ready', true);
        }
        scheduleE2ESnapshot('did-finish-load', bridgeInfo.token ? 1200 : 3200);
        maybeCompleteDesktopSmoke('did-finish-load');
    });

    mainWindow.webContents.on('did-fail-load', (_event, code, description, validatedURL) => {
        if (WSHAWK_DESKTOP_SMOKE && !desktopSmokeSnapshotWritten) {
            writeDesktopSmokeSnapshot({
                ok: false,
                reason: 'did-fail-load',
                code,
                description,
                validatedURL,
                bridgeInfo: { port: bridgeInfo.port, tokenPresent: Boolean(bridgeInfo.token) },
                sidecar: sidecarState,
                smokeState: { ...desktopSmokeState },
            });
        }
        writeE2ESnapshot({
            reason: 'did-fail-load',
            code,
            description,
            validatedURL,
            bridgeInfo: { port: bridgeInfo.port, tokenPresent: Boolean(bridgeInfo.token) },
            sidecar: sidecarState,
        });
    });
}

function startPythonSidecar() {
    console.log('[*] Starting WSHawk Python Sidecar...');

    let executablePath;
    let args = [];
    let options = {};

    const bridgePort = process.env.WSHAWK_BRIDGE_PORT || '8080';

    if (app.isPackaged) {
        if (process.platform === 'win32') {
            executablePath = path.join(process.resourcesPath, 'bin', 'wshawk-bridge.exe');
        } else {
            const bundledPath = path.join(process.resourcesPath, 'bin', 'wshawk-bridge');
            const systemPath = path.join(__dirname, 'bin', 'wshawk-bridge');
            executablePath = fs.existsSync(systemPath) ? systemPath : bundledPath;
        }

        if (!fs.existsSync(executablePath)) {
            console.error(`[FATAL] Sidecar binary not found at: ${executablePath}`);
            dialog.showErrorBox(
                'WSHawk Sidecar Missing',
                `Could not find the Python sidecar binary at:\n${executablePath}\n\nPlease reinstall WSHawk.`
            );
            return;
        }

        if (process.platform !== 'win32') {
            try {
                fs.accessSync(executablePath, fs.constants.W_OK);
                fs.chmodSync(executablePath, 0o755);
                console.log('[+] Set execute permission on sidecar binary');
            } catch (error) {
                if (error.code !== 'EACCES' && error.code !== 'EPERM') {
                    console.error(`[-] Failed to set execute permission: ${error.message}`);
                }
            }
        }

        options = { stdio: 'pipe', env: { ...process.env, WSHAWK_BRIDGE_PORT: bridgePort } };
    } else {
        executablePath = resolveDevPythonExecutable();
        options = {
            cwd: path.join(__dirname, '..'),
            stdio: 'pipe',
            env: { ...process.env, WSHAWK_BRIDGE_PORT: bridgePort },
        };
        args = ['-m', 'wshawk.gui_bridge'];
    }

    console.log(`[Main] Spawning: ${executablePath} ${args.join(' ')} (CWD: ${options.cwd || 'default'})`);
    console.log(`[Main] Platform: ${process.platform}, Arch: ${process.arch}, Packaged: ${app.isPackaged}`);

    try {
        pythonProcess = spawn(executablePath, args, options);
    } catch (error) {
        console.error(`[FATAL] Failed to spawn sidecar: ${error.message}`);
        dialog.showErrorBox('WSHawk Sidecar Error', `Failed to start Python engine:\n${error.message}`);
        return;
    }

    pythonProcess.stdout.on('data', (data) => {
        const text = data.toString();
        console.log(`[Python] ${text}`);
        rememberSidecarLog('stdout', text);

        const portMatch = text.match(/\[BRIDGE_PORT\]\s*(\d+)/);
        if (portMatch) {
            const actualPort = parseInt(portMatch[1], 10);
            bridgeInfo.port = actualPort;
            desktopSmokeState.bridgePort = true;
            console.log(`[Main] Bridge is listening on port ${actualPort}`);
            if (mainWindow && !mainWindow.isDestroyed() && mainWindow.webContents) {
                mainWindow.webContents.send('bridge-port', actualPort);
            }
            scheduleE2ESnapshot('bridge-port', bridgeInfo.token ? 800 : 1800);
            maybeCompleteDesktopSmoke('bridge-port');
        }

        const tokenMatch = text.match(/\[BRIDGE_TOKEN\]\s*(\S+)/);
        if (tokenMatch) {
            bridgeInfo.token = tokenMatch[1];
            desktopSmokeState.bridgeReady = true;
            console.log('[Main] Bridge token received');
            if (mainWindow && !mainWindow.isDestroyed() && mainWindow.webContents) {
                mainWindow.webContents.send('bridge-ready', true);
            }
            scheduleE2ESnapshot('bridge-ready', 900);
            maybeCompleteDesktopSmoke('bridge-ready');
        }
    });

    pythonProcess.stderr.on('data', (data) => {
        const msg = data.toString();
        console.error(`[Python Error] ${msg}`);
        rememberSidecarLog('stderr', msg);
        if (mainWindow && !mainWindow.isDestroyed() && mainWindow.webContents) {
            mainWindow.webContents.send('sidecar-error', msg);
        }
    });

    pythonProcess.on('exit', (code, signal) => {
        console.error(`[Main] Sidecar exited with code=${code}, signal=${signal}`);
        sidecarState.exited = true;
        sidecarState.exitCode = code;
        sidecarState.exitSignal = signal;
        if (code !== 0 && code !== null) {
            if (mainWindow && !mainWindow.isDestroyed() && mainWindow.webContents) {
                mainWindow.webContents.send('sidecar-error', `Sidecar crashed (exit code ${code})`);
            }
        }
        if (WSHAWK_E2E && !e2eSnapshotWritten) {
            scheduleE2ESnapshot('sidecar-exit', 400);
        }
        if (WSHAWK_DESKTOP_SMOKE && !desktopSmokeSnapshotWritten) {
            captureDesktopSmokeSnapshot('sidecar-exit', false).catch((error) => {
                writeDesktopSmokeSnapshot({
                    ok: false,
                    reason: 'sidecar-exit',
                    error: error.message,
                    timestamp: new Date().toISOString(),
                    smokeState: { ...desktopSmokeState },
                    bridgeInfo: { port: bridgeInfo.port, tokenPresent: Boolean(bridgeInfo.token) },
                    sidecar: sidecarState,
                });
            });
        }
    });

    pythonProcess.on('error', (err) => {
        console.error(`[FATAL] Sidecar process error: ${err.message}`);
        rememberSidecarLog('stderr', err.message);
        if (!WSHAWK_DESKTOP_SMOKE) {
            dialog.showErrorBox('WSHawk Sidecar Error', `Python engine failed to start:\n${err.message}`);
        }
        if (WSHAWK_E2E) {
            writeE2ESnapshot({
                reason: 'sidecar-process-error',
                error: err.message,
                bridgeInfo: { port: bridgeInfo.port, tokenPresent: Boolean(bridgeInfo.token) },
                sidecar: sidecarState,
            });
        }
        if (WSHAWK_DESKTOP_SMOKE) {
            writeDesktopSmokeSnapshot({
                ok: false,
                reason: 'sidecar-process-error',
                error: err.message,
                bridgeInfo: { port: bridgeInfo.port, tokenPresent: Boolean(bridgeInfo.token) },
                sidecar: sidecarState,
                smokeState: { ...desktopSmokeState },
            });
        }
    });
}

function checkPythonDependency() {
    try {
        const pyVersion = execSync(`${resolveDevPythonExecutable()} --version`, { encoding: 'utf8', stdio: 'pipe' });
        console.log(`[+] System Python Check Passed: ${pyVersion.trim()}`);
    } catch (err) {
        console.error('[-] Python not found on the system');
        const resp = dialog.showMessageBoxSync({
            type: 'error',
            title: 'Critical Dependency Missing',
            message: 'WSHawk requires Python 3.8+ to execute automated exploit payloads and verification sequences.\n\nPlease install Python and restart the application.',
            buttons: ['Download Python', 'Quit WSHawk'],
        });

        if (resp === 0) {
            shell.openExternal('https://www.python.org/downloads/');
        }
        app.quit();
    }
}

app.whenReady().then(() => {
    if (!app.isPackaged) checkPythonDependency();
    startPythonSidecar();
    createWindow();
    scheduleE2ESnapshot('app-ready', 6000);
    scheduleDesktopSmokeTimeout();

    ipcMain.handle('dialog:openProject', async () => {
        const result = await dialog.showOpenDialog(mainWindow, {
            title: 'Open WSHawk Project',
            filters: [{ name: 'WSHawk Projects', extensions: ['wshawk'] }],
            properties: ['openFile'],
        });

        if (!result.canceled && result.filePaths.length > 0) {
            try {
                const data = fs.readFileSync(result.filePaths[0], 'utf-8');
                return { success: true, data: sanitizeProjectState(JSON.parse(data)), path: result.filePaths[0] };
            } catch (error) {
                return { success: false, error: error.message };
            }
        }
        return { success: false, canceled: true };
    });

    ipcMain.handle('dialog:saveProject', async (_event, projectData) => {
        const result = await dialog.showSaveDialog(mainWindow, {
            title: 'Save WSHawk Project',
            filters: [{ name: 'WSHawk Projects', extensions: ['wshawk'] }],
            defaultPath: `project_wshawk_${Date.now()}.wshawk`,
        });

        if (!result.canceled && result.filePath) {
            try {
                fs.writeFileSync(result.filePath, JSON.stringify(sanitizeProjectState(projectData), null, 2), 'utf-8');
                return { success: true, path: result.filePath };
            } catch (error) {
                return { success: false, error: error.message };
            }
        }
        return { success: false, canceled: true };
    });

    ipcMain.handle('dialog:exportReport', async (_event, htmlContent) => {
        const result = await dialog.showSaveDialog(mainWindow, {
            title: 'Export HTML Report',
            filters: [{ name: 'HTML Document', extensions: ['html'] }],
            defaultPath: `WSHawk_Report_${Date.now()}.html`,
        });

        if (!result.canceled && result.filePath) {
            try {
                fs.writeFileSync(result.filePath, htmlContent, 'utf-8');
                return { success: true, path: result.filePath };
            } catch (error) {
                return { success: false, error: error.message };
            }
        }
        return { success: false, canceled: true };
    });

    ipcMain.handle('dialog:exportExploit', async (_event, explData) => {
        const result = await dialog.showSaveDialog(mainWindow, {
            title: 'Export Exploit PoC',
            filters: [{ name: 'Python Script', extensions: ['py'] }],
            defaultPath: `exploit_${Date.now()}.py`,
        });

        if (!result.canceled && result.filePath) {
            try {
                fs.writeFileSync(result.filePath, explData, 'utf-8');
                return { success: true, path: result.filePath };
            } catch (error) {
                return { success: false, error: error.message };
            }
        }
        return { success: false, canceled: true };
    });

    ipcMain.on('window:minimize', () => {
        if (mainWindow) mainWindow.minimize();
    });

    ipcMain.on('window:maximize', () => {
        if (mainWindow) {
            if (mainWindow.isMaximized()) {
                mainWindow.restore();
            } else {
                mainWindow.maximize();
            }
        }
    });

    ipcMain.on('window:close', () => {
        if (mainWindow) mainWindow.close();
    });

    app.on('activate', () => {
        if (BrowserWindow.getAllWindows().length === 0) createWindow();
    });
});

app.on('window-all-closed', () => {
    if (pythonProcess) {
        pythonProcess.kill();
    }
    if (WSHAWK_E2E && !e2eSnapshotWritten) {
        writeE2ESnapshot({
            reason: 'window-all-closed',
            bridgeInfo: { port: bridgeInfo.port, tokenPresent: Boolean(bridgeInfo.token) },
            sidecar: sidecarState,
        });
    }
    if (WSHAWK_DESKTOP_SMOKE && !desktopSmokeSnapshotWritten) {
        writeDesktopSmokeSnapshot({
            ok: false,
            reason: 'window-all-closed',
            bridgeInfo: { port: bridgeInfo.port, tokenPresent: Boolean(bridgeInfo.token) },
            sidecar: sidecarState,
            smokeState: { ...desktopSmokeState },
        });
    }
    if (process.platform !== 'darwin') app.quit();
});
