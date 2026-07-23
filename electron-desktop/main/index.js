'use strict';

const { app, BrowserWindow, dialog, ipcMain, safeStorage, session } = require('electron');
const crypto = require('crypto');
const fs = require('fs');
const os = require('os');
const path = require('path');

const { validateInvokeRequest } = require('../shared/contract');
const { PlaywrightService } = require('./playwright-service');
const { WorkerClient } = require('./worker-client');

const APP_ID = 'com.rothackers.wshawk.electrongo';
const IPC_INVOKE = 'wshawk:invoke';
const IPC_CANCEL = 'wshawk:cancel';
const ELECTRON_GO_DATA_DIR = 'WSHawkElectronGo';
const ELECTRON_GO_DATA_OVERRIDE = process.env.WSHAWK_ELECTRON_GO_DATA_DIR || process.env.WSHAWK_PREVIEW_DATA_DIR;
const DIRECT_SMOKE = process.env.WSHAWK_DIRECT_SMOKE === '1';
const DIRECT_SMOKE_OUT = process.env.WSHAWK_DIRECT_SMOKE_OUT
    || path.join(os.tmpdir(), 'wshawk-direct-ipc-smoke.json');

let mainWindow = null;
let worker = null;
let quitting = false;
let smokeCompleted = false;
const playwright = new PlaywrightService();

if (DIRECT_SMOKE) {
    app.disableHardwareAcceleration();
    app.commandLine.appendSwitch('headless');
    app.commandLine.appendSwitch('disable-gpu');
    app.commandLine.appendSwitch('disable-dev-shm-usage');
}

app.enableSandbox();
app.setName('WSHawk Electron Go');
app.setAppUserModelId(APP_ID);
app.setPath('userData', ELECTRON_GO_DATA_OVERRIDE ? path.resolve(ELECTRON_GO_DATA_OVERRIDE) : path.join(app.getPath('appData'), ELECTRON_GO_DATA_DIR));

function workerExecutable() {
    const executableName = process.platform === 'win32' ? 'wshawk-worker.exe' : 'wshawk-worker';
    return app.isPackaged
        ? path.join(process.resourcesPath, 'bin', executableName)
        : path.join(__dirname, '..', 'bin', executableName);
}

function projectStorageKey() {
	if (process.env.WSHAWK_STORAGE_KEY) return process.env.WSHAWK_STORAGE_KEY;
	if (!safeStorage.isEncryptionAvailable()) throw new Error('Operating-system secure storage is unavailable; set WSHAWK_STORAGE_KEY explicitly before opening encrypted projects.');
	const keyPath = path.join(app.getPath('userData'), 'storage-key.protected');
	fs.mkdirSync(path.dirname(keyPath), { recursive: true, mode: 0o700 });
	if (fs.existsSync(keyPath)) return safeStorage.decryptString(fs.readFileSync(keyPath));
	const key = crypto.randomBytes(32).toString('base64');
	fs.writeFileSync(keyPath, safeStorage.encryptString(key), { mode: 0o600, flag: 'wx' });
	return key;
}

function createWorker() {
    const client = new WorkerClient({
        executable: workerExecutable(),
		args: ['--data-dir', app.getPath('userData')],
        cwd: app.getPath('userData'),
		environment: { WSHAWK_STORAGE_KEY: projectStorageKey() },
    });
	let restartAttempts = 0;
    client.on('status', (status) => {
		mainWindow?.webContents.send('worker:status', status);
		if (status.state === 'crashed' && !quitting && restartAttempts < 2) {
			restartAttempts += 1;
			const delay = restartAttempts * 500;
			setTimeout(() => client.start().catch(error => console.error(`[Main] Go worker restart failed: ${error.message}`)), delay).unref?.();
		}
	});
    client.on('event', (event) => mainWindow?.webContents.send('worker:event', event));
    client.on('diagnostic', (line) => console.warn(`[GoWorker] ${line}`));
    return client;
}

function senderIsMainWindow(event) {
    return Boolean(mainWindow && !mainWindow.isDestroyed() && event.sender === mainWindow.webContents);
}

function registerIPC() {
    ipcMain.handle(IPC_INVOKE, async (event, rawRequest) => {
        if (!senderIsMainWindow(event)) throw new Error('Untrusted IPC sender');
        const request = validateInvokeRequest(rawRequest);

        if (request.method === 'browser.status') return playwright.status();
        if (request.method === 'browser.dom_xss.verify') return playwright.verifyDOMXSS(request.params);
        if (request.method === 'browser.auth.record') return playwright.recordAuthentication(request.params);
        if (request.method === 'browser.auth.replay') return playwright.replayAuthentication(request.params);
        if (request.method === 'browser.evidence.capture') return playwright.captureEvidence(request.params);
        if (request.method === 'browser.close_all') return playwright.closeAll();
        if (request.method === 'window.minimize') { mainWindow.minimize(); return { accepted: true }; }
        if (request.method === 'window.maximize') {
            if (mainWindow.isMaximized()) mainWindow.unmaximize(); else mainWindow.maximize();
            return { maximized: mainWindow.isMaximized() };
        }
        if (request.method === 'window.close') { mainWindow.close(); return { accepted: true }; }
        if (!worker) throw new Error('Go worker is unavailable');

        if (request.method === 'dialog.project.open') {
            const choice = await dialog.showOpenDialog(mainWindow, { properties: ['openFile'], filters: [{ name: 'WSHawk Project', extensions: ['wshawk', 'json'] }] });
            if (choice.canceled || !choice.filePaths[0]) return { canceled: true };
            const file = choice.filePaths[0];
            const info = await fs.promises.stat(file);
            if (info.size > 5 * 1024 * 1024) throw new RangeError('Project import exceeds the 5 MiB desktop limit');
            const content = await fs.promises.readFile(file);
            return worker.request('projects.import', { content_base64: content.toString('base64') }, 60_000);
        }
        if (request.method === 'dialog.project.export') {
            const snapshot = await worker.request('projects.snapshot', { id: request.params.project_id }, 60_000);
            const choice = await dialog.showSaveDialog(mainWindow, { defaultPath: `${snapshot.project?.name || 'wshawk-project'}.wshawk`, filters: [{ name: 'WSHawk Project', extensions: ['wshawk'] }] });
            if (choice.canceled || !choice.filePath) return { canceled: true };
            await fs.promises.writeFile(choice.filePath, JSON.stringify(snapshot, null, 2), { encoding: 'utf8', mode: 0o600, flag: 'wx' }).catch(async (error) => {
                if (error.code !== 'EEXIST') throw error;
                await fs.promises.writeFile(choice.filePath, JSON.stringify(snapshot, null, 2), { encoding: 'utf8', mode: 0o600 });
            });
			return { canceled: false, saved: true, path: choice.filePath };
        }
        if (request.method === 'dialog.report.save') {
            const content = String(request.params.content || '');
            if (Buffer.byteLength(content, 'utf8') > 16 * 1024 * 1024) throw new RangeError('Report exceeds 16 MiB');
            const extension = String(request.params.extension || 'json').replace(/[^a-z0-9]/gi, '').slice(0, 8) || 'json';
            const choice = await dialog.showSaveDialog(mainWindow, { defaultPath: `wshawk-report.${extension}` });
            if (choice.canceled || !choice.filePath) return { canceled: true };
            await fs.promises.writeFile(choice.filePath, content, { encoding: 'utf8', mode: 0o600 });
			return { canceled: false, saved: true, path: choice.filePath };
        }

		const longRunning = /^(scanner\.|workflow\.|web\.crawl|web\.dirscan)/.test(request.method);
		const networkOrReport = /^(http\.request|tls\.inspect|network\.|reports\.|evidence\.)/.test(request.method);
		const result = await worker.request(request.method, request.params, longRunning ? 5 * 60_000 : networkOrReport ? 2 * 60_000 : 30_000);
        if (request.method === 'system.capabilities') {
            return { ...result, browserAutomation: playwright.status() };
        }
        return result;
    });

    ipcMain.handle(IPC_CANCEL, async (event, operationId) => {
        if (!senderIsMainWindow(event)) throw new Error('Untrusted IPC sender');
        if (typeof operationId !== 'string' || operationId.length > 128) {
            throw new TypeError('A valid operation ID is required');
        }
        if (!worker) return { cancelled: false, operationId, reason: 'Go worker is unavailable' };
        return worker.request('operation.cancel', { operation_id: operationId });
    });
}

function createWindow() {
    mainWindow = new BrowserWindow({
        width: 1220,
        height: 800,
        minWidth: 900,
        minHeight: 620,
        show: false,
        backgroundColor: '#090d14',
        webPreferences: {
            preload: path.join(__dirname, '..', 'preload', 'index.js'),
            contextIsolation: true,
            nodeIntegration: false,
            sandbox: true,
            webSecurity: true,
            allowRunningInsecureContent: false,
        },
    });

    mainWindow.webContents.setWindowOpenHandler(() => ({ action: 'deny' }));
    mainWindow.webContents.on('will-navigate', (event, url) => {
        if (url !== mainWindow.webContents.getURL()) event.preventDefault();
    });
    mainWindow.webContents.on('will-attach-webview', (event) => event.preventDefault());
    mainWindow.once('ready-to-show', () => {
        if (!DIRECT_SMOKE) mainWindow.show();
    });
    mainWindow.webContents.once('did-finish-load', () => {
        if (DIRECT_SMOKE) runSmokeGate('did-finish-load');
    });
    mainWindow.on('closed', () => { mainWindow = null; });
    mainWindow.loadFile(path.join(__dirname, '..', 'renderer', 'index.html'));
}

async function runSmokeGate(reason) {
    if (smokeCompleted) return;
    smokeCompleted = true;
    const snapshot = {
        ok: false,
        reason,
        timestamp: new Date().toISOString(),
        appId: APP_ID,
        userData: app.getPath('userData'),
        browserAutomation: playwright.status(),
    };
    try {
        snapshot.worker = await worker.request('system.health');
        snapshot.window = {
            loaded: Boolean(mainWindow && !mainWindow.isDestroyed()),
            url: mainWindow?.webContents.getURL() || '',
            title: mainWindow?.getTitle() || '',
            visible: mainWindow?.isVisible() || false,
        };
        snapshot.ok = snapshot.worker.noNetworkBridge === true
            && snapshot.worker.transport === 'stdio-json-rpc'
            && snapshot.window.loaded
            && snapshot.browserAutomation.available === true;
    } catch (error) {
        snapshot.error = error.message;
    }
    fs.mkdirSync(path.dirname(DIRECT_SMOKE_OUT), { recursive: true });
    fs.writeFileSync(DIRECT_SMOKE_OUT, JSON.stringify(snapshot, null, 2), 'utf8');
    app.quit();
}

app.whenReady().then(async () => {
    session.defaultSession.setPermissionRequestHandler((_webContents, _permission, callback) => callback(false));
    registerIPC();
    worker = createWorker();
    try {
        await worker.start();
    } catch (error) {
        console.error(`[Main] Go worker failed to start: ${error.message}`);
    }
    createWindow();
    if (DIRECT_SMOKE) {
        const timeout = setTimeout(() => runSmokeGate('timeout'), 12_000);
        timeout.unref?.();
    }
});

app.on('before-quit', (event) => {
    if (quitting || !worker) return;
    event.preventDefault();
    quitting = true;
    worker.stop().finally(() => app.quit());
});

app.on('window-all-closed', () => app.quit());
