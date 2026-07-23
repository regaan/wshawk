'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawnSync } = require('child_process');

if (process.platform !== 'win32') {
    process.stdout.write('Windows lifecycle test skipped on this platform.\n');
    process.exit(0);
}

const root = path.resolve(__dirname, '..');
const output = path.join(root, 'dist-electron-go');
const installer = fs.readdirSync(output)
    .filter(name => /^wshawk-electron-go-.*-win-.*\.exe$/i.test(name) && !name.includes('__uninstaller'))
    .map(name => path.join(output, name))
    .sort((left, right) => fs.statSync(right).mtimeMs - fs.statSync(left).mtimeMs)[0];
if (!installer) throw new Error('Windows Electron + Go installer was not found');

const lifecycleRoot = fs.mkdtempSync(path.join(os.tmpdir(), 'wshawk-electron-go-lifecycle-'));
const installDir = path.join(lifecycleRoot, 'app');
const dataDir = path.join(lifecycleRoot, 'data');
const reportPath = path.join(output, 'WINDOWS-LIFECYCLE.json');

function run(executable, args, options = {}) {
    const result = spawnSync(executable, args, {
        cwd: options.cwd || root,
        env: options.env || process.env,
        encoding: 'utf8',
        windowsHide: true,
        timeout: options.timeout || 5 * 60_000,
    });
    if (result.error || result.status !== 0) {
        throw new Error(`${path.basename(executable)} failed (${result.status ?? result.signal}): ${result.error?.message || result.stderr || result.stdout || 'no diagnostics'}`);
    }
    return result;
}

function waitFor(predicate, timeout = 30_000, interval = 250) {
    const deadline = Date.now() + timeout;
    const signal = new Int32Array(new SharedArrayBuffer(4));
    while (Date.now() < deadline) {
        if (predicate()) return true;
        Atomics.wait(signal, 0, 0, interval);
    }
    return predicate();
}

function findApplication() {
    const candidates = [
        path.join(installDir, 'WSHawk Electron Go.exe'),
    ];
    return candidates.find(fs.existsSync) || '';
}

function verifyInstalledLayout() {
    const executable = findApplication();
    if (!executable) throw new Error('Installed application executable is missing');
    const worker = path.join(installDir, 'resources', 'bin', 'wshawk-worker.exe');
    if (!fs.existsSync(worker) || fs.statSync(worker).size === 0) throw new Error('Installed Go worker is missing');
    const browserRoot = path.join(installDir, 'resources', 'playwright-browsers');
    const pending = [browserRoot];
    let browser = '';
    while (pending.length && !browser) {
        const current = pending.pop();
        if (!fs.existsSync(current)) continue;
        for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
            const candidate = path.join(current, entry.name);
            if (entry.isDirectory()) pending.push(candidate);
            else if (['chrome.exe', 'chrome-headless-shell.exe', 'headless_shell.exe'].includes(entry.name)) { browser = candidate; break; }
        }
    }
    if (!browser) throw new Error('Installed Chromium runtime is missing');
    return { executable, worker, browser };
}

function smokeInstalled(executable, name) {
    const snapshotPath = path.join(lifecycleRoot, `${name}-smoke.json`);
    run(executable, [], {
        cwd: installDir,
        timeout: 45_000,
        env: {
            ...process.env,
            WSHAWK_DIRECT_SMOKE: '1',
            WSHAWK_DIRECT_SMOKE_OUT: snapshotPath,
            WSHAWK_ELECTRON_GO_DATA_DIR: dataDir,
        },
    });
    if (!fs.existsSync(snapshotPath)) throw new Error(`${name} installed smoke snapshot was not created`);
    const snapshot = JSON.parse(fs.readFileSync(snapshotPath, 'utf8'));
    if (!snapshot.ok || snapshot.worker?.backend !== 'go' || snapshot.worker?.noNetworkBridge !== true) throw new Error(`${name} installed worker smoke failed`);
    if (!snapshot.browserAutomation?.browserReady || !String(snapshot.browserAutomation.browserExecutable || '').startsWith(path.join(installDir, 'resources'))) {
        throw new Error(`${name} installed app did not select its packaged Chromium runtime`);
    }
    return { worker: snapshot.worker, browserAutomation: snapshot.browserAutomation, window: snapshot.window };
}

const report = { platform: process.platform, architecture: process.arch, installer: path.basename(installer), installerBytes: fs.statSync(installer).size, steps: [] };
let succeeded = false;
try {
    run(installer, ['/S', `/D=${installDir}`]);
    const installed = verifyInstalledLayout();
    report.steps.push({ name: 'install', passed: true, layout: { workerBytes: fs.statSync(installed.worker).size, browserBytes: fs.statSync(installed.browser).size } });
    report.steps.push({ name: 'first-launch-smoke', passed: true, snapshot: smokeInstalled(installed.executable, 'install') });

    run(installer, ['/S', `/D=${installDir}`]);
    const upgraded = verifyInstalledLayout();
    report.steps.push({ name: 'upgrade', passed: true });
    report.steps.push({ name: 'upgrade-launch-smoke', passed: true, snapshot: smokeInstalled(upgraded.executable, 'upgrade') });

    const uninstallers = [];
    const pending = [installDir];
    while (pending.length) {
        const current = pending.pop();
        for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
            const candidate = path.join(current, entry.name);
            if (entry.isDirectory()) pending.push(candidate);
            else if (/^uninstall.*\.exe$/i.test(entry.name)) uninstallers.push(candidate);
        }
    }
    if (!uninstallers[0]) throw new Error('Uninstaller was not found');
    run(uninstallers[0], ['/S']);
	if (!waitFor(() => !findApplication())) throw new Error('Application executable remains after the uninstaller cleanup window');
    report.steps.push({ name: 'uninstall', passed: true });
    report.passed = true;
    succeeded = true;
} catch (error) {
	report.passed = false;
	report.error = error.message;
	throw error;
} finally {
    report.completedAt = new Date().toISOString();
    report.debugDirectory = succeeded ? null : lifecycleRoot;
    fs.writeFileSync(reportPath, JSON.stringify(report, null, 2), 'utf8');
    if (succeeded) {
        const relative = path.relative(os.tmpdir(), lifecycleRoot);
        if (relative && !relative.startsWith('..') && path.basename(lifecycleRoot).startsWith('wshawk-electron-go-lifecycle-')) fs.rmSync(lifecycleRoot, { recursive: true, force: true });
    }
}

process.stdout.write(`Windows install, first launch, upgrade, second launch, and uninstall passed for ${path.basename(installer)}.\n`);
