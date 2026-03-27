#!/usr/bin/env node
const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');

const desktopDir = path.resolve(__dirname, '..');
const electronBinary = process.platform === 'win32'
    ? path.join(desktopDir, 'node_modules', '.bin', 'electron.cmd')
    : path.join(desktopDir, 'node_modules', '.bin', 'electron');
const snapshotPath = process.env.WSHAWK_DESKTOP_SMOKE_OUT || path.join(os.tmpdir(), 'wshawk-desktop-smoke.json');
const timeoutMs = Number.parseInt(process.env.WSHAWK_DESKTOP_SMOKE_TIMEOUT_MS || '15000', 10);

try {
    fs.rmSync(snapshotPath, { force: true });
} catch (_) {
    // ignore cleanup errors
}

const env = {
    ...process.env,
    WSHAWK_DESKTOP_SMOKE: '1',
    WSHAWK_DESKTOP_SMOKE_OUT: snapshotPath,
    WSHAWK_DESKTOP_SMOKE_TIMEOUT_MS: String(timeoutMs),
};
delete env.ELECTRON_RUN_AS_NODE;

const child = spawn(electronBinary, [desktopDir], {
    cwd: desktopDir,
    env,
    stdio: ['ignore', 'pipe', 'pipe'],
});

let stdout = '';
let stderr = '';
let finished = false;

const timer = setTimeout(() => {
    if (finished) return;
    child.kill('SIGTERM');
}, timeoutMs + 2000);

child.stdout.on('data', (data) => {
    stdout += data.toString();
});

child.stderr.on('data', (data) => {
    stderr += data.toString();
});

child.on('exit', (code, signal) => {
    finished = true;
    clearTimeout(timer);

    let snapshot = null;
    if (fs.existsSync(snapshotPath)) {
        try {
            snapshot = JSON.parse(fs.readFileSync(snapshotPath, 'utf-8'));
        } catch (error) {
            console.error(`[SMOKE] Failed to parse snapshot: ${error.message}`);
        }
    }

    if (snapshot && snapshot.ok) {
        console.log(JSON.stringify({
            status: 'ok',
            reason: snapshot.reason,
            snapshotPath,
            bridgeInfo: snapshot.bridgeInfo,
            window: snapshot.window,
            renderer: snapshot.renderer,
        }, null, 2));
        process.exit(0);
    }

    console.error(JSON.stringify({
        status: 'error',
        code,
        signal,
        snapshotPath,
        snapshot,
        stdout: stdout.trim(),
        stderr: stderr.trim(),
    }, null, 2));
    process.exit(1);
});
