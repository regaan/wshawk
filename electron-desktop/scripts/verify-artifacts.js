'use strict';

const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const output = path.join(root, 'dist-electron-go');
if (!fs.existsSync(output)) throw new Error('dist-electron-go does not exist');
const names = fs.readdirSync(output);
const expected = process.platform === 'win32'
    ? [/\.exe$/i]
    : process.platform === 'darwin'
        ? [/\.dmg$/i, /-mac\.zip$|\.zip$/i]
        : [/\.AppImage$/i, /\.deb$/i, /\.tar\.gz$/i];
for (const pattern of expected) {
    if (!names.some(name => pattern.test(name))) throw new Error(`Missing artifact matching ${pattern}`);
}
const workerName = process.platform === 'win32' ? 'wshawk-worker.exe' : 'wshawk-worker';
const workerPath = path.join(root, 'bin', workerName);
if (!fs.existsSync(workerPath) || fs.statSync(workerPath).size === 0) throw new Error('Bundled Go worker was not built');
const browserRoot = path.join(root, 'browser-runtime');
if (!fs.existsSync(browserRoot)) throw new Error('Packaged Chromium runtime was not prepared');
const browserNames = process.platform === 'win32'
    ? new Set(['chrome.exe', 'chrome-headless-shell.exe', 'headless_shell.exe'])
    : process.platform === 'darwin'
        ? new Set(['Chromium', 'Google Chrome for Testing', 'chrome-headless-shell'])
        : new Set(['chrome', 'chrome-headless-shell', 'headless_shell']);
let browserFound = false;
const pending = [browserRoot];
while (pending.length && !browserFound) {
    const current = pending.pop();
    for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
        if (entry.isDirectory()) pending.push(path.join(current, entry.name));
        else if (browserNames.has(entry.name)) { browserFound = true; break; }
    }
}
if (!browserFound) throw new Error('Packaged Chromium executable is missing');
process.stdout.write(`Verified ${expected.length} platform artifact type(s), ${workerName}, and packaged Chromium.\n`);
