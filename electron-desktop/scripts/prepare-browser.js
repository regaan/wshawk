'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const root = path.resolve(__dirname, '..');
const target = path.join(root, 'browser-runtime');
const packageRoot = path.dirname(require.resolve('playwright-core/package.json'));
const cli = path.join(packageRoot, 'cli.js');

function hasBrowser(directory) {
    if (!fs.existsSync(directory)) return false;
    const names = new Set(process.platform === 'win32'
        ? ['chrome.exe', 'chrome-headless-shell.exe', 'headless_shell.exe']
        : process.platform === 'darwin'
            ? ['Chromium', 'Google Chrome for Testing', 'chrome-headless-shell']
            : ['chrome', 'chrome-headless-shell', 'headless_shell']);
    const pending = [directory];
    while (pending.length) {
        const current = pending.pop();
        for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
            if (entry.isDirectory()) pending.push(path.join(current, entry.name));
            else if (names.has(entry.name)) return true;
        }
    }
    return false;
}

if (hasBrowser(target)) {
    process.stdout.write(`Bundled Chromium runtime already prepared at ${target}\n`);
    process.exit(0);
}

fs.mkdirSync(target, { recursive: true });
const result = spawnSync(process.execPath, [cli, 'install', 'chromium'], {
    cwd: root,
    stdio: 'inherit',
    env: { ...process.env, PLAYWRIGHT_BROWSERS_PATH: target },
});
if (result.status !== 0 || !hasBrowser(target)) {
    process.stderr.write('Failed to prepare the packaged Playwright Chromium runtime.\n');
    process.exit(result.status || 1);
}
process.stdout.write(`Prepared packaged Playwright Chromium runtime at ${target}\n`);
