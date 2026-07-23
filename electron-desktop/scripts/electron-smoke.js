'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { spawn } = require('child_process');
const { isolatedElectronEnvironment } = require('./electron-harness');

const projectRoot = path.resolve(__dirname, '..');
const outputPath = path.join(os.tmpdir(), `wshawk-direct-ipc-smoke-${process.pid}.json`);
const dataDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'wshawk-direct-ipc-smoke-data-'));

function electronExecutable() {
    try {
        return require('electron');
    } catch (_error) {
        const distRoot = path.resolve(projectRoot, '..', 'desktop', 'node_modules', 'electron', 'dist');
        if (process.platform === 'win32') return path.join(distRoot, 'electron.exe');
        if (process.platform === 'darwin') {
            return path.join(distRoot, 'Electron.app', 'Contents', 'MacOS', 'Electron');
        }
        return path.join(distRoot, 'electron');
    }
}

async function main() {
    const executable = electronExecutable();
    if (!fs.existsSync(executable)) {
        throw new Error(`Electron executable not found: ${executable}`);
    }
    const child = spawn(executable, [projectRoot], {
        cwd: projectRoot,
        env: isolatedElectronEnvironment(dataDirectory, {
            WSHAWK_DIRECT_SMOKE: '1',
            WSHAWK_DIRECT_SMOKE_OUT: outputPath,
        }),
        shell: false,
        stdio: ['ignore', 'pipe', 'pipe'],
        windowsHide: true,
    });
    let stderr = '';
    child.stderr.on('data', chunk => { stderr += String(chunk).slice(0, 4_096); });

    const exitCode = await new Promise((resolve, reject) => {
        const timeout = setTimeout(() => {
            child.kill();
            reject(new Error('Electron smoke test timed out'));
        }, 20_000);
        child.once('error', reject);
        child.once('exit', code => {
            clearTimeout(timeout);
            resolve(code);
        });
    });
    if (exitCode !== 0) {
        throw new Error(`Electron exited with ${exitCode}: ${stderr.trim()}`);
    }
    const snapshot = JSON.parse(fs.readFileSync(outputPath, 'utf8'));
    fs.unlinkSync(outputPath);
    fs.rmSync(dataDirectory, { recursive: true, force: true });
    if (!snapshot.ok) {
        throw new Error(`Electron smoke gate failed: ${JSON.stringify(snapshot)}`);
    }
    process.stdout.write(
        `Electron smoke passed (${snapshot.worker.backend}, ${snapshot.worker.transport}, `
        + `Playwright ${snapshot.browserAutomation.version}, visible=${snapshot.window.visible}).\n`,
    );
}

main().catch((error) => {
    if (fs.existsSync(dataDirectory)) fs.rmSync(dataDirectory, { recursive: true, force: true });
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exitCode = 1;
});
