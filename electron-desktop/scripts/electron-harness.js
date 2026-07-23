'use strict';

const crypto = require('crypto');

function isolatedElectronEnvironment(dataDirectory, extra = {}) {
    return {
        ...process.env,
        ...extra,
        WSHAWK_ELECTRON_GO_DATA_DIR: dataDirectory,
        WSHAWK_STORAGE_KEY: process.env.WSHAWK_STORAGE_KEY || crypto.randomBytes(32).toString('base64'),
    };
}

async function firstWindowWithDiagnostics(application, timeout = 60_000) {
    const child = application.process();
    let stdout = '';
    let stderr = '';
    child.stdout?.on('data', chunk => { stdout = `${stdout}${chunk}`.slice(-16_384); });
    child.stderr?.on('data', chunk => { stderr = `${stderr}${chunk}`.slice(-16_384); });
    try {
        return await application.firstWindow({ timeout });
    } catch (error) {
        const diagnostics = [
            `Electron PID: ${child.pid || 'unavailable'}`,
            `Electron exit code: ${child.exitCode ?? 'still-running'}`,
            stderr.trim() ? `Electron stderr:\n${stderr.trim()}` : '',
            stdout.trim() ? `Electron stdout:\n${stdout.trim()}` : '',
        ].filter(Boolean).join('\n');
        throw new Error(`${error.message}\n${diagnostics}`, { cause: error });
    }
}

module.exports = { firstWindowWithDiagnostics, isolatedElectronEnvironment };
