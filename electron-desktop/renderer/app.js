'use strict';

const workerStatus = document.getElementById('worker-status');
const workerDetail = document.getElementById('worker-detail');
const browserStatus = document.getElementById('browser-status');
const browserDetail = document.getElementById('browser-detail');
const capabilities = document.getElementById('capabilities');
const protocolVersion = document.getElementById('protocol-version');
const errorBox = document.getElementById('error');

function showError(error) {
    errorBox.textContent = error?.message || String(error);
    errorBox.hidden = false;
}

function renderCapabilities(items) {
    capabilities.replaceChildren();
    for (const item of items) {
        const node = document.createElement('li');
        node.textContent = item;
        capabilities.appendChild(node);
    }
}

async function refreshStatus() {
    errorBox.hidden = true;
    try {
        const [health, capabilityResult, browser] = await Promise.all([
            window.wshawk.invoke('system.health'),
            window.wshawk.invoke('system.capabilities'),
            window.wshawk.invoke('browser.status'),
        ]);
        workerStatus.textContent = String(health.status || 'unknown').toUpperCase();
        workerDetail.textContent = `PID ${health.pid} · ${health.backend} ${health.version}`;
        protocolVersion.textContent = `Protocol ${capabilityResult.protocolVersion}`;
        renderCapabilities(capabilityResult.methods || []);
        browserStatus.textContent = browser.available ? 'AVAILABLE' : 'OPTIONAL';
        browserDetail.textContent = browser.available
            ? `${browser.package} ${browser.version}`
            : 'Install optional playwright-core dependency';
    } catch (error) {
        workerStatus.textContent = 'UNAVAILABLE';
        workerDetail.textContent = 'Go worker did not answer';
        showError(error);
    }
}

window.wshawk.subscribe('worker:status', (status) => {
    workerStatus.textContent = String(status.state || 'unknown').toUpperCase();
    if (status.pid) workerDetail.textContent = `Private worker PID ${status.pid}`;
});

document.getElementById('refresh').addEventListener('click', refreshStatus);
refreshStatus();
