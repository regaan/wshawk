document.addEventListener('DOMContentLoaded', () => {
    const toggleBtn = document.getElementById('toggleBtn');
    const detectBtn = document.getElementById('detectBtn');
    const bridgeUrlInput = document.getElementById('bridgeUrl');
    const projectIdInput = document.getElementById('projectId');
    const captureScopesInput = document.getElementById('captureScopes');
    const autoDetectCheckbox = document.getElementById('autoDetectBridge');
    const statusText = document.getElementById('statusText');

    function sendMessage(message) {
        return new Promise((resolve) => {
            chrome.runtime.sendMessage(message, (response) => resolve(response || {}));
        });
    }

    function pairedSummary(config) {
        if (config.hasPairedSession && config.pairedOrigin) {
            return `Paired: ${config.pairedOrigin}`;
        }
        if (config.pairedOrigin) {
            return `Pair remembered: ${config.pairedOrigin}`;
        }
        return 'Pairing: not established';
    }

    async function loadConfig() {
        const response = await sendMessage({ type: 'wshawk:get-config' });
        const config = response.config || {};
        bridgeUrlInput.value = config.bridgeUrl || config.lastDetectedBridgeUrl || '';
        projectIdInput.value = config.projectId || '';
        captureScopesInput.value = config.captureScopes || '';
        autoDetectCheckbox.checked = config.autoDetectBridge !== false;
        updateUI(config.capturingEnabled !== false, config.lastBridgeStatus || null, config);
    }

    function updateUI(enabled, bridgeInfo, config = {}) {
        if (enabled) {
            toggleBtn.textContent = 'STOP CAPTURING';
            toggleBtn.className = 'toggle-btn btn-on';
        } else {
            toggleBtn.textContent = 'START CAPTURING';
            toggleBtn.className = 'toggle-btn btn-off';
        }

        const details = [];
        details.push(`Capture: ${enabled ? 'enabled' : 'paused'}`);
        if ((config.captureScopes || '').trim()) {
            details.push(`Scopes: ${(config.captureScopes || '').split(',').filter(Boolean).length}`);
        } else {
            details.push('Scopes: not set');
        }

        if (bridgeInfo?.status === 'online') {
            details.push(`Bridge: online (${bridgeInfo.bridge_version || 'unknown'})`);
            details.push(pairedSummary(config));
        } else {
            details.push('Bridge: not detected');
        }

        statusText.textContent = details.join(' • ');
        statusText.style.color = bridgeInfo?.status === 'online'
            ? '#34d399'
            : enabled
                ? '#fbbf24'
                : '#f87171';
    }

    async function saveConfig(overrides = {}) {
        const capturingEnabled = overrides.capturingEnabled ?? !toggleBtn.classList.contains('btn-off');
        const response = await sendMessage({
            type: 'wshawk:save-config',
            bridgeUrl: bridgeUrlInput.value,
            projectId: projectIdInput.value,
            captureScopes: captureScopesInput.value,
            autoDetectBridge: autoDetectCheckbox.checked,
            capturingEnabled,
        });
        updateUI(response.config?.capturingEnabled !== false, response.config?.lastBridgeStatus || null, response.config || {});
    }

    async function detectBridge() {
        statusText.textContent = 'Detecting and pairing with local WSHawk bridge...';
        statusText.style.color = '#22d3ee';
        const response = await sendMessage({ type: 'wshawk:discover-bridge' });
        if (response.ok) {
            bridgeUrlInput.value = response.bridgeUrl || bridgeUrlInput.value;
            const config = await sendMessage({ type: 'wshawk:get-config' });
            updateUI(!toggleBtn.classList.contains('btn-off'), response.bridgeInfo || null, config.config || {});
        } else {
            updateUI(!toggleBtn.classList.contains('btn-off'), { status: 'offline' }, {});
        }
    }

    toggleBtn.addEventListener('click', async () => {
        const nextEnabled = toggleBtn.classList.contains('btn-off');
        await saveConfig({ capturingEnabled: nextEnabled });
    });

    detectBtn.addEventListener('click', async () => {
        await detectBridge();
        await saveConfig();
    });

    [bridgeUrlInput, projectIdInput, captureScopesInput].forEach((element) => {
        element.addEventListener('change', () => {
            void saveConfig();
        });
    });

    autoDetectCheckbox.addEventListener('change', () => {
        void saveConfig();
    });

    void loadConfig().then(() => {
        if (autoDetectCheckbox.checked && !bridgeUrlInput.value.trim()) {
            void detectBridge();
        }
    });
});
