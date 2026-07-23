'use strict';

const { contextBridge, ipcRenderer } = require('electron');

// Sandboxed Electron preloads cannot load arbitrary local CommonJS modules.
// Keep this renderer-facing subset explicit and verify it against the shared
// contract in test/contract.test.js.
const INVOKE_METHODS = new Set([
    'system.health', 'system.capabilities',
    'projects.list', 'projects.get', 'projects.save', 'projects.delete', 'projects.snapshot',
    'entities.list', 'entities.get', 'entities.save', 'entities.delete', 'storage.backup',
	'protocol.map',
    'ws.connect', 'ws.send', 'ws.disconnect', 'ws.replay', 'ws.intercept.set', 'ws.intercept.action', 'ws.probe', 'ws.race',
    'http.request', 'web.crawl', 'web.dirscan', 'web.analyze', 'tls.inspect', 'oast.poll',
    'scanner.catalog', 'scanner.mutate', 'scanner.run', 'scanner.authz_diff', 'scanner.authz_matrix', 'scanner.race', 'scanner.binary_analyze',
    'scanner.ws_mutate', 'scanner.subscription_abuse', 'scanner.auth_test',
    'operation.cancel', 'reports.generate', 'evidence.bundle', 'evidence.verify', 'integration.send',
    'cert.ca.generate', 'cert.host.generate',
	'network.dns', 'network.subdomains', 'network.portscan',
	'workflow.run',
    'browser.status', 'browser.dom_xss.verify', 'browser.auth.record', 'browser.auth.replay',
    'browser.evidence.capture', 'browser.close_all',
    'dialog.project.open', 'dialog.project.export', 'dialog.report.save',
    'window.minimize', 'window.maximize', 'window.close',
]);
const EVENT_NAMES = new Set(['worker:status', 'worker:event']);

contextBridge.exposeInMainWorld('wshawk', Object.freeze({
    invoke(method, params = {}) {
        if (!INVOKE_METHODS.has(method)) {
            return Promise.reject(new TypeError(`Unsupported desktop method: ${String(method)}`));
        }
        return ipcRenderer.invoke('wshawk:invoke', { method, params });
    },
    cancel(operationId) {
		return ipcRenderer.invoke('wshawk:invoke', { method: 'operation.cancel', params: { operation_id: operationId } });
    },
    subscribe(eventName, callback) {
        if (!EVENT_NAMES.has(eventName) || typeof callback !== 'function') {
            throw new TypeError('Unsupported desktop event subscription');
        }
        const listener = (_event, payload) => callback(payload);
        ipcRenderer.on(eventName, listener);
        return () => ipcRenderer.removeListener(eventName, listener);
    },
}));
