'use strict';

const IPC_VERSION = '1';
const MAX_REQUEST_BYTES = 8 * 1024 * 1024;
const MAX_RESPONSE_BYTES = 16 * 1024 * 1024;

const WORKER_METHODS = Object.freeze([
    'system.health',
    'system.capabilities',
    'system.shutdown',
    'projects.list', 'projects.get', 'projects.save', 'projects.delete', 'projects.snapshot', 'projects.import',
    'entities.list', 'entities.get', 'entities.save', 'entities.delete', 'storage.backup',
	'protocol.map',
    'ws.connect', 'ws.send', 'ws.disconnect', 'ws.replay', 'ws.intercept.set', 'ws.intercept.action', 'ws.probe', 'ws.race',
    'http.request', 'web.crawl', 'web.dirscan', 'web.analyze', 'tls.inspect', 'oast.poll',
    'scanner.catalog', 'scanner.mutate', 'scanner.run', 'scanner.authz_diff', 'scanner.authz_matrix', 'scanner.race', 'scanner.binary_analyze',
    'scanner.ws_mutate', 'scanner.subscription_abuse', 'scanner.auth_test',
    'operation.cancel',
    'reports.generate', 'evidence.bundle', 'evidence.verify', 'integration.send',
    'cert.ca.generate', 'cert.host.generate',
	'network.dns', 'network.subdomains', 'network.portscan',
	'workflow.run',
]);

const MAIN_METHODS = Object.freeze([
    'browser.status',
    'browser.dom_xss.verify', 'browser.auth.record', 'browser.auth.replay',
    'browser.evidence.capture', 'browser.close_all',
    'dialog.project.open', 'dialog.project.export', 'dialog.report.save',
    'window.minimize', 'window.maximize', 'window.close',
]);

const INVOKE_METHODS = Object.freeze([...WORKER_METHODS, ...MAIN_METHODS]);
const EVENT_NAMES = Object.freeze(['worker:status', 'worker:event']);

function isRecord(value) {
    return value !== null && typeof value === 'object' && !Array.isArray(value);
}

function jsonByteLength(value) {
    try {
        return Buffer.byteLength(JSON.stringify(value), 'utf8');
    } catch (error) {
        throw new TypeError(`IPC payload must be JSON serializable: ${error.message}`);
    }
}

function validateInvokeRequest(value) {
    if (!isRecord(value)) {
        throw new TypeError('IPC request must be an object');
    }
    if (!INVOKE_METHODS.includes(value.method)) {
        throw new TypeError(`Unsupported IPC method: ${String(value.method || '')}`);
    }
    const params = value.params === undefined ? {} : value.params;
    if (!isRecord(params)) {
        throw new TypeError('IPC request params must be an object');
    }
    if (jsonByteLength({ method: value.method, params }) > MAX_REQUEST_BYTES) {
        throw new RangeError('IPC request exceeds the payload limit');
    }
    return { method: value.method, params };
}

module.exports = Object.freeze({
    EVENT_NAMES,
    INVOKE_METHODS,
    IPC_VERSION,
    MAIN_METHODS,
    MAX_REQUEST_BYTES,
    MAX_RESPONSE_BYTES,
    WORKER_METHODS,
    isRecord,
    jsonByteLength,
    validateInvokeRequest,
});
