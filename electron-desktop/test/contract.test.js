'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const {
	INVOKE_METHODS,
    IPC_VERSION,
    MAX_REQUEST_BYTES,
    validateInvokeRequest,
} = require('../shared/contract');
const fs = require('fs');
const path = require('path');

test('contract accepts an allowlisted request', () => {
    assert.deepEqual(
        validateInvokeRequest({ method: 'system.health', params: {} }),
        { method: 'system.health', params: {} },
    );
    assert.equal(IPC_VERSION, '1');
	assert.ok(INVOKE_METHODS.includes('scanner.authz_matrix'));
});

test('contract rejects unknown methods and non-object params', () => {
    assert.throws(
        () => validateInvokeRequest({ method: 'network.listen', params: {} }),
        /Unsupported IPC method/,
    );
    assert.throws(
        () => validateInvokeRequest({ method: 'system.health', params: [] }),
        /params must be an object/,
    );
});

test('contract rejects oversized payloads', () => {
    assert.throws(
        () => validateInvokeRequest({
            method: 'system.health',
            params: { value: 'x'.repeat(MAX_REQUEST_BYTES) },
        }),
        /payload limit/,
    );
});

test('sandboxed preload methods stay within the shared contract', () => {
	const source = fs.readFileSync(path.join(__dirname, '..', 'preload', 'index.js'), 'utf8');
	const quotedMethods = [...source.matchAll(/'([a-z][a-z0-9_.]+)'/g)].map(match => match[1]);
	const rendererMethods = quotedMethods.filter(method => method.includes('.') && !method.startsWith('worker.'));
	for (const method of rendererMethods) assert.ok(INVOKE_METHODS.includes(method), `preload method missing from contract: ${method}`);
	assert.doesNotMatch(source, /system\.shutdown|projects\.import/);
});
