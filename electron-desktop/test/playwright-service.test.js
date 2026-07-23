'use strict';

const test = require('node:test');
const assert = require('node:assert/strict');

const { PlaywrightService } = require('../main/playwright-service');

test('Playwright capability degrades safely when its optional package is absent', () => {
    const service = new PlaywrightService({ moduleName: 'wshawk-definitely-missing-playwright-package' });
    const status = service.status();
    assert.equal(status.available, false);
    assert.equal(status.provider, 'electron-playwright');
    assert.equal(status.reason, 'package-not-installed');
    assert.throws(() => service.load(), (error) => error.code === 'playwright_unavailable');
});

test('browser contexts and processes close when an operation fails', async () => {
	let contextClosed = 0;
	let browserClosed = 0;
	const context = { addCookies: async () => {}, close: async () => { contextClosed += 1; } };
	const browser = { newContext: async () => context, close: async () => { browserClosed += 1; } };
	const service = new PlaywrightService();
	service.loaded = { chromium: { executablePath: () => process.execPath, launch: async () => browser } };
	await assert.rejects(service.withContext({}, async () => { throw new Error('lab failure'); }), /lab failure/);
	assert.equal(contextClosed, 1);
	assert.equal(browserClosed, 1);
	assert.equal(service.active.size, 0);
});

test('closeAll terminates active isolated contexts', async () => {
	let contextClosed = 0;
	let browserClosed = 0;
	let release;
	const hold = new Promise(resolve => { release = resolve; });
	const context = { addCookies: async () => {}, close: async () => { contextClosed += 1; } };
	const browser = { newContext: async () => context, close: async () => { browserClosed += 1; } };
	const service = new PlaywrightService();
	service.loaded = { chromium: { executablePath: () => process.execPath, launch: async () => browser } };
	const operation = service.withContext({}, async () => hold);
	await new Promise(resolve => setImmediate(resolve));
	const result = await service.closeAll();
	assert.equal(result.closed, 1);
	assert.equal(result.activeContexts, 0);
	assert.equal(contextClosed, 1);
	assert.equal(browserClosed, 1);
	release();
	await operation;
});
