'use strict';

const fs = require('fs');
const path = require('path');

function boundedTimeout(value, fallback = 30_000) {
    if (!Number.isFinite(value) || value <= 0) return fallback;
    return Math.max(1_000, Math.min(120_000, Math.trunc(value)));
}

function findBundledBrowser(root) {
    if (!root || !fs.existsSync(root)) return '';
    const preferred = process.platform === 'win32'
        ? ['chrome.exe', 'chrome-headless-shell.exe', 'headless_shell.exe']
        : process.platform === 'darwin'
            ? ['Chromium', 'Google Chrome for Testing', 'chrome-headless-shell']
            : ['chrome', 'chrome-headless-shell', 'headless_shell'];
    const matches = [];
    const visit = (directory, depth = 0) => {
        if (depth > 8) return;
        let entries = [];
        try { entries = fs.readdirSync(directory, { withFileTypes: true }); } catch (_) { return; }
        for (const entry of entries) {
            const candidate = path.join(directory, entry.name);
            if (entry.isDirectory()) visit(candidate, depth + 1);
            else if (preferred.includes(entry.name)) matches.push(candidate);
        }
    };
    visit(root);
    matches.sort((left, right) => preferred.indexOf(path.basename(left)) - preferred.indexOf(path.basename(right)));
    return matches[0] || '';
}

function browserExecutable(playwright) {
    const candidates = [
        process.env.PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH,
        findBundledBrowser(process.resourcesPath ? path.join(process.resourcesPath, 'playwright-browsers') : ''),
    ];
    try { candidates.push(playwright.chromium?.executablePath?.()); } catch (_) {}
    if (process.platform === 'win32') {
        for (const root of [process.env.PROGRAMFILES, process.env['PROGRAMFILES(X86)'], process.env.LOCALAPPDATA]) {
            if (!root) continue;
            candidates.push(
                path.join(root, 'Microsoft', 'Edge', 'Application', 'msedge.exe'),
                path.join(root, 'Google', 'Chrome', 'Application', 'chrome.exe'),
            );
        }
    } else if (process.platform === 'darwin') {
        candidates.push('/Applications/Google Chrome.app/Contents/MacOS/Google Chrome', '/Applications/Microsoft Edge.app/Contents/MacOS/Microsoft Edge');
    } else {
        candidates.push('/usr/bin/google-chrome', '/usr/bin/google-chrome-stable', '/usr/bin/chromium', '/usr/bin/chromium-browser', '/usr/bin/microsoft-edge');
    }
    return candidates.find(candidate => candidate && fs.existsSync(candidate)) || '';
}

class PlaywrightService {
    constructor(options = {}) {
        this.moduleName = options.moduleName || 'playwright-core';
        this.loaded = null;
        this.active = new Map();
        this.maxConcurrent = options.maxConcurrent || 2;
    }

    status() {
        try {
            const packagePath = require.resolve(`${this.moduleName}/package.json`);
            const packageInfo = require(packagePath);
            const module = this.loadModuleOnly();
            const candidate = browserExecutable(module);
            return {
                available: true,
                provider: 'electron-playwright',
                package: this.moduleName,
                version: packageInfo.version,
                execution: 'electron-main',
                browserExecutable: candidate && fs.existsSync(candidate) ? candidate : null,
                browserReady: Boolean(candidate && fs.existsSync(candidate)),
                activeContexts: this.active.size,
            };
        } catch (error) {
            return {
                available: false,
                provider: 'electron-playwright',
                package: this.moduleName,
                version: null,
                execution: 'electron-main',
                reason: error.code === 'MODULE_NOT_FOUND' ? 'package-not-installed' : 'package-load-failed',
            };
        }
    }

    load() {
        if (!this.loaded) {
            const status = this.status();
            if (!status.available) {
                const error = new Error('Electron Playwright capability is unavailable');
                error.code = 'playwright_unavailable';
                throw error;
            }
            this.loaded = this.loadModuleOnly();
        }
        return this.loaded;
    }

    loadModuleOnly() {
        if (!this.loaded) this.loaded = require(this.moduleName);
        return this.loaded;
    }

    async withContext(options, callback) {
        if (this.active.size >= this.maxConcurrent) {
            const error = new Error('Browser automation concurrency limit reached');
            error.code = 'browser_busy';
            throw error;
        }
        const playwright = this.load();
        const executablePath = browserExecutable(playwright);
        if (!executablePath || !fs.existsSync(executablePath)) {
            const error = new Error('Playwright Chromium is not installed; run npx playwright install chromium or set PLAYWRIGHT_CHROMIUM_EXECUTABLE_PATH');
            error.code = 'browser_executable_missing';
            throw error;
        }
        const token = Symbol('browser-context');
		const activeEntry = { browser: null, context: null };
        this.active.set(token, activeEntry);
        let browser;
        let context;
        try {
            browser = await playwright.chromium.launch({
                executablePath,
                headless: options.headless !== false,
                args: ['--disable-background-networking', '--disable-sync'],
            });
			activeEntry.browser = browser;
            context = await browser.newContext({
                ignoreHTTPSErrors: options.ignoreHTTPSErrors === true,
                viewport: options.viewport || { width: 1440, height: 900 },
            });
			activeEntry.context = context;
            if (Array.isArray(options.cookies) && options.cookies.length) {
                await context.addCookies(options.cookies);
            }
            return await callback(context);
        } finally {
            if (context) await context.close().catch(() => {});
            if (browser) await browser.close().catch(() => {});
            this.active.delete(token);
        }
    }

    async verifyDOMXSS(options) {
        if (options.authorizationConfirmed !== true) throw new Error('authorizationConfirmed must be true');
        const timeout = boundedTimeout(options.timeoutMs);
        return this.withContext({ headless: true, ignoreHTTPSErrors: options.ignoreHTTPSErrors }, async (context) => {
            const page = await context.newPage();
            const dialogs = [];
            page.on('dialog', async (dialog) => { dialogs.push({ type: dialog.type(), message: dialog.message() }); await dialog.dismiss(); });
            await page.addInitScript((marker) => {
                globalThis.__wshawkEvidence = [];
                const original = globalThis.alert;
                globalThis.alert = (...args) => { globalThis.__wshawkEvidence.push({ sink: 'alert', args: args.map(String), marker }); return undefined; };
                globalThis.__wshawkOriginalAlert = original;
            }, options.marker || 'wshawk_xss_probe');
            await page.goto(options.url, { waitUntil: 'domcontentloaded', timeout });
            if (options.selector && options.payload !== undefined) {
                await page.locator(options.selector).fill(String(options.payload), { timeout });
                if (options.submitSelector) await page.locator(options.submitSelector).click({ timeout });
            }
            await page.waitForTimeout(Math.min(1_500, timeout));
            const evidence = await page.evaluate(() => globalThis.__wshawkEvidence || []);
            const html = await page.content();
            const marker = String(options.marker || 'wshawk_xss_probe');
            const screenshot = await page.screenshot({ type: 'png', fullPage: true });
            const matchingEvidence = evidence.filter(item => (item.args || []).some(value => String(value).includes(marker)));
            return {
                confirmed: matchingEvidence.length > 0 || dialogs.some(item => item.message.includes(marker)),
                evidence,
                dialogs,
                markerReflected: html.includes(marker),
                finalURL: page.url(),
                screenshotBase64: screenshot.toString('base64'),
            };
        });
    }

    async recordAuthentication(options) {
        const timeout = boundedTimeout(options.timeoutMs, 120_000);
        return this.withContext({ headless: options.visible !== true, ignoreHTTPSErrors: options.ignoreHTTPSErrors }, async (context) => {
            const page = await context.newPage();
            await page.goto(options.url, { waitUntil: 'domcontentloaded', timeout });
            if (options.waitForURL) {
                await page.waitForURL(options.waitForURL, { timeout });
            } else if (options.visible === true) {
                const initialURL = page.url();
                const initialCookies = JSON.stringify(await context.cookies());
                const deadline = Date.now() + timeout;
                while (Date.now() < deadline) {
                    await page.waitForTimeout(Math.min(500, Math.max(1, deadline - Date.now())));
                    const cookiesChanged = JSON.stringify(await context.cookies()) !== initialCookies;
                    const hasAuthStorage = await page.evaluate(() => [...Object.keys(localStorage), ...Object.keys(sessionStorage)].some(key => /(token|jwt|auth|session)/i.test(key))).catch(() => false);
                    if (page.url() !== initialURL || cookiesChanged || hasAuthStorage) {
                        await page.waitForTimeout(Math.min(1_000, Math.max(1, deadline - Date.now())));
                        break;
                    }
                }
            } else {
                await page.waitForTimeout(Math.min(timeout, options.settleMs || 2_000));
            }
            const cookies = await context.cookies();
            const storage = await page.evaluate(() => ({
                localStorage: Object.fromEntries(Object.entries(localStorage)),
                sessionStorage: Object.fromEntries(Object.entries(sessionStorage)),
            }));
            const screenshot = await page.screenshot({ type: 'png', fullPage: true });
            return { url: page.url(), cookies, storage, screenshotBase64: screenshot.toString('base64') };
        });
    }

    async replayAuthentication(options) {
        return this.withContext({ headless: true, cookies: options.cookies, ignoreHTTPSErrors: options.ignoreHTTPSErrors }, async (context) => {
            if (options.storage) {
                await context.addInitScript((storage) => {
                    for (const [key, value] of Object.entries(storage.localStorage || {})) localStorage.setItem(key, value);
                    for (const [key, value] of Object.entries(storage.sessionStorage || {})) sessionStorage.setItem(key, value);
                }, options.storage);
            }
            const page = await context.newPage();
            const response = await page.goto(options.url, { waitUntil: 'domcontentloaded', timeout: boundedTimeout(options.timeoutMs) });
            const screenshot = await page.screenshot({ type: 'png', fullPage: true });
            return { url: page.url(), status: response?.status() || 0, title: await page.title(), screenshotBase64: screenshot.toString('base64') };
        });
    }

    async captureEvidence(options) {
        return this.withContext({ headless: true, cookies: options.cookies, ignoreHTTPSErrors: options.ignoreHTTPSErrors }, async (context) => {
            const page = await context.newPage();
            await page.goto(options.url, { waitUntil: options.waitUntil || 'networkidle', timeout: boundedTimeout(options.timeoutMs) });
            if (options.selector) await page.locator(options.selector).waitFor({ timeout: boundedTimeout(options.timeoutMs) });
            const screenshot = await page.screenshot({ type: 'png', fullPage: options.fullPage !== false });
            return { url: page.url(), title: await page.title(), screenshotBase64: screenshot.toString('base64'), capturedAt: new Date().toISOString() };
        });
    }

    async closeAll() {
		const entries = [...this.active.entries()];
		await Promise.all(entries.map(async ([token, entry]) => {
			if (entry.context) await entry.context.close().catch(() => {});
			if (entry.browser) await entry.browser.close().catch(() => {});
			this.active.delete(token);
		}));
		return { closed: entries.length, activeContexts: this.active.size };
    }
}

module.exports = { PlaywrightService };
