'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const { _electron: electron } = require('playwright-core');

const root = path.resolve(__dirname, '..');
const authorizationPhrase = 'I_OWN_OR_AM_AUTHORIZED';
const targetValue = String(process.env.WSHAWK_AUTHORIZED_TARGET || '').trim();

if (process.env.WSHAWK_AUTHORIZATION_CONFIRMED !== authorizationPhrase) {
	throw new Error(`Set WSHAWK_AUTHORIZATION_CONFIRMED=${authorizationPhrase} only for a target you own or are authorized to test.`);
}

const target = new URL(targetValue);
if (target.protocol !== 'https:' || target.username || target.password) {
	throw new Error('WSHAWK_AUTHORIZED_TARGET must be an absolute HTTPS URL without embedded credentials.');
}
target.hash = '';
const baseURL = target.toString().replace(/\/$/, '');
const hostname = target.hostname;
const probeURL = new URL(target);
probeURL.searchParams.set('wshawk_probe', 'baseline');
const missingURL = new URL('/.well-known/wshawk-nonexistent-audit-probe', target).toString();
const canaryOrigin = 'https://wshawk-audit.invalid';

const uiTargets = [
	'httpforge', 'httpfuzzer', 'dirscanner', 'headeranalyzer', 'jwtanalyzer', 'subdomain',
	'webcrawler', 'vulnscanner', 'techfp', 'sslanalyzer', 'sensitivefinder', 'wafdetect',
	'corstester', 'portscanner', 'dnslookup', 'csrfforge', 'blindprobe', 'redirecthunter',
	'protopolluter', 'hawkproxyca', 'attackchainer', 'cybernode', 'teammode',
];

function markdownEscape(value) {
	return String(value ?? '').replace(/\|/g, '\\|').replace(/[\r\n]+/g, ' ');
}

function reportMarkdown(report) {
	const counts = report.modules.reduce((result, item) => {
		result[item.status] = (result[item.status] || 0) + 1;
		return result;
	}, {});
	const rows = report.modules.map(item => `| ${markdownEscape(item.module)} | ${item.status} | ${item.duration_ms} ms | ${markdownEscape(item.quality)} | ${markdownEscape(item.summary)} | ${markdownEscape(item.limitations)} |`).join('\n');
	return `# WSHawk authorized web-module audit\n\n` +
		`- Target: \`${report.target}\`\n` +
		`- Started: ${report.started_at}\n` +
		`- Finished: ${report.finished_at}\n` +
		`- Authorization: operator-confirmed ownership or permission\n` +
		`- Safety profile: HTTPS, same target, bounded GET probes, two TCP ports, no live state-changing race tests\n` +
		`- Result: ${counts.pass || 0} passed, ${counts.limited || 0} limited, ${counts.fail || 0} failed\n\n` +
		`| Module | Status | Duration | Quality | Observed result | Limitation |\n` +
		`|---|---:|---:|---|---|---|\n${rows}\n\n` +
		`## Interpretation\n\n` +
		`A passed result means the complete Electron renderer -> private IPC -> Go worker path returned a valid result. It does not prove the target has no vulnerability. A limited result means the module needs a controlled endpoint, account, OAST callback, or state-changing workflow for a meaningful security conclusion.\n`;
}

async function ipcRequest(window, requestPath, body) {
	return window.evaluate(async ({ requestPath, body }) => {
		const response = await window.ipcRequest(requestPath, {
			method: 'POST',
			headers: { 'Content-Type': 'application/json' },
			body: JSON.stringify(body || {}),
		});
		const data = await response.json();
		if (!response.ok) {
			const error = new Error(data?.message || data?.detail || `IPC request failed with ${response.status}`);
			error.code = data?.code || 'ipc_error';
			throw error;
		}
		return data;
	}, { requestPath, body });
}

async function activateView(window, targetName) {
	return window.evaluate((targetName) => {
		const button = document.querySelector(`.nav-item[data-target="${targetName}"]`);
		const view = document.getElementById(`view-${targetName}`);
		if (!button || !view) return { button: Boolean(button), view: Boolean(view), active: false };
		button.click();
		return { button: true, view: true, active: view.classList.contains('active') };
	}, targetName);
}

(async () => {
	const startedAt = new Date();
	const outputDirectory = path.join(root, 'audit-results');
	fs.mkdirSync(outputDirectory, { recursive: true });
	const dataDirectory = fs.mkdtempSync(path.join(os.tmpdir(), 'wshawk-authorized-audit-'));
	const application = await electron.launch({
		args: [root],
		env: { ...process.env, WSHAWK_ELECTRON_GO_DATA_DIR: dataDirectory },
	});
	const modules = [];
	let projectId = '';
	try {
		const window = await application.firstWindow();
		await window.waitForLoadState('domcontentloaded');
		if ((await window.title()) !== 'WSHawk Intelligence') throw new Error('The full WSHawk interface did not load.');
		if (await window.locator('#btn-agree-tos').isVisible()) await window.locator('#btn-agree-tos').click();
		await window.locator('#btn-new-project').click();
		await window.locator('#main-app').waitFor({ state: 'visible' });

		const health = await window.evaluate(() => window.wshawk.invoke('system.health'));
		if (health.backend !== 'go' || health.noNetworkBridge !== true) throw new Error('The Electron renderer did not reach the private Go worker.');
		await window.locator('#toggle-mode-btn').click();
		await window.locator('#toggle-mode-btn').click();
		await window.locator('#web-menu').waitFor({ state: 'visible' });

		const project = await ipcRequest(window, '/platform/projects', { name: `Authorized audit - ${hostname}`, url: baseURL });
		projectId = project.project?.id || '';
		if (!projectId) throw new Error('Project storage did not return a project ID.');

		const run = async (definition, operation) => {
			const started = Date.now();
			const ui = await activateView(window, definition.ui);
			try {
				if (!ui.button || !ui.view || !ui.active) throw new Error(`UI view ${definition.ui} is missing or did not activate.`);
				const observed = await operation();
				modules.push({
					module: definition.name,
					ui_target: definition.ui,
					status: definition.limited ? 'limited' : 'pass',
					duration_ms: Date.now() - started,
					quality: definition.quality,
					summary: observed,
					limitations: definition.limitations || '',
				});
			} catch (error) {
				modules.push({
					module: definition.name,
					ui_target: definition.ui,
					status: 'fail',
					duration_ms: Date.now() - started,
					quality: definition.quality,
					summary: `${error.code ? `${error.code}: ` : ''}${error.message}`,
					limitations: definition.limitations || '',
				});
			}
		};

		await run({ name: 'HTTP Request Forge', ui: 'httpforge', quality: 'Strong transport and evidence capture' }, async () => {
			const result = await ipcRequest(window, '/web/request', { project_id: projectId, url: baseURL, method: 'GET', timeout_ms: 10000, follow_redirects: false, restrict_redirect_origin: true });
			return `HTTP ${result.status}; ${result.duration_ms || 0} ms; ${result.body_bytes || 0} response bytes`;
		});

		await run({ name: 'HTTP Fuzzer', ui: 'httpfuzzer', quality: 'Moderate bounded differential scanner', limitations: 'Two harmless reflected-XSS query mutations were used; deeper coverage needs endpoint parameters.' }, async () => {
			const result = await ipcRequest(window, '/web/fuzz', { project_id: projectId, url: probeURL.toString().replace('baseline', 'FUZZ'), parameter: 'wshawk_probe', location: 'query', categories: ['xss'], max_requests: 2, concurrency: 1, timeout_ms: 5000, operation_timeout_ms: 20000 });
			return `${result.completed || 0} probes; ${(result.findings || []).length} candidate findings`;
		});

		await run({ name: 'Directory Scanner', ui: 'dirscanner', quality: 'Good bounded discovery', limitations: 'Four high-value paths only; this is a production-safe smoke test, not full content discovery.' }, async () => {
			const result = await ipcRequest(window, '/web/dirscan', { project_id: projectId, url: baseURL, words: ['robots.txt', 'sitemap.xml', '.well-known/security.txt', '.well-known/wshawk-nonexistent-audit-probe'], concurrency: 2, timeout_ms: 5000, operation_timeout_ms: 30000 });
			return `${result.checked || 0} paths checked; ${(result.found || []).length} credible responses; ${result.soft_404_filtered || 0} soft-404 responses filtered`;
		});

		await run({ name: 'Security Header Analyzer', ui: 'headeranalyzer', quality: 'Good for common browser hardening headers' }, async () => {
			const result = await ipcRequest(window, '/web/headers', { project_id: projectId, url: baseURL });
			const missing = Object.values(result.headers || {}).filter(item => item.value === 'Missing').length;
			return `${Object.keys(result.headers || {}).length} headers evaluated; ${missing} missing`;
		});

		await run({ name: 'JWT Analyzer', ui: 'jwtanalyzer', quality: 'Useful local decoder; narrow attack assistance', limitations: 'Decoding and alg:none generation only; it does not validate a server acceptance path.' }, async () => {
			const token = 'eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJhdWQiOiJ3c2hhd2stYXVkaXQiLCJleHAiOjQxMDI0NDQ4MDB9.c2lnbmF0dXJl';
			await window.locator('#jwt-input').fill(token);
			await window.locator('#jwt-decode-btn').click();
			const decoded = await window.locator('#jwt-payload').innerText();
			if (!decoded.includes('wshawk-audit')) throw new Error('Synthetic JWT payload was not decoded.');
			return 'Synthetic JWT decoded locally without sending a token to the target';
		});

		await run({ name: 'Subdomain Finder', ui: 'subdomain', quality: 'Moderate DNS wordlist discovery', limitations: 'Restricted to www and api labels for the live audit.' }, async () => {
			const result = await ipcRequest(window, '/web/subdomains', { project_id: projectId, target: hostname, names: ['www', 'api'] });
			return `${(result.subdomains || []).length} of 2 candidate labels resolved`;
		});

		await run({ name: 'Web Crawler', ui: 'webcrawler', quality: 'Good same-origin bounded crawler', limitations: 'Depth 1 and 10-page ceiling for production safety.' }, async () => {
			const result = await ipcRequest(window, '/web/crawl', { project_id: projectId, url: baseURL, max_pages: 10, depth: 1, timeout_ms: 5000, operation_timeout_ms: 30000 });
			return `${result.visited || 0} pages visited; ${(result.endpoints || []).length} endpoints recorded`;
		});

		await run({ name: 'Vulnerability Scanner', ui: 'vulnscanner', quality: 'Good orchestration; moderate active detection depth', limitations: 'GET-only SQLi/XSS query probes, five crawl pages, and four mutations. Authenticated and stateful coverage was not attempted.' }, async () => {
			const result = await ipcRequest(window, '/web/vulnscan', { project_id: projectId, url: probeURL.toString(), parameter: 'wshawk_probe', location: 'query', categories: ['sqli', 'xss'], max_requests: 4, scan_concurrency: 2, words: ['robots.txt', '.well-known/wshawk-nonexistent-audit-probe'], concurrency: 2, max_pages: 5, depth: 1, request_timeout_ms: 5000, operation_timeout_ms: 45000 });
			const activeFindings = result.active_scan?.findings?.length || 0;
			const passiveFindings = Math.max(0, (result.total_findings || 0) - activeFindings);
			return `${result.active_scan?.completed || 0} active probes; ${activeFindings} active candidate findings; ${passiveFindings} passive observations; ${result.elapsed || 0} s`;
		});

		await run({ name: 'Technology Fingerprint', ui: 'techfp', quality: 'Weak passive fingerprinting', limitations: 'Currently based mainly on Server and X-Powered-By response headers.' }, async () => {
			const result = await ipcRequest(window, '/web/fingerprint', { project_id: projectId, url: baseURL });
			return `${result.count || 0} disclosed technologies detected`;
		});

		await run({ name: 'TLS Analyzer', ui: 'sslanalyzer', quality: 'Good certificate and negotiated-protocol inspection' }, async () => {
			const result = await ipcRequest(window, '/web/ssl', { project_id: projectId, url: baseURL });
			return `${result.certificate?.protocol || 'unknown protocol'}; ${result.certificate?.days_remaining ?? 'unknown'} certificate days remaining; ${result.issues?.length || 0} issues`;
		});

		await run({ name: 'Sensitive Data Finder', ui: 'sensitivefinder', quality: 'Moderate passive pattern scanner', limitations: 'This smoke test analyzes the target entry response only.' }, async () => {
			const result = await ipcRequest(window, '/web/sensitive', { project_id: projectId, url: baseURL });
			return `${result.total || 0} candidate disclosures in the entry response`;
		});

		await run({ name: 'WAF Detector', ui: 'wafdetect', quality: 'Weak passive signature detection', limitations: 'No active WAF bypass or behavioral challenge was sent to production.' }, async () => {
			const result = await ipcRequest(window, '/web/waf', { project_id: projectId, url: baseURL });
			return `${result.waf_count || 0} passive signatures; HTTP blocked=${Boolean(result.blocked)}`;
		});

		await run({ name: 'CORS Tester', ui: 'corstester', quality: 'Good for wildcard or reflected credentialed-origin checks' }, async () => {
			const result = await ipcRequest(window, '/web/cors', { project_id: projectId, url: baseURL, origin: canaryOrigin });
			return `${result.total || 0} risky CORS combinations; risk=${result.risk_score}`;
		});

		await run({ name: 'TCP Port Scanner', ui: 'portscanner', quality: 'Good bounded TCP reachability scan', limitations: 'Only ports 80 and 443 were tested.' }, async () => {
			const result = await ipcRequest(window, '/web/portscan', { project_id: projectId, target: hostname, ports: '80,443', timeout_ms: 1500 });
			return `${result.ports_scanned || 0} ports checked; ${(result.open_ports || []).length} open`;
		});

		await run({ name: 'DNS Lookup', ui: 'dnslookup', quality: 'Good basic DNS enumeration' }, async () => {
			const result = await ipcRequest(window, '/web/dns', { project_id: projectId, target: hostname });
			const recordCount = Object.values(result.dns_records || {}).reduce((count, values) => count + (Array.isArray(values) ? values.length : 0), 0);
			return `${recordCount} DNS records returned`;
		});

		await run({ name: 'CSRF Forge', ui: 'csrfforge', quality: 'Limited heuristic and PoC generator', limited: true, limitations: 'A GET request only verifies transport and PoC generation. Meaningful CSRF validation needs an authorized state-changing endpoint and authenticated session.' }, async () => {
			const result = await ipcRequest(window, '/web/csrf', { project_id: projectId, url: baseURL, method: 'GET', body: '', headers: {} });
			return `GET PoC generated (${result.poc_type}); target exploitability not concluded`;
		});

		await run({ name: 'Blind SSRF Probe', ui: 'blindprobe', quality: 'Good OAST-gated design; not measurable without callback', limited: true, limitations: 'No controlled OAST callback was supplied, so the live target received no SSRF payload.' }, async () => {
			await window.locator('#ssrf-url').fill(`${baseURL}/?url=value`);
			await window.locator('#ssrf-param').fill('url');
			await window.locator('#ssrf-oast-url').fill('');
			await window.locator('#ssrf-start-btn').click();
			const focused = await window.evaluate(() => document.activeElement?.id);
			if (focused !== 'ssrf-oast-url') throw new Error('The SSRF module did not enforce the controlled OAST requirement.');
			return 'OAST safety gate verified; no target request sent';
		});

		await run({ name: 'Redirect Hunter', ui: 'redirecthunter', quality: 'Good bounded redirect differential checks', limitations: 'Canary redirects are never followed and one harmless query parameter was tested.' }, async () => {
			const redirectURL = new URL(target);
			redirectURL.searchParams.set('next', 'FUZZ');
			const result = await ipcRequest(window, '/web/redirect', { project_id: projectId, url: redirectURL.toString(), parameter: 'next', max_requests: 4, concurrency: 2, timeout_ms: 5000, operation_timeout_ms: 20000 });
			return `${result.completed || 0} payload(s); ${result.total_findings || 0} candidate redirects`;
		});

		await run({ name: 'Prototype Pollution', ui: 'protopolluter', quality: 'Moderate response-differential probes', limited: true, limitations: 'Only a GET request to a guaranteed missing path was used. Meaningful JSON mutation requires a controlled API endpoint.' }, async () => {
			const result = await ipcRequest(window, '/web/proto', { project_id: projectId, url: missingURL, method: 'GET', location: 'json', body: '{}', parameter: 'wshawk_probe', max_requests: 2, concurrency: 1, timeout_ms: 5000, operation_timeout_ms: 20000 });
			return `${result.tests_run || 0} safe transport probes; target exploitability not concluded`;
		});

		await run({ name: 'Proxy Certificate Utilities', ui: 'hawkproxyca', quality: 'Strong local in-memory certificate boundary' }, async () => {
			const ca = await ipcRequest(window, '/proxy/ca/generate', { common_name: 'WSHawk Authorized Audit CA', valid_days: 2 });
			const host = await ipcRequest(window, '/proxy/ca/host', { hostname, valid_days: 1 });
			if (!ca.fingerprint || !host.fingerprint || ca.private_key_pem || host.private_key_pem) throw new Error('Certificate boundary or generation failed.');
			return 'CA and host certificate generated in worker memory; private keys not exposed';
		});

		await run({ name: 'Attack Chainer', ui: 'attackchainer', quality: 'Good sequential workflow and extraction engine', limitations: 'One read-only GET step was used on production.' }, async () => {
			const result = await ipcRequest(window, '/web/chain', { project_id: projectId, steps: [{ name: 'Read target entry page', method: 'GET', url: baseURL, headers: {}, body: '' }] });
			return `${result.workflow?.summary?.completed || 0} workflow steps completed`;
		});

		await run({ name: 'Cyber Node', ui: 'cybernode', quality: 'Limited local orchestration shell', limited: true, limitations: 'Its underlying web operations were validated individually; no multi-node distributed run was configured.' }, async () => 'UI and navigation loaded; distributed execution not configured');
		await run({ name: 'Team Mode', ui: 'teammode', quality: 'Limited local-only collaboration placeholder', limited: true, limitations: 'The bridge-free edition reports one local member and does not provide remote collaboration.' }, async () => {
			const result = await ipcRequest(window, '/team/stats', {});
			return `${result.status}; ${result.members} local member`;
		});

		await run({ name: 'Session Storage', ui: 'webworkspace', quality: 'Good project-backed local persistence' }, async () => {
			const name = `audit-${Date.now()}`;
			await ipcRequest(window, '/session/save', { project_id: projectId, name, session: { target: baseURL, scope: hostname } });
			const loaded = await ipcRequest(window, '/session/load', { project_id: projectId, name });
			if (loaded.session?.name !== name) throw new Error('Saved session could not be loaded.');
			return 'Project session saved and loaded successfully';
		});

		await run({ name: 'JSON Reporting', ui: 'evidence', quality: 'Good structured local report generation' }, async () => {
			const result = await window.evaluate((projectId) => window.wshawk.invoke('reports.generate', { project_id: projectId, format: 'json' }), projectId);
			if (!result.content || !result.extension) throw new Error('Report generation returned no content.');
			return `${result.extension.toUpperCase()} report generated in memory (${result.content.length} characters)`;
		});

		const missingViews = uiTargets.filter(name => !modules.some(item => item.ui_target === name));
		if (missingViews.length) throw new Error(`Audit harness did not cover UI targets: ${missingViews.join(', ')}`);

		const report = {
			schema: 'wshawk-authorized-web-audit/v1',
			target: baseURL,
			hostname,
			started_at: startedAt.toISOString(),
			finished_at: new Date().toISOString(),
			transport: health.transport,
			backend: health.backend,
			project_id: projectId,
			modules,
		};
		const stamp = new Date().toISOString().replace(/[:.]/g, '-');
		const baseName = `${hostname.replace(/[^a-z0-9.-]/gi, '_')}-${stamp}`;
		const jsonPath = path.join(outputDirectory, `${baseName}.json`);
		const markdownPath = path.join(outputDirectory, `${baseName}.md`);
		fs.writeFileSync(jsonPath, `${JSON.stringify(report, null, 2)}\n`, 'utf8');
		fs.writeFileSync(markdownPath, reportMarkdown(report), 'utf8');
		const failed = modules.filter(item => item.status === 'fail');
		process.stdout.write(`${JSON.stringify({ target: baseURL, total: modules.length, passed: modules.filter(item => item.status === 'pass').length, limited: modules.filter(item => item.status === 'limited').length, failed: failed.length, json: jsonPath, markdown: markdownPath })}\n`);
		if (failed.length) process.exitCode = 2;
	} finally {
		await application.close();
	}
})().catch(error => {
	console.error(error);
	process.exit(1);
});
