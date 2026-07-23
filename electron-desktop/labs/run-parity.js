'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const readline = require('readline');
const { spawn, spawnSync } = require('child_process');
const { WorkerClient } = require('../main/worker-client');

const root = path.resolve(__dirname, '..');
const groundTruth = require('./ground-truth.json');
const workerPath = path.join(root, 'bin', process.platform === 'win32' ? 'wshawk-worker.exe' : 'wshawk-worker');

function percentile(values, ratio) {
    const sorted = [...values].sort((left, right) => left - right);
    return sorted[Math.min(sorted.length - 1, Math.floor(sorted.length * ratio))] || 0;
}

function legacyEnvironment(repoRoot) {
	return {
		...process.env,
		PYTHONPATH: [repoRoot, process.env.PYTHONPATH || ''].filter(Boolean).join(path.delimiter),
		NO_PROXY: ['127.0.0.1', 'localhost', process.env.NO_PROXY || ''].filter(Boolean).join(','),
		no_proxy: ['127.0.0.1', 'localhost', process.env.no_proxy || ''].filter(Boolean).join(','),
	};
}

function resolveLegacyPython(repoRoot, environment) {
	const localRuntime = process.platform === 'win32'
		? path.join(repoRoot, 'venv', 'Scripts', 'python.exe')
		: path.join(repoRoot, 'venv', 'bin', 'python');
	const localDotRuntime = process.platform === 'win32'
		? path.join(repoRoot, '.venv', 'Scripts', 'python.exe')
		: path.join(repoRoot, '.venv', 'bin', 'python');
	const candidates = [
		process.env.WSHAWK_PYTHON,
		process.env.PYTHON,
		localRuntime,
		localDotRuntime,
		process.platform === 'win32' ? 'python' : 'python3',
		...(process.platform === 'win32' ? [] : ['python']),
	].filter((candidate, index, values) => candidate && values.indexOf(candidate) === index);
	const probe = 'from wshawk.attacks import WebSocketReplayService; from wshawk.web_pentest import WSHawkFuzzer';
	const diagnostics = [];
	for (const candidate of candidates) {
		if (path.isAbsolute(candidate) && !fs.existsSync(candidate)) continue;
		const result = spawnSync(candidate, ['-c', probe], {
			cwd: repoRoot,
			env: environment,
			encoding: 'utf8',
			windowsHide: true,
			timeout: 15_000,
		});
		if (!result.error && result.status === 0) return candidate;
		diagnostics.push(`${candidate}: ${result.error?.message || result.stderr?.trim() || `exit ${result.status}`}`);
	}
	throw new Error(
		'No usable Python runtime was found for classic parity. Install the WSHawk Python dependencies '
		+ 'or set WSHAWK_PYTHON to the intended interpreter. Probes: '
		+ diagnostics.join(' | '),
	);
}

function runLegacyParity(ready) {
	const repoRoot = path.resolve(root, '..');
	const environment = legacyEnvironment(repoRoot);
	const python = resolveLegacyPython(repoRoot, environment);
	return new Promise((resolve, reject) => {
		const child = spawn(python, [path.join(__dirname, 'legacy-parity.py'), ready.http, ready.ws], {
			cwd: repoRoot,
			windowsHide: true,
			env: environment,
			stdio: ['ignore', 'pipe', 'pipe'],
		});
		let output = '';
		let diagnostics = '';
		child.stdout.on('data', chunk => { output += chunk; });
		child.stderr.on('data', chunk => { diagnostics += chunk; });
		child.once('error', reject);
		child.once('exit', code => {
			const line = output.split(/\r?\n/).find(value => value.startsWith('WSHAWK_LEGACY_PARITY='));
			if (code !== 0 || !line) return reject(new Error(`legacy parity failed (${code}): ${diagnostics || output}`));
			try { resolve(JSON.parse(line.slice('WSHAWK_LEGACY_PARITY='.length))); }
			catch (error) { reject(new Error(`legacy parity returned invalid JSON: ${error.message}`)); }
		});
	});
}

async function startLab() {
    const child = spawn(process.execPath, [path.join(__dirname, 'server.js')], { stdio: ['ignore', 'pipe', 'inherit'], windowsHide: true });
    const lines = readline.createInterface({ input: child.stdout, crlfDelay: Infinity });
    const ready = await new Promise((resolve, reject) => {
        const timeout = setTimeout(() => reject(new Error('lab startup timed out')), 10_000);
        lines.once('line', line => { clearTimeout(timeout); resolve(JSON.parse(line)); });
        child.once('exit', code => reject(new Error(`lab exited during startup (${code})`)));
    });
    return { child, ready };
}

async function loginLab(origin, username, password) {
	const response = await fetch(`${origin}/login`, {
		method: 'POST',
		headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
		body: new URLSearchParams({ username, password }),
		redirect: 'manual',
	});
	const cookie = String(response.headers.get('set-cookie') || '').split(';', 1)[0];
	if (response.status !== 303 || !cookie.startsWith('wshawk_lab_session=')) {
		throw new Error(`lab login failed for ${username} (${response.status})`);
	}
	return cookie;
}

async function main() {
	const includeLegacy = process.argv.includes('--legacy');
    const lab = await startLab();
    const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wshawk-go-parity-'));
    const worker = new WorkerClient({ executable: workerPath, args: ['--data-dir', dataDir], cwd: dataDir, requestTimeoutMs: 30_000 });
    const events = [];
    worker.on('event', event => events.push(event));
    const timings = { http: [], websocket: [] };
    const checks = [];
    try {
        await worker.start();
        const saved = await worker.request('projects.save', { name: 'Industry parity lab', target_url: lab.ready.http });
        const projectId = saved.project.id;
		const labApplication = await worker.request('http.request', { project_id: projectId, url: `${lab.ready.http}/`, method: 'GET' });
		checks.push({ name: 'owned testing web application', passed: labApplication.response.status === 200 && labApplication.response.body.includes('WSHawk Owned Security Lab') && Object.keys(labApplication.response.headers).some(name => name.toLowerCase() === 'content-security-policy') });
        const scanStart = performance.now();
        const scan = await worker.request('scanner.run', {
            project_id: projectId, request: { url: `${lab.ready.http}/scan`, method: 'GET' },
            parameter: 'q', location: 'query', categories: ['sqli', 'xss'], authorization_confirmed: true,
        }, 60_000);
        timings.http.push(performance.now() - scanStart);
        const types = new Set(scan.findings.map(item => item.type));
        checks.push({ name: 'expected HTTP findings', passed: groundTruth.expected.http_findings.every(item => types.has(item)), observed: [...types] });
		const activeTypes = new Set();
		for (const spec of [
			{ path: '/command', category: 'command_injection', parameter: 'q', location: 'query', request: { method: 'GET' } },
			{ path: '/traversal', category: 'path_traversal', parameter: 'q', location: 'query', request: { method: 'GET' } },
			{ path: '/nosql', category: 'nosql_injection', parameter: 'user', location: 'json', request: { method: 'POST', body: '{"user":"guest"}', headers: { 'Content-Type': 'application/json' } } },
			{ path: '/prototype', category: 'prototype_pollution', parameter: 'unused', location: 'json', request: { method: 'POST', body: '{"user":"guest"}', headers: { 'Content-Type': 'application/json' } } },
			{ path: '/xxe', category: 'xxe', parameter: 'document', location: 'xml', request: { method: 'POST', body: '<r>baseline</r>', headers: { 'Content-Type': 'application/xml' } } },
			{ path: '/redirect', category: 'redirect', parameter: 'next', location: 'query', request: { method: 'GET' } },
		]) {
			const result = await worker.request('scanner.run', {
				project_id: projectId,
				request: { project_id: projectId, url: `${lab.ready.http}${spec.path}`, ...spec.request },
				parameter: spec.parameter, location: spec.location, categories: [spec.category], authorization_confirmed: true,
			}, 60_000);
			for (const finding of result.findings) activeTypes.add(finding.type);
		}
		checks.push({ name: 'active attack-family labs', passed: groundTruth.expected.active_attack_findings.every(item => activeTypes.has(item)), observed: [...activeTypes] });
		await worker.request('scanner.run', {
			project_id: projectId,
			request: { project_id: projectId, url: `${lab.ready.http}/ssrf`, method: 'GET' },
			parameter: 'url', location: 'query', categories: ['ssrf'], oast_url: `${lab.ready.http}/oast-callback`, authorization_confirmed: true,
		}, 60_000);
		const oast = await worker.request('oast.poll', { project_id: projectId, url: `${lab.ready.http}/oast-status` });
		checks.push({ name: 'OAST callback and polling', passed: Number(oast.interactions?.interactions || 0) > 0, observed: oast.interactions });
		const safeScan = await worker.request('scanner.run', {
			project_id: projectId, request: { url: `${lab.ready.http}/safe`, method: 'GET' },
			parameter: 'q', location: 'query', categories: ['sqli', 'xss'], authorization_confirmed: true,
		}, 60_000);
		checks.push({ name: 'safe endpoint false-positive control', passed: safeScan.findings.length === groundTruth.expected.safe_endpoint_false_positives, observed: safeScan.findings.length });
        const analysis = await worker.request('web.analyze', { request: { project_id: projectId, url: `${lab.ready.http}/headers`, method: 'GET' } });
        checks.push({ name: 'header analysis', passed: analysis.findings.length >= groundTruth.expected.header_findings_min, observed: analysis.findings.length });
		const mutations = await worker.request('scanner.mutate', { payload: "' OR 1=1", strategy: 'auto', count: 8 });
		checks.push({ name: 'bounded smart payload mutation', passed: mutations.mutations.length === 8 && new Set(mutations.mutations).size === 8, observed: mutations.mutations.length });
		const binaryAnalysis = await worker.request('scanner.binary_analyze', { payload_base64: 'iVBORw0KGgo=' });
		checks.push({ name: 'binary protocol analysis', passed: binaryAnalysis.magic === 'png' && binaryAnalysis.size === 8, observed: binaryAnalysis });
		const authCheck = await worker.request('scanner.auth_test', { project_id: projectId, url: lab.ready.ws.replace('/ws/echo', '/ws/auth'), authenticated_headers: { 'X-Lab-Token': 'authorized-lab-token' }, authorization_confirmed: true });
		checks.push({ name: 'WebSocket authentication enforcement', passed: authCheck.authentication_enforced === true, observed: authCheck });
		const authz = await worker.request('scanner.authz_diff', {
			left: { project_id: projectId, url: `${lab.ready.http}/auth`, method: 'GET', headers: { 'X-Lab-Role': 'guest' } },
			right: { project_id: projectId, url: `${lab.ready.http}/auth`, method: 'GET', headers: { 'X-Lab-Role': 'admin' } },
			authorization_confirmed: true,
		});
		checks.push({ name: 'HTTP authorization difference', passed: authz.authorization_difference === 'high', observed: authz.authorization_difference });
		const userACookie = await loginLab(lab.ready.http, 'user_a', 'user-a-lab-pass');
		const userBCookie = await loginLab(lab.ready.http, 'user_b', 'user-b-lab-pass');
		const adminCookie = await loginLab(lab.ready.http, 'admin', 'admin-lab-pass');
		const recordedSession = await worker.request('http.request', {
			project_id: projectId,
			url: `${lab.ready.http}/auth/me`,
			method: 'GET',
			headers: { Cookie: userACookie },
		});
		checks.push({ name: 'recorded browser session replay', passed: recordedSession.response.status === 200 && JSON.parse(recordedSession.response.body).username === 'user_a' });
		const horizontalControl = await worker.request('scanner.authz_diff', {
			left: { project_id: projectId, url: `${lab.ready.http}/auth/resource/resource-a`, method: 'GET', headers: { Cookie: userACookie } },
			right: { project_id: projectId, url: `${lab.ready.http}/auth/resource/resource-a`, method: 'GET', headers: { Cookie: userBCookie } },
			authorization_confirmed: true,
		});
		checks.push({ name: 'recorded-identity horizontal AuthZ control', passed: horizontalControl.left.status === 200 && horizontalControl.right.status === 403 && horizontalControl.authorization_difference === 'high', observed: horizontalControl.authorization_difference });
		const horizontalIDOR = await worker.request('scanner.authz_diff', {
			left: { project_id: projectId, url: `${lab.ready.http}/auth/resource-insecure/resource-a`, method: 'GET', headers: { Cookie: userACookie } },
			right: { project_id: projectId, url: `${lab.ready.http}/auth/resource-insecure/resource-a`, method: 'GET', headers: { Cookie: userBCookie } },
			authorization_confirmed: true,
		});
		checks.push({ name: 'recorded-identity intentional IDOR ground truth', passed: horizontalIDOR.left.status === 200 && horizontalIDOR.right.status === 200 && horizontalIDOR.authorization_difference === 'none' && horizontalIDOR.left.body.includes('intentional-horizontal-idor'), observed: horizontalIDOR.authorization_difference });
		const verticalControl = await worker.request('scanner.authz_diff', {
			left: { project_id: projectId, url: `${lab.ready.http}/auth/admin`, method: 'GET', headers: { Cookie: userACookie } },
			right: { project_id: projectId, url: `${lab.ready.http}/auth/admin`, method: 'GET', headers: { Cookie: adminCookie } },
			authorization_confirmed: true,
		});
		checks.push({ name: 'recorded-identity vertical AuthZ control', passed: verticalControl.left.status === 403 && verticalControl.right.status === 200 && verticalControl.authorization_difference === 'high', observed: verticalControl.authorization_difference });
		const httpRace = await worker.request('scanner.race', { request: { project_id: projectId, url: `${lab.ready.http}/race`, method: 'POST' }, count: 10, authorization_confirmed: true });
		checks.push({ name: 'HTTP race outcome analysis', passed: httpRace.responses.length === 10 && httpRace.possible_race === true, observed: httpRace.distinct_outcomes });
        const connected = await worker.request('ws.connect', { project_id: projectId, url: lab.ready.ws });
        const wsStart = performance.now();
        await worker.request('ws.send', { connection_id: connected.connection_id, message_type: 'text', payload: 'parity-echo' });
        const textDeadline = Date.now() + 5_000;
        while (Date.now() < textDeadline && !events.some(event => event.event === 'ws.frame' && event.data.direction === 'inbound' && event.data.payload === 'parity-echo')) await new Promise(resolve => setTimeout(resolve, 20));
        timings.websocket.push(performance.now() - wsStart);
        checks.push({ name: 'WebSocket text echo', passed: events.some(event => event.event === 'ws.frame' && event.data.payload === 'parity-echo') });
        await worker.request('ws.send', { connection_id: connected.connection_id, message_type: 'binary', payload_base64: 'AAEC/w==' });
        const binaryDeadline = Date.now() + 5_000;
        while (Date.now() < binaryDeadline && !events.some(event => event.event === 'ws.frame' && event.data.direction === 'inbound' && event.data.payload_base64 === 'AAEC/w==')) await new Promise(resolve => setTimeout(resolve, 20));
        checks.push({ name: 'WebSocket binary echo', passed: events.some(event => event.event === 'ws.frame' && event.data.payload_base64 === 'AAEC/w==') });
		const wsRace = await worker.request('ws.race', { connection_id: connected.connection_id, message_type: 'text', payload: 'race-echo', count: 5, authorization_confirmed: true });
		checks.push({ name: 'WebSocket race execution', passed: wsRace.sent === 5 && wsRace.received === 5, observed: wsRace });
		const subscription = await worker.request('scanner.subscription_abuse', { project_id: projectId, connection_id: connected.connection_id, payload: '{"type":"subscribe","channel":"admin"}', authorization_confirmed: true });
		checks.push({ name: 'subscription abuse lab signal', passed: subscription.possible_subscription_abuse === true });
        await worker.request('ws.disconnect', { connection_id: connected.connection_id });
		const protocolMap = await worker.request('protocol.map', { project_id: projectId });
		checks.push({ name: 'protocol map and timeline inference', passed: protocolMap.protocol_map?.summary?.frame_count >= 4, observed: protocolMap.protocol_map?.summary });
        for (const format of groundTruth.expected.report_formats) {
            const report = await worker.request('reports.generate', { project_id: projectId, format });
            checks.push({ name: `${format} report`, passed: report.bytes > 0 && report.sha256.length === 64 });
        }
        const bundle = await worker.request('evidence.bundle', { project_id: projectId });
        const verified = await worker.request('evidence.verify', { content_base64: bundle.content_base64 });
        checks.push({ name: 'evidence integrity', passed: verified.valid === true });
        const cancellationID = `cancel_${Date.now()}`;
        const slowScan = worker.request('scanner.run', {
            operation_id: cancellationID, project_id: projectId,
            request: { url: `${lab.ready.http}/slow`, method: 'GET' }, parameter: 'q', location: 'query',
            categories: ['sqli', 'xss'], authorization_confirmed: true,
        }, 60_000).then(() => false, () => true);
        await new Promise(resolve => setTimeout(resolve, 100));
        const cancellation = await worker.request('operation.cancel', { operation_id: cancellationID });
        checks.push({ name: 'in-flight cancellation', passed: cancellation.cancelled === true && await slowScan });
        let health = await worker.request('system.health');
        checks.push({ name: 'bounded memory telemetry', passed: health.memory?.heapInUseBytes > 0 && health.memory?.goroutines > 0, observed: health.memory });
        const crashObserved = new Promise(resolve => worker.once('status', status => resolve(status.state === 'crashed')));
        worker.child.kill();
        const didCrash = await crashObserved;
        await worker.start();
        health = await worker.request('system.health');
        checks.push({ name: 'worker crash restart', passed: didCrash && health.status === 'ready' && health.noNetworkBridge === true });
		let legacy = null;
		if (includeLegacy) {
			legacy = await runLegacyParity(lab.ready);
			checks.push({ name: 'legacy Python uses identical HTTP and WebSocket lab', passed: legacy.passed === groundTruth.expected.legacy_python_same_lab, observed: legacy });
			checks.push({ name: 'old/new finding and false-positive parity', passed: groundTruth.expected.http_findings.every(item => legacy.http_findings.includes(item) && types.has(item)) && legacy.false_positives === safeScan.findings.length });
		}
        const result = {
            lab: groundTruth.lab, timestamp: new Date().toISOString(), passed: checks.every(check => check.passed),
            checks, performance: { http_p95_ms: percentile(timings.http, 0.95), websocket_p95_ms: percentile(timings.websocket, 0.95) },
			events: events.length, worker: health, legacy,
        };
        process.stdout.write(`${JSON.stringify(result, null, 2)}\n`);
        if (!result.passed) process.exitCode = 1;
    } finally {
        await worker.stop().catch(() => {});
        lab.child.kill();
    }
}

main().catch(error => { console.error(error); process.exitCode = 1; });
