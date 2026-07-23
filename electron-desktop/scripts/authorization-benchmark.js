'use strict';

const fs = require('fs');
const os = require('os');
const path = require('path');
const readline = require('readline');
const { spawn } = require('child_process');
const { _electron: electron } = require('playwright-core');
const { firstWindowWithDiagnostics, isolatedElectronEnvironment } = require('./electron-harness');

const root = path.resolve(__dirname, '..');

async function startLab() {
	const child = spawn(process.execPath, [path.join(root, 'labs', 'server.js')], { stdio: ['ignore', 'pipe', 'inherit'], windowsHide: true });
	const lines = readline.createInterface({ input: child.stdout, crlfDelay: Infinity });
	const ready = await new Promise((resolve, reject) => {
		const timeout = setTimeout(() => reject(new Error('Authorization lab startup timed out')), 10_000);
		lines.once('line', line => { clearTimeout(timeout); resolve(JSON.parse(line)); });
		child.once('exit', code => reject(new Error(`Authorization lab exited (${code})`)));
	});
	return { child, ready };
}

function escapeHTML(value) { return String(value ?? '').replace(/[&<>"']/g, character => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[character]); }

function markdown(report) {
	const rows = report.scenarios.map(item => `| ${item.transport} | ${item.name} | ${item.expected_vulnerable ? 'vulnerable' : 'secure'} | ${item.observed_finding ? 'finding' : 'no finding'} | ${item.passed ? 'PASS' : 'FAIL'} | ${item.verdict} | ${item.duration_ms} | ${item.request_count} |`).join('\n');
	return `# WSHawk Authorization Benchmark\n\n- Generated: ${report.generated_at}\n- Lab: loopback-owned WSHawk authorization lab\n- Version: ${report.wshawk_version}\n- Scenarios: ${report.summary.scenario_count}\n- Passed: ${report.summary.passed}\n- Failed: ${report.summary.failed}\n- True positives: ${report.summary.true_positives}\n- True negatives: ${report.summary.true_negatives}\n- False positives: ${report.summary.false_positives}\n- False negatives: ${report.summary.false_negatives}\n- Precision: ${report.summary.precision}\n- Recall: ${report.summary.recall}\n- Mean latency: ${report.summary.mean_latency_ms} ms\n- P95 latency: ${report.summary.p95_latency_ms} ms\n- Network requests: ${report.summary.request_count}\n- Worker heap delta: ${report.summary.worker_heap_delta_bytes} bytes\n\n| Transport | Scenario | Expected | Observed | Result | Verdict | ms | Requests |\n|---|---|---|---|---|---|---:|---:|\n${rows}\n\n## Safety controls\n\n- State-changing cases use dry-run or explicit bounded execution.\n- Ownership-transfer and note-write cases collect before/after evidence and verify rollback.\n- Findings use redacted or hash-only evidence in this benchmark.\n- The target binds only to 127.0.0.1 and uses disposable accounts.\n`;
}

function html(report) {
	const rows = report.scenarios.map(item => `<tr><td>${escapeHTML(item.transport)}</td><td>${escapeHTML(item.name)}</td><td>${item.expected_vulnerable ? 'vulnerable' : 'secure'}</td><td>${item.observed_finding ? 'finding' : 'no finding'}</td><td class="${item.passed ? 'pass' : 'fail'}">${item.passed ? 'PASS' : 'FAIL'}</td><td>${escapeHTML(item.verdict)}</td><td>${item.duration_ms}</td><td>${item.request_count}</td></tr>`).join('');
	return `<!doctype html><html><head><meta charset="utf-8"><title>WSHawk Authorization Benchmark</title><style>body{font-family:system-ui;background:#090d14;color:#e6edf3;padding:28px}table{border-collapse:collapse;width:100%}th,td{border:1px solid #30363d;padding:7px;text-align:left}.pass{color:#2ee59d}.fail{color:#ff6174}code{white-space:pre-wrap}</style></head><body><h1>WSHawk Authorization Benchmark</h1><pre>${escapeHTML(JSON.stringify(report.summary, null, 2))}</pre><table><thead><tr><th>Transport</th><th>Scenario</th><th>Expected</th><th>Observed</th><th>Result</th><th>Verdict</th><th>ms</th><th>Requests</th></tr></thead><tbody>${rows}</tbody></table></body></html>`;
}

function findingsMarkdown(findings, generatedAt) {
	const sections = findings.map((item, index) => {
		let evidence = {}; try { evidence = JSON.parse(item.value || '{}'); } catch (_) {}
		const metadata = item.metadata || {};
		return `## ${index + 1}. ${metadata.title || item.name || 'Finding'}\n\n- ID: ${item.id}\n- Type: ${metadata.type || evidence.type || 'unknown'}\n- Severity: ${metadata.severity || 'INFO'}\n- Confidence: ${metadata.confidence || 'unknown'}\n- State: ${metadata.lifecycle_status || 'open'}\n- Endpoint: ${metadata.url || evidence.endpoint || ''}\n- Policy: ${metadata.policy_mode || evidence.policy?.mode || ''}\n- Attacker: ${metadata.attacker_alias || evidence.attacker?.alias || ''}\n- Owner/control: ${metadata.owner_alias || evidence.owner_control?.alias || ''}\n- Confirmed objects: ${metadata.confirmation_count || evidence.policy?.confirmation_count || 0}\n- Target fingerprint: ${metadata.target_fingerprint || evidence.target_fingerprint || ''}\n- Tested: ${metadata.last_tested || evidence.tested_at || ''}\n- Retest: ${metadata.last_retest_classification || 'not retested'}\n\n${metadata.description || evidence.policy?.detail || ''}\n\nResponse hashes: ${(metadata.response_hashes || []).join(', ')}\n\nReproduction: ${evidence.curl_reproduction ? `\`${evidence.curl_reproduction.replaceAll('`', '')}\`` : evidence.replay_instructions || 'Use the saved replay recipe.'}\n`;
	}).join('\n');
	return `# WSHawk Authorization Findings Report\n\nGenerated ${generatedAt} from the loopback-owned authorization lab. Stored bodies use each finding's configured redacted or hash-only evidence policy.\n\n- Findings: ${findings.length}\n\n${sections}`;
}

(async () => {
	const lab = await startLab();
	const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wshawk-authz-benchmark-'));
	const application = await electron.launch({ args: [root], env: isolatedElectronEnvironment(dataDir) });
	try {
		const window = await firstWindowWithDiagnostics(application); await window.waitForLoadState('domcontentloaded'); await window.waitForTimeout(150);
		const benchmark = await window.evaluate(async ({ labURL, labWS }) => {
			const request = async (url, init = {}) => { const response = await window.ipcRequest(url, init); const data = await response.json(); if (!response.ok) throw new Error(data.detail || `${url} failed (${response.status})`); return data; };
			const project = (await request('/platform/projects', { method: 'POST', body: JSON.stringify({ name: 'Authorization benchmark', url: labURL, metadata: { owned_lab: true } }) })).project;
			const login = async (alias, username, password) => {
				const response = await request('/web/request', { method: 'POST', body: JSON.stringify({ project_id: project.id, url: `${labURL}/login`, method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ username, password }).toString(), follow_redirects: false }) });
				const cookie = String(response.headers || '').match(/^Set-Cookie:\s*([^;\r\n]+)/im)?.[1]; if (!cookie) throw new Error(`No session cookie for ${alias}`);
				return (await request(`/platform/projects/${project.id}/identities`, { method: 'POST', body: JSON.stringify({ alias, headers: { Cookie: cookie }, storage: { auth_user: username, auth_role: username === 'admin' ? 'admin' : 'user' } }) })).identity;
			};
			const admin = await login('admin-admin', 'admin', 'admin-lab-pass'); const userA = await login('user-a-user', 'user_a', 'user-a-lab-pass'); const userB = await login('user-b-user', 'user_b', 'user-b-lab-pass');
			const healthBefore = await window.wshawk.invoke('system.health'); const scenarios = [];
			const identities = [userA.id, userB.id, admin.id];
			const runHTTP = async (name, expected, options) => {
				const started = performance.now();
				const data = await request(`/platform/projects/${project.id}/attacks/http-authz-matrix`, { method: 'POST', body: JSON.stringify({ identity_ids: identities, primary_identity_id: options.primary_id || userA.id, owner_identity_id: options.owner_id || userB.id, policy_mode: options.policy || 'primary_denied_owner_allowed', object_location: options.location || 'none', object_field: options.field || '', object_values: options.values || ['current-object'], minimum_confirmations: options.minimum || Math.min(2, (options.values || []).length || 1), include_anonymous: options.include_anonymous !== false, evidence_mode: options.evidence_mode || 'redacted', safe_write_confirmed: options.safe_write_confirmed === true, write_mode: options.write_mode, before_template: options.before_template, after_template: options.after_template, cleanup_template: options.cleanup_template, template: options.template }) });
				const matrix = data.matrix || {}; const observed = matrix.evaluation?.finding === true;
				scenarios.push({ transport: options.transport || 'HTTP', name, expected_vulnerable: expected, observed_finding: observed, passed: observed === expected, verdict: matrix.evaluation?.verdict || 'none', duration_ms: Math.round(performance.now() - started), request_count: matrix.summary?.planned_request_count || matrix.summary?.request_count || 0, confirmation_count: matrix.evaluation?.confirmation_count || 0, finding_id: matrix.summary?.finding_id || '', rollback_verified: (matrix.results || []).filter(item => item.response?.status >= 200 && item.write_evidence?.transmitted).every(item => item.write_evidence?.cleanup_succeeded !== false && item.write_evidence?.rollback_verified !== false) });
			};
			const runWS = async (name, expected, path) => {
				const started = performance.now(); const matrix = (await request(`/platform/projects/${project.id}/attacks/ws-authz-matrix`, { method: 'POST', body: JSON.stringify({ url: labWS.replace('/ws/echo', path), payload: { action: 'subscribe', room: 'user_b' }, identity_ids: identities, primary_identity_id: userA.id, owner_identity_id: userB.id, policy_mode: 'primary_denied_owner_allowed', object_field: path.startsWith('/ws/room-') ? 'url.room' : 'room', object_values: ['user_b', 'tenant-b'], minimum_confirmations: 2, include_anonymous: true, evidence_mode: 'redacted', timeout: 3 }) })).matrix;
				const observed = matrix.evaluation?.finding === true; scenarios.push({ transport: 'WebSocket', name, expected_vulnerable: expected, observed_finding: observed, passed: observed === expected, verdict: matrix.evaluation?.verdict || 'none', duration_ms: Math.round(performance.now() - started), request_count: matrix.summary?.request_count || 0, confirmation_count: matrix.evaluation?.confirmation_count || 0, finding_id: matrix.summary?.finding_id || '' });
			};
			const pathPair = async (baseName, securePath, insecurePath, values, field, policy = 'primary_denied_owner_allowed') => {
				await runHTTP(`${baseName} secure control`, false, { policy, location: 'path', field, values, template: { method: 'GET', url: `${labURL}${securePath}`, headers: {} } });
				await runHTTP(`${baseName} vulnerable`, true, { policy, location: 'path', field, values, template: { method: 'GET', url: `${labURL}${insecurePath}`, headers: {} } });
			};
			await pathPair('Horizontal IDOR/BOLA', '/auth/resource/resource-b', '/auth/resource-insecure/resource-b', ['resource-b', 'resource-b-2'], 'resource-b');
			await pathPair('UUID object authorization', '/auth/uuid/22222222-2222-4222-8222-222222222222', '/auth/uuid-insecure/22222222-2222-4222-8222-222222222222', ['22222222-2222-4222-8222-222222222222', '33333333-3333-4333-8333-333333333333'], 'path.3');
			await pathPair('Numeric neighboring object authorization', '/auth/numeric/2001', '/auth/numeric-insecure/2001', ['2001', '2002'], 'path.3');
			await pathPair('Nested account/order authorization', '/auth/accounts/account-b/orders/order-b', '/auth/accounts-insecure/account-b/orders/order-b', ['order-b', 'order-b-2'], 'path.5');
			await pathPair('Tenant isolation', '/auth/tenant/resource-b', '/auth/tenant-insecure/resource-b', ['resource-b', 'resource-b-2'], 'resource-b', 'tenant_isolation');
			await pathPair('Missing authentication', '/auth/missing-auth/resource-b', '/auth/missing-auth-insecure/resource-b', ['resource-b', 'resource-b-2'], 'resource-b', 'anonymous_denied_authenticated_allowed');
			await runHTTP('Query-parameter IDOR secure control', false, { location: 'query', field: 'account_id', values: ['resource-b', 'resource-b-2'], template: { method: 'GET', url: `${labURL}/auth/resource-query?account_id=resource-b`, headers: {} } });
			await runHTTP('Query-parameter IDOR vulnerable', true, { location: 'query', field: 'account_id', values: ['resource-b', 'resource-b-2'], template: { method: 'GET', url: `${labURL}/auth/resource-query-insecure?account_id=resource-b`, headers: {} } });
			await runHTTP('JSON-body IDOR secure control', false, { location: 'json', field: 'document_id', values: ['resource-b', 'resource-b-2'], safe_write_confirmed: true, write_mode: 'execute', template: { method: 'POST', url: `${labURL}/auth/resource-json`, headers: { 'Content-Type': 'application/json' }, body: '{"document_id":"resource-b"}' } });
			await runHTTP('JSON-body IDOR vulnerable', true, { location: 'json', field: 'document_id', values: ['resource-b', 'resource-b-2'], safe_write_confirmed: true, write_mode: 'execute', template: { method: 'POST', url: `${labURL}/auth/resource-json-insecure`, headers: { 'Content-Type': 'application/json' }, body: '{"document_id":"resource-b"}' } });
			await runHTTP('Vertical privilege escalation secure control', false, { policy: 'lower_privilege_denied_privileged_allowed', owner_id: admin.id, values: ['admin'], minimum: 1, template: { method: 'GET', url: `${labURL}/auth/admin`, headers: {} } });
			await runHTTP('Vertical privilege escalation vulnerable', true, { policy: 'lower_privilege_denied_privileged_allowed', owner_id: admin.id, values: ['admin'], minimum: 1, template: { method: 'GET', url: `${labURL}/auth/admin-insecure`, headers: {} } });
			await runHTTP('Admin-only secure control', false, { policy: 'admin_only_operation', owner_id: admin.id, values: ['admin-operation'], minimum: 1, template: { method: 'GET', url: `${labURL}/auth/admin-operation`, headers: {} } });
			await runHTTP('Admin-only vulnerable', true, { policy: 'admin_only_operation', owner_id: admin.id, values: ['admin-operation'], minimum: 1, template: { method: 'GET', url: `${labURL}/auth/admin-operation-insecure`, headers: {} } });
			await runHTTP('BFLA secure control', false, { policy: 'function_level_authorization', owner_id: admin.id, values: ['admin-action'], minimum: 1, template: { method: 'GET', url: `${labURL}/auth/admin-action`, headers: {} } });
			await runHTTP('BFLA vulnerable', true, { policy: 'function_level_authorization', owner_id: admin.id, values: ['admin-action'], minimum: 1, template: { method: 'GET', url: `${labURL}/auth/admin-action-insecure`, headers: {} } });
			const graphQL = insecure => ({ method: 'POST', url: `${labURL}/graphql`, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ query: `query($id: ID!){ ${insecure ? 'resourceInsecure' : 'resource'}(id:$id){ id owner secret } }`, variables: { id: 'resource-b' } }) });
			await runHTTP('GraphQL secure control', false, { transport: 'GraphQL', location: 'graphql', field: 'id', values: ['resource-b', 'resource-b-2'], safe_write_confirmed: true, write_mode: 'execute', template: graphQL(false) });
			await runHTTP('GraphQL vulnerable', true, { transport: 'GraphQL', location: 'graphql', field: 'id', values: ['resource-b', 'resource-b-2'], safe_write_confirmed: true, write_mode: 'execute', template: graphQL(true) });
			const writeControls = { location: 'path', field: 'resource-b', values: ['resource-b', 'resource-b-2'], safe_write_confirmed: true, write_mode: 'execute_with_rollback', include_anonymous: false, before_template: { method: 'GET', url: `${labURL}/auth/write-state/resource-b`, headers: {} }, after_template: { method: 'GET', url: `${labURL}/auth/write-state/resource-b`, headers: {} }, cleanup_template: { method: 'POST', url: `${labURL}/auth/rollback`, headers: { 'Content-Type': 'application/json' }, body: '{"rollback_token":"{{rollback_token}}"}', mutate_object: false } };
			await runHTTP('State-changing IDOR secure control', false, { ...writeControls, template: { method: 'PATCH', url: `${labURL}/auth/resource/resource-b/note`, headers: { 'Content-Type': 'application/json' }, body: '{"note":"benchmark"}' } });
			await runHTTP('State-changing IDOR vulnerable', true, { ...writeControls, template: { method: 'PATCH', url: `${labURL}/auth/resource-insecure/resource-b/note`, headers: { 'Content-Type': 'application/json' }, body: '{"note":"benchmark"}' } });
			await runHTTP('Ownership transfer secure control', false, { ...writeControls, policy: 'ownership_transfer', template: { method: 'POST', url: `${labURL}/auth/ownership-transfer/resource-b`, headers: { 'Content-Type': 'application/json' }, body: '{"new_owner":"user_a"}' } });
			await runHTTP('Ownership transfer vulnerable', true, { ...writeControls, policy: 'ownership_transfer', template: { method: 'POST', url: `${labURL}/auth/ownership-transfer-insecure/resource-b`, headers: { 'Content-Type': 'application/json' }, body: '{"new_owner":"user_a"}' } });
			await runHTTP('Mass assignment secure control', false, { policy: 'function_level_authorization', owner_id: admin.id, values: ['resource-b'], minimum: 1, safe_write_confirmed: true, write_mode: 'execute', include_anonymous: false, template: { method: 'PATCH', url: `${labURL}/auth/mass-assignment/resource-b`, headers: { 'Content-Type': 'application/json' }, body: '{"owner":"user_a","role":"admin"}' } });
			await runHTTP('Mass assignment vulnerable', true, { policy: 'function_level_authorization', owner_id: admin.id, values: ['resource-b'], minimum: 1, safe_write_confirmed: true, write_mode: 'execute', include_anonymous: false, template: { method: 'PATCH', url: `${labURL}/auth/mass-assignment-insecure/resource-b`, headers: { 'Content-Type': 'application/json' }, body: '{"owner":"user_a","role":"admin"}' } });
			await runWS('WebSocket room secure control', false, '/ws/room-secure?room=user_b'); await runWS('WebSocket room vulnerable', true, '/ws/room-insecure?room=user_b'); await runWS('WebSocket subscription secure control', false, '/ws/subscription-secure'); await runWS('WebSocket subscription vulnerable', true, '/ws/subscription-insecure');
			const stale = (await request(`/platform/projects/${project.id}/identities`, { method: 'POST', body: JSON.stringify({ alias: 'expired-user', headers: { Cookie: 'wshawk_lab_session=expired' }, storage: { auth_user: 'expired' } }) })).identity;
			const seedRetest = async (name, recipe) => {
				const evidence = { version: 3, type: 'idor-bola', title: name, recipe };
				const seeded = await request(`/platform/projects/${project.id}/findings`, { method: 'POST', body: JSON.stringify({ name, value: JSON.stringify(evidence), type: 'idor-bola', title: name, category: 'authorization', severity: 'HIGH', confidence: 'high', lifecycle_status: 'confirmed' }) });
				const retest = await request(`/platform/projects/${project.id}/findings/${seeded.finding.id}/retest`, { method: 'POST', body: '{}' });
				return retest.matrix?.summary?.retest_classification;
			};
			const baseRecipe = { version: 1, variables: {}, identity_ids: identities, primary_identity_id: userA.id, owner_identity_id: userB.id, policy_mode: 'primary_denied_owner_allowed', object_values: ['resource-b'], object_location: 'path', object_field: 'resource-b', minimum_confirmations: 1, include_anonymous: false, evidence_mode: 'hash_only', safe_write_confirmed: false };
			const retestClassifications = {
				fixed: await seedRetest('Retest fixed control', { ...baseRecipe, template: { method: 'GET', url: `${labURL}/auth/resource/resource-b`, headers: {} } }),
				authentication_expired: await seedRetest('Retest expired authentication', { ...baseRecipe, identity_ids: [stale.id, userB.id], primary_identity_id: stale.id, template: { method: 'GET', url: `${labURL}/auth/resource-insecure/resource-b`, headers: {} } }),
				endpoint_changed: await seedRetest('Retest changed endpoint', { ...baseRecipe, template: { method: 'GET', url: 'http://127.0.0.1:1/auth/resource/resource-b', headers: {} } }),
				inconclusive: await seedRetest('Retest invalid control', { ...baseRecipe, identity_ids: [admin.id, userA.id], primary_identity_id: admin.id, owner_identity_id: userA.id, template: { method: 'GET', url: `${labURL}/auth/resource/resource-b`, headers: {} } }),
			};
			const firstFindingId = scenarios.find(item => item.name === 'Horizontal IDOR/BOLA vulnerable')?.finding_id;
			const duplicateMatrix = await request(`/platform/projects/${project.id}/attacks/http-authz-matrix`, { method: 'POST', body: JSON.stringify({ identity_ids: identities, primary_identity_id: userA.id, owner_identity_id: userB.id, policy_mode: 'primary_denied_owner_allowed', object_location: 'path', object_field: 'resource-b', object_values: ['resource-b', 'resource-b-2'], minimum_confirmations: 2, include_anonymous: true, evidence_mode: 'redacted', template: { method: 'GET', url: `${labURL}/auth/resource-insecure/resource-b`, headers: {} } }) });
			const edited = await request(`/platform/projects/${project.id}/findings/${firstFindingId}`, { method: 'PATCH', body: JSON.stringify({ lifecycle_status: 'confirmed', severity: 'CRITICAL', confidence: 'confirmed' }) });
			const retested = await request(`/platform/projects/${project.id}/findings/${firstFindingId}/retest`, { method: 'POST', body: '{}' });
			const selectedIds = scenarios.filter(item => item.finding_id).slice(0, 3).map(item => item.finding_id);
			const exports = {};
			for (const format of ['json', 'markdown', 'csv']) exports[format] = await request(`/platform/projects/${project.id}/findings/export-selected`, { method: 'POST', body: JSON.stringify({ finding_ids: selectedIds, format }) });
			const management = { duplicate_same_id: duplicateMatrix.matrix?.summary?.finding_id === firstFindingId, duplicate_marked: duplicateMatrix.matrix?.finding?.deduplicated === true, edited: edited.finding?.metadata?.severity === 'CRITICAL' && edited.finding?.metadata?.confidence === 'confirmed' && edited.finding?.metadata?.lifecycle_status === 'confirmed', retest_classification: retested.matrix?.summary?.retest_classification, retest_classifications: retestClassifications, selected_exports: Object.fromEntries(Object.entries(exports).map(([format, value]) => [format, { count: value.count, nonempty: Boolean(value.content) }])) };
			const findings = await request(`/platform/projects/${project.id}/findings?limit=5000`); const projectHTML = await request(`/platform/projects/${project.id}/exports/html`); const healthAfter = await window.wshawk.invoke('system.health');
			return { project, scenarios, findings: findings.findings || [], project_html: projectHTML, management, health_before: healthBefore, health_after: healthAfter };
		}, { labURL: lab.ready.http, labWS: lab.ready.ws });

		const scenarios = benchmark.scenarios; const latencies = scenarios.map(item => item.duration_ms).sort((a, b) => a - b);
		const tp = scenarios.filter(item => item.expected_vulnerable && item.observed_finding).length; const tn = scenarios.filter(item => !item.expected_vulnerable && !item.observed_finding).length; const fp = scenarios.filter(item => !item.expected_vulnerable && item.observed_finding).length; const fn = scenarios.filter(item => item.expected_vulnerable && !item.observed_finding).length;
		const managementPassed = benchmark.management.duplicate_same_id && benchmark.management.duplicate_marked && benchmark.management.edited && benchmark.management.retest_classification === 'still_vulnerable' && ['fixed', 'authentication_expired', 'endpoint_changed', 'inconclusive'].every(name => benchmark.management.retest_classifications[name] === name) && Object.values(benchmark.management.selected_exports).every(value => value.count === 3 && value.nonempty);
		const report = { format: 'wshawk-authorization-benchmark', version: 1, generated_at: new Date().toISOString(), wshawk_version: benchmark.health_after.version, target: { type: 'owned-loopback-lab', origin: lab.ready.http, websocket_origin: lab.ready.ws }, summary: { scenario_count: scenarios.length, passed: scenarios.filter(item => item.passed).length, failed: scenarios.filter(item => !item.passed).length, true_positives: tp, true_negatives: tn, false_positives: fp, false_negatives: fn, precision: tp + fp ? Number((tp / (tp + fp)).toFixed(4)) : 1, recall: tp + fn ? Number((tp / (tp + fn)).toFixed(4)) : 1, mean_latency_ms: Math.round(latencies.reduce((sum, value) => sum + value, 0) / latencies.length), p95_latency_ms: latencies[Math.min(latencies.length - 1, Math.ceil(latencies.length * .95) - 1)], request_count: scenarios.reduce((sum, item) => sum + item.request_count, 0), finding_count: benchmark.findings.length, worker_heap_before_bytes: benchmark.health_before.memory.heapInUseBytes, worker_heap_after_bytes: benchmark.health_after.memory.heapInUseBytes, worker_heap_delta_bytes: benchmark.health_after.memory.heapInUseBytes - benchmark.health_before.memory.heapInUseBytes, encrypted_database: benchmark.health_after.database.encryption === 'AES-256-GCM', finding_management_passed: managementPassed }, finding_management: benchmark.management, scenarios };
		const stamp = report.generated_at.replace(/[:.]/g, '-'); const output = path.join(root, 'audit-results', `authorization-benchmark-${stamp}`); fs.mkdirSync(output, { recursive: true });
		fs.writeFileSync(path.join(output, 'authorization-benchmark.json'), JSON.stringify(report, null, 2)); fs.writeFileSync(path.join(output, 'authorization-benchmark.md'), markdown(report)); fs.writeFileSync(path.join(output, 'authorization-benchmark.html'), html(report));
		fs.writeFileSync(path.join(output, 'authorization-findings.json'), JSON.stringify({ generated_at: report.generated_at, findings: benchmark.findings }, null, 2)); fs.writeFileSync(path.join(output, 'authorization-findings.md'), findingsMarkdown(benchmark.findings, report.generated_at)); fs.writeFileSync(path.join(output, 'authorization-findings.html'), typeof benchmark.project_html === 'string' ? benchmark.project_html : JSON.stringify(benchmark.project_html));
		if (report.summary.failed || !managementPassed) throw new Error(`Authorization benchmark had ${report.summary.failed} failed scenarios or finding-management checks failed; artifacts: ${output}`);
		process.stdout.write(`${JSON.stringify({ passed: true, output, summary: report.summary })}\n`);
	} finally { await application.close(); lab.child.kill(); }
})().catch(error => { console.error(error); process.exitCode = 1; });
