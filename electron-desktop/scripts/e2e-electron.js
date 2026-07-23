'use strict';

const path = require('path');
const fs = require('fs');
const os = require('os');
const readline = require('readline');
const { spawn } = require('child_process');
const { _electron: electron } = require('playwright-core');
const { firstWindowWithDiagnostics, isolatedElectronEnvironment } = require('./electron-harness');

const root = path.resolve(__dirname, '..');

async function startLab() {
	const child = spawn(process.execPath, [path.join(root, 'labs', 'server.js')], { stdio: ['ignore', 'pipe', 'inherit'], windowsHide: true });
	const lines = readline.createInterface({ input: child.stdout, crlfDelay: Infinity });
	const ready = await new Promise((resolve, reject) => {
		const timeout = setTimeout(() => reject(new Error('E2E lab startup timed out')), 10_000);
		lines.once('line', line => { clearTimeout(timeout); resolve(JSON.parse(line)); });
		child.once('exit', code => reject(new Error(`E2E lab exited during startup (${code})`)));
	});
	return { child, ready };
}

(async () => {
	const lab = await startLab();
	const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wshawk-electron-e2e-'));
	const application = await electron.launch({ args: [root], env: isolatedElectronEnvironment(dataDir) });
    try {
        const window = await firstWindowWithDiagnostics(application);
		const rendererErrors = [];
		window.on('pageerror', error => rendererErrors.push(error.stack || error.message));
		await window.reload();
        await window.waitForLoadState('domcontentloaded');
        if ((await window.title()) !== 'WSHawk Intelligence') throw new Error('Full WSHawk interface did not load');
		await window.waitForTimeout(100);
		if (await window.locator('#btn-agree-tos').isVisible()) await window.locator('#btn-agree-tos').click();
		await window.locator('#btn-new-project').click();
		await window.locator('#main-app').waitFor({ state: 'visible' });
        const health = await window.evaluate(() => window.wshawk.invoke('system.health'));
        if (health.backend !== 'go' || health.noNetworkBridge !== true) throw new Error('Renderer did not reach the private Go worker');
        const navigationCount = await window.locator('.nav-item').count();
        if (navigationCount < 10) throw new Error(`Expected full navigation, found ${navigationCount}`);
		const routes = await window.evaluate(async ({ labURL, labWS }) => {
			const request = async (url, init) => { const response = await window.ipcRequest(url, init); return { ok: response.ok, status: response.status, data: await response.json() }; };
			const project = await request('/platform/projects', { method: 'POST', body: JSON.stringify({ name: 'Electron route lab', url: labURL }) });
			const projectId = project.data.project.id;
			const identity = await request(`/platform/projects/${projectId}/identities`, { method: 'POST', body: JSON.stringify({ alias: 'lab-user', headers: { 'X-Lab-Role': 'user', 'X-Lab-Token': 'authorized-lab-token' } }) });
			const loginIdentity = async (alias, username, password) => {
				const login = await request('/web/request', { method: 'POST', body: JSON.stringify({
					project_id: projectId,
					url: `${labURL}/login`,
					method: 'POST',
					headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
					body: new URLSearchParams({ username, password }).toString(),
					follow_redirects: false,
				}) });
				const cookie = String(login.data.headers || '').match(/^Set-Cookie:\s*([^;\r\n]+)/im)?.[1] || '';
				if (login.data.status !== 303 || !cookie) throw new Error(`Lab login failed for ${alias}`);
				return request(`/platform/projects/${projectId}/identities`, { method: 'POST', body: JSON.stringify({ alias, headers: { Cookie: cookie }, storage: { auth_user: username } }) });
			};
			const adminIdentity = await loginIdentity('lab-admin', 'admin', 'admin-lab-pass');
			const userIdentity = await loginIdentity('lab-user-a', 'user_a', 'user-a-lab-pass');
			const userBIdentity = await loginIdentity('lab-user-b', 'user_b', 'user-b-lab-pass');
			const staleIdentity = await request(`/platform/projects/${projectId}/identities`, { method: 'POST', body: JSON.stringify({ alias: 'lab-stale-user', headers: { Cookie: 'wshawk_lab_session=invalid-session' }, storage: { auth_user: 'stale_user' } }) });
			const template = await request(`/platform/projects/${projectId}/http-templates`, { method: 'POST', body: JSON.stringify({ name: 'health', method: 'GET', url: `${labURL}/health`, headers: {} }) });
			const authzTemplate = await request(`/platform/projects/${projectId}/http-templates`, { method: 'POST', body: JSON.stringify({ name: 'admin-check', method: 'GET', url: `${labURL}/auth/admin`, headers: {} }) });
			const authzDiff = await request(`/platform/projects/${projectId}/attacks/http-authz-diff`, { method: 'POST', body: JSON.stringify({ template: authzTemplate.data.template, identity_ids: [adminIdentity.data.identity.id, userIdentity.data.identity.id] }) });
			const secureObjectTemplate = await request(`/platform/projects/${projectId}/http-templates`, { method: 'POST', body: JSON.stringify({ name: 'secure-resource-b', method: 'GET', url: `${labURL}/auth/resource/resource-b`, headers: {} }) });
			const insecureObjectTemplate = await request(`/platform/projects/${projectId}/http-templates`, { method: 'POST', body: JSON.stringify({ name: 'insecure-resource-b', method: 'GET', url: `${labURL}/auth/resource-insecure/resource-b`, headers: {} }) });
			const ownershipPolicy = 'primary_denied_owner_allowed';
			const secureObjectDiff = await request(`/platform/projects/${projectId}/attacks/http-authz-diff`, { method: 'POST', body: JSON.stringify({ template: secureObjectTemplate.data.template, identity_ids: [userIdentity.data.identity.id, userBIdentity.data.identity.id], policy_mode: ownershipPolicy }) });
			const insecureObjectDiff = await request(`/platform/projects/${projectId}/attacks/http-authz-diff`, { method: 'POST', body: JSON.stringify({ template: insecureObjectTemplate.data.template, identity_ids: [userIdentity.data.identity.id, userBIdentity.data.identity.id], policy_mode: ownershipPolicy }) });
			const staleObjectDiff = await request(`/platform/projects/${projectId}/attacks/http-authz-diff`, { method: 'POST', body: JSON.stringify({ template: insecureObjectTemplate.data.template, identity_ids: [staleIdentity.data.identity.id, userBIdentity.data.identity.id], policy_mode: ownershipPolicy }) });
			const matrixInput = {
				identity_ids: [userIdentity.data.identity.id, userBIdentity.data.identity.id, adminIdentity.data.identity.id],
				primary_identity_id: userIdentity.data.identity.id, owner_identity_id: userBIdentity.data.identity.id,
				policy_mode: ownershipPolicy, object_location: 'path', object_field: 'resource-b',
				object_values: ['resource-b', 'resource-b-2'], minimum_confirmations: 2,
				include_anonymous: true, evidence_mode: 'redacted',
			};
			const secureMatrix = await request(`/platform/projects/${projectId}/attacks/http-authz-matrix`, { method: 'POST', body: JSON.stringify({ ...matrixInput, template: secureObjectTemplate.data.template }) });
			const insecureMatrix = await request(`/platform/projects/${projectId}/attacks/http-authz-matrix`, { method: 'POST', body: JSON.stringify({ ...matrixInput, template: insecureObjectTemplate.data.template }) });
			const discovery = await request(`/platform/projects/${projectId}/attacks/http-authz-discover`, { method: 'POST', body: JSON.stringify({ template: { method: 'PATCH', url: `${labURL}/auth/accounts/account-b/orders/order-b?tenant_id=tenant-b&account_id=123`, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ document_id: '22222222-2222-4222-8222-222222222222' }) } }) });
			const matrixFindingId = insecureMatrix.data.matrix?.summary?.finding_id;
			const confirmedMatrixFinding = matrixFindingId ? await request(`/platform/projects/${projectId}/findings/${matrixFindingId}`, { method: 'PATCH', body: JSON.stringify({ lifecycle_status: 'confirmed' }) }) : null;
			const retestedMatrixFinding = matrixFindingId ? await request(`/platform/projects/${projectId}/findings/${matrixFindingId}/retest`, { method: 'POST', body: '{}' }) : null;
			const graphQLTemplate = { name: 'graphql-idor', method: 'POST', url: `${labURL}/graphql`, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ query: 'query($id: ID!){ resourceInsecure(id:$id){ id owner secret } }', variables: { id: 'resource-b' } }) };
			const blockedUnsafeGraphQLMatrix = await request(`/platform/projects/${projectId}/attacks/http-authz-matrix`, { method: 'POST', body: JSON.stringify({ ...matrixInput, template: graphQLTemplate, object_location: 'graphql', object_field: 'id', safe_write_confirmed: false }) });
			const graphQLMatrix = await request(`/platform/projects/${projectId}/attacks/http-authz-matrix`, { method: 'POST', body: JSON.stringify({ ...matrixInput, template: graphQLTemplate, object_location: 'graphql', object_field: 'id', safe_write_confirmed: true }) });
			const adminMatrixInput = { identity_ids: [userIdentity.data.identity.id, userBIdentity.data.identity.id, adminIdentity.data.identity.id], primary_identity_id: userIdentity.data.identity.id, owner_identity_id: adminIdentity.data.identity.id, policy_mode: 'admin_only_operation', object_values: ['admin-operation'], minimum_confirmations: 1, include_anonymous: true, evidence_mode: 'hash_only' };
			const secureAdminMatrix = await request(`/platform/projects/${projectId}/attacks/http-authz-matrix`, { method: 'POST', body: JSON.stringify({ ...adminMatrixInput, template: { method: 'GET', url: `${labURL}/auth/admin-operation`, headers: {} } }) });
			const insecureAdminMatrix = await request(`/platform/projects/${projectId}/attacks/http-authz-matrix`, { method: 'POST', body: JSON.stringify({ ...adminMatrixInput, template: { method: 'GET', url: `${labURL}/auth/admin-operation-insecure`, headers: {} } }) });
			const writeTemplate = { method: 'POST', url: `${labURL}/auth/ownership-transfer-insecure/resource-b`, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ new_owner: 'user_a' }) };
			const writeMatrixBase = { ...matrixInput, template: writeTemplate, policy_mode: 'ownership_transfer', object_values: ['resource-b', 'resource-b-2'], write_mode: 'execute_with_rollback', safe_write_confirmed: true, include_anonymous: false, before_template: { method: 'GET', url: `${labURL}/auth/write-state/resource-b`, headers: {} }, after_template: { method: 'GET', url: `${labURL}/auth/write-state/resource-b`, headers: {} }, cleanup_template: { method: 'POST', url: `${labURL}/auth/rollback`, headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ rollback_token: '{{rollback_token}}' }), mutate_object: false } };
			const writeMatrix = await request(`/platform/projects/${projectId}/attacks/http-authz-matrix`, { method: 'POST', body: JSON.stringify(writeMatrixBase) });
			const wsPolicyInput = { payload: { action: 'read-private-room' }, identity_ids: [userIdentity.data.identity.id, userBIdentity.data.identity.id], primary_identity_id: userIdentity.data.identity.id, owner_identity_id: userBIdentity.data.identity.id, policy_mode: ownershipPolicy, evidence_mode: 'redacted', timeout: 3 };
			const secureWSAuthz = await request(`/platform/projects/${projectId}/attacks/authz-diff`, { method: 'POST', body: JSON.stringify({ ...wsPolicyInput, url: labWS.replace('/ws/echo', '/ws/room-secure?room=user_b') }) });
			const insecureWSAuthz = await request(`/platform/projects/${projectId}/attacks/authz-diff`, { method: 'POST', body: JSON.stringify({ ...wsPolicyInput, url: labWS.replace('/ws/echo', '/ws/room-insecure?room=user_b') }) });
			const wsMatrixInput = { payload: { action: 'subscribe', room: 'user_b' }, identity_ids: [userIdentity.data.identity.id, userBIdentity.data.identity.id, adminIdentity.data.identity.id], primary_identity_id: userIdentity.data.identity.id, owner_identity_id: userBIdentity.data.identity.id, policy_mode: ownershipPolicy, object_field: 'room', object_values: ['user_b', 'tenant-b'], minimum_confirmations: 2, include_anonymous: true, evidence_mode: 'redacted', timeout: 3 };
			const secureWSMatrix = await request(`/platform/projects/${projectId}/attacks/ws-authz-matrix`, { method: 'POST', body: JSON.stringify({ ...wsMatrixInput, url: labWS.replace('/ws/echo', '/ws/subscription-secure') }) });
			const insecureWSMatrix = await request(`/platform/projects/${projectId}/attacks/ws-authz-matrix`, { method: 'POST', body: JSON.stringify({ ...wsMatrixInput, url: labWS.replace('/ws/echo', '/ws/subscription-insecure') }) });
			const wsFindingId = insecureWSAuthz.data.diff?.summary?.finding_id;
			const retestedWSFinding = wsFindingId ? await request(`/platform/projects/${projectId}/findings/${wsFindingId}/retest`, { method: 'POST', body: '{}' }) : null;
			const policyFindings = await request(`/platform/projects/${projectId}/findings`);
			const http = await request('/web/request', { method: 'POST', body: JSON.stringify({ project_id: projectId, url: `${labURL}/health` }) });
			const headers = await request('/web/headers', { method: 'POST', body: JSON.stringify({ project_id: projectId, url: `${labURL}/headers` }) });
			const cors = await request('/web/cors', { method: 'POST', body: JSON.stringify({ project_id: projectId, url: `${labURL}/cors`, origin: 'https://attacker.invalid' }) });
			const reflectedCors = await request('/web/cors', { method: 'POST', body: JSON.stringify({ project_id: projectId, url: `${labURL}/cors-reflect`, origin: 'https://attacker.invalid' }) });
			const sensitive = await request('/web/sensitive', { method: 'POST', body: JSON.stringify({ project_id: projectId, url: `${labURL}/sensitive` }) });
			const fingerprint = await request('/web/fingerprint', { method: 'POST', body: JSON.stringify({ project_id: projectId, url: `${labURL}/headers` }) });
			const directory = await request('/web/dirscan', { method: 'POST', body: JSON.stringify({ project_id: projectId, url: labURL, words: ['health', 'missing'] }) });
			const vulnerability = await request('/web/vulnscan', { method: 'POST', body: JSON.stringify({ project_id: projectId, url: `${labURL}/scan`, parameter: 'q', location: 'query', categories: ['sqli', 'xss'], max_requests: 10 }) });
			const redirectStarted = performance.now();
			const redirect = await request('/web/redirect', { method: 'POST', body: JSON.stringify({ project_id: projectId, url: `${labURL}/redirect?next=FUZZ`, parameter: 'next' }) });
			const redirectElapsedMS = performance.now() - redirectStarted;
			const wsReplay = await request(`/platform/projects/${projectId}/replay/ws`, { method: 'POST', body: JSON.stringify({ url: labWS.replace('/ws/echo', '/ws/auth'), payload: 'identity-echo', identity_id: identity.data.identity.id }) });
			const blaster = await request('/blaster/start', { method: 'POST', body: JSON.stringify({ project_id: projectId, url: labWS, template: '{"probe":"§inject§"}', payloads: ['alpha', 'beta'] }) });
			const mutation = await request('/mutate', { method: 'POST', body: JSON.stringify({ payload: "' OR 1=1", strategy: 'auto', count: 6 }) });
			const binary = await request('/binary/analyze', { method: 'POST', body: JSON.stringify({ payload_base64: 'iVBORw0KGgo=' }) });
			const workflow = await request('/web/chain', { method: 'POST', body: JSON.stringify({ project_id: projectId, steps: [{ name: 'health', method: 'GET', url: `${labURL}/health`, extract: [{ var: 'lab', from: 'body', regex: '"lab":"([^"]+)' }] }] }) });
			const ca = await request('/proxy/ca/generate', { method: 'POST', body: JSON.stringify({ common_name: 'WSHawk E2E Lab CA', valid_days: 7 }) });
			const hostCertificate = await request('/proxy/ca/host', { method: 'POST', body: JSON.stringify({ hostname: 'lab.example', valid_days: 2 }) });
			const protocol = await request(`/platform/projects/${projectId}/protocol-map`);
			const config = await request('/config/save', { method: 'POST', body: JSON.stringify({ jiraUrl: 'https://jira.invalid', jiraToken: 'must-not-persist' }) });
			const configRead = await request('/config/get');
			const browserStatus = await window.wshawk.invoke('browser.status');
			const auth = browserStatus.browserReady ? await window.wshawk.invoke('browser.auth.record', { url: `${labURL}/auth-state`, visible: false, settleMs: 200, timeoutMs: 10_000 }) : null;
			const authReplay = auth ? await window.wshawk.invoke('browser.auth.replay', { url: `${labURL}/auth-state`, cookies: auth.cookies, storage: auth.storage, timeoutMs: 10_000 }) : null;
			const marker = 'wshawk_xss_probe';
			const dom = browserStatus.browserReady ? await window.wshawk.invoke('browser.dom_xss.verify', { url: `${labURL}/dom-xss?payload=${encodeURIComponent(`<script>alert('${marker}')</script>`)}`, marker, timeoutMs: 10_000, authorizationConfirmed: true }) : null;
			return { project, identity, adminIdentity, userIdentity, userBIdentity, template, authzDiff, secureObjectDiff, insecureObjectDiff, staleObjectDiff, secureMatrix, insecureMatrix, discovery, confirmedMatrixFinding, retestedMatrixFinding, blockedUnsafeGraphQLMatrix, graphQLMatrix, secureAdminMatrix, insecureAdminMatrix, writeMatrix, secureWSAuthz, insecureWSAuthz, secureWSMatrix, insecureWSMatrix, retestedWSFinding, policyFindings, http, headers, cors, reflectedCors, sensitive, fingerprint, directory, vulnerability, redirect, redirectElapsedMS, wsReplay, blaster, mutation, binary, workflow, ca, hostCertificate, protocol, config, configRead, browserStatus, auth, authReplay, dom };
		}, { labURL: lab.ready.http, labWS: lab.ready.ws });
		if (!routes.project.ok || !routes.identity.data.identity?.id || !routes.template.data.template?.id) throw new Error('Project, identity, or template IPC route failed');
		if (routes.authzDiff.data.diff?.authorization_difference !== 'high'
			|| routes.authzDiff.data.diff?.left?.status !== 200
			|| routes.authzDiff.data.diff?.right?.status !== 403
			|| routes.authzDiff.data.diff?.results?.[0]?.identity_alias !== 'lab-admin'
			|| routes.authzDiff.data.diff?.results?.[1]?.identity_alias !== 'lab-user-a') {
			throw new Error(`HTTP AuthZ diff did not preserve distinct identities: ${JSON.stringify(routes.authzDiff.data)}`);
		}
		if (routes.secureObjectDiff.data.diff?.policy_evaluation?.verdict !== 'access_control_enforced'
			|| routes.secureObjectDiff.data.diff?.summary?.finding_saved !== false) {
			throw new Error(`Secure object policy was misclassified: ${JSON.stringify(routes.secureObjectDiff.data)}`);
		}
		if (routes.insecureObjectDiff.data.diff?.policy_evaluation?.verdict !== 'potential_idor'
			|| routes.insecureObjectDiff.data.diff?.policy_evaluation?.confidence !== 'high'
			|| !routes.insecureObjectDiff.data.diff?.summary?.finding_saved
			|| !routes.insecureObjectDiff.data.diff?.summary?.finding_id) {
			throw new Error(`Insecure object policy did not persist an IDOR finding: ${JSON.stringify(routes.insecureObjectDiff.data)}`);
		}
		if (routes.staleObjectDiff.data.diff?.policy_evaluation?.verdict !== 'invalid_identity'
			|| routes.staleObjectDiff.data.diff?.summary?.finding_saved !== false) {
			throw new Error(`Stale identity policy was not marked inconclusive: ${JSON.stringify(routes.staleObjectDiff.data)}`);
		}
		if (routes.secureMatrix.data.matrix?.evaluation?.verdict !== 'access_control_enforced'
			|| routes.secureMatrix.data.matrix?.summary?.finding_saved !== false) {
			throw new Error(`Secure authorization matrix was misclassified: ${JSON.stringify(routes.secureMatrix.data)}`);
		}
		if (routes.insecureMatrix.data.matrix?.evaluation?.verdict !== 'potential_idor'
			|| routes.insecureMatrix.data.matrix?.evaluation?.confirmation_count !== 2
			|| routes.insecureMatrix.data.matrix?.summary?.finding_saved !== true) {
			throw new Error(`Multi-object IDOR matrix was not confirmed: ${JSON.stringify(routes.insecureMatrix.data)}`);
		}
		if (routes.confirmedMatrixFinding?.data?.finding?.metadata?.lifecycle_status !== 'confirmed'
			|| routes.retestedMatrixFinding?.data?.matrix?.summary?.finding_id !== routes.insecureMatrix.data.matrix.summary.finding_id) {
			throw new Error(`Finding lifecycle or stable-ID retest failed: ${JSON.stringify({ confirmed: routes.confirmedMatrixFinding, retested: routes.retestedMatrixFinding })}`);
		}
		if (!routes.blockedUnsafeGraphQLMatrix.ok || routes.blockedUnsafeGraphQLMatrix.data.matrix?.evaluation?.verdict !== 'dry_run_planned' || routes.graphQLMatrix.data.matrix?.evaluation?.verdict !== 'potential_idor') {
			throw new Error(`GraphQL write guard or semantic authorization matrix failed: ${JSON.stringify({ blocked: routes.blockedUnsafeGraphQLMatrix, allowed: routes.graphQLMatrix })}`);
		}
		if (!routes.discovery.data.discoveries?.some(item => item.location === 'path' && item.current_value === 'order-b') || !routes.discovery.data.discoveries?.some(item => item.location === 'query' && item.field === 'tenant_id') || !routes.discovery.data.discoveries?.some(item => item.location === 'query' && item.field === 'account_id' && item.candidates.includes('122') && item.candidates.includes('124')) || !routes.discovery.data.discoveries?.some(item => item.location === 'json' && item.field === 'document_id')) throw new Error(`Automatic object discovery missed nested/query/JSON/numeric identifiers: ${JSON.stringify(routes.discovery.data)}`);
		if (routes.secureAdminMatrix.data.matrix?.evaluation?.verdict !== 'access_control_enforced' || routes.insecureAdminMatrix.data.matrix?.evaluation?.verdict !== 'potential_admin_operation_bypass') throw new Error('Explicit admin-only authorization policy failed');
		if (routes.writeMatrix.data.matrix?.evaluation?.verdict !== 'potential_ownership_transfer_bypass' || !routes.writeMatrix.data.matrix?.results?.filter(item => item.response?.status === 200).every(item => item.write_evidence?.cleanup_succeeded === true && item.write_evidence?.rollback_verified === true)) throw new Error(`Write rollback evidence failed: ${JSON.stringify(routes.writeMatrix.data)}`);
		if (routes.secureWSAuthz.data.diff?.policy_evaluation?.verdict !== 'access_control_enforced'
			|| routes.secureWSAuthz.data.diff?.summary?.finding_saved !== false
			|| routes.insecureWSAuthz.data.diff?.policy_evaluation?.verdict !== 'potential_websocket_authorization_bypass'
			|| routes.insecureWSAuthz.data.diff?.summary?.finding_saved !== true
			|| routes.retestedWSFinding?.data?.diff?.summary?.finding_id !== routes.insecureWSAuthz.data.diff.summary.finding_id) {
			throw new Error(`WebSocket authorization policy failed: ${JSON.stringify({ secure: routes.secureWSAuthz, insecure: routes.insecureWSAuthz })}`);
		}
		if (routes.secureWSMatrix.data.matrix?.evaluation?.verdict !== 'access_control_enforced' || routes.insecureWSMatrix.data.matrix?.evaluation?.confirmation_count !== 2 || routes.insecureWSMatrix.data.matrix?.summary?.finding_saved !== true) throw new Error(`WebSocket subscription authorization matrix failed: ${JSON.stringify({ secure: routes.secureWSMatrix.data, insecure: routes.insecureWSMatrix.data })}`);
		const storedPolicyFinding = routes.policyFindings.data.findings?.find(item => item.id === routes.insecureObjectDiff.data.diff.summary.finding_id);
		const storedPolicyEvidence = storedPolicyFinding ? JSON.parse(storedPolicyFinding.value) : null;
		if (storedPolicyFinding?.metadata?.type !== 'idor-bola'
			|| storedPolicyFinding.metadata.attacker_alias !== 'lab-user-a'
			|| storedPolicyFinding.metadata.owner_alias !== 'lab-user-b'
			|| storedPolicyFinding.metadata.attacker_status !== 200
			|| storedPolicyFinding.metadata.owner_status !== 200
			|| !storedPolicyEvidence?.responses?.attacker?.body
			|| !storedPolicyEvidence?.responses?.attacker?.sha256
			|| !storedPolicyEvidence?.responses?.owner_control?.body
			|| !storedPolicyEvidence?.responses?.owner_control?.sha256) {
			throw new Error(`Persisted IDOR evidence is incomplete: ${JSON.stringify(storedPolicyFinding)}`);
		}
		const storedMatrixFinding = routes.policyFindings.data.findings?.find(item => item.id === routes.insecureMatrix.data.matrix.summary.finding_id);
		const storedMatrixEvidence = storedMatrixFinding ? JSON.parse(storedMatrixFinding.value) : null;
		if (storedMatrixFinding?.metadata?.confirmation_count !== 2
			|| storedMatrixFinding?.metadata?.lifecycle_status !== 'confirmed'
			|| storedMatrixEvidence?.results?.length < 6
			|| !storedMatrixEvidence.results.every(item => item.response?.sha256)
			|| !storedMatrixEvidence.results.some(item => item.response?.body_redacted === true && item.response.body.includes('[REDACTED]'))
			|| !storedMatrixEvidence?.recipe?.identity_ids?.length) {
			throw new Error(`Persisted authorization-matrix evidence or replay recipe is incomplete: ${JSON.stringify(storedMatrixFinding)}`);
		}
		if (routes.http.data.status !== 200 || routes.headers.data.status !== 'success') throw new Error('HTTP security IPC routes failed');
		if (!routes.cors.data.findings?.length || !routes.sensitive.data.findings?.length || !routes.fingerprint.data.technologies?.length || routes.directory.data.checked !== 2) throw new Error('Web security analysis route shapes failed');
		if (!routes.reflectedCors.data.findings?.some(item => item.test === 'cors-reflected-origin-credentials' && item.acao_received === 'https://attacker.invalid' && item.credentials === true)) throw new Error('CORS analyzer did not send and detect a reflected credentialed Origin');
		if (!routes.vulnerability.data.findings?.some(item => item.type === 'sql-injection') || !routes.vulnerability.data.findings?.some(item => item.type === 'xss')) throw new Error('Orchestrated vulnerability scan failed');
		if (!routes.redirect.data.findings?.some(item => item.type === 'open-redirect') || routes.redirectElapsedMS > 5_000) throw new Error(`Redirect scan followed the external canary or missed the finding (${routes.redirectElapsedMS.toFixed(0)}ms)`);
		if (routes.wsReplay.data.result?.status !== 'received' || routes.blaster.data.sent !== 2) throw new Error('Identity replay or payload blaster workflow failed');
		if (routes.mutation.data.mutations?.length !== 6 || routes.binary.data.analysis?.magic !== 'png' || routes.workflow.data.workflow?.summary?.completed !== 1) throw new Error('Mutation, binary analysis, or workflow IPC route failed');
		if (!routes.ca.data.fingerprint || !routes.hostCertificate.data.fingerprint || routes.ca.data.private_key_pem || routes.hostCertificate.data.private_key_pem) throw new Error('Private certificate utility boundary failed');
		if (!routes.protocol.data.protocol_map?.summary) throw new Error('Protocol map IPC route failed');
		if (routes.configRead.data.jiraToken) throw new Error('Renderer config persisted a secret');
		if (!routes.browserStatus.browserReady) throw new Error('A Chromium executable was not available for browser verification');
		if (!routes.auth?.cookies?.length || !routes.auth.storage?.localStorage?.access_token || routes.authReplay?.status !== 200) throw new Error('Authentication recording or replay failed');
		if (!routes.dom?.confirmed || !routes.dom.screenshotBase64) throw new Error('DOM XSS execution evidence was not confirmed');

		if (await window.locator('#btn-agree-tos').isVisible()) await window.locator('#btn-agree-tos').click();
		const uiSessionName = `ui-session-${Date.now()}`;
		await window.locator('#target-url').fill(lab.ready.http);
		await window.locator('#session-save-btn').click();
		await window.locator('#session-dialog').waitFor({ state: 'visible' });
		await window.locator('#session-dialog-name').fill(uiSessionName);
		await window.locator('#session-dialog-confirm').click();
		await window.waitForFunction(name => document.querySelector('#session-save-btn')?.textContent?.includes('Saved'), uiSessionName, { timeout: 10_000 });
		await window.locator('#target-url').fill('http://changed.invalid/');
		await window.locator('#session-load-btn').click();
		await window.locator('#session-dialog').waitFor({ state: 'visible' });
		await window.locator('#session-dialog-list').selectOption('0');
		await window.locator('#session-dialog-confirm').click();
		await window.waitForFunction(target => document.querySelector('#target-url')?.value === target, lab.ready.http, { timeout: 10_000 });
		if (rendererErrors.length) throw new Error(`Renderer errors during E2E: ${JSON.stringify(rendererErrors)}`);

		await window.locator('#toggle-mode-btn').click();
		await window.locator('#toggle-mode-btn').click();
		await window.locator('#web-menu').waitFor({ state: 'visible' });
		await window.locator('.web-workspace-btn[data-web-workspace="attacks"]').click();
		await window.locator('.nav-item[data-target="vulnscanner"]').click();
		await window.locator('#vuln-target').fill(`${lab.ready.http}/scan?q=baseline`);
		await window.locator('#vuln-parameter').fill('q');
		const manualScanStarted = Date.now();
		await window.locator('#vuln-start-btn').click();
		await window.waitForFunction(() => document.querySelector('#vuln-progress-status')?.textContent?.startsWith('Completed:'), null, { timeout: 20_000 });
		const manualScanElapsedMS = Date.now() - manualScanStarted;
		const manualFindingText = await window.locator('#vuln-findings-tbody').innerText();
		if (!manualFindingText.includes('sql-injection') || !manualFindingText.includes('xss') || manualScanElapsedMS > 15_000) {
			throw new Error(`Real UI scan did not return SQLi/XSS findings promptly (${manualScanElapsedMS}ms): ${manualFindingText}`);
		}

		await window.locator('#vuln-target').fill('http://127.0.0.1:1/unreachable');
		await window.locator('#vuln-start-btn').click();
		await window.waitForFunction(() => document.querySelector('#vuln-progress-status')?.textContent === 'Scan failed' && getComputedStyle(document.querySelector('#vuln-start-btn')).display !== 'none', null, { timeout: 10_000 });

		await window.locator('#vuln-target').fill(`${lab.ready.http}/slow?delay_ms=8000&q=baseline`);
		await window.locator('#vuln-start-btn').click();
		await window.waitForFunction(() => document.querySelector('#vuln-progress-status')?.textContent?.includes('CRAWL running'), null, { timeout: 5_000 });
		await window.locator('#vuln-stop-btn').click();
		await window.waitForFunction(() => document.querySelector('#vuln-progress-status')?.textContent === 'Scan cancelled' && getComputedStyle(document.querySelector('#vuln-start-btn')).display !== 'none', null, { timeout: 8_000 });

		process.stdout.write(`Electron Playwright E2E passed (${navigationCount} navigation items, ${health.transport}, UI scan ${manualScanElapsedMS}ms, failure/cancellation recovery verified).\n`);
    } finally {
        await application.close();
		lab.child.kill();
    }
})().catch(error => { console.error(error); process.exit(1); });
