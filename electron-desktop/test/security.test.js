'use strict';

const fs = require('fs');
const path = require('path');
const test = require('node:test');
const assert = require('node:assert/strict');

const root = path.resolve(__dirname, '..');
const read = (relativePath) => fs.readFileSync(path.join(root, relativePath), 'utf8');

test('Electron window keeps sandbox and context isolation enabled', () => {
    const source = read('main/index.js');
    assert.match(source, /app\.enableSandbox\(\)/);
    assert.match(source, /contextIsolation:\s*true/);
    assert.match(source, /nodeIntegration:\s*false/);
    assert.match(source, /sandbox:\s*true/);
    assert.match(source, /setPermissionRequestHandler/);
    assert.match(source, /setWindowOpenHandler/);
});

test('renderer CSP forbids network connections and inline scripts', () => {
    const source = read('renderer/index.html');
    assert.match(source, /connect-src 'none'/);
    assert.match(source, /script-src 'self'/);
    assert.doesNotMatch(source, /script-src[^;]*(?:unsafe-inline|unsafe-eval)|onclick=/i);
});

test('migrated renderer uses direct IPC without fetch or Socket.IO', () => {
    const rendererRoot = path.join(root, 'renderer');
    const sources = [];
    function walk(directory) {
        for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
            const target = path.join(directory, entry.name);
            if (entry.isDirectory()) walk(target);
            else if (/\.(?:js|html)$/.test(entry.name)) sources.push(fs.readFileSync(target, 'utf8'));
        }
    }
    walk(rendererRoot);
    const source = sources.join('\n');
    assert.doesNotMatch(source, /\bfetch\s*\(/);
    assert.doesNotMatch(source, /\bio\s*\(/);
    assert.doesNotMatch(source, /socket\.io-client/);
    assert.doesNotMatch(source, /127\.0\.0\.1:8080/);
    assert.match(source, /window\.wshawk\.invoke/);
});

test('identity aliases survive automatic project snapshot refreshes', () => {
    const adapter = read('renderer/ipc-adapter.js');
    const identities = read('renderer/modules/identities.js');
    assert.match(adapter, /snapshot\.identities\.map\(expandIdentity\)/);
    assert.match(adapter, /metadata\.alias\s*\|\|\s*entity\?\.alias\s*\|\|\s*entity\?\.name/);
    assert.match(identities, /identity\.storage\?\.auth_user/);
    assert.doesNotMatch(identities, /option\.textContent\s*=\s*`\$\{identity\.alias\}/);
});

test('auth recording rejects incomplete scheme-only URLs and HTTP replay labels identity behavior', () => {
    const attacksUI = read('renderer/modules/attacks_ui.js');
    const webViews = read('renderer/components/web_workspace_views.js');
    assert.match(attacksUI, /Boolean\(parsed\.hostname\)/);
    assert.match(attacksUI, /validLoginUrl\(loginUrl\)/);
    assert.match(webViews, />Send Raw<\/button>/);
    assert.match(webViews, />Replay as Identity<\/button>/);
    assert.match(webViews, /id="http-compare-identity-select"/);
});

test('HTTP authorization diff requires an explicit pair with distinct authentication material', () => {
    const adapter = read('renderer/ipc-adapter.js');
    const webPentest = read('renderer/modules/web_pentest.js');
    const webViews = read('renderer/components/web_workspace_views.js');
    assert.match(webPentest, /identity_ids:\s*\[leftIdentityId, rightIdentityId\]/);
    assert.match(webPentest, /policy_mode:\s*policyMode/);
    assert.match(webPentest, /Choose two different identities/);
    assert.match(webPentest, /potential_idor:\s*\{\s*badge:\s*'POTENTIAL IDOR'/);
    assert.match(webViews, /id="http-authz-policy"/);
    assert.match(webViews, /primary_denied_owner_allowed/);
    assert.match(adapter, /identical authentication material/);
    assert.match(adapter, /identity_alias:\s*identities\[0\]\.alias/);
    assert.match(adapter, /kind:\s*'findings'/);
    assert.match(adapter, /attacker_response_sha256/);
    assert.match(adapter, /owner_response_sha256/);
});

test('authorization matrix is bounded, policy-aware, redactable, and retestable', () => {
	const adapter = read('renderer/ipc-adapter.js');
	const webPentest = read('renderer/modules/web_pentest.js');
	const webViews = read('renderer/components/web_workspace_views.js');
	const contract = read('shared/contract.js');
	assert.match(contract, /scanner\.authz_matrix/);
	assert.match(webViews, /id="http-authz-matrix-btn"/);
	assert.match(webViews, /id="http-authz-object-values"/);
	assert.match(webViews, /tenant_isolation/);
	assert.match(webViews, /function_level_authorization/);
	assert.match(webPentest, /safe_write_confirmed:\s*safeWriteConfirmed/);
	assert.match(webPentest, /minimum_confirmations:\s*minimumConfirmations/);
	assert.match(adapter, /executeHTTPAuthzMatrix/);
	assert.match(adapter, /max_requests:\s*80/);
	assert.match(adapter, /redactEvidenceText/);
	assert.match(adapter, /lifecycle_status/);
	assert.match(adapter, /Finding has no authorization retest recipe/);
});

test('complete authorization workspace includes discovery, rollback, WS matrices, protected evidence, and management', () => {
	const adapter = read('renderer/ipc-adapter.js');
	const httpViews = read('renderer/components/web_workspace_views.js');
	const coreViews = read('renderer/components/core_views.js');
	const findings = read('renderer/modules/findings_workspace.js');
	const main = read('main/index.js');
	assert.match(adapter, /http-authz-discover/);
	assert.match(adapter, /discoverAuthorizationObjects/);
	assert.match(adapter, /ws-authz-matrix/);
	assert.match(adapter, /admin_only_operation/);
	assert.match(adapter, /ownership_transfer/);
	assert.match(adapter, /last_retest_classification/);
	assert.match(adapter, /fingerprint/);
	assert.match(httpViews, /http-authz-write-dialog/);
	assert.match(httpViews, /execute_with_rollback/);
	assert.match(httpViews, /http-authz-matrix-visual/);
	assert.match(coreViews, /view-findingsworkspace/);
	assert.match(coreViews, /Export Selected/);
	assert.match(findings, /exportSelected/);
	assert.match(findings, /Reveal Evidence/);
	assert.match(findings, /severity/);
	assert.match(main, /safeStorage\.encryptString/);
	assert.doesNotMatch(findings, /\.innerHTML\s*=/);
});

test('workspace session picker excludes HTTP templates and loads by stable ID', () => {
    const adapter = read('renderer/ipc-adapter.js');
    const webPentest = read('renderer/modules/web_pentest.js');
    const index = read('renderer/index.html');
    assert.match(adapter, /type:\s*'workspace-session'/);
    assert.match(adapter, /item\.metadata\.type === 'workspace-session'/);
    assert.match(adapter, /candidate\.metadata\?\.type !== 'http-template'/);
    assert.match(webPentest, /id:\s*selectedSession\.id/);
    assert.match(webPentest, /project_id:\s*selectedSession\.project_id/);
    assert.match(webPentest, /sessionButtonFeedback\(loadBtn, 'Loaded'/);
    assert.match(index, /id="session-dialog"/);
    assert.doesNotMatch(webPentest, /\bprompt\s*\(/);
});

test('preload exposes narrow invoke, subscribe, and cancel operations', () => {
    const source = read('preload/index.js');
    assert.match(source, /contextBridge\.exposeInMainWorld\('wshawk'/);
    assert.doesNotMatch(source, /exposeInMainWorld\([^\n]+ipcRenderer/);
    assert.doesNotMatch(source, /remote|shell\.openExternal/);
});

test('production Go worker source does not create a local control listener', () => {
    const goFiles = [];
    function walk(directory) {
        for (const entry of fs.readdirSync(directory, { withFileTypes: true })) {
            const target = path.join(directory, entry.name);
            if (entry.isDirectory()) walk(target);
            else if (entry.name.endsWith('.go') && !entry.name.endsWith('_test.go')) goFiles.push(target);
        }
    }
    walk(path.join(root, 'backend-go'));
    const source = goFiles.map(file => fs.readFileSync(file, 'utf8')).join('\n');
    assert.doesNotMatch(source, /net\.Listen|http\.ListenAndServe|localhost|127\.0\.0\.1/);
});
