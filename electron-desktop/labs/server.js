'use strict';

const fs = require('fs');
const crypto = require('crypto');
const http = require('http');
const path = require('path');
const { WebSocketServer } = require('ws');

const host = '127.0.0.1';
const requestedPort = Number(process.env.WSHAWK_LAB_PORT || 0);
let raceValue = 0;
let oastInteractions = 0;
const publicRoot = path.join(__dirname, 'public');
const sessionTTLMS = 60 * 60 * 1000;
const sessions = new Map();
const accounts = Object.freeze({
    user_a: Object.freeze({ username: 'user_a', password: 'user-a-lab-pass', role: 'user', tenant: 'tenant-a', displayName: 'User A' }),
    user_b: Object.freeze({ username: 'user_b', password: 'user-b-lab-pass', role: 'user', tenant: 'tenant-b', displayName: 'User B' }),
    admin: Object.freeze({ username: 'admin', password: 'admin-lab-pass', role: 'admin', tenant: 'root', displayName: 'Lab Admin' }),
});
const ownedResources = Object.freeze({
    'resource-a': Object.freeze({ id: 'resource-a', owner: 'user_a', tenant: 'tenant-a', note: 'Private evidence owned by User A' }),
    'resource-a-2': Object.freeze({ id: 'resource-a-2', owner: 'user_a', tenant: 'tenant-a', note: 'Second private object owned by User A' }),
    'resource-b': Object.freeze({ id: 'resource-b', owner: 'user_b', tenant: 'tenant-b', note: 'Private evidence owned by User B' }),
    'resource-b-2': Object.freeze({ id: 'resource-b-2', owner: 'user_b', tenant: 'tenant-b', note: 'Second private object owned by User B' }),
});
const uuidResources = Object.freeze({
    '11111111-1111-4111-8111-111111111111': Object.freeze({ id: '11111111-1111-4111-8111-111111111111', owner: 'user_a', tenant: 'tenant-a', note: 'UUID object owned by User A' }),
    '22222222-2222-4222-8222-222222222222': Object.freeze({ id: '22222222-2222-4222-8222-222222222222', owner: 'user_b', tenant: 'tenant-b', note: 'UUID object owned by User B' }),
    '33333333-3333-4333-8333-333333333333': Object.freeze({ id: '33333333-3333-4333-8333-333333333333', owner: 'user_b', tenant: 'tenant-b', note: 'Second UUID object owned by User B' }),
});
const numericResources = Object.freeze({
	'2001': Object.freeze({ id: 2001, owner: 'user_b', tenant: 'tenant-b', note: 'Numeric object 2001 owned by User B' }),
	'2002': Object.freeze({ id: 2002, owner: 'user_b', tenant: 'tenant-b', note: 'Numeric object 2002 owned by User B' }),
});
const nestedOrders = Object.freeze({
    'account-a/order-a': Object.freeze({ account_id: 'account-a', id: 'order-a', owner: 'user_a', tenant: 'tenant-a', total: 41 }),
    'account-b/order-b': Object.freeze({ account_id: 'account-b', id: 'order-b', owner: 'user_b', tenant: 'tenant-b', total: 73 }),
    'account-b/order-b-2': Object.freeze({ account_id: 'account-b', id: 'order-b-2', owner: 'user_b', tenant: 'tenant-b', total: 99 }),
});
const writeState = new Map(Object.values(ownedResources).map(resource => [resource.id, { note: resource.note, owner: resource.owner }]));
const rollbackTokens = new Map();

function escapeHTML(value) {
    return String(value || '')
        .replaceAll('&', '&amp;')
        .replaceAll('<', '&lt;')
        .replaceAll('>', '&gt;')
        .replaceAll('"', '&quot;')
        .replaceAll("'", '&#39;');
}

function parseCookies(request) {
    const cookies = {};
    for (const part of String(request.headers.cookie || '').split(';')) {
        const separator = part.indexOf('=');
        if (separator < 1) continue;
        const name = part.slice(0, separator).trim();
        const value = part.slice(separator + 1).trim();
        if (name) cookies[name] = value;
    }
    return cookies;
}

function bearerToken(request) {
    const match = String(request.headers.authorization || '').match(/^Bearer\s+(.+)$/i);
    return match ? match[1].trim() : '';
}

function safeSecretEqual(candidate, expected) {
    const candidateBytes = Buffer.from(String(candidate || ''));
    const expectedBytes = Buffer.from(String(expected || ''));
    return candidateBytes.length === expectedBytes.length && crypto.timingSafeEqual(candidateBytes, expectedBytes);
}

function sessionFor(request) {
    const token = parseCookies(request).wshawk_lab_session || bearerToken(request);
    const session = token ? sessions.get(token) : null;
    if (!session) return null;
    if (session.expiresAt <= Date.now()) {
        sessions.delete(token);
        return null;
    }
    return session;
}

function createSession(account) {
    const token = crypto.randomBytes(24).toString('base64url');
    const session = {
        id: crypto.randomUUID(),
        token,
        csrfToken: crypto.randomBytes(18).toString('base64url'),
        username: account.username,
        role: account.role,
        tenant: account.tenant,
        displayName: account.displayName,
        expiresAt: Date.now() + sessionTTLMS,
    };
    sessions.set(token, session);
    return session;
}

function sessionCookie(token, maxAge = Math.floor(sessionTTLMS / 1000)) {
    return `wshawk_lab_session=${token}; HttpOnly; SameSite=Lax; Path=/; Max-Age=${maxAge}`;
}

function redirect(response, location, headers = {}) {
    response.writeHead(303, { Location: location, 'Cache-Control': 'no-store', ...headers });
    response.end();
}

function html(response, status, body, headers = {}) {
    response.writeHead(status, {
        'Content-Type': 'text/html; charset=utf-8',
        'Cache-Control': 'no-store',
        'X-Content-Type-Options': 'nosniff',
        ...headers,
    });
    response.end(body);
}

function loginPage(error = '') {
    const errorBlock = error ? `<p class="login-error" role="alert">${escapeHTML(error)}</p>` : '';
    return `<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>WSHawk Lab Login</title>
    <link rel="stylesheet" href="/lab/styles.css">
</head>
<body>
    <main class="auth-shell">
        <section class="card auth-card">
            <p class="eyebrow">AUTH FLOW RECORDING</p>
            <h1>Sign in to the owned lab</h1>
            <p class="lede">Use a disposable identity below while WSHawk's visible recorder is open.</p>
            ${errorBlock}
            <form method="post" action="/login">
                <label for="username">Username</label>
                <input id="username" name="username" autocomplete="username" required autofocus>
                <label for="password">Password</label>
                <input id="password" name="password" type="password" autocomplete="current-password" required>
                <button type="submit">Sign in</button>
            </form>
            <div class="credential-grid" aria-label="Disposable lab accounts">
                <code>user_a / user-a-lab-pass</code>
                <code>user_b / user-b-lab-pass</code>
                <code>admin / admin-lab-pass</code>
            </div>
            <p class="auth-note">Loopback-only test credentials. Never reuse these values outside this lab.</p>
        </section>
    </main>
</body>
</html>`;
}

function dashboardPage(session) {
    const nonce = crypto.randomBytes(16).toString('base64');
    const bootstrap = JSON.stringify({
        accessToken: session.token,
        sessionId: session.id,
        csrfToken: session.csrfToken,
        username: session.username,
        role: session.role,
    }).replaceAll('<', '\\u003c');
    return {
        nonce,
        body: `<!doctype html>
<html lang="en">
<head>
    <meta charset="utf-8">
    <meta name="viewport" content="width=device-width, initial-scale=1">
    <title>Authenticated WSHawk Lab</title>
    <link rel="stylesheet" href="/lab/styles.css">
</head>
<body>
    <main class="auth-shell">
        <section class="card auth-card">
            <p class="eyebrow">AUTHENTICATED SESSION</p>
            <h1>${escapeHTML(session.displayName)}</h1>
            <p class="lede">Identity <code>${escapeHTML(session.username)}</code> has role <code>${escapeHTML(session.role)}</code>.</p>
            <div class="auth-actions">
                <a class="button-link" href="/auth/me">Open session API</a>
                <a class="button-link" href="/auth/resource/resource-a">Secure Resource A</a>
                <a class="button-link" href="/auth/resource/resource-b">Secure Resource B</a>
            </div>
            <form method="post" action="/auth/logout"><button type="submit">Log out</button></form>
            <p class="auth-note">WSHawk can now capture the HttpOnly cookie, bearer token, session ID and CSRF token.</p>
        </section>
    </main>
    <script nonce="${nonce}">
        const auth = ${bootstrap};
        localStorage.setItem('access_token', auth.accessToken);
        localStorage.setItem('auth_user', auth.username);
        localStorage.setItem('auth_role', auth.role);
        sessionStorage.setItem('session_id', auth.sessionId);
        sessionStorage.setItem('csrf_token', auth.csrfToken);
    </script>
</body>
</html>`,
    };
}

async function requestFields(request) {
    const raw = await readBody(request);
    if (String(request.headers['content-type'] || '').includes('application/json')) {
        try { return JSON.parse(raw); } catch (_) { return {}; }
    }
    return Object.fromEntries(new URLSearchParams(raw));
}

function requireSession(request, response) {
    const session = sessionFor(request);
    if (!session) json(response, 401, { error: 'authentication_required', message: 'Sign in through /login and replay the recorded identity.' });
    return session;
}

function staticFile(response, filename, contentType) {
    const absolute = path.join(publicRoot, filename);
    const body = fs.readFileSync(absolute);
    response.writeHead(200, {
        'Content-Type': contentType,
        'Content-Length': body.length,
        'Cache-Control': 'no-store',
        'Content-Security-Policy': "default-src 'self'; connect-src 'self' ws:; style-src 'self'; script-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'",
        'X-Content-Type-Options': 'nosniff',
    });
    response.end(body);
}

function readBody(request) {
    return new Promise((resolve, reject) => {
        const chunks = [];
        let bytes = 0;
        request.on('data', chunk => {
            bytes += chunk.length;
            if (bytes > 1024 * 1024) {
                reject(new Error('lab request body too large'));
                request.destroy();
                return;
            }
            chunks.push(chunk);
        });
        request.on('end', () => resolve(Buffer.concat(chunks).toString('utf8')));
        request.on('error', reject);
    });
}

function json(response, status, value, headers = {}) {
    response.writeHead(status, { 'Content-Type': 'application/json', ...headers });
    response.end(JSON.stringify(value));
}

const server = http.createServer(async (request, response) => {
    const url = new URL(request.url, `http://${host}`);
    if (url.pathname === '/' || url.pathname === '/lab' || url.pathname === '/lab/') return staticFile(response, 'index.html', 'text/html; charset=utf-8');
    if (url.pathname === '/lab/styles.css') return staticFile(response, 'styles.css', 'text/css; charset=utf-8');
    if (url.pathname === '/lab/app.js') return staticFile(response, 'app.js', 'text/javascript; charset=utf-8');
    if (url.pathname === '/lab/manifest') return json(response, 200, { name: 'WSHawk Owned Security Lab', scope: host, http: true, websocket: true, intentionally_vulnerable: true });
    if (url.pathname === '/health') return json(response, 200, { status: 'ready', lab: 'electron-go-industry-parity' });
    if (url.pathname === '/login' && request.method === 'GET') {
        return html(response, 200, loginPage(), {
            'Content-Security-Policy': "default-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
        });
    }
    if (url.pathname === '/login' && request.method === 'POST') {
        const fields = await requestFields(request);
        const account = accounts[String(fields.username || '')];
        if (!account || !safeSecretEqual(fields.password, account.password)) {
            return html(response, 401, loginPage('Invalid lab username or password.'), {
                'Content-Security-Policy': "default-src 'self'; style-src 'self'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'",
            });
        }
        const session = createSession(account);
        return redirect(response, '/auth/dashboard', { 'Set-Cookie': sessionCookie(session.token) });
    }
    if (url.pathname === '/auth/dashboard') {
        const session = sessionFor(request);
        if (!session) return redirect(response, '/login');
        const dashboard = dashboardPage(session);
        return html(response, 200, dashboard.body, {
            'Content-Security-Policy': `default-src 'self'; style-src 'self'; script-src 'nonce-${dashboard.nonce}'; object-src 'none'; base-uri 'none'; frame-ancestors 'none'; form-action 'self'`,
        });
    }
    if (url.pathname === '/auth/me') {
        const session = requireSession(request, response);
        if (!session) return;
        return json(response, 200, {
            authenticated: true,
            username: session.username,
            role: session.role,
            tenant: session.tenant,
            session_id: session.id,
            expires_at: new Date(session.expiresAt).toISOString(),
        });
    }
    if (url.pathname === '/auth/admin') {
        const session = requireSession(request, response);
        if (!session) return;
        if (session.role !== 'admin') return json(response, 403, { error: 'forbidden', message: 'Administrator role required.' });
        return json(response, 200, { role: session.role, secret: 'admin-only-lab-evidence' });
    }
	if (url.pathname === '/auth/admin-insecure') {
		const session = requireSession(request, response); if (!session) return;
		return json(response, 200, { role: 'admin-equivalent', secret: 'vertical-escalation-lab-evidence', actor: session.username, vulnerability: 'intentional-vertical-privilege-escalation' });
	}
    if (url.pathname === '/auth/admin-action' || url.pathname === '/auth/admin-action-insecure') {
        const session = requireSession(request, response);
        if (!session) return;
        if (url.pathname === '/auth/admin-action' && session.role !== 'admin') {
            return json(response, 403, { error: 'forbidden', message: 'Administrator action required.' });
        }
        return json(response, 200, { accepted: true, actor: session.username, privileged_action: 'rotate-lab-secret', vulnerability: url.pathname.endsWith('-insecure') ? 'intentional-bfla' : undefined });
    }
	if (url.pathname === '/auth/admin-operation' || url.pathname === '/auth/admin-operation-insecure') {
		const session = requireSession(request, response);
		if (!session) return;
		const insecure = url.pathname.endsWith('-insecure');
		if (!insecure && session.role !== 'admin') return json(response, 403, { error: 'forbidden', message: 'This operation is reserved for administrators.' });
		return json(response, 200, { executed: true, operation: 'export-all-tenant-secrets', actor: session.username, vulnerability: insecure ? 'intentional-admin-only-bypass' : undefined });
	}
	const missingAuthMatch = url.pathname.match(/^\/auth\/missing-auth(?:-insecure)?\/(resource-[ab](?:-2)?)$/);
	if (missingAuthMatch) {
		const insecure = url.pathname.startsWith('/auth/missing-auth-insecure/');
		const session = sessionFor(request);
		if (!insecure && !session) return json(response, 401, { error: 'authentication_required', message: 'Authentication is required.' });
		return json(response, 200, { ...ownedResources[missingAuthMatch[1]], protected: true, vulnerability: insecure ? 'intentional-missing-authentication' : undefined });
	}
    const secureResourceMatch = url.pathname.match(/^\/auth\/resource\/(resource-[ab](?:-2)?)$/);
    if (secureResourceMatch) {
        const session = requireSession(request, response);
        if (!session) return;
        const resource = ownedResources[secureResourceMatch[1]];
        if (session.role !== 'admin' && resource.owner !== session.username) {
            return json(response, 403, { error: 'forbidden', message: 'The authenticated identity does not own this resource.' });
        }
        return json(response, 200, { ...resource, authorization_control: 'owner-or-admin' });
    }
    const insecureResourceMatch = url.pathname.match(/^\/auth\/resource-insecure\/(resource-[ab](?:-2)?)$/);
    if (insecureResourceMatch) {
        const session = requireSession(request, response);
        if (!session) return;
        const resource = ownedResources[insecureResourceMatch[1]];
        return json(response, 200, {
            ...resource,
            vulnerability: 'intentional-horizontal-idor',
        });
    }
	const uuidResourceMatch = url.pathname.match(/^\/auth\/uuid(?:-insecure)?\/([0-9a-f-]{36})$/i);
	if (uuidResourceMatch && uuidResources[uuidResourceMatch[1]]) {
		const session = requireSession(request, response);
		if (!session) return;
		const resource = uuidResources[uuidResourceMatch[1]];
		const insecure = url.pathname.startsWith('/auth/uuid-insecure/');
		if (!insecure && session.role !== 'admin' && resource.owner !== session.username) return json(response, 403, { error: 'forbidden', message: 'UUID object ownership is enforced.' });
		return json(response, 200, { ...resource, vulnerability: insecure ? 'intentional-uuid-idor' : undefined });
	}
	const numericResourceMatch = url.pathname.match(/^\/auth\/numeric(?:-insecure)?\/(\d+)$/);
	if (numericResourceMatch && numericResources[numericResourceMatch[1]]) {
		const session = requireSession(request, response); if (!session) return;
		const resource = numericResources[numericResourceMatch[1]]; const insecure = url.pathname.startsWith('/auth/numeric-insecure/');
		if (!insecure && session.role !== 'admin' && resource.owner !== session.username) return json(response, 403, { error: 'forbidden', message: 'Numeric object ownership is enforced.' });
		return json(response, 200, { ...resource, vulnerability: insecure ? 'intentional-numeric-idor' : undefined });
	}
	if (url.pathname === '/auth/resource-query' || url.pathname === '/auth/resource-query-insecure') {
		const session = requireSession(request, response); if (!session) return;
		const resource = ownedResources[String(url.searchParams.get('account_id') || '')]; if (!resource) return json(response, 404, { error: 'not_found' });
		const insecure = url.pathname.endsWith('-insecure');
		if (!insecure && session.role !== 'admin' && resource.owner !== session.username) return json(response, 403, { error: 'forbidden', message: 'Query object ownership is enforced.' });
		return json(response, 200, { ...resource, source: 'query', vulnerability: insecure ? 'intentional-query-idor' : undefined });
	}
	if ((url.pathname === '/auth/resource-json' || url.pathname === '/auth/resource-json-insecure') && request.method === 'POST') {
		const session = requireSession(request, response); if (!session) return;
		const fields = await requestFields(request); const resource = ownedResources[String(fields.document_id || '')]; if (!resource) return json(response, 404, { error: 'not_found' });
		const insecure = url.pathname.endsWith('-insecure');
		if (!insecure && session.role !== 'admin' && resource.owner !== session.username) return json(response, 403, { error: 'forbidden', message: 'JSON document ownership is enforced.' });
		return json(response, 200, { ...resource, source: 'json', vulnerability: insecure ? 'intentional-json-idor' : undefined });
	}
	const nestedMatch = url.pathname.match(/^\/auth\/accounts(?:-insecure)?\/([^/]+)\/orders\/([^/]+)$/);
	if (nestedMatch) {
		const session = requireSession(request, response);
		if (!session) return;
		const order = nestedOrders[`${nestedMatch[1]}/${nestedMatch[2]}`];
		if (!order) return json(response, 404, { error: 'not_found' });
		const insecure = url.pathname.startsWith('/auth/accounts-insecure/');
		if (!insecure && session.role !== 'admin' && order.owner !== session.username) return json(response, 403, { error: 'forbidden', message: 'Nested account and order ownership is enforced.' });
		return json(response, 200, { ...order, vulnerability: insecure ? 'intentional-nested-object-idor' : undefined });
	}
    const tenantResourceMatch = url.pathname.match(/^\/auth\/tenant(?:-insecure)?\/(resource-[ab](?:-2)?)$/);
    if (tenantResourceMatch) {
        const session = requireSession(request, response);
        if (!session) return;
        const resource = ownedResources[tenantResourceMatch[1]];
        const insecure = url.pathname.startsWith('/auth/tenant-insecure/');
        if (!insecure && session.role !== 'admin' && resource.tenant !== session.tenant) {
            return json(response, 403, { error: 'forbidden', message: 'Cross-tenant resource access denied.' });
        }
        return json(response, 200, { ...resource, authorization_control: insecure ? 'none' : 'tenant-or-admin', vulnerability: insecure ? 'intentional-tenant-isolation-bypass' : undefined });
    }
    const writeResourceMatch = url.pathname.match(/^\/auth\/resource(?:-insecure)?\/(resource-[ab](?:-2)?)\/note$/);
    if (writeResourceMatch && ['PUT', 'PATCH'].includes(request.method)) {
        const session = requireSession(request, response);
        if (!session) return;
        const resource = ownedResources[writeResourceMatch[1]];
        const insecure = url.pathname.startsWith('/auth/resource-insecure/');
        if (!insecure && session.role !== 'admin' && resource.owner !== session.username) {
            return json(response, 403, { error: 'forbidden', message: 'The authenticated identity does not own this resource.' });
        }
		const fields = await requestFields(request);
		const previous = { ...writeState.get(resource.id) };
		const next = { ...previous, note: String(fields.note || '') };
		writeState.set(resource.id, next);
		const rollbackToken = crypto.randomUUID();
		rollbackTokens.set(rollbackToken, { id: resource.id, previous });
		return json(response, 200, { updated: true, id: resource.id, owner: next.owner, requested_note: next.note, rollback_token: rollbackToken, vulnerability: insecure ? 'intentional-write-idor' : undefined });
    }
	const writeStateMatch = url.pathname.match(/^\/auth\/write-state\/(resource-[ab](?:-2)?)$/);
	if (writeStateMatch) {
		const session = requireSession(request, response);
		if (!session) return;
		return json(response, 200, { id: writeStateMatch[1], ...writeState.get(writeStateMatch[1]) });
	}
	if (url.pathname === '/auth/rollback' && request.method === 'POST') {
		const session = requireSession(request, response);
		if (!session) return;
		const fields = await requestFields(request);
		const rollback = rollbackTokens.get(String(fields.rollback_token || ''));
		if (!rollback) return json(response, 400, { error: 'invalid_rollback_token' });
		writeState.set(rollback.id, rollback.previous);
		rollbackTokens.delete(String(fields.rollback_token));
		return json(response, 200, { rolled_back: true, id: rollback.id });
	}
	const transferMatch = url.pathname.match(/^\/auth\/ownership-transfer(?:-insecure)?\/(resource-[ab](?:-2)?)$/);
	if (transferMatch && request.method === 'POST') {
		const session = requireSession(request, response);
		if (!session) return;
		const state = writeState.get(transferMatch[1]);
		const insecure = url.pathname.startsWith('/auth/ownership-transfer-insecure/');
		if (!insecure && session.role !== 'admin' && state.owner !== session.username) return json(response, 403, { error: 'forbidden', message: 'Only the owner or an administrator may transfer ownership.' });
		const fields = await requestFields(request);
		const previous = { ...state };
		const nextOwner = String(fields.new_owner || 'user_a');
		writeState.set(transferMatch[1], { ...state, owner: nextOwner });
		const rollbackToken = crypto.randomUUID(); rollbackTokens.set(rollbackToken, { id: transferMatch[1], previous });
		return json(response, 200, { transferred: true, id: transferMatch[1], previous_owner: previous.owner, owner: nextOwner, rollback_token: rollbackToken, vulnerability: insecure ? 'intentional-ownership-transfer-bypass' : undefined });
	}
	const massAssignmentMatch = url.pathname.match(/^\/auth\/mass-assignment(?:-insecure)?\/(resource-[ab](?:-2)?)$/);
	if (massAssignmentMatch && ['PUT', 'PATCH'].includes(request.method)) {
		const session = requireSession(request, response);
		if (!session) return;
		const fields = await requestFields(request);
		const insecure = url.pathname.startsWith('/auth/mass-assignment-insecure/');
		if (!insecure && session.role !== 'admin' && (Object.hasOwn(fields, 'owner') || Object.hasOwn(fields, 'role') || Object.hasOwn(fields, 'tenant'))) return json(response, 403, { error: 'protected_field', message: 'Owner, role, and tenant fields cannot be mass assigned.' });
		return json(response, 200, { accepted_fields: Object.keys(fields), owner: insecure ? fields.owner : writeState.get(massAssignmentMatch[1]).owner, role: insecure ? fields.role : session.role, vulnerability: insecure ? 'intentional-mass-assignment' : undefined });
	}
    if (url.pathname === '/graphql' && request.method === 'POST') {
        const session = requireSession(request, response);
        if (!session) return;
        const document = await requestFields(request);
        const query = String(document.query || '');
        const resource = ownedResources[String(document.variables?.id || '')];
        if (!resource) return json(response, 200, { data: null, errors: [{ message: 'Resource not found' }] });
        const insecure = /resourceInsecure/i.test(query);
        if (!insecure && session.role !== 'admin' && resource.owner !== session.username) {
            return json(response, 200, { data: null, errors: [{ message: 'Forbidden', extensions: { code: 'FORBIDDEN' } }] });
        }
        const field = insecure ? 'resourceInsecure' : 'resource';
        return json(response, 200, { data: { [field]: { ...resource, secret: `graphql-${resource.id}-secret` } }, extensions: { request_id: crypto.randomUUID() } });
    }
    if (url.pathname === '/auth/logout' && request.method === 'POST') {
        const session = sessionFor(request);
        if (session) sessions.delete(session.token);
        return redirect(response, '/login', { 'Set-Cookie': sessionCookie('', 0) });
    }
    if (url.pathname === '/auth/expire' && request.method === 'POST') {
        const session = requireSession(request, response);
        if (!session) return;
        sessions.delete(session.token);
        return json(response, 200, { expired: true, session_id: session.id }, { 'Set-Cookie': sessionCookie('', 0) });
    }
    if (url.pathname === '/scan') {
        const value = url.searchParams.get('q') || '';
        if (/['"`]/.test(value)) return json(response, 500, { error: 'SQL syntax error near quote', reflected: value });
        response.writeHead(200, { 'Content-Type': 'text/html' });
        return response.end(`<main data-lab="scan">${value}</main>`);
    }
	if (url.pathname === '/safe') return json(response, 200, { status: 'ok', message: 'constant response' });
    if (url.pathname === '/command') {
        const value = url.searchParams.get('q') || '';
        return json(response, 200, value.includes('WSHK_CMD_PROBE') ? { output: 'WSHK_CMD_PROBE' } : { output: 'clean' });
    }
    if (url.pathname === '/traversal') {
        const value = url.searchParams.get('q') || '';
        if (value.includes('etc/passwd')) return response.end('root:x:0:0:lab:/root:/bin/sh');
        if (value.toLowerCase().includes('win.ini')) return response.end('[fonts]\n[extensions]');
        return response.end('not found');
    }
    if (url.pathname === '/nosql' || url.pathname === '/prototype') {
        let document = {};
        try { document = JSON.parse(await readBody(request)); } catch (_) {}
        if (url.pathname === '/nosql' && document.user && typeof document.user === 'object' && Object.hasOwn(document.user, '$ne')) return json(response, 200, { matched: '$ne' });
        if (url.pathname === '/prototype' && Object.hasOwn(document, '__proto__')) return json(response, 200, { marker: 'wshawk_probe' });
        return json(response, 200, { matched: false });
    }
    if (url.pathname === '/xxe') {
        const body = await readBody(request);
        if (body.includes('<!DOCTYPE') && body.includes('nonexistent-wshawk-probe')) return json(response, 500, { error: 'cannot resolve nonexistent-wshawk-probe' });
        return json(response, 200, { parsed: true });
    }
    if (url.pathname === '/ssrf') {
        const target = url.searchParams.get('url') || '';
        if (/^http:\/\/127\.0\.0\.1:\d+\/oast-callback$/.test(target)) await fetch(target);
        return json(response, 200, { accepted: Boolean(target) });
    }
    if (url.pathname === '/oast-callback') { oastInteractions += 1; return json(response, 200, { received: true }); }
    if (url.pathname === '/oast-status') return json(response, 200, { interactions: oastInteractions });
    if (url.pathname === '/headers') {
        response.writeHead(200, { 'Content-Type': 'text/html', 'X-Powered-By': 'WSHawk-Lab/1' });
        return response.end('<form action="/race"><input name="value"></form>');
    }
    if (url.pathname === '/cors') return json(response, 200, { cors: 'intentionally weak' }, { 'Access-Control-Allow-Origin': '*', 'Access-Control-Allow-Credentials': 'true' });
    if (url.pathname === '/cors-reflect') {
        const origin = request.headers.origin || '';
        return json(response, 200, { cors: 'intentionally reflects Origin' }, { 'Access-Control-Allow-Origin': origin, 'Access-Control-Allow-Credentials': 'true', Vary: 'Origin' });
    }
    if (url.pathname === '/sensitive') return json(response, 200, { token: 'eyJhbGciOiJub25lIn0.eyJsYWIiOnRydWV9.c2lnbmF0dXJl' });
    if (url.pathname === '/dom-xss') {
        response.writeHead(200, { 'Content-Type': 'text/html', 'Content-Security-Policy': "default-src 'self' 'unsafe-inline'" });
        return response.end(`<main id="result">${url.searchParams.get('payload') || ''}</main>`);
    }
    if (url.pathname === '/auth-state') {
        response.writeHead(200, { 'Content-Type': 'text/html', 'Set-Cookie': 'wshawk_lab_session=authorized; HttpOnly; SameSite=Lax' });
        return response.end('<title>Authenticated lab</title><script>localStorage.setItem("access_token", "authorized-lab-token"); sessionStorage.setItem("session_id", "lab-session");</script><main>Authenticated</main>');
    }
    if (url.pathname === '/redirect') { response.writeHead(302, { Location: url.searchParams.get('next') || '/' }); return response.end(); }
    if (url.pathname === '/auth') {
        const role = request.headers['x-lab-role'] || 'guest';
        return json(response, role === 'admin' ? 200 : 403, { role, secret: role === 'admin' ? 'lab-only' : undefined });
    }
    if (url.pathname === '/race') { const observed = raceValue; await new Promise(resolve => setTimeout(resolve, 15)); raceValue = observed + 1; return json(response, 200, { observed, committed: raceValue }); }
    if (url.pathname === '/slow') {
        const requestedDelay = Number.parseInt(url.searchParams.get('delay_ms') || '500', 10);
        const delayMS = Math.min(15_000, Math.max(0, Number.isFinite(requestedDelay) ? requestedDelay : 500));
        await new Promise(resolve => setTimeout(resolve, delayMS));
        return json(response, 200, { slow: true, delay_ms: delayMS, q: url.searchParams.get('q') });
    }
    return json(response, 404, { error: 'not found' });
});

const sockets = new WebSocketServer({ noServer: true, maxPayload: 8 * 1024 * 1024 });
server.on('upgrade', (request, socket, head) => {
    const url = new URL(request.url, `http://${host}`);
    if (!['/ws/echo', '/ws/auth', '/ws/room-secure', '/ws/room-insecure', '/ws/subscription-secure', '/ws/subscription-insecure'].includes(url.pathname)) return socket.destroy();
    if (url.pathname === '/ws/auth' && request.headers['x-lab-token'] !== 'authorized-lab-token') {
        socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
        return socket.destroy();
    }
    if (url.pathname === '/ws/room-secure' || url.pathname === '/ws/room-insecure') {
        const session = sessionFor(request);
        if (!session) {
            socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n');
            return socket.destroy();
        }
        const room = url.searchParams.get('room') || '';
        if (url.pathname === '/ws/room-secure' && session.role !== 'admin' && room !== session.username && room !== session.tenant) {
            socket.write('HTTP/1.1 403 Forbidden\r\nConnection: close\r\n\r\n');
            return socket.destroy();
        }
        request.wshawkLabSession = session;
    }
	if (url.pathname === '/ws/subscription-secure' || url.pathname === '/ws/subscription-insecure') {
		const session = sessionFor(request);
		if (!session) { socket.write('HTTP/1.1 401 Unauthorized\r\nConnection: close\r\n\r\n'); return socket.destroy(); }
		request.wshawkLabSession = session;
	}
    sockets.handleUpgrade(request, socket, head, connection => sockets.emit('connection', connection, request));
});
sockets.on('connection', (socket, request) => {
    if (!request.url.startsWith('/ws/subscription-')) socket.send(JSON.stringify({ type: 'ready', path: request.url }));
    if (request.url.startsWith('/ws/room-')) {
        const room = new URL(request.url, `http://${host}`).searchParams.get('room');
        socket.send(JSON.stringify({ type: 'private-room', room, owner: room, secret: `room-${room}-evidence`, viewer: request.wshawkLabSession?.username }));
    }
	socket.on('message', (data, binary) => {
		if (request.url.startsWith('/ws/subscription-')) {
			let message = {}; try { message = JSON.parse(data.toString()); } catch (_) {}
			const room = String(message.room || message.channel || message.tenant || '');
			const insecure = request.url.startsWith('/ws/subscription-insecure');
			const session = request.wshawkLabSession;
			if (!insecure && session.role !== 'admin' && room !== session.username && room !== session.tenant) return socket.send(JSON.stringify({ type: 'error', code: 'FORBIDDEN', message: 'Subscription access denied.' }));
			return socket.send(JSON.stringify({ type: 'event', room, owner: room, secret: `subscription-${room}-evidence`, viewer: session.username, vulnerability: insecure ? 'intentional-subscription-authorization-bypass' : undefined }));
		}
		socket.send(data, { binary });
	});
});

server.listen(requestedPort, host, () => {
    const address = server.address();
    process.stdout.write(`${JSON.stringify({ ready: true, host, port: address.port, http: `http://${host}:${address.port}`, ws: `ws://${host}:${address.port}/ws/echo` })}\n`);
});

function shutdown() { sockets.close(); server.close(() => process.exit(0)); }
process.on('SIGINT', shutdown);
process.on('SIGTERM', shutdown);
