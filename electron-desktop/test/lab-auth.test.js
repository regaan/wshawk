'use strict';

const path = require('path');
const { spawn } = require('child_process');
const test = require('node:test');
const assert = require('node:assert/strict');

const labServer = path.resolve(__dirname, '..', 'labs', 'server.js');

function startLab() {
    return new Promise((resolve, reject) => {
        const child = spawn(process.execPath, [labServer], {
            env: { ...process.env, WSHAWK_LAB_PORT: '0' },
            stdio: ['ignore', 'pipe', 'pipe'],
        });
        let stdout = '';
        let stderr = '';
        const timer = setTimeout(() => {
            child.kill();
            reject(new Error(`lab startup timed out: ${stderr}`));
        }, 10_000);
        child.stderr.on('data', chunk => { stderr += chunk.toString(); });
        child.stdout.on('data', chunk => {
            stdout += chunk.toString();
            const newline = stdout.indexOf('\n');
            if (newline < 0) return;
            clearTimeout(timer);
            try {
                const ready = JSON.parse(stdout.slice(0, newline));
                resolve({ child, origin: ready.http });
            } catch (error) {
                child.kill();
                reject(error);
            }
        });
        child.once('error', error => {
            clearTimeout(timer);
            reject(error);
        });
        child.once('exit', code => {
            if (code && !stdout.includes('\n')) {
                clearTimeout(timer);
                reject(new Error(`lab exited with ${code}: ${stderr}`));
            }
        });
    });
}

async function login(origin, username, password) {
    const response = await fetch(`${origin}/login`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/x-www-form-urlencoded' },
        body: new URLSearchParams({ username, password }),
        redirect: 'manual',
    });
    const setCookie = response.headers.get('set-cookie') || '';
    return {
        response,
        cookie: setCookie.split(';', 1)[0],
        token: setCookie.match(/wshawk_lab_session=([^;]+)/)?.[1] || '',
    };
}

test('owned lab supports recordable multi-account authentication and authorization controls', async (t) => {
    const lab = await startLab();
    t.after(() => lab.child.kill());

    const loginPage = await fetch(`${lab.origin}/login`);
    assert.equal(loginPage.status, 200);
    const loginHTML = await loginPage.text();
    assert.match(loginHTML, /user_a \/ user-a-lab-pass/);
    assert.match(loginHTML, /user_b \/ user-b-lab-pass/);
    assert.match(loginHTML, /admin \/ admin-lab-pass/);

    const rejected = await login(lab.origin, 'user_a', 'wrong-password');
    assert.equal(rejected.response.status, 401);
    assert.equal(rejected.cookie, '');

    const userA = await login(lab.origin, 'user_a', 'user-a-lab-pass');
    const userB = await login(lab.origin, 'user_b', 'user-b-lab-pass');
    const admin = await login(lab.origin, 'admin', 'admin-lab-pass');
    for (const identity of [userA, userB, admin]) {
        assert.equal(identity.response.status, 303);
        assert.equal(identity.response.headers.get('location'), '/auth/dashboard');
        assert.ok(identity.cookie.startsWith('wshawk_lab_session='));
        assert.ok(identity.token.length >= 32);
    }

    const dashboard = await fetch(`${lab.origin}/auth/dashboard`, { headers: { Cookie: userA.cookie } });
    assert.equal(dashboard.status, 200);
    const dashboardHTML = await dashboard.text();
    assert.match(dashboardHTML, /localStorage\.setItem\('access_token'/);
    assert.match(dashboardHTML, /sessionStorage\.setItem\('csrf_token'/);

    const meFromCookie = await fetch(`${lab.origin}/auth/me`, { headers: { Cookie: userA.cookie } });
    assert.equal(meFromCookie.status, 200);
    assert.deepEqual((await meFromCookie.json()).username, 'user_a');

    const meFromBearer = await fetch(`${lab.origin}/auth/me`, { headers: { Authorization: `Bearer ${userB.token}` } });
    assert.equal(meFromBearer.status, 200);
    assert.deepEqual((await meFromBearer.json()).username, 'user_b');

    const userAOwnObject = await fetch(`${lab.origin}/auth/resource/resource-a`, { headers: { Cookie: userA.cookie } });
    const userBBlockedFromA = await fetch(`${lab.origin}/auth/resource/resource-a`, { headers: { Cookie: userB.cookie } });
    assert.equal(userAOwnObject.status, 200);
    assert.equal(userBBlockedFromA.status, 403);

    const intentionalIDOR = await fetch(`${lab.origin}/auth/resource-insecure/resource-a`, { headers: { Cookie: userB.cookie } });
    assert.equal(intentionalIDOR.status, 200);
    const exposedObject = await intentionalIDOR.json();
    assert.equal(exposedObject.owner, 'user_a');
    assert.equal(exposedObject.vulnerability, 'intentional-horizontal-idor');

	const secondIDOR = await fetch(`${lab.origin}/auth/resource-insecure/resource-a-2`, { headers: { Cookie: userB.cookie } });
	assert.equal(secondIDOR.status, 200);
	assert.equal((await secondIDOR.json()).owner, 'user_a');

	const tenantBlocked = await fetch(`${lab.origin}/auth/tenant/resource-b`, { headers: { Cookie: userA.cookie } });
	const tenantBypass = await fetch(`${lab.origin}/auth/tenant-insecure/resource-b`, { headers: { Cookie: userA.cookie } });
	assert.equal(tenantBlocked.status, 403);
	assert.equal(tenantBypass.status, 200);

	const graphqlDenied = await fetch(`${lab.origin}/graphql`, {
		method: 'POST', headers: { Cookie: userA.cookie, 'Content-Type': 'application/json' },
		body: JSON.stringify({ query: 'query($id: ID!){ resource(id:$id){ id secret } }', variables: { id: 'resource-b' } }),
	});
	assert.equal(graphqlDenied.status, 200);
	assert.ok((await graphqlDenied.json()).errors?.length);
	const graphqlIDOR = await fetch(`${lab.origin}/graphql`, {
		method: 'POST', headers: { Cookie: userA.cookie, 'Content-Type': 'application/json' },
		body: JSON.stringify({ query: 'query($id: ID!){ resourceInsecure(id:$id){ id secret } }', variables: { id: 'resource-b' } }),
	});
	assert.equal((await graphqlIDOR.json()).data.resourceInsecure.owner, 'user_b');

	const secureWrite = await fetch(`${lab.origin}/auth/resource/resource-b/note`, {
		method: 'PATCH', headers: { Cookie: userA.cookie, 'Content-Type': 'application/json' }, body: JSON.stringify({ note: 'bounded-test' }),
	});
	const insecureWrite = await fetch(`${lab.origin}/auth/resource-insecure/resource-b/note`, {
		method: 'PATCH', headers: { Cookie: userA.cookie, 'Content-Type': 'application/json' }, body: JSON.stringify({ note: 'bounded-test' }),
	});
	assert.equal(secureWrite.status, 403);
	assert.equal(insecureWrite.status, 200);
	const insecureWriteBody = await insecureWrite.json();
	assert.ok(insecureWriteBody.rollback_token);
	const rollback = await fetch(`${lab.origin}/auth/rollback`, { method: 'POST', headers: { Cookie: userA.cookie, 'Content-Type': 'application/json' }, body: JSON.stringify({ rollback_token: insecureWriteBody.rollback_token }) });
	assert.equal(rollback.status, 200);
	assert.equal((await rollback.json()).rolled_back, true);

    const userAdminCheck = await fetch(`${lab.origin}/auth/admin`, { headers: { Cookie: userA.cookie } });
    const adminCheck = await fetch(`${lab.origin}/auth/admin`, { headers: { Cookie: admin.cookie } });
    assert.equal(userAdminCheck.status, 403);
    assert.equal(adminCheck.status, 200);
	const bflaBlocked = await fetch(`${lab.origin}/auth/admin-action`, { headers: { Cookie: userA.cookie } });
	const bflaVulnerable = await fetch(`${lab.origin}/auth/admin-action-insecure`, { headers: { Cookie: userA.cookie } });
	assert.equal(bflaBlocked.status, 403);
	assert.equal(bflaVulnerable.status, 200);

    const expired = await fetch(`${lab.origin}/auth/expire`, { method: 'POST', headers: { Cookie: userA.cookie } });
    assert.equal(expired.status, 200);
    const rejectedExpiredSession = await fetch(`${lab.origin}/auth/me`, { headers: { Cookie: userA.cookie } });
    assert.equal(rejectedExpiredSession.status, 401);

    const logout = await fetch(`${lab.origin}/auth/logout`, { method: 'POST', headers: { Cookie: userB.cookie }, redirect: 'manual' });
    assert.equal(logout.status, 303);
    const rejectedLoggedOutSession = await fetch(`${lab.origin}/auth/me`, { headers: { Cookie: userB.cookie } });
    assert.equal(rejectedLoggedOutSession.status, 401);
});
