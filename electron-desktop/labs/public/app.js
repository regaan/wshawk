'use strict';

const origin = location.origin;
const websocketURL = `ws://${location.host}/ws/echo`;
const targets = [
    ['SQL injection + reflected XSS', '/scan?q=baseline', 'SQL error and reflected canary'],
    ['Command injection', '/command?q=baseline', 'Execution marker without original payload'],
    ['Path traversal', '/traversal?q=baseline', 'Unix and Windows file markers'],
    ['NoSQL operator injection', '/nosql', 'POST JSON field accepts an operator object'],
    ['Prototype pollution', '/prototype', 'POST JSON accepts a top-level __proto__ key'],
    ['XXE', '/xxe', 'POST XML produces a controlled entity-resolution error'],
    ['SSRF + OAST', '/ssrf?url=VALUE', 'Owned callback reaches /oast-callback'],
    ['Open redirect', '/redirect?next=VALUE', 'External Location header accepted'],
    ['Authorization difference', '/auth', 'guest=403, admin=200 via X-Lab-Role'],
    ['Browser authentication', '/login', 'Records separate User A, User B and Admin sessions'],
    ['Secure object authorization', '/auth/resource/resource-a', 'Owner/admin allowed; other user receives 403'],
    ['Intentional horizontal IDOR', '/auth/resource-insecure/resource-a', 'Any signed-in lab user can read the object'],
    ['Vertical authorization', '/auth/admin', 'Admin allowed; normal users receive 403'],
    ['Race condition', '/race', 'Concurrent state-changing requests accepted'],
    ['Weak headers / CSRF', '/headers', 'Missing defenses and form without token'],
    ['CORS', '/cors', 'Wildcard origin with credentials'],
    ['Sensitive data', '/sensitive', 'JWT-like response value'],
    ['WebSocket echo', websocketURL, 'Text and binary frame echo'],
    ['Authenticated WebSocket', `ws://${location.host}/ws/auth`, 'Requires X-Lab-Token: authorized-lab-token'],
];

function show(id, value) { document.getElementById(id).textContent = String(value); }
function pretty(value) { return JSON.stringify(value, null, 2); }

async function refresh() {
    const status = document.getElementById('lab-status');
    try {
        const [healthResponse, oastResponse] = await Promise.all([fetch('/health'), fetch('/oast-status')]);
        const health = await healthResponse.json();
        const oast = await oastResponse.json();
        status.className = 'status ready'; status.textContent = 'LAB READY';
        show('health-value', health.status);
        show('ws-value', 'echo ready');
        show('oast-value', oast.interactions);
    } catch (error) {
        status.className = 'status error'; status.textContent = 'LAB ERROR';
        show('health-value', error.message);
    }
}

document.getElementById('lab-origin').textContent = origin;
document.getElementById('target-matrix').replaceChildren(...targets.map(([feature, target, expected]) => {
    const row = document.createElement('tr');
    for (const value of [feature, target, expected]) {
        const cell = document.createElement('td');
        if (value === target) { const code = document.createElement('code'); code.textContent = value; cell.append(code); }
        else cell.textContent = value;
        row.append(cell);
    }
    return row;
}));
document.getElementById('dom-link').href = `/dom-xss?payload=${encodeURIComponent("<script>alert('wshawk_xss_probe')</script>")}`;
document.querySelector('[data-copy="origin"]').addEventListener('click', () => navigator.clipboard.writeText(origin));
document.getElementById('refresh-btn').addEventListener('click', refresh);
document.getElementById('auth-btn').addEventListener('click', async () => {
    const role = document.getElementById('role-select').value;
    const response = await fetch('/auth', { headers: { 'X-Lab-Role': role } });
    show('auth-output', pretty({ status: response.status, body: await response.json() }));
});
document.getElementById('ws-btn').addEventListener('click', () => {
    const output = document.getElementById('ws-output');
    const socket = new WebSocket(websocketURL);
    const messages = [];
    socket.addEventListener('open', () => socket.send(document.getElementById('ws-payload').value));
    socket.addEventListener('message', event => {
        messages.push(event.data);
        output.textContent = messages.join('\n');
        if (messages.length >= 2) socket.close();
    });
    socket.addEventListener('error', () => { output.textContent = 'WebSocket connection failed.'; });
});

refresh();
