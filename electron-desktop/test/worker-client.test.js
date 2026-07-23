'use strict';

const path = require('path');
const test = require('node:test');
const assert = require('node:assert/strict');

const { WorkerClient } = require('../main/worker-client');

test('worker client exchanges versioned RPC and stops cleanly', async () => {
    const fixture = path.join(__dirname, 'fixtures', 'rpc-worker.js');
    const client = new WorkerClient({
        executable: process.execPath,
        args: [fixture],
        cwd: path.dirname(fixture),
        requestTimeoutMs: 2_000,
    });
    const statuses = [];
    client.on('status', status => statuses.push(status.state));

    await client.start();
    const health = await client.request('system.health');
    assert.equal(health.status, 'ready');
    await client.stop();

    await new Promise(resolve => setTimeout(resolve, 100));
    assert.ok(statuses.includes('running'));
    assert.ok(statuses.includes('stopped'));
});
test('worker client rejects methods outside the Go allowlist', async () => {
    const client = new WorkerClient({ executable: process.execPath });
    await assert.rejects(client.request('network.listen'), /Unsupported Go worker method/);
});
