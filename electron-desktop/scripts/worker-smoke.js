'use strict';

const path = require('path');
const fs = require('fs');
const os = require('os');
const { WorkerClient } = require('../main/worker-client');

async function main() {
    const projectRoot = path.resolve(__dirname, '..');
    const executableName = process.platform === 'win32' ? 'wshawk-worker.exe' : 'wshawk-worker';
	const dataDir = fs.mkdtempSync(path.join(os.tmpdir(), 'wshawk-worker-smoke-'));
    const client = new WorkerClient({
        executable: path.join(projectRoot, 'bin', executableName),
		args: ['--data-dir', dataDir],
		cwd: dataDir,
        requestTimeoutMs: 5_000,
    });

    await client.start();
    const health = await client.request('system.health');
    const capabilities = await client.request('system.capabilities');
    if (health.backend !== 'go' || health.transport !== 'stdio-json-rpc' || health.noNetworkBridge !== true) {
        throw new Error(`Unexpected health response: ${JSON.stringify(health)}`);
    }
    if (capabilities.protocolVersion !== '1') {
        throw new Error(`Unexpected capabilities response: ${JSON.stringify(capabilities)}`);
    }
    await client.stop();
    process.stdout.write(`Go worker smoke passed (PID ${health.pid}, protocol ${capabilities.protocolVersion}).\n`);
}

main().catch((error) => {
    process.stderr.write(`${error.stack || error.message}\n`);
    process.exitCode = 1;
});
