'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const projectRoot = path.resolve(__dirname, '..');
const backendRoot = path.join(projectRoot, 'backend-go');
const binRoot = path.join(projectRoot, 'bin');
const executableName = process.platform === 'win32' ? 'wshawk-worker.exe' : 'wshawk-worker';
const outputPath = path.join(binRoot, executableName);
const goCache = path.join(projectRoot, '.cache', 'go-build');
const goPath = path.join(projectRoot, '.cache', 'go-path');

fs.mkdirSync(binRoot, { recursive: true });
fs.mkdirSync(goCache, { recursive: true });
fs.mkdirSync(goPath, { recursive: true });
const result = spawnSync(
    'go',
    ['build', '-trimpath', '-o', outputPath, './cmd/wshawk-worker'],
    {
        cwd: backendRoot,
        encoding: 'utf8',
        shell: false,
        env: { ...process.env, GOCACHE: goCache, GOPATH: goPath },
    },
);

if (result.status !== 0) {
    process.stderr.write(result.stderr || result.stdout || 'Go worker build failed\n');
    process.exit(result.status || 1);
}

process.stdout.write(`Built private Go worker: ${outputPath}\n`);
