'use strict';

const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const projectRoot = path.resolve(__dirname, '..');
const goCache = path.join(projectRoot, '.cache', 'go-build');
const goPath = path.join(projectRoot, '.cache', 'go-path');
fs.mkdirSync(goCache, { recursive: true });
fs.mkdirSync(goPath, { recursive: true });

for (const args of [['test', './...'], ['vet', './...']]) {
    const result = spawnSync('go', args, {
        cwd: path.join(projectRoot, 'backend-go'),
        encoding: 'utf8',
        shell: false,
        env: { ...process.env, GOCACHE: goCache, GOPATH: goPath },
    });
    process.stdout.write(result.stdout || '');
    process.stderr.write(result.stderr || '');
    if (result.error) throw result.error;
    if (result.status !== 0) process.exit(result.status || 1);
}
