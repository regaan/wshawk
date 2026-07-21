#!/usr/bin/env node
const fs = require('fs');
const path = require('path');
const { spawnSync } = require('child_process');

const desktopDir = path.resolve(__dirname, '..');
const repoDir = path.resolve(desktopDir, '..');
const roots = [
    path.join(desktopDir, 'index.js'),
    path.join(desktopDir, 'preload.js'),
    path.join(desktopDir, 'scripts'),
    path.join(desktopDir, 'src'),
    path.join(repoDir, 'extension'),
];
const ignoredDirectories = new Set(['dist', 'node_modules']);

function collectJavaScript(target, files = []) {
    const stat = fs.statSync(target);
    if (stat.isFile()) {
        if (target.endsWith('.js')) files.push(target);
        return files;
    }

    for (const entry of fs.readdirSync(target, { withFileTypes: true })) {
        if (entry.isDirectory() && ignoredDirectories.has(entry.name)) continue;
        collectJavaScript(path.join(target, entry.name), files);
    }
    return files;
}

const files = roots.flatMap((target) => collectJavaScript(target));
const failures = [];

for (const file of files) {
    const result = spawnSync(process.execPath, ['--check', file], {
        cwd: repoDir,
        encoding: 'utf8',
    });
    if (result.status !== 0) {
        failures.push({
            file: path.relative(repoDir, file),
            output: (result.stderr || result.stdout || '').trim(),
        });
    }
}

if (failures.length > 0) {
    console.error(JSON.stringify({ status: 'error', failures }, null, 2));
    process.exit(1);
}

console.log(`JavaScript syntax check passed for ${files.length} files.`);
