'use strict';

const assert = require('assert');
const fs = require('fs');
const os = require('os');
const path = require('path');
const test = require('node:test');

const { assembleRelease, parseArguments, platformFor } = require('../scripts/assemble-release');

test('release assembler requires complete native package coverage', () => {
    const root = fs.mkdtempSync(path.join(os.tmpdir(), 'wshawk-release-'));
    const artifacts = path.join(root, 'artifacts');
    const output = path.join(root, 'output');
    const packageNames = [
        'wshawk-electron-go-4.0.3-win-x64.exe',
        'wshawk-electron-go-4.0.3-linux-x86_64.AppImage',
        'wshawk-electron-go-4.0.3-linux-amd64.deb',
        'wshawk-electron-go-4.0.3-linux-x64.tar.gz',
        'wshawk-electron-go-4.0.3-mac-arm64.dmg',
        'wshawk-electron-go-4.0.3-mac-arm64.zip',
    ];
    fs.mkdirSync(path.join(artifacts, 'native'), { recursive: true });
    for (const name of packageNames) fs.writeFileSync(path.join(artifacts, 'native', name), name, 'utf8');

    const result = assembleRelease({ artifacts, output, tag: 'v4.0.3', repository: 'owner/wshawk' });
    assert.strictEqual(result.releaseTag, 'electron-go-v4.0.3');
    assert.strictEqual(result.packages.length, packageNames.length);
    for (const name of packageNames) assert.match(result.notes, new RegExp(name.replaceAll('.', '\\.')));

    const checksums = fs.readFileSync(path.join(output, 'SHA256SUMS-ELECTRON-GO.txt'), 'utf8').trim().split('\n');
    assert.strictEqual(checksums.length, packageNames.length);
    assert.ok(checksums.every(line => /^[a-f0-9]{64}  wshawk-electron-go-/.test(line)));
});

test('release helpers reject incomplete arguments and identify platforms', () => {
    assert.throws(() => parseArguments(['--tag', 'v4.0.3']), /Missing --artifacts/);
    assert.strictEqual(platformFor('wshawk.exe'), 'Windows');
    assert.strictEqual(platformFor('wshawk.AppImage'), 'Linux');
    assert.strictEqual(platformFor('wshawk.dmg'), 'macOS');
});

test('Electron workflow uses pinned actions and a separate release tag', () => {
    const workflow = fs.readFileSync(path.resolve(__dirname, '../../.github/workflows/electron-go-release.yml'), 'utf8');
    const actionReferences = [...workflow.matchAll(/^\s*-\s*uses:\s*([^\s#]+)/gm)].map(match => match[1]);
    assert.ok(actionReferences.length >= 8);
    assert.ok(actionReferences.every(reference => reference.startsWith('./') || /@[a-f0-9]{40}$/.test(reference)));
    assert.match(workflow, /tags:\s*\n\s+- "v\*\.\*\.\*"/);
    assert.match(workflow, /tag_name: electron-go-\$\{\{ github\.ref_name \}\}/);
    assert.match(workflow, /test:lifecycle:win/);

    const pythonPublish = fs.readFileSync(path.resolve(__dirname, '../../.github/workflows/python-publish.yml'), 'utf8');
    assert.match(pythonPublish, /startsWith\(github\.event\.release\.tag_name, 'v'\)/);
});
