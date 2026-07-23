'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const root = path.resolve(__dirname, '..');
const output = path.join(root, 'dist-electron-go');
const packageInfo = require(path.join(root, 'package.json'));
fs.mkdirSync(output, { recursive: true });

const artifacts = fs.readdirSync(output, { withFileTypes: true })
    .filter(entry => entry.isFile() && !/\.ya?ml$|\.blockmap$|RELEASE-NOTES|SHA256SUMS|LIFECYCLE/i.test(entry.name))
    .map(entry => {
        const target = path.join(output, entry.name);
        const data = fs.readFileSync(target);
        return { name: entry.name, bytes: data.length, sha256: crypto.createHash('sha256').update(data).digest('hex') };
    });

const notes = [
    `# WSHawk Electron + Go ${packageInfo.version}`,
    '',
    'This edition uses a sandboxed Electron renderer and a private stdio JSON-RPC Go worker. It does not start a localhost control bridge and remains independent from the classic desktop application.',
    '',
    '## Included',
    '',
    '- Componentized WSHawk interface with direct IPC transport',
    '- SQLite projects, evidence, traffic, identities, sessions, migrations, backups and imports',
    '- WebSocket capture, replay, interception, TLS options and bounded event streaming',
    '- SQLi, XSS, command, NoSQL, traversal, XXE, SSRF/OAST, AuthZ, race, subscription, prototype and redirect labs',
    '- HTTP/web security analysis, bounded smart mutation, binary analysis and Playwright evidence workflows',
    '- Packaged Playwright Chromium runtime and platform-specific Go worker',
    '- JSON, HTML, CSV, SARIF and Markdown reports plus integrity-verifiable evidence bundles',
    '- Repository-owned loopback testing web application and operator start/use guide',
	'- Bounded four-worker web scanner with live UI progress, cross-phase cancellation and visible error recovery',
	'- Same-origin crawl redirects and non-followed active redirect probes to avoid out-of-scope canary delays',
    '',
    '## Validation gates',
    '',
    '- Node IPC, CSP, sandbox, navigation and worker lifecycle tests',
    '- Go unit tests and vet',
    '- Same-lab legacy Python versus Go finding/false-positive parity',
    '- Electron Playwright end-to-end browser, HTTP and WebSocket workflows',
	'- Real Vulnerability Scanner UI launch, findings, unreachable-target recovery and slow-crawl cancellation',
	'- Windows install, first launch, upgrade, second launch and uninstall lifecycle',
    '- Artifact checksum and bundled worker/browser verification',
    '',
    '## Artifact checksums',
    '',
    ...(artifacts.length
        ? artifacts.map(item => `- \`${item.name}\` - ${item.bytes} bytes - SHA-256 \`${item.sha256}\``)
        : ['- No platform artifacts were present when notes were generated.']),
    '',
    'The Electron + Go edition keeps its own application ID and user-data directory.',
    '',
].join('\n');

fs.writeFileSync(path.join(output, 'ELECTRON-GO-RELEASE-NOTES.md'), notes, 'utf8');
fs.writeFileSync(path.join(output, 'SHA256SUMS.json'), JSON.stringify(artifacts, null, 2), 'utf8');
process.stdout.write(`Generated Electron + Go notes for ${artifacts.length} artifact(s).\n`);
