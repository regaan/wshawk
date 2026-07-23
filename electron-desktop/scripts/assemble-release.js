'use strict';

const crypto = require('crypto');
const fs = require('fs');
const path = require('path');

const ALLOWED_SUFFIXES = ['.exe', '.AppImage', '.deb', '.tar.gz', '.dmg', '.zip'];

function parseArguments(argv) {
    const result = {};
    for (let index = 0; index < argv.length; index += 2) {
        const key = argv[index];
        const value = argv[index + 1];
        if (!key?.startsWith('--') || !value) throw new Error(`Invalid argument near ${key || '<end>'}`);
        result[key.slice(2)] = value;
    }
    for (const required of ['artifacts', 'output', 'tag', 'repository']) {
        if (!result[required]) throw new Error(`Missing --${required}`);
    }
    return result;
}

function listFiles(root) {
    const files = [];
    const pending = [path.resolve(root)];
    while (pending.length) {
        const current = pending.pop();
        for (const entry of fs.readdirSync(current, { withFileTypes: true })) {
            const target = path.join(current, entry.name);
            if (entry.isDirectory()) pending.push(target);
            else if (entry.isFile()) files.push(target);
        }
    }
    return files;
}

function isPackage(name) {
    return ALLOWED_SUFFIXES.some(suffix => name.endsWith(suffix));
}

function platformFor(name) {
    if (name.endsWith('.exe')) return 'Windows';
    if (name.endsWith('.AppImage') || name.endsWith('.deb') || name.endsWith('.tar.gz')) return 'Linux';
    if (name.endsWith('.dmg') || name.endsWith('.zip')) return 'macOS';
    throw new Error(`Unsupported package: ${name}`);
}

function sha256(target) {
    return crypto.createHash('sha256').update(fs.readFileSync(target)).digest('hex');
}

function assembleRelease(options) {
    const artifactRoot = path.resolve(options.artifacts);
    const outputRoot = path.resolve(options.output);
    if (!fs.existsSync(artifactRoot)) throw new Error(`Artifact directory does not exist: ${artifactRoot}`);

    const packages = listFiles(artifactRoot)
        .filter(target => isPackage(path.basename(target)))
        .map(target => ({
            target,
            name: path.basename(target),
            platform: platformFor(path.basename(target)),
            bytes: fs.statSync(target).size,
            sha256: sha256(target),
        }))
        .sort((left, right) => left.name.localeCompare(right.name));

    const duplicateNames = packages
        .map(item => item.name)
        .filter((name, index, names) => names.indexOf(name) !== index);
    if (duplicateNames.length) throw new Error(`Duplicate artifact name: ${duplicateNames[0]}`);

    const required = {
        Windows: ['.exe'],
        Linux: ['.AppImage', '.deb', '.tar.gz'],
        macOS: ['.dmg', '.zip'],
    };
    for (const [platform, suffixes] of Object.entries(required)) {
        for (const suffix of suffixes) {
            if (!packages.some(item => item.platform === platform && item.name.endsWith(suffix))) {
                throw new Error(`Missing ${platform} artifact ending in ${suffix}`);
            }
        }
    }

    fs.mkdirSync(outputRoot, { recursive: true });
    const releaseTag = `electron-go-${options.tag}`;
    const releaseBase = `https://github.com/${options.repository}/releases/download/${releaseTag}`;
    const checksumLines = packages.map(item => `${item.sha256}  ${item.name}`);
    fs.writeFileSync(
        path.join(outputRoot, 'SHA256SUMS-ELECTRON-GO.txt'),
        `${checksumLines.join('\n')}\n`,
        'utf8',
    );

    const table = packages.map(item =>
        `| ${item.platform} | [\`${item.name}\`](${releaseBase}/${encodeURIComponent(item.name)}) | ${item.bytes} |`,
    );
    const notes = [
        `# WSHawk Electron + Go ${options.tag}`,
        '',
        'This is the Electron frontend and private Go-worker edition of WSHawk. The classic desktop release is published separately under the original version tag.',
        '',
        '## Downloads',
        '',
        '| Platform | Package | Bytes |',
        '| --- | --- | ---: |',
        ...table,
        '',
        'Use the Windows installer, Linux AppImage or DEB, or macOS DMG for the normal installation path. TAR.GZ and ZIP packages are portable alternatives.',
        '',
        '## Included in this release',
        '',
        '- Electron interface connected directly to a private Go worker over IPC',
        '- HTTP, WebSocket, GraphQL and authorization testing workspaces',
        '- Authorization matrices, object-ID mutation, policy-aware findings and retesting',
        '- Encrypted project storage, evidence redaction and integrity hashes',
        '- Bundled Chromium runtime for browser validation and evidence capture',
        '- Local authorization and vulnerability lab for repeatable testing',
        '',
        '## Validation',
        '',
        '- Node and Go unit tests, worker smoke tests and Electron end-to-end tests',
        '- Classic Python versus Go parity checks and authorization benchmarks',
        '- Native Windows, Linux and macOS package verification',
        '- Windows install, upgrade, launch and uninstall lifecycle checks',
        '',
        '## Integrity verification',
        '',
        'Download `SHA256SUMS-ELECTRON-GO.txt` and compare the SHA-256 value for your package before installation.',
        '',
        `Source version: \`${options.tag}\`. Electron release tag: \`${releaseTag}\`.`,
        '',
    ].join('\n');
    fs.writeFileSync(path.join(outputRoot, 'release-notes.md'), notes, 'utf8');
    return { packages, releaseTag, notes };
}

if (require.main === module) {
    const options = parseArguments(process.argv.slice(2));
    const result = assembleRelease(options);
    process.stdout.write(`Prepared ${result.packages.length} Electron + Go package(s) for ${result.releaseTag}.\n`);
}

module.exports = { ALLOWED_SUFFIXES, assembleRelease, parseArguments, platformFor };
