(function initCodec() {
    const input = document.getElementById('codec-input');
    const output = document.getElementById('codec-output');
    const chainContainer = document.getElementById('codec-chain-container');
    const chainList = document.getElementById('codec-chain-list');
    const chainLabel = document.getElementById('codec-chain-label');
    if (!input) return;

    // Encode/Decode operations
    const ops = {
        'base64-encode': (s) => btoa(unescape(encodeURIComponent(s))),
        'base64-decode': (s) => decodeURIComponent(escape(atob(s.trim()))),
        'url-encode': (s) => encodeURIComponent(s),
        'url-decode': (s) => decodeURIComponent(s),
        'html-encode': (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;').replace(/'/g, '&#39;'),
        'html-decode': (s) => { const t = document.createElement('textarea'); t.innerHTML = s; return t.value; },
        'hex-encode': (s) => Array.from(new TextEncoder().encode(s)).map(b => b.toString(16).padStart(2, '0')).join(' '),
        'hex-decode': (s) => new TextCodec().decode(new Uint8Array(s.trim().split(/[\s,]+/).map(h => parseInt(h, 16)))),
        'unicode-encode': (s) => Array.from(s).map(c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')).join(''),
        'unicode-decode': (s) => s.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16))),
        'gzip-decompress': (s) => {
            // Decode base64 input, then decompress using DecompressionStream API
            try {
                const binary = atob(s.trim());
                const bytes = Uint8Array.from(binary, c => c.charCodeAt(0));
                const ds = new DecompressionStream('gzip');
                const writer = ds.writable.getWriter();
                writer.write(bytes);
                writer.close();
                return new Response(ds.readable).text();
            } catch (e) {
                throw new Error('Gzip decompression failed. Input must be base64-encoded gzip data.');
            }
        },
    };

    // MD5 pure-JS implementation (SubtleCrypto doesn't support MD5)
    function md5(string) {
        function md5cycle(x, k) {
            let a = x[0], b = x[1], c = x[2], d = x[3];
            a = ff(a, b, c, d, k[0], 7, -680876936); d = ff(d, a, b, c, k[1], 12, -389564586); c = ff(c, d, a, b, k[2], 17, 606105819); b = ff(b, c, d, a, k[3], 22, -1044525330);
            a = ff(a, b, c, d, k[4], 7, -176418897); d = ff(d, a, b, c, k[5], 12, 1200080426); c = ff(c, d, a, b, k[6], 17, -1473231341); b = ff(b, c, d, a, k[7], 22, -45705983);
            a = ff(a, b, c, d, k[8], 7, 1770035416); d = ff(d, a, b, c, k[9], 12, -1958414417); c = ff(c, d, a, b, k[10], 17, -42063); b = ff(b, c, d, a, k[11], 22, -1990404162);
            a = ff(a, b, c, d, k[12], 7, 1804603682); d = ff(d, a, b, c, k[13], 12, -40341101); c = ff(c, d, a, b, k[14], 17, -1502002290); b = ff(b, c, d, a, k[15], 22, 1236535329);
            a = gg(a, b, c, d, k[1], 5, -165796510); d = gg(d, a, b, c, k[6], 9, -1069501632); c = gg(c, d, a, b, k[11], 14, 643717713); b = gg(b, c, d, a, k[0], 20, -373897302);
            a = gg(a, b, c, d, k[5], 5, -701558691); d = gg(d, a, b, c, k[10], 9, 38016083); c = gg(c, d, a, b, k[15], 14, -660478335); b = gg(b, c, d, a, k[4], 20, -405537848);
            a = gg(a, b, c, d, k[9], 5, 568446438); d = gg(d, a, b, c, k[14], 9, -1019803690); c = gg(c, d, a, b, k[3], 14, -187363961); b = gg(b, c, d, a, k[8], 20, 1163531501);
            a = gg(a, b, c, d, k[13], 5, -1444681467); d = gg(d, a, b, c, k[2], 9, -51403784); c = gg(c, d, a, b, k[7], 14, 1735328473); b = gg(b, c, d, a, k[12], 20, -1926607734);
            a = hh(a, b, c, d, k[5], 4, -378558); d = hh(d, a, b, c, k[8], 11, -2022574463); c = hh(c, d, a, b, k[11], 16, 1839030562); b = hh(b, c, d, a, k[14], 23, -35309556);
            a = hh(a, b, c, d, k[1], 4, -1530992060); d = hh(d, a, b, c, k[4], 11, 1272893353); c = hh(c, d, a, b, k[7], 16, -155497632); b = hh(b, c, d, a, k[10], 23, -1094730640);
            a = hh(a, b, c, d, k[13], 4, 681279174); d = hh(d, a, b, c, k[0], 11, -358537222); c = hh(c, d, a, b, k[3], 16, -722521979); b = hh(b, c, d, a, k[6], 23, 76029189);
            a = hh(a, b, c, d, k[9], 4, -640364487); d = hh(d, a, b, c, k[12], 11, -421815835); c = hh(c, d, a, b, k[15], 16, 530742520); b = hh(b, c, d, a, k[2], 23, -995338651);
            a = ii(a, b, c, d, k[0], 6, -198630844); d = ii(d, a, b, c, k[7], 10, 1126891415); c = ii(c, d, a, b, k[14], 15, -1416354905); b = ii(b, c, d, a, k[5], 21, -57434055);
            a = ii(a, b, c, d, k[12], 6, 1700485571); d = ii(d, a, b, c, k[3], 10, -1894986606); c = ii(c, d, a, b, k[10], 15, -1051523); b = ii(b, c, d, a, k[1], 21, -2054922799);
            a = ii(a, b, c, d, k[8], 6, 1873313359); d = ii(d, a, b, c, k[15], 10, -30611744); c = ii(c, d, a, b, k[6], 15, -1560198380); b = ii(b, c, d, a, k[13], 21, 1309151649);
            a = ii(a, b, c, d, k[4], 6, -145523070); d = ii(d, a, b, c, k[11], 10, -1120210379); c = ii(c, d, a, b, k[2], 15, 718787259); b = ii(b, c, d, a, k[9], 21, -343485551);
            x[0] = add32(a, x[0]); x[1] = add32(b, x[1]); x[2] = add32(c, x[2]); x[3] = add32(d, x[3]);
        }
        function cmn(q, a, b, x, s, t) { a = add32(add32(a, q), add32(x, t)); return add32((a << s) | (a >>> (32 - s)), b); }
        function ff(a, b, c, d, x, s, t) { return cmn((b & c) | ((~b) & d), a, b, x, s, t); }
        function gg(a, b, c, d, x, s, t) { return cmn((b & d) | (c & (~d)), a, b, x, s, t); }
        function hh(a, b, c, d, x, s, t) { return cmn(b ^ c ^ d, a, b, x, s, t); }
        function ii(a, b, c, d, x, s, t) { return cmn(c ^ (b | (~d)), a, b, x, s, t); }
        function md5blk(s) { const md5blks = []; for (let i = 0; i < 64; i += 4)md5blks[i >> 2] = s.charCodeAt(i) + (s.charCodeAt(i + 1) << 8) + (s.charCodeAt(i + 2) << 16) + (s.charCodeAt(i + 3) << 24); return md5blks; }
        function add32(a, b) { return (a + b) & 0xFFFFFFFF; }
        function rhex(n) { let s = '', j; for (j = 0; j < 4; j++)s += '0123456789abcdef'.charAt((n >> (j * 8 + 4)) & 0x0F) + '0123456789abcdef'.charAt((n >> (j * 8)) & 0x0F); return s; }
        function hex(x) { for (let i = 0; i < x.length; i++)x[i] = rhex(x[i]); return x.join(''); }
        const n = string.length; let state = [1732584193, -271733879, -1732584194, 271733878], i;
        for (i = 64; i <= n; i += 64)md5cycle(state, md5blk(string.substring(i - 64, i)));
        string = string.substring(i - 64); const tail = [0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0];
        for (i = 0; i < string.length; i++)tail[i >> 2] |= string.charCodeAt(i) << ((i % 4) << 3);
        tail[i >> 2] |= 0x80 << ((i % 4) << 3); if (i > 55) { md5cycle(state, tail); for (i = 0; i < 16; i++)tail[i] = 0; }
        tail[14] = n * 8; md5cycle(state, tail); return hex(state);
    }

    // Hash via SubtleCrypto (SHA family)
    async function hashWith(algo, text) {
        const data = new TextEncoder().encode(text);
        const buf = await crypto.subtle.digest(algo, data);
        return Array.from(new Uint8Array(buf)).map(b => b.toString(16).padStart(2, '0')).join('');
    }

    // Button click handlers
    document.querySelectorAll('.codec-op-btn').forEach(btn => {
        btn.addEventListener('click', async () => {
            const op = btn.dataset.op;
            const src = input.value;
            if (!src) return;

            try {
                let result;
                if (op === 'md5') result = md5(src);
                else if (op === 'sha1') result = await hashWith('SHA-1', src);
                else if (op === 'sha256') result = await hashWith('SHA-256', src);
                else if (op === 'sha512') result = await hashWith('SHA-512', src);
                else if (ops[op]) {
                    const r = ops[op](src);
                    result = (r instanceof Promise) ? await r : r;
                }
                else { output.value = '[ERR] Unknown operation'; return; }

                output.value = result;
                chainLabel.textContent = op;
            } catch (e) {
                output.value = `[ERR] ${e.message}`;
            }
        });
    });

    // Smart Decode: recursively peel layers
    document.getElementById('codec-smart-btn').addEventListener('click', () => {
        let data = input.value;
        if (!data) return;

        const layers = [];
        let maxIterations = 10;

        while (maxIterations-- > 0) {
            let decoded = null, type = null;

            // Try URL decode
            try {
                const d = decodeURIComponent(data);
                if (d !== data && d.length < data.length) { decoded = d; type = 'URL Decode'; }
            } catch (_) { }

            // Try Base64 decode
            if (!decoded) {
                try {
                    if (/^[A-Za-z0-9+/]+={0,2}$/.test(data.trim()) && data.trim().length > 3) {
                        const d = decodeURIComponent(escape(atob(data.trim())));
                        if (d.length > 0) { decoded = d; type = 'Base64 Decode'; }
                    }
                } catch (_) { }
            }

            // Try HTML entity decode
            if (!decoded) {
                const el = document.createElement('textarea');
                el.innerHTML = data;
                if (el.value !== data) { decoded = el.value; type = 'HTML Decode'; }
            }

            // Try Unicode unescape
            if (!decoded && data.includes('\\u')) {
                try {
                    const d = data.replace(/\\u([0-9a-fA-F]{4})/g, (_, h) => String.fromCharCode(parseInt(h, 16)));
                    if (d !== data) { decoded = d; type = 'Unicode Unescape'; }
                } catch (_) { }
            }

            // Try Hex decode
            if (!decoded && /^([0-9a-fA-F]{2}[\s,]*)+$/.test(data.trim())) {
                try {
                    const d = new TextCodec().decode(new Uint8Array(data.trim().split(/[\s,]+/).map(h => parseInt(h, 16))));
                    if (d.length > 0) { decoded = d; type = 'Hex Decode'; }
                } catch (_) { }
            }

            if (!decoded) break;

            layers.push({ type, preview: decoded.substring(0, 80) });
            data = decoded;
        }

        output.value = data;

        if (layers.length > 0) {
            chainContainer.classList.add('visible');
            chainList.innerHTML = layers.map((l, i) =>
                `<div class="codec-chain-item">
                    <span class="chain-step">${i + 1}</span>
                    <span class="chain-type">${esc(l.type)}</span>
                    <span class="chain-preview">${esc(l.preview)}</span>
                </div>`
            ).join('');
            chainLabel.textContent = `${layers.length} layers`;
        } else {
            chainContainer.classList.remove('visible');
            chainLabel.textContent = 'No encoding detected';
        }
    });

    // Utility buttons
    document.getElementById('codec-copy-btn').addEventListener('click', () => {
        navigator.clipboard.writeText(output.value);
        appendLog('info', 'Codec output copied to clipboard.');
    });

    document.getElementById('codec-swap-btn').addEventListener('click', () => {
        input.value = output.value;
        output.value = '';
        chainContainer.classList.remove('visible');
    });

    document.getElementById('codec-clear-btn').addEventListener('click', () => {
        input.value = '';
        output.value = '';
        chainLabel.textContent = '';
        chainContainer.classList.remove('visible');
        chainList.innerHTML = '';
    });
})();

// ═══════════════════════════════════════════════════════════════
// COMPARER
// ═══════════════════════════════════════════════════════════════
(function initComparer() {
    const inputA = document.getElementById('comparer-input-a');
    const inputB = document.getElementById('comparer-input-b');
    const diffOutput = document.getElementById('comparer-diff-output');
    const diffCount = document.getElementById('comparer-diff-count');
    const stats = document.getElementById('comparer-stats');
    if (!inputA) return;

    document.getElementById('comparer-paste-a').addEventListener('click', async () => {
        try { inputA.value = await navigator.clipboard.readText(); } catch (_) { }
    });
    document.getElementById('comparer-paste-b').addEventListener('click', async () => {
        try { inputB.value = await navigator.clipboard.readText(); } catch (_) { }
    });

    document.getElementById('comparer-run-btn').addEventListener('click', () => {
        const a = inputA.value;
        const b = inputB.value;
        if (!a && !b) { diffOutput.innerHTML = '<div class="empty-state">Paste data into both panels first.</div>'; return; }

        const linesA = a.split('\n');
        const linesB = b.split('\n');
        const maxLen = Math.max(linesA.length, linesB.length);

        let html = '';
        let differences = 0;

        for (let i = 0; i < maxLen; i++) {
            const la = linesA[i] !== undefined ? linesA[i] : '';
            const lb = linesB[i] !== undefined ? linesB[i] : '';

            if (la === lb) {
                html += `<div class="diff-line diff-same">${esc(la)}</div>`;
            } else {
                differences++;
                if (la) html += `<div class="diff-line diff-remove">- ${esc(la)}</div>`;
                if (lb) html += `<div class="diff-line diff-add">+ ${esc(lb)}</div>`;
            }
        }

        diffOutput.innerHTML = html || '<div class="empty-state">Responses are identical.</div>';
        diffCount.textContent = `${differences} difference${differences !== 1 ? 's' : ''}`;

        const sizeA = new Blob([a]).size;
        const sizeB = new Blob([b]).size;
        const sizeDiff = sizeB - sizeA;
        stats.innerHTML = `A: ${sizeA}B<br>B: ${sizeB}B<br>Δ: <span style="color:${Math.abs(sizeDiff) > 20 ? 'var(--danger)' : 'var(--text-muted)'}">${sizeDiff > 0 ? '+' : ''}${sizeDiff}B</span>`;
    });

    document.getElementById('comparer-clear-btn').addEventListener('click', () => {
        inputA.value = '';
        inputB.value = '';
        diffOutput.innerHTML = '<div class="empty-state">Run a comparison to see differences.</div>';
        diffCount.textContent = '';
        stats.innerHTML = '';
    });
})();

// ═══════════════════════════════════════════════════════════════
// NOTES
// ═══════════════════════════════════════════════════════════════
(function initNotes() {
    const listContainer = document.getElementById('notes-list-container');
    const editor = document.getElementById('notes-editor');
    const editorTitle = document.getElementById('notes-editor-title');
    if (!listContainer) return;

    let notes = JSON.parse(localStorage.getItem('wshawk_notes') || '[]');
    let activeNoteId = null;

    function saveNotes() {
        safeStore('wshawk_notes', notes);
    }

    function renderList() {
        if (notes.length === 0) {
            listContainer.innerHTML = '<div class="empty-state" style="padding: 20px;">No notes yet. Click + New.</div>';
            return;
        }
        listContainer.innerHTML = notes.map(n => `
            <div class="note-item ${n.id === activeNoteId ? 'active' : ''}" data-id="${n.id}">
                <div class="note-item-title">${esc(n.title) || 'Untitled'}</div>
                <div class="note-item-date">${esc(n.date)}</div>
                ${n.linkedFindings ? '<div class="note-item-linked">' + parseInt(n.linkedFindings) + ' finding(s) linked</div>' : ''}
            </div>
        `).join('');

        listContainer.querySelectorAll('.note-item').forEach(el => {
            el.addEventListener('click', () => {
                activeNoteId = el.dataset.id;
                const note = notes.find(n => n.id === activeNoteId);
                if (note) {
                    editor.value = note.content;
                    editorTitle.textContent = note.title || 'Untitled';
                }
                renderList();
            });
        });
    }

    // Auto-save on typing (debounced to prevent jank)
    let noteSaveTimer = null;
    editor.addEventListener('input', () => {
        if (!activeNoteId) return;
        const note = notes.find(n => n.id === activeNoteId);
        if (note) {
            note.content = editor.value;
            const firstLine = editor.value.split('\n')[0].trim();
            note.title = firstLine.substring(0, 50) || 'Untitled';
            editorTitle.textContent = note.title;
            clearTimeout(noteSaveTimer);
            noteSaveTimer = setTimeout(() => {
                saveNotes();
                renderList();
            }, 300);
        }
    });

    document.getElementById('notes-add-btn').addEventListener('click', () => {
        const id = 'n_' + Date.now();
        const newNote = {
            id,
            title: 'Untitled',
            content: '',
            date: new Date().toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric' }),
            linkedFindings: 0
        };
        notes.unshift(newNote);
        activeNoteId = id;
        editor.value = '';
        editorTitle.textContent = 'Untitled';
        saveNotes();
        renderList();
        editor.focus();
    });

    document.getElementById('notes-delete-btn').addEventListener('click', () => {
        if (!activeNoteId) return;
        notes = notes.filter(n => n.id !== activeNoteId);
        activeNoteId = null;
        editor.value = '';
        editorTitle.textContent = 'Select a note';
        saveNotes();
        renderList();
    });

    document.getElementById('notes-link-btn').addEventListener('click', () => {
        if (!activeNoteId) return;
        const note = notes.find(n => n.id === activeNoteId);
        if (!note) return;

        const findings = findingsContainer.querySelectorAll('.finding-card');
        if (findings.length === 0) {
            appendLog('info', 'No findings to link.');
            return;
        }

        let linked = '\n\n── Linked Findings ──\n';
        findings.forEach(f => {
            const name = f.querySelector('.f-name')?.textContent || 'Unknown';
            const sev = f.querySelector('.sev-badge')?.textContent || '';
            const payload = f.querySelector('.f-payload')?.textContent || '';
            linked += `[${sev}] ${name}: ${payload}\n`;
        });

        note.content += linked;
        note.linkedFindings = findings.length;
        editor.value = note.content;
        saveNotes();
        renderList();
        appendLog('info', `${findings.length} finding(s) linked to note.`);
    });

    renderList();
})();

// ═══════════════════════════════════════════════════════════════
// ENDPOINT MAP
// ═══════════════════════════════════════════════════════════════
(function initWSMap() {
    if (window.WSHawkModules?.protocol?.initWSMap) {
        window.WSHawkModules.protocol.initWSMap({
            appendLog,
            ensurePlatformProject: (typeof ensurePlatformProject === 'function' ? ensurePlatformProject : null),
            getCurrentProject: (typeof getCurrentProject === 'function' ? getCurrentProject : null),
            targetUrlInput,
        });
    }
})();

// ═══════════════════════════════════════════════════════════════
// AUTH BUILDER
// ═══════════════════════════════════════════════════════════════
(function initAuthBuilder() {
    const stepsContainer = document.getElementById('auth-steps-container');
    const rulesContainer = document.getElementById('auth-rules-container');
    const testOutput = document.getElementById('auth-test-output');
    if (!stepsContainer) return;

    let steps = JSON.parse(localStorage.getItem('wshawk_auth_steps') || '[]');
    let rules = JSON.parse(localStorage.getItem('wshawk_auth_rules') || '[]');

    function save() {
        safeStore('wshawk_auth_steps', steps);
        safeStore('wshawk_auth_rules', rules);
    }

    function renderSteps() {
        if (steps.length === 0) {
            stepsContainer.innerHTML = '<div class="empty-state">Define multi-step authentication sequences.<br>Click + Add Step to begin.</div>';
            return;
        }
        stepsContainer.innerHTML = steps.map((s, i) => `
            <div class="auth-step-card">
                <div class="step-header">
                    <span class="step-num">STEP ${i + 1}</span>
                    <button class="step-remove" data-idx="${i}">&times;</button>
                </div>
                <input class="auth-step-input step-action" data-idx="${i}" placeholder="Action (e.g. send, wait, connect)" value="${esc(s.action) || ''}">
                <textarea class="auth-step-input step-payload" data-idx="${i}" placeholder='Payload (e.g. {"type":"login","user":"admin","pass":"§token§"})' style="min-height: 60px; resize: vertical;">${esc(s.payload) || ''}</textarea>
                <input class="auth-step-input step-delay" data-idx="${i}" placeholder="Delay after (ms), default: 500" value="${esc(s.delay) || ''}">
            </div>
        `).join('');

        // Remove handlers
        stepsContainer.querySelectorAll('.step-remove').forEach(btn => {
            btn.addEventListener('click', () => {
                steps.splice(parseInt(btn.dataset.idx), 1);
                save(); renderSteps();
            });
        });

        // Auto-save on input
        stepsContainer.querySelectorAll('.step-action').forEach(el => {
            el.addEventListener('input', () => { steps[el.dataset.idx].action = el.value; save(); });
        });
        stepsContainer.querySelectorAll('.step-payload').forEach(el => {
            el.addEventListener('input', () => { steps[el.dataset.idx].payload = el.value; save(); });
        });
        stepsContainer.querySelectorAll('.step-delay').forEach(el => {
            el.addEventListener('input', () => { steps[el.dataset.idx].delay = el.value; save(); });
        });
    }

    function renderRules() {
        if (rules.length === 0) {
            rulesContainer.innerHTML = '<div class="empty-state">Define token extraction rules.<br>Use regex or JSONPath to capture session tokens from responses.</div>';
            return;
        }
        rulesContainer.innerHTML = rules.map((r, i) => `
            <div class="auth-rule-card" style="position: relative;">
                <div class="rule-label">Rule ${i + 1} — ${esc(r.type) || 'regex'}</div>
                <input class="auth-step-input rule-name" data-idx="${i}" placeholder="Variable name (e.g. token)" value="${esc(r.name) || ''}">
                <input class="auth-step-input rule-pattern" data-idx="${i}" placeholder='Pattern (regex: "token":"(.*?)" | jsonpath: $.data.token)' value="${esc(r.pattern) || ''}">
                <button class="step-remove" data-idx="${i}" style="position: absolute; top: 8px; right: 8px;">&times;</button>
            </div>
        `).join('');

        rulesContainer.querySelectorAll('.rule-name').forEach(el => {
            el.addEventListener('input', () => { rules[el.dataset.idx].name = el.value; save(); });
        });
        rulesContainer.querySelectorAll('.rule-pattern').forEach(el => {
            el.addEventListener('input', () => { rules[el.dataset.idx].pattern = el.value; save(); });
        });
        rulesContainer.querySelectorAll('.step-remove').forEach(btn => {
            btn.addEventListener('click', () => { rules.splice(parseInt(btn.dataset.idx), 1); save(); renderRules(); });
        });
    }

    document.getElementById('auth-add-step').addEventListener('click', () => {
        steps.push({ action: 'send', payload: '', delay: '500' });
        save(); renderSteps();
    });

    document.getElementById('auth-clear-all').addEventListener('click', () => {
        steps = []; rules = [];
        save(); renderSteps(); renderRules();
        testOutput.value = '';
    });

    document.getElementById('auth-add-rule').addEventListener('click', () => {
        rules.push({ type: 'regex', name: '', pattern: '' });
        save(); renderRules();
    });

    document.getElementById('auth-test-btn').addEventListener('click', async () => {
        const url = targetUrlInput.value.trim();
        if (!url) { testOutput.value = '[ERR] Target URL is required.'; return; }
        if (steps.length === 0) { testOutput.value = '[ERR] No auth steps defined.'; return; }

        testOutput.value = 'Executing authentication sequence...';

        try {
            const res = await fetch('/auth/test', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ url, steps, rules })
            });
            const data = await res.json();
            testOutput.value = JSON.stringify(data, null, 2);

            if (data.extracted_tokens) {
                appendLog('success', `Auth sequence complete. Extracted ${Object.keys(data.extracted_tokens).length} token(s).`);
            }
        } catch (e) {
            testOutput.value = `[ERR] ${e.message}`;
        }
    });

    document.getElementById('auth-save-btn').addEventListener('click', () => {
        const preset = { steps, rules, saved: new Date().toISOString() };
        const presets = JSON.parse(localStorage.getItem('wshawk_auth_presets') || '[]');
        presets.push(preset);
        safeStore('wshawk_auth_presets', presets);
        appendLog('info', 'Auth sequence saved as preset.');
    });

    renderSteps();
    renderRules();
})();

// ═══════════════════════════════════════════════════════════════
// SCHEDULER
// ═══════════════════════════════════════════════════════════════
(function initScheduler() {
    const tbody = document.getElementById('sched-tbody');
    const deltaContainer = document.getElementById('sched-delta-container');
    if (!tbody) return;

    let schedules = JSON.parse(localStorage.getItem('wshawk_schedules') || '[]');
    let timers = {};

    function save() {
        safeStore('wshawk_schedules', schedules);
    }

    function renderTable() {
        if (schedules.length === 0) {
            tbody.innerHTML = '<tr class="empty-tr"><td colspan="6">No scheduled scans configured.</td></tr>';
            return;
        }
        tbody.innerHTML = schedules.map((s, i) => `
            <tr>
                <td style="max-width: 200px; overflow: hidden; text-overflow: ellipsis;" title="${esc(s.url)}">${esc(s.url)}</td>
                <td>${esc(s.interval)}</td>
                <td>${esc(s.lastRun) || 'Never'}</td>
                <td>${parseInt(s.lastFindings) || 0}</td>
                <td><span class="sched-status ${s.status || 'idle'}">${s.status || 'idle'}</span></td>
                <td style="white-space: nowrap;">
                    <button class="btn secondary small sched-toggle" data-idx="${i}" style="font-size:10px; padding: 2px 8px;">${s.status === 'active' ? 'Pause' : 'Start'}</button>
                    <button class="btn secondary small sched-view" data-idx="${i}" style="font-size:10px; padding: 2px 8px;">Delta</button>
                    <button class="btn secondary small sched-delete" data-idx="${i}" style="font-size:10px; padding: 2px 8px; color: var(--danger);">&times;</button>
                </td>
            </tr>
        `).join('');

        tbody.querySelectorAll('.sched-toggle').forEach(btn => {
            btn.addEventListener('click', () => {
                const idx = parseInt(btn.dataset.idx);
                if (schedules[idx].status === 'active') {
                    schedules[idx].status = 'paused';
                    if (timers[idx]) { clearInterval(timers[idx]); delete timers[idx]; }
                } else {
                    schedules[idx].status = 'active';
                    startSchedule(idx);
                }
                save(); renderTable();
            });
        });

        tbody.querySelectorAll('.sched-view').forEach(btn => {
            btn.addEventListener('click', () => showDelta(parseInt(btn.dataset.idx)));
        });

        tbody.querySelectorAll('.sched-delete').forEach(btn => {
            btn.addEventListener('click', () => {
                const idx = parseInt(btn.dataset.idx);
                if (timers[idx]) { clearInterval(timers[idx]); delete timers[idx]; }
                schedules.splice(idx, 1);
                save(); renderTable();
            });
        });
    }

    function startSchedule(idx) {
        const sched = schedules[idx];
        const ms = parseInterval(sched.interval);
        if (!ms) return;

        timers[idx] = setInterval(async () => {
            appendLog('info', `[Scheduler] Running scan: ${sched.url}`);
            sched.lastRun = new Date().toLocaleString();
            const prevFindings = sched.lastFindings || 0;

            try {
                const project = await ensurePlatformProject('scheduled_scan', sched.url);
                const res = await fetch('/scan/start', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        project_id: project.id,
                        url: sched.url,
                        rate: 10
                    })
                });
                const data = await res.json();
                sched.lastFindings = data.vulnerabilities_count || 0;

                // Track delta
                if (!sched.history) sched.history = [];
                sched.history.push({
                    time: sched.lastRun,
                    findings: sched.lastFindings,
                    delta: sched.lastFindings - prevFindings
                });
            } catch (e) {
                appendLog('vuln', `[Scheduler] Scan failed: ${e.message}`);
            }
            save(); renderTable();
        }, ms);
    }

    function parseInterval(str) {
        const map = { '1h': 3600000, '6h': 21600000, '12h': 43200000, '24h': 86400000, 'daily': 86400000, 'weekly': 604800000 };
        return map[str.toLowerCase()] || null;
    }

    function showDelta(idx) {
        const sched = schedules[idx];
        if (!sched.history || sched.history.length === 0) {
            deltaContainer.innerHTML = '<div class="empty-state">No scan history for this schedule yet.</div>';
            return;
        }

        deltaContainer.innerHTML = sched.history.slice(-10).reverse().map(h => `
            <div class="sched-delta-item">
                <div style="color: var(--text-primary); margin-bottom: 4px;">${h.time}</div>
                <div>Findings: ${h.findings} ${h.delta > 0 ? `<span class="delta-new">(+${h.delta} new)</span>` : h.delta < 0 ? `<span class="delta-resolved">(${h.delta} resolved)</span>` : '<span style="color: var(--text-muted);">(no change)</span>'}</div>
            </div>
        `).join('');
    }

    document.getElementById('sched-add-btn').addEventListener('click', () => {
        const url = targetUrlInput.value.trim();
        if (!url) {
            appendLog('vuln', 'Input Error: Target URL required for scheduling.');
            return;
        }

        // Build a temporary inline selector instead of prompt()
        const intervals = ['1h', '6h', '12h', '24h', 'daily', 'weekly'];
        const existing = document.getElementById('sched-interval-picker');
        if (existing) existing.remove();

        const picker = document.createElement('div');
        picker.id = 'sched-interval-picker';
        picker.style.cssText = 'position:fixed;top:50%;left:50%;transform:translate(-50%,-50%);background:var(--bg-panel);border:1px solid var(--border-highlight);border-radius:var(--radius-lg);padding:24px;z-index:99999;box-shadow:var(--shadow-lg);min-width:280px;';
        picker.innerHTML = `
            <div style="font-size:14px;font-weight:600;margin-bottom:16px;color:var(--text-primary);">Schedule Scan</div>
            <div style="font-size:12px;color:var(--text-muted);margin-bottom:8px;">Target: ${esc(url)}</div>
            <select id="sched-interval-select" class="modal-input" style="margin-bottom:16px;">
                ${intervals.map(iv => `<option value="${iv}">${iv === 'daily' ? 'Daily (24h)' : iv === 'weekly' ? 'Weekly' : 'Every ' + iv}</option>`).join('')}
            </select>
            <div style="display:flex;gap:8px;">
                <button id="sched-confirm" class="btn primary" style="flex:1;">Schedule</button>
                <button id="sched-cancel" class="btn secondary" style="flex:1;">Cancel</button>
            </div>
        `;
        document.body.appendChild(picker);

        document.getElementById('sched-cancel').addEventListener('click', () => picker.remove());
        document.getElementById('sched-confirm').addEventListener('click', () => {
            const interval = document.getElementById('sched-interval-select').value;
            schedules.push({
                url, interval,
                status: 'idle',
                lastRun: null,
                lastFindings: 0,
                history: []
            });
            save(); renderTable();
            appendLog('info', `Scheduled scan added: ${url} every ${interval}`);
            picker.remove();
        });
    });

    renderTable();

    // Auto-resume active schedules on startup
    schedules.forEach((s, idx) => {
        if (s.status === 'active') {
            startSchedule(idx);
            appendLog('info', `[Scheduler] Resumed: ${s.url} every ${s.interval}`);
        }
    });
})();

// Init
bridgeConnectRequested = true;
connectBridge();
setTimeout(() => {
    console.log('[UI] Running delayed init tasks...');
    showToS();
    updateStatusBar();
    loadProfiles();
}, 500);

// ═══════════════════════════════════════════════════════════════
// FEATURE 1: FINDINGS FILTER & SEARCH
// ═══════════════════════════════════════════════════════════════
(function initFindingsFilter() {
    const searchInput = document.getElementById('findings-search');
    const filterBtns = document.querySelectorAll('.sev-filter-btn');
    let activeSev = 'all';

    function applyFilter() {
        const term = (searchInput?.value || '').toLowerCase();
        const cards = findingsContainer.querySelectorAll('.finding-card');
        cards.forEach(card => {
            const sev = card.getAttribute('data-severity') || '';
            const text = card.innerText.toLowerCase();
            const matchSev = activeSev === 'all' || sev === activeSev;
            const matchSearch = !term || text.includes(term);
            card.style.display = (matchSev && matchSearch) ? '' : 'none';
        });
    }

    filterBtns.forEach(btn => {
        btn.addEventListener('click', () => {
            filterBtns.forEach(b => b.classList.remove('active'));
            btn.classList.add('active');
            activeSev = btn.getAttribute('data-sev');
            applyFilter();
        });
    });

    if (searchInput) searchInput.addEventListener('input', applyFilter);
})();

// ═══════════════════════════════════════════════════════════════
// FEATURE 2 & 10: HISTORY → REQUEST FORGE BRIDGE
// ═══════════════════════════════════════════════════════════════
window.sendToForge = function (rowId) {
    const data = historyData[rowId];
    if (!data) return;
    document.getElementById('reqforge-req').value = data;
    document.querySelector('.nav-item[data-target="reqforge"]')?.click();
    appendLog('info', 'Frame sent to Request Forge for manual testing.');
};

// ═══════════════════════════════════════════════════════════════
// FEATURE 3: RESPONSE REGEX EXTRACTOR
// ═══════════════════════════════════════════════════════════════
(function initExtractor() {
    const runBtn = document.getElementById('extractor-run-btn');
    const regexInput = document.getElementById('extractor-regex');
    const resultsDiv = document.getElementById('extractor-results');
    const forgeRes = document.getElementById('reqforge-res');

    if (!runBtn || !regexInput || !resultsDiv || !forgeRes) return;

    runBtn.addEventListener('click', () => {
        const pattern = regexInput.value.trim();
        if (!pattern) {
            resultsDiv.innerHTML = '<div class="empty-state" style="padding:10px;">Enter a regex pattern first.</div>';
            return;
        }

        const text = forgeRes.value;
        if (!text || text === 'Awaiting execution...') {
            resultsDiv.innerHTML = '<div class="empty-state" style="padding:10px;">No response to extract from. Fire a payload first.</div>';
            return;
        }

        try {
            const re = new RegExp(pattern, 'g');
            let match;
            let html = '';
            let count = 0;

            while ((match = re.exec(text)) !== null && count < 50) {
                count++;
                html += `<div class="extractor-match">
                    <span class="match-idx">#${count}</span>
                    <span class="match-val">${esc(match[0])}</span>`;
                if (match.length > 1) {
                    for (let g = 1; g < match.length; g++) {
                        html += `<span class="match-group">Group ${g}: ${esc(match[g] || '')}</span>`;
                    }
                }
                html += '</div>';
                if (re.lastIndex === match.index) re.lastIndex++;
            }

            if (count === 0) {
                html = '<div class="empty-state" style="padding:10px;">No matches found.</div>';
            }

            resultsDiv.innerHTML = html;
        } catch (e) {
            resultsDiv.innerHTML = `<div class="empty-state" style="padding:10px; color:var(--danger);">Invalid regex: ${esc(e.message)}</div>`;
        }
    });

    // Request Forge copy button
    document.getElementById('reqforge-copy-btn')?.addEventListener('click', () => {
        navigator.clipboard.writeText(forgeRes.value).then(() => {
            appendLog('info', 'Response copied to clipboard.');
        });
    });
})();

// ═══════════════════════════════════════════════════════════════
// FEATURE 4: CONNECTION PROFILES
// ═══════════════════════════════════════════════════════════════
function loadProfiles() {
    const profiles = JSON.parse(localStorage.getItem('wshawk_profiles') || '[]');
    const select = document.getElementById('profile-select');
    if (!select) return;

    // Keep "No Profile" option, clear rest
    select.innerHTML = '<option value="">No Profile</option>';
    profiles.forEach((p, i) => {
        const opt = document.createElement('option');
        opt.value = i;
        opt.textContent = p.name;
        select.appendChild(opt);
    });
}

(function initProfiles() {
    const select = document.getElementById('profile-select');
    const saveBtn = document.getElementById('profile-save-btn');
    const deleteBtn = document.getElementById('profile-delete-btn');

    if (!select || !saveBtn) return;

    select.addEventListener('change', () => {
        const profiles = JSON.parse(localStorage.getItem('wshawk_profiles') || '[]');
        const idx = parseInt(select.value);
        if (isNaN(idx) || !profiles[idx]) return;

        targetUrlInput.value = profiles[idx].url || '';
        document.getElementById('auth-payload').value = profiles[idx].auth || '';
        appendLog('info', `Profile loaded: ${profiles[idx].name}`);
    });

    saveBtn.addEventListener('click', () => {
        const url = targetUrlInput.value.trim();
        if (!url) {
            appendLog('vuln', 'Enter a target URL before saving a profile.');
            return;
        }

        // Inline name picker instead of prompt()
        const existing = document.getElementById('profile-name-picker');
        if (existing) existing.remove();

        const picker = document.createElement('div');
        picker.id = 'profile-name-picker';
        picker.style.cssText = 'position:fixed;top:0;left:0;width:100%;height:100%;background:rgba(0,0,0,0.6);display:flex;align-items:center;justify-content:center;z-index:9999;';
        picker.innerHTML = `
            <div style="background:var(--bg-panel);border:1px solid var(--border-color);border-radius:var(--radius);padding:20px;min-width:320px;">
                <h3 style="margin:0 0 12px;font-size:14px;color:var(--text-primary);">Save Connection Profile</h3>
                <input type="text" id="profile-name-input" placeholder="Profile name (e.g. Staging API)"
                    style="width:100%;background:var(--bg-secondary);border:1px solid var(--border-color);border-radius:var(--radius);padding:8px 12px;color:var(--text-primary);font-size:13px;margin-bottom:12px;box-sizing:border-box;">
                <div style="display:flex;gap:8px;justify-content:flex-end;">
                    <button class="btn secondary small" data-action="close-profile-picker">Cancel</button>
                    <button class="btn primary small" id="profile-name-confirm">Save</button>
                </div>
            </div>
        `;
        document.body.appendChild(picker);

        const nameInput = document.getElementById('profile-name-input');
        nameInput.focus();

        const confirmSave = () => {
            const name = nameInput.value.trim();
            if (!name) return;

            const profiles = JSON.parse(localStorage.getItem('wshawk_profiles') || '[]');
            profiles.push({
                name: name,
                url: url,
                auth: document.getElementById('auth-payload').value.trim()
            });
            safeStore('wshawk_profiles', profiles);
            loadProfiles();
            appendLog('info', `Profile saved: ${name}`);
            picker.remove();
        };

        document.getElementById('profile-name-confirm').addEventListener('click', confirmSave);
        nameInput.addEventListener('keydown', (e) => {
            if (e.key === 'Enter') confirmSave();
            if (e.key === 'Escape') picker.remove();
        });
    });

    deleteBtn?.addEventListener('click', () => {
        const idx = parseInt(select.value);
        if (isNaN(idx)) {
            appendLog('vuln', 'Select a profile to delete.');
            return;
        }
        const profiles = JSON.parse(localStorage.getItem('wshawk_profiles') || '[]');
        const removed = profiles.splice(idx, 1);
        safeStore('wshawk_profiles', profiles);
        loadProfiles();
        select.value = '';
        appendLog('info', `Profile deleted: ${removed[0]?.name}`);
    });
})();

// ═══════════════════════════════════════════════════════════════
// FEATURE 5: JSON & CSV EXPORT
// ═══════════════════════════════════════════════════════════════
document.getElementById('btn-export-json')?.addEventListener('click', async () => {
    if (typeof getCurrentProject === 'function') {
        const project = getCurrentProject();
        if (project?.projectId && window.WSHawkModules?.evidence?.exportProjectBundle) {
            try {
                await window.WSHawkModules.evidence.exportProjectBundle({
                    projectId: project.projectId,
                    format: 'json',
                    appendLog,
                });
                return;
            } catch (error) {
                appendLog('vuln', `Project JSON export failed: ${error.message}`);
            }
        }
    }

    const data = {
        target: targetUrlInput.value,
        generated: new Date().toISOString(),
        vulnerabilities: Object.values(globalVulns).map(v => ({
            type: v.type,
            severity: v.severity,
            description: v.description,
            payload: v.payload
        })),
        stats: {
            total_vulns: parseInt(valVulns.innerText) || 0,
            frames_analyzed: msgCount
        }
    };

    const json = JSON.stringify(data, null, 2);
    const blob = new Blob([json], { type: 'application/json' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `wshawk_report_${Date.now()}.json`;
    a.click();
    URL.revokeObjectURL(url);
    appendLog('info', 'JSON report downloaded.');
});

document.getElementById('btn-export-csv')?.addEventListener('click', async () => {
    const vulns = Object.values(globalVulns);
    if (vulns.length === 0) {
        appendLog('vuln', 'No findings to export.');
        return;
    }

    let csv = 'Type,Severity,Description,Payload\n';
    vulns.forEach(v => {
        const escape = (s) => '"' + String(s || '').replace(/"/g, '""') + '"';
        csv += `${escape(v.type)},${escape(v.severity)},${escape(v.description)},${escape(v.payload)}\n`;
    });

    const blob = new Blob([csv], { type: 'text/csv' });
    const url = URL.createObjectURL(blob);
    const a = document.createElement('a');
    a.href = url;
    a.download = `wshawk_findings_${Date.now()}.csv`;
    a.click();
    URL.revokeObjectURL(url);
    appendLog('info', 'CSV report downloaded.');
});

// ═══════════════════════════════════════════════════════════════
// FEATURE 6: OAST CALLBACK PANEL
// ═══════════════════════════════════════════════════════════════
(function initOAST() {
    const listDiv = document.getElementById('oast-list');
    const detailDiv = document.getElementById('oast-detail');
    const pollBtn = document.getElementById('oast-poll-btn');
    const clearBtn = document.getElementById('oast-clear-btn');

    if (!listDiv || !pollBtn) return;

    let callbacks = [];

    pollBtn.addEventListener('click', async () => {
        try {
            const res = await fetch('/oast/poll');
            const data = await res.json();
            if (data.callbacks && data.callbacks.length > 0) {
                callbacks = callbacks.concat(data.callbacks);
                renderCallbacks();
                appendLog('info', `OAST: ${data.callbacks.length} new callback(s) received.`);
            } else {
                appendLog('info', 'OAST: No new callbacks.');
            }
        } catch (e) {
            appendLog('vuln', 'OAST poll failed: ' + e.message);
        }
    });

    clearBtn?.addEventListener('click', () => {
        callbacks = [];
        listDiv.innerHTML = '<div class="empty-state">No callbacks received yet.</div>';
        detailDiv.innerHTML = '<div class="empty-state">Select a callback to view details.</div>';
    });

    function renderCallbacks() {
        if (callbacks.length === 0) {
            listDiv.innerHTML = '<div class="empty-state">No callbacks received yet.</div>';
            return;
        }

        listDiv.innerHTML = callbacks.map((cb, i) => `
            <div class="oast-item" data-idx="${i}">
                <div class="oast-item-type">${esc(cb.type || 'DNS')}</div>
                <div>${esc(cb.subdomain || cb.id || 'callback-' + i)}</div>
                <div class="oast-item-time">${esc(cb.timestamp || new Date().toISOString())}</div>
            </div>
        `).join('');

        listDiv.querySelectorAll('.oast-item').forEach(item => {
            item.addEventListener('click', () => {
                listDiv.querySelectorAll('.oast-item').forEach(x => x.classList.remove('active'));
                item.classList.add('active');
                const idx = parseInt(item.getAttribute('data-idx'));
                const cb = callbacks[idx];
                detailDiv.innerHTML = `
                    <h4 style="color:var(--warning); margin-bottom: 10px;">${esc(cb.type || 'DNS')} Callback</h4>
                    <pre style="white-space: pre-wrap; word-break: break-all; color: var(--text-primary);">${esc(JSON.stringify(cb, null, 2))}</pre>
                `;
            });
        });
    }
})();

// ═══════════════════════════════════════════════════════════════
// FEATURE 7: COPY FINDING TO CLIPBOARD
// ═══════════════════════════════════════════════════════════════
window.copyFinding = function (id) {
    const vuln = globalVulns[id];
    if (!vuln) return;
    const text = `[${vuln.severity}] ${vuln.type}\n${vuln.description}\nPayload: ${vuln.payload}`;
    navigator.clipboard.writeText(text).then(() => {
        appendLog('info', 'Finding copied to clipboard.');
    });
};

// ═══════════════════════════════════════════════════════════════
// FEATURE 8: STATUS BAR
// ═══════════════════════════════════════════════════════════════
let scanStartTime = null;
let scanTimerInterval = null;

function startScanTimer() {
    scanStartTime = Date.now();
    scanTimerInterval = setInterval(() => {
        const elapsed = Math.floor((Date.now() - scanStartTime) / 1000);
        const h = String(Math.floor(elapsed / 3600)).padStart(2, '0');
        const m = String(Math.floor((elapsed % 3600) / 60)).padStart(2, '0');
        const s = String(elapsed % 60).padStart(2, '0');
        document.getElementById('status-timer').innerText = `${h}:${m}:${s}`;
    }, 1000);
}

function stopScanTimer() {
    if (scanTimerInterval) clearInterval(scanTimerInterval);
    scanTimerInterval = null;
}

function updateStatusBar() {
    // Storage usage
    try {
        let totalSize = 0;
        for (let i = 0; i < localStorage.length; i++) {
            const key = localStorage.key(i);
            if (key.startsWith('wshawk_')) {
                totalSize += (localStorage.getItem(key) || '').length * 2; // UTF-16
            }
        }
        const kb = (totalSize / 1024).toFixed(1);
        document.getElementById('status-storage').innerText = `Storage: ${kb} KB`;
    } catch (e) { /* ignore */ }

    // Active schedulers count
    const schedules = JSON.parse(localStorage.getItem('wshawk_schedules') || '[]');
    const activeCount = schedules.filter(s => s.status === 'active').length;
    document.getElementById('status-schedulers').innerText = `${activeCount} scheduler${activeCount !== 1 ? 's' : ''}`;
}

// Update status bar every 5 seconds
setInterval(updateStatusBar, 5000);

// ═══════════════════════════════════════════════════════════════
// FEATURE 9: SEVERITY DISTRIBUTION CHART
// ═══════════════════════════════════════════════════════════════
function updateSeverityChart() {
    const cards = findingsContainer.querySelectorAll('.finding-card');
    let high = 0, medium = 0, low = 0;

    cards.forEach(card => {
        const sev = card.getAttribute('data-severity');
        if (sev === 'HIGH') high++;
        else if (sev === 'MEDIUM') medium++;
        else low++;
    });

    const total = high + medium + low;
    const maxBar = Math.max(high, medium, low, 1);

    document.getElementById('sev-count-high').innerText = high;
    document.getElementById('sev-count-medium').innerText = medium;
    document.getElementById('sev-count-low').innerText = low;

    document.getElementById('sev-bar-high').style.height = `${(high / maxBar) * 40}px`;
    document.getElementById('sev-bar-medium').style.height = `${(medium / maxBar) * 40}px`;
    document.getElementById('sev-bar-low').style.height = `${(low / maxBar) * 40}px`;
}

// ═══════════════════════════════════════════════════════════════
// FEATURE 11: PAYLOAD MUTATION LAB
// ═══════════════════════════════════════════════════════════════
(function initMutationLab() {
    const runBtn = document.getElementById('mutation-run-btn');
    const input = document.getElementById('mutation-input');
    const results = document.getElementById('mutation-results');
    const strategySelect = document.getElementById('mutation-strategy');
    const countInput = document.getElementById('mutation-count');

    if (!runBtn || !input || !results) return;

    const strategies = {
        case: function (payload) {
            const out = [];
            for (let i = 0; i < 5; i++) {
                let s = '';
                for (const ch of payload) {
                    s += Math.random() > 0.5 ? ch.toUpperCase() : ch.toLowerCase();
                }
                out.push({ strategy: 'CASE', value: s });
            }
            return out;
        },
        encode: function (payload) {
            return [
                { strategy: 'URL', value: encodeURIComponent(payload) },
                { strategy: 'B64', value: btoa(payload) },
                { strategy: 'HEX', value: Array.from(payload).map(c => '%' + c.charCodeAt(0).toString(16).padStart(2, '0')).join('') },
                { strategy: 'HTML-ENT', value: Array.from(payload).map(c => '&#' + c.charCodeAt(0) + ';').join('') },
                { strategy: 'UNICODE', value: Array.from(payload).map(c => '\\u' + c.charCodeAt(0).toString(16).padStart(4, '0')).join('') }
            ];
        },
        fragment: function (payload) {
            const out = [];
            const tags = ['<img src=x onerror=', '<svg onload=', '<body onload=', '<details open ontoggle=', '<marquee onstart='];
            tags.forEach(tag => {
                const inner = payload.replace(/<script>/gi, '').replace(/<\/script>/gi, '');
                out.push({ strategy: 'FRAG', value: `${tag}${inner}>` });
            });
            return out;
        },
        comment: function (payload) {
            const out = [];
            const insertComment = (s, pos) => s.slice(0, pos) + '/**/' + s.slice(pos);
            for (let i = 1; i < Math.min(payload.length, 6); i++) {
                out.push({ strategy: 'COMMENT', value: insertComment(payload, Math.floor(payload.length / (i + 1))) });
            }
            return out;
        },
        unicode: function (payload) {
            const subs = { '<': '\uFF1C', '>': '\uFF1E', '\'': '\u2019', '"': '\u201D', '/': '\u2215', '(': '\uFF08', ')': '\uFF09' };
            const out = [];
            // Single sub
            for (const [from, to] of Object.entries(subs)) {
                if (payload.includes(from)) {
                    out.push({ strategy: 'UNICODE', value: payload.replaceAll(from, to) });
                }
            }
            // All subs
            let full = payload;
            for (const [from, to] of Object.entries(subs)) full = full.replaceAll(from, to);
            if (full !== payload) out.push({ strategy: 'UNI-ALL', value: full });
            return out;
        },
        double: function (payload) {
            return [
                { strategy: 'DBL-URL', value: encodeURIComponent(encodeURIComponent(payload)) },
                { strategy: 'DBL-B64', value: btoa(btoa(payload)) },
                { strategy: 'URL+B64', value: encodeURIComponent(btoa(payload)) },
                { strategy: 'B64+URL', value: btoa(encodeURIComponent(payload)) }
            ];
        }
    };

    runBtn.addEventListener('click', async () => {
        const payload = input.value.trim();
        if (!payload) {
            results.innerHTML = '<div class="empty-state">Enter a base payload first.</div>';
            return;
        }

        const strategy = strategySelect.value;
        const maxCount = parseInt(countInput.value) || 10;
        let mutations = [];
        let engineUsed = 'CLIENT';

        // Try backend SPE engine first
        try {
            const res = await fetch('/mutate', {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ payload, strategy, count: maxCount })
            });
            const data = await res.json();
            if (data.status === 'success' && data.mutations.length > 0) {
                mutations = data.mutations;
                engineUsed = 'SPE';
            }
        } catch (e) {
            // Backend unavailable — fall through to client-side
        }

        // Client-side fallback
        if (mutations.length === 0) {
            if (strategy === 'all') {
                for (const fn of Object.values(strategies)) {
                    mutations = mutations.concat(fn(payload));
                }
            } else if (strategies[strategy]) {
                mutations = strategies[strategy](payload);
            }

            // Deduplicate and limit
            const seen = new Set();
            mutations = mutations.filter(m => {
                if (seen.has(m.value)) return false;
                seen.add(m.value);
                return true;
            }).slice(0, maxCount);
        }

        if (mutations.length === 0) {
            results.innerHTML = '<div class="empty-state">No mutations generated for this payload.</div>';
            return;
        }

        results.innerHTML = mutations.map((m, i) => `
            <div class="mutation-card">
                <span class="mut-idx">#${i + 1}</span>
                <span class="mut-strategy">${esc(m.strategy)}</span>
                <span class="mut-payload">${esc(m.value)}</span>
                <button class="mut-copy-btn" data-action="copy-mutation">Copy</button>
            </div>
        `).join('');

        appendLog('info', `Mutation Lab [${engineUsed}]: ${mutations.length} variants generated.`);
    });
})();

// ═══════════════════════════════════════════════════════════════
// FEATURE 12: GLOBAL SEARCH (Ctrl+K)
// ═══════════════════════════════════════════════════════════════
function toggleGlobalSearch() {
    const modal = document.getElementById('global-search-modal');
    if (!modal) return;

    if (modal.style.display === 'flex') {
        modal.style.display = 'none';
    } else {
        modal.style.display = 'flex';
        const input = document.getElementById('global-search-input');
        input.value = '';
        input.focus();
        document.getElementById('global-search-results').innerHTML = '<div class="empty-state" style="padding:20px;">Type to search across all data.</div>';
    }
}

(function initGlobalSearch() {
    const modal = document.getElementById('global-search-modal');
    const input = document.getElementById('global-search-input');
    const resultsDiv = document.getElementById('global-search-results');

    if (!modal || !input || !resultsDiv) return;

    // Close on backdrop click
    modal.addEventListener('click', (e) => {
        if (e.target === modal) modal.style.display = 'none';
    });

    let searchTimeout;
    input.addEventListener('input', () => {
        clearTimeout(searchTimeout);
        searchTimeout = setTimeout(() => performSearch(input.value.trim().toLowerCase()), 150);
    });

    function performSearch(term) {
        if (!term || term.length < 2) {
            resultsDiv.innerHTML = '<div class="empty-state" style="padding:20px;">Type at least 2 characters.</div>';
            return;
        }

        let html = '';
        let totalResults = 0;

        // Search findings
        const findingResults = [];
        for (const [id, v] of Object.entries(globalVulns)) {
            const text = `${v.type} ${v.description} ${v.payload} ${v.severity}`.toLowerCase();
            if (text.includes(term)) {
                findingResults.push({ id, vuln: v });
            }
        }
        if (findingResults.length > 0) {
            html += '<div class="gsearch-category">Findings</div>';
            findingResults.slice(0, 5).forEach(f => {
                html += `<div class="gsearch-item" data-action="gsearch-nav" data-target="dashboard">
                    <div>[${esc(f.vuln.severity)}] ${esc(f.vuln.type)}</div>
                    <div class="gsearch-meta">${esc(truncate(f.vuln.description, 60))}</div>
                </div>`;
            });
            totalResults += findingResults.length;
        }

        // Search notes
        try {
            const notes = JSON.parse(localStorage.getItem('wshawk_notes') || '[]');
            const noteResults = notes.filter(n =>
                (n.title || '').toLowerCase().includes(term) ||
                (n.body || '').toLowerCase().includes(term)
            );
            if (noteResults.length > 0) {
                html += '<div class="gsearch-category">Notes</div>';
                noteResults.slice(0, 5).forEach(n => {
                    html += `<div class="gsearch-item" data-action="gsearch-nav" data-target="notes">
                        <div>${esc(n.title || 'Untitled')}</div>
                        <div class="gsearch-meta">${esc(truncate(n.body || '', 60))}</div>
                    </div>`;
                });
                totalResults += noteResults.length;
            }
        } catch (e) { /* ignore */ }

        // Search history
        const histResults = [];
        for (const [id, data] of Object.entries(historyData)) {
            if (String(data).toLowerCase().includes(term)) {
                histResults.push({ id, data });
            }
        }
        if (histResults.length > 0) {
            html += '<div class="gsearch-category">History</div>';
            histResults.slice(0, 5).forEach(h => {
                html += `<div class="gsearch-item" data-action="gsearch-history" data-row-id="${esc(h.id)}">
                    <div>${esc(truncate(h.data, 70))}</div>
                    <div class="gsearch-meta">Click to send to Request Forge</div>
                </div>`;
            });
            totalResults += histResults.length;
        }

        // Search endpoints (from discovery)
        try {
            const epContainer = document.getElementById('wsmap-results');
            if (epContainer) {
                const epItems = epContainer.querySelectorAll('.endpoint-card, .ep-card, tr');
                const epResults = [];
                epItems.forEach(el => {
                    if (el.innerText.toLowerCase().includes(term)) {
                        epResults.push(el.innerText.slice(0, 80));
                    }
                });
                if (epResults.length > 0) {
                    html += '<div class="gsearch-category">Endpoints</div>';
                    epResults.slice(0, 5).forEach(ep => {
                        html += `<div class="gsearch-item" data-action="gsearch-nav" data-target="wsmap">
                            <div>${esc(truncate(ep, 70))}</div>
                        </div>`;
                    });
                    totalResults += epResults.length;
                }
            }
        } catch (e) { /* ignore */ }

        if (totalResults === 0) {
            html = `<div class="empty-state" style="padding:20px;">No results for "${esc(term)}".</div>`;
        }

        resultsDiv.innerHTML = html;
    }
})();

// ═══════════════════════════════════════════════════════════════
// WEB PENTEST TOOLS LOGIC
// ═══════════════════════════════════════════════════════════════
