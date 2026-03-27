(function CyberNodeEngine() {
    'use strict';

    // ── Node Type Registry ──────────────────────────────────────────
    const NODE_REGISTRY = {
        subdomain: { icon: 'SD', label: 'Subdomain Finder', endpoint: '/web/subdomains', inputField: 'target', outputKey: 'subdomains', color: '#06b6d4' },
        crawler: { icon: 'WC', label: 'Web Crawler', endpoint: '/web/crawl', inputField: 'url', outputKey: 'pages', color: '#8b5cf6' },
        techfp: { icon: 'TF', label: 'Tech Fingerprint', endpoint: '/web/fingerprint', inputField: 'url', outputKey: 'technologies', color: '#f59e0b' },
        dnslookup: { icon: 'DN', label: 'DNS / WHOIS', endpoint: '/web/dns', inputField: 'domain', outputKey: 'records', color: '#14b8a6' },
        portscan: { icon: 'PS', label: 'Port Scanner', endpoint: '/web/portscan', inputField: 'target', outputKey: 'open_ports', color: '#6366f1' },
        dirscan: { icon: 'DS', label: 'Dir Scanner', endpoint: '/web/dirscan', inputField: 'url', outputKey: 'found', color: '#22c55e' },
        headeranalyzer: { icon: 'HA', label: 'Header Analyzer', endpoint: '/web/headers', inputField: 'url', outputKey: 'headers', color: '#a855f7' },
        sslanalyzer: { icon: 'SS', label: 'SSL/TLS Analyzer', endpoint: '/web/ssl', inputField: 'url', outputKey: 'certificate', color: '#3b82f6' },
        sensitivefinder: { icon: 'SF', label: 'Sensitive Finder', endpoint: '/web/sensitive', inputField: 'url', outputKey: 'findings', color: '#ef4444' },
        vulnscan: { icon: 'VS', label: 'Vuln Scanner', endpoint: '/web/vulnscan', inputField: 'url', outputKey: 'findings', color: '#dc2626' },
        wafdetect: { icon: 'WF', label: 'WAF Detector', endpoint: '/web/waf', inputField: 'url', outputKey: 'results', color: '#f97316' },
        httpfuzzer: { icon: 'FZ', label: 'HTTP Fuzzer', endpoint: '/web/fuzz', inputField: 'url', outputKey: 'results', color: '#e11d48' },
        corstester: { icon: 'CR', label: 'CORS Tester', endpoint: '/web/cors', inputField: 'url', outputKey: 'findings', color: '#d946ef' },
        csrfforge: { icon: 'XF', label: 'CSRF Forge', endpoint: '/web/csrf', inputField: 'url', outputKey: 'result', color: '#f43f5e' },
        ssrfprobe: { icon: 'BP', label: 'Blind Probe', endpoint: '/web/ssrf', inputField: 'url', outputKey: 'findings', color: '#be123c' },
        redirect: { icon: 'RH', label: 'Redirect Hunter', endpoint: '/web/redirect', inputField: 'url', outputKey: 'redirects', color: '#fb923c' },
        protopollute: { icon: 'PP', label: 'Proto Polluter', endpoint: '/web/proto', inputField: 'url', outputKey: 'findings', color: '#7c3aed' },
        filter: { icon: 'FG', label: 'Filter / Grep', endpoint: null, inputField: 'pattern', outputKey: 'filtered', color: '#64748b' },
        note: { icon: 'NT', label: 'Note / Label', endpoint: null, inputField: null, outputKey: null, color: '#475569' },
    };

    // ── State ───────────────────────────────────────────────────────
    let nodes = [];
    let wires = [];
    let nextId = 1;
    let zoom = 1;
    let panX = 0, panY = 0;
    let selectedNode = null;
    let draggingNode = null;
    let dragOffX = 0, dragOffY = 0;
    let connectingFrom = null; // { nodeId, portType: 'output' }
    let tempWirePath = null;

    // ── DOM refs ────────────────────────────────────────────────────
    const canvas = document.getElementById('cn-canvas');
    const canvasWrap = document.getElementById('cn-canvas-wrap');
    const svgLayer = document.getElementById('cn-svg-layer');
    const minimapCanvas = document.getElementById('cn-minimap-canvas');
    const execPanel = document.getElementById('cn-exec-panel');
    const execLog = document.getElementById('cn-exec-log');
    const zoomLabel = document.getElementById('cn-zoom-level');

    if (!canvas) return; // Guard: only init if CyberNode panel exists

    // ── Helpers ─────────────────────────────────────────────────────
    function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }

    function getNodeById(id) { return nodes.find(n => n.id === id); }

    function getCanvasOffset() {
        const r = canvasWrap.getBoundingClientRect();
        return { x: r.left, y: r.top };
    }

    function screenToCanvas(sx, sy) {
        const off = getCanvasOffset();
        return {
            x: (sx - off.x - panX) / zoom,
            y: (sy - off.y - panY) / zoom
        };
    }

    // ── Create Node DOM ─────────────────────────────────────────────
    function createNodeElement(node) {
        const reg = NODE_REGISTRY[node.type] || {};
        const el = document.createElement('div');
        el.className = 'cn-node';
        el.dataset.nodeId = node.id;
        el.style.left = node.x + 'px';
        el.style.top = node.y + 'px';
        el.style.transform = `scale(${zoom})`;
        el.style.transformOrigin = 'top left';

        const isLogic = node.type === 'filter' || node.type === 'note';

        let bodyHTML = '';
        if (node.type === 'note') {
            bodyHTML = `<label>Note</label><textarea class="cn-node-input" data-field="note" rows="3" placeholder="Write a note...">${esc(node.config.note || '')}</textarea>`;
        } else if (node.type === 'filter') {
            bodyHTML = `
                <label>Grep Pattern</label>
                <input class="cn-node-input" data-field="pattern" placeholder="e.g. status:200" value="${esc(node.config.pattern || '')}">
                <label>Field Path</label>
                <input class="cn-node-input" data-field="field" placeholder="e.g. url or ." value="${esc(node.config.field || '')}">
            `;
        } else {
            bodyHTML = `<label>Target</label><input class="cn-node-input" data-field="target" placeholder="e.g. https://target.com" value="${esc(node.config.target || '')}">`;
        }

        el.innerHTML = `
            <div class="cn-node-status idle"></div>
            <div class="cn-node-header" style="background: ${reg.color || '#333'};">
                <span class="cn-node-icon">${reg.icon || '●'}</span>
                <span class="cn-node-title">${esc(reg.label || node.type)}</span>
                <button class="cn-node-delete" title="Remove node">✕</button>
            </div>
            <div class="cn-node-body">${bodyHTML}</div>
            <div class="cn-node-footer">
                ${node.type !== 'note' ? '<div class="cn-port input" data-port="input" title="Input"></div>' : '<div></div>'}
                ${node.type !== 'note' ? '<div class="cn-port output" data-port="output" title="Output"></div>' : '<div></div>'}
            </div>
        `;

        // ── Input change handlers ──
        el.querySelectorAll('.cn-node-input').forEach(inp => {
            inp.addEventListener('input', () => {
                node.config[inp.dataset.field] = inp.value;
            });
            // Prevent canvas drag when typing
            inp.addEventListener('mousedown', e => e.stopPropagation());
        });

        // ── Delete button ──
        el.querySelector('.cn-node-delete').addEventListener('click', (e) => {
            e.stopPropagation();
            removeNode(node.id);
        });

        // ── Node drag ──
        el.addEventListener('mousedown', (e) => {
            if (e.target.classList.contains('cn-port') || e.target.tagName === 'INPUT' || e.target.tagName === 'TEXTAREA' || e.target.tagName === 'BUTTON') return;
            e.preventDefault();
            draggingNode = node;
            const pos = screenToCanvas(e.clientX, e.clientY);
            dragOffX = pos.x - node.x;
            dragOffY = pos.y - node.y;
            el.classList.add('dragging');
            selectNode(node.id);
        });

        // ── Port connection start ──
        el.querySelectorAll('.cn-port').forEach(port => {
            port.addEventListener('mousedown', (e) => {
                e.stopPropagation();
                e.preventDefault();
                const portType = port.dataset.port;
                if (portType === 'output') {
                    connectingFrom = { nodeId: node.id };
                    canvasWrap.classList.add('connecting');
                    // Create temp wire
                    const svgNS = 'http://www.w3.org/2000/svg';
                    tempWirePath = document.createElementNS(svgNS, 'path');
                    tempWirePath.setAttribute('class', 'cn-wire');
                    tempWirePath.setAttribute('stroke-dasharray', '6 3');
                    tempWirePath.style.opacity = '0.4';
                    svgLayer.appendChild(tempWirePath);
                }
            });

            port.addEventListener('mouseup', (e) => {
                e.stopPropagation();
                const portType = port.dataset.port;
                if (connectingFrom && portType === 'input' && connectingFrom.nodeId !== node.id) {
                    // Prevent duplicate wires
                    const exists = wires.some(w => w.from === connectingFrom.nodeId && w.to === node.id);
                    if (!exists) {
                        wires.push({ from: connectingFrom.nodeId, to: node.id });
                        updateAllWires();
                        updatePortStyles();
                    }
                }
            });
        });

        // ── Click select ──
        el.addEventListener('click', (e) => {
            if (e.target.tagName !== 'INPUT' && e.target.tagName !== 'TEXTAREA' && e.target.tagName !== 'BUTTON') {
                selectNode(node.id);
            }
        });

        return el;
    }

    // ── Add Node ────────────────────────────────────────────────────
    function addNode(type, x, y) {
        const node = {
            id: nextId++,
            type,
            x: x || 100,
            y: y || 100,
            config: {},
            _result: null,
            _status: 'idle' // idle | running | done | error
        };
        nodes.push(node);
        const el = createNodeElement(node);
        canvas.appendChild(el);
        applyTransform();
        updateMinimap();
        return node;
    }

    // ── Remove Node ─────────────────────────────────────────────────
    function removeNode(id) {
        wires = wires.filter(w => w.from !== id && w.to !== id);
        nodes = nodes.filter(n => n.id !== id);
        const el = canvas.querySelector(`[data-node-id="${id}"]`);
        if (el) el.remove();
        updateAllWires();
        updatePortStyles();
        updateMinimap();
        if (selectedNode === id) selectedNode = null;
    }

    // ── Select Node ─────────────────────────────────────────────────
    function selectNode(id) {
        selectedNode = id;
        canvas.querySelectorAll('.cn-node').forEach(el => {
            el.classList.toggle('selected', parseInt(el.dataset.nodeId) === id);
        });
    }

    // ── Wire Drawing ────────────────────────────────────────────────
    function getPortPosition(nodeId, portType) {
        const el = canvas.querySelector(`[data-node-id="${nodeId}"]`);
        if (!el) return { x: 0, y: 0 };
        const port = el.querySelector(`.cn-port.${portType}`);
        if (!port) return { x: 0, y: 0 };

        const node = getNodeById(nodeId);
        const portRect = port.getBoundingClientRect();
        const wrapRect = canvasWrap.getBoundingClientRect();

        return {
            x: (portRect.left + portRect.width / 2 - wrapRect.left - panX) / zoom,
            y: (portRect.top + portRect.height / 2 - wrapRect.top - panY) / zoom
        };
    }

    function drawWire(from, to, wireEl) {
        const dx = Math.abs(to.x - from.x) * 0.5;
        const d = `M ${from.x} ${from.y} C ${from.x + dx} ${from.y}, ${to.x - dx} ${to.y}, ${to.x} ${to.y}`;
        wireEl.setAttribute('d', d);
    }

    function updateAllWires() {
        // Remove old wire paths
        svgLayer.querySelectorAll('.cn-wire:not([data-temp])').forEach(p => p.remove());

        const svgNS = 'http://www.w3.org/2000/svg';
        wires.forEach((w, idx) => {
            const fromPos = getPortPosition(w.from, 'output');
            const toPos = getPortPosition(w.to, 'input');
            const path = document.createElementNS(svgNS, 'path');
            path.setAttribute('class', 'cn-wire');
            path.dataset.wireIdx = idx;

            // Double-click to delete wire
            path.style.pointerEvents = 'stroke';
            path.addEventListener('dblclick', (e) => {
                e.stopPropagation();
                wires.splice(idx, 1);
                updateAllWires();
                updatePortStyles();
            });

            drawWire(fromPos, toPos, path);
            svgLayer.appendChild(path);
        });
    }

    function updatePortStyles() {
        canvas.querySelectorAll('.cn-port').forEach(port => {
            port.classList.remove('connected');
        });
        wires.forEach(w => {
            const fromEl = canvas.querySelector(`[data-node-id="${w.from}"] .cn-port.output`);
            const toEl = canvas.querySelector(`[data-node-id="${w.to}"] .cn-port.input`);
            if (fromEl) fromEl.classList.add('connected');
            if (toEl) toEl.classList.add('connected');
        });
    }

    // ── Canvas Mouse Events ─────────────────────────────────────────
    let isPanning = false;
    let panStartX = 0, panStartY = 0;

    canvasWrap.addEventListener('mousedown', (e) => {
        if (e.target === canvasWrap || e.target === canvas || e.target.classList.contains('cn-canvas')) {
            // Deselect
            selectNode(null);
            // Start panning (middle click or if no node is being dragged)
            if (e.button === 1 || (e.button === 0 && !draggingNode)) {
                isPanning = true;
                panStartX = e.clientX - panX;
                panStartY = e.clientY - panY;
                canvasWrap.classList.add('panning');
            }
        }
    });

    window.addEventListener('mousemove', (e) => {
        // Node dragging
        if (draggingNode) {
            const pos = screenToCanvas(e.clientX, e.clientY);
            draggingNode.x = Math.round((pos.x - dragOffX) / 12) * 12; // Snap to 12px grid
            draggingNode.y = Math.round((pos.y - dragOffY) / 12) * 12;
            const el = canvas.querySelector(`[data-node-id="${draggingNode.id}"]`);
            if (el) {
                el.style.left = draggingNode.x + 'px';
                el.style.top = draggingNode.y + 'px';
            }
            updateAllWires();
            updateMinimap();
        }

        // Panning
        if (isPanning) {
            panX = e.clientX - panStartX;
            panY = e.clientY - panStartY;
            applyTransform();
            updateAllWires();
            updateMinimap();
        }

        // Temp wire while connecting
        if (connectingFrom && tempWirePath) {
            const fromPos = getPortPosition(connectingFrom.nodeId, 'output');
            const toPos = screenToCanvas(e.clientX, e.clientY);
            drawWire(fromPos, toPos, tempWirePath);
        }
    });

    window.addEventListener('mouseup', () => {
        if (draggingNode) {
            const el = canvas.querySelector(`[data-node-id="${draggingNode.id}"]`);
            if (el) el.classList.remove('dragging');
            draggingNode = null;
        }
        if (isPanning) {
            isPanning = false;
            canvasWrap.classList.remove('panning');
        }
        if (connectingFrom) {
            connectingFrom = null;
            canvasWrap.classList.remove('connecting');
            if (tempWirePath) {
                tempWirePath.remove();
                tempWirePath = null;
            }
        }
    });

    // ── Zoom ────────────────────────────────────────────────────────
    canvasWrap.addEventListener('wheel', (e) => {
        e.preventDefault();
        const delta = e.deltaY > 0 ? -0.05 : 0.05;
        zoom = Math.min(2, Math.max(0.25, zoom + delta));
        zoomLabel.textContent = Math.round(zoom * 100) + '%';
        applyTransform();
        updateAllWires();
        updateMinimap();
    }, { passive: false });

    document.getElementById('cn-zoom-in')?.addEventListener('click', () => {
        zoom = Math.min(2, zoom + 0.1);
        zoomLabel.textContent = Math.round(zoom * 100) + '%';
        applyTransform(); updateAllWires(); updateMinimap();
    });
    document.getElementById('cn-zoom-out')?.addEventListener('click', () => {
        zoom = Math.max(0.25, zoom - 0.1);
        zoomLabel.textContent = Math.round(zoom * 100) + '%';
        applyTransform(); updateAllWires(); updateMinimap();
    });
    document.getElementById('cn-zoom-fit')?.addEventListener('click', () => {
        zoom = 1; panX = 0; panY = 0;
        zoomLabel.textContent = '100%';
        applyTransform(); updateAllWires(); updateMinimap();
    });

    function applyTransform() {
        canvas.style.transform = `translate(${panX}px, ${panY}px) scale(${zoom})`;
        canvas.style.transformOrigin = '0 0';
        svgLayer.style.transform = `translate(${panX}px, ${panY}px) scale(${zoom})`;
        svgLayer.style.transformOrigin = '0 0';
    }

    // ── Drag & Drop from Toolbox ────────────────────────────────────
    canvasWrap.addEventListener('dragover', (e) => {
        e.preventDefault();
        canvasWrap.classList.add('drag-over');
    });

    canvasWrap.addEventListener('dragleave', () => {
        canvasWrap.classList.remove('drag-over');
    });

    canvasWrap.addEventListener('drop', (e) => {
        e.preventDefault();
        canvasWrap.classList.remove('drag-over');
        const type = e.dataTransfer.getData('text/plain');
        if (!NODE_REGISTRY[type]) return;

        const pos = screenToCanvas(e.clientX, e.clientY);
        addNode(type, pos.x, pos.y);
    });

    document.querySelectorAll('.cn-tool-node').forEach(toolEl => {
        toolEl.addEventListener('dragstart', (e) => {
            e.dataTransfer.setData('text/plain', toolEl.dataset.nodeType);
            e.dataTransfer.effectAllowed = 'copy';
        });
    });

    // ── Minimap ─────────────────────────────────────────────────────
    function updateMinimap() {
        if (!minimapCanvas) return;
        const ctx = minimapCanvas.getContext('2d');
        const w = minimapCanvas.width;
        const h = minimapCanvas.height;
        ctx.clearRect(0, 0, w, h);

        if (nodes.length === 0) return;

        // Compute bounds
        let minX = Infinity, minY = Infinity, maxX = -Infinity, maxY = -Infinity;
        nodes.forEach(n => {
            if (n.x < minX) minX = n.x;
            if (n.y < minY) minY = n.y;
            if (n.x + 180 > maxX) maxX = n.x + 180;
            if (n.y + 100 > maxY) maxY = n.y + 100;
        });

        const padding = 50;
        minX -= padding; minY -= padding; maxX += padding; maxY += padding;
        const rangeX = maxX - minX || 1;
        const rangeY = maxY - minY || 1;
        const scale = Math.min(w / rangeX, h / rangeY);

        // Draw wires
        ctx.strokeStyle = '#3b82f6';
        ctx.lineWidth = 1;
        ctx.globalAlpha = 0.4;
        wires.forEach(wire => {
            const fromNode = getNodeById(wire.from);
            const toNode = getNodeById(wire.to);
            if (!fromNode || !toNode) return;
            const fx = (fromNode.x + 90 - minX) * scale;
            const fy = (fromNode.y + 50 - minY) * scale;
            const tx = (toNode.x + 90 - minX) * scale;
            const ty = (toNode.y + 50 - minY) * scale;
            ctx.beginPath();
            ctx.moveTo(fx, fy);
            ctx.lineTo(tx, ty);
            ctx.stroke();
        });

        // Draw nodes
        ctx.globalAlpha = 0.8;
        nodes.forEach(n => {
            const reg = NODE_REGISTRY[n.type] || {};
            ctx.fillStyle = reg.color || '#555';
            const nx = (n.x - minX) * scale;
            const ny = (n.y - minY) * scale;
            const nw = 180 * scale;
            const nh = 60 * scale;
            ctx.fillRect(nx, ny, Math.max(nw, 4), Math.max(nh, 3));
        });

        ctx.globalAlpha = 1;
    }

    // ── Pipeline Execution ──────────────────────────────────────────
    document.getElementById('cn-exec-btn')?.addEventListener('click', executePipeline);

    async function executePipeline() {
        // Build execution order via topological sort
        const order = topologicalSort();
        if (!order) {
            alert('Pipeline contains a cycle! Please remove circular connections.');
            return;
        }

        // Show execution panel
        execPanel.style.display = 'flex';
        execLog.innerHTML = '';

        // Reset all node statuses
        nodes.forEach(n => { n._status = 'idle'; n._result = null; setNodeStatus(n.id, 'idle'); });

        const results = {};

        for (const nodeId of order) {
            const node = getNodeById(nodeId);
            if (!node) continue;
            const reg = NODE_REGISTRY[node.type];
            if (!reg) continue;

            // Skip note nodes
            if (node.type === 'note') continue;

            setNodeStatus(node.id, 'running');
            addExecLog(node, 'running', 'Executing...');

            try {
                // Gather input from upstream wires
                const upstreamWires = wires.filter(w => w.to === node.id);
                let inputTargets = [];

                if (upstreamWires.length > 0) {
                    upstreamWires.forEach(w => {
                        const upstream = getNodeById(w.from);
                        if (upstream && upstream._result) {
                            const data = upstream._result;
                            // Try to extract URLs or targets from upstream results
                            if (Array.isArray(data)) {
                                data.forEach(item => {
                                    if (typeof item === 'string') inputTargets.push(item);
                                    else if (item && item.url) inputTargets.push(item.url);
                                    else if (item && item.hostname) inputTargets.push(item.hostname);
                                });
                            }
                        }
                    });
                }

                // Filter node: apply grep locally
                if (node.type === 'filter') {
                    const pattern = (node.config.pattern || '').toLowerCase();
                    const field = node.config.field || '';
                    let filtered = inputTargets;
                    if (pattern) {
                        filtered = inputTargets.filter(item => {
                            const str = typeof item === 'string' ? item : JSON.stringify(item);
                            return str.toLowerCase().includes(pattern);
                        });
                    }
                    node._result = filtered;
                    node._status = 'done';
                    results[node.id] = filtered;
                    setNodeStatus(node.id, 'done');
                    addExecLog(node, 'done', `Filtered: ${filtered.length} items passed`, filtered);
                    renderNodeResults(node.id, filtered);
                    setWireStatus(node.id, 'active');
                    continue;
                }

                // If no upstream and no manual target, use config target
                let target = node.config.target || '';
                if (inputTargets.length > 0 && !target) {
                    target = inputTargets[0]; // Use first upstream result as target
                }

                if (!target && !reg.endpoint) {
                    node._status = 'done';
                    setNodeStatus(node.id, 'done');
                    addExecLog(node, 'skipped', 'No target and no endpoint');
                    continue;
                }

                if (!reg.endpoint) {
                    node._status = 'done';
                    setNodeStatus(node.id, 'done');
                    continue;
                }

                // Call the backend
                const payload = {};
                payload[reg.inputField] = target;

                // Add optional params from config
                Object.entries(node.config).forEach(([k, v]) => {
                    if (k !== 'target' && v) payload[k] = v;
                });

                const resp = await fetch(`http://127.0.0.1:8080${reg.endpoint}`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(payload)
                });

                const data = await resp.json();

                if (data.status === 'error' || resp.status >= 400) {
                    throw new Error(data.detail || data.error || 'Request failed');
                }

                // Store result
                const output = data[reg.outputKey] || data;
                node._result = output;
                node._status = 'done';
                results[node.id] = output;

                const count = Array.isArray(output) ? output.length : (typeof output === 'object' ? Object.keys(output).length : 1);
                setNodeStatus(node.id, 'done');
                addExecLog(node, 'done', `✓ ${count} results`, output);
                renderNodeResults(node.id, output);
                crossPopulateTab(node.type, output, target);
                setWireStatus(node.id, 'active');

            } catch (err) {
                node._status = 'error';
                setNodeStatus(node.id, 'error');
                addExecLog(node, 'error', err.message);
                setWireStatus(node.id, 'error');
            }
        }

        addExecLog(null, 'done', '— Pipeline Complete —');
    }

    function topologicalSort() {
        const inDegree = {};
        const adj = {};
        nodes.forEach(n => { inDegree[n.id] = 0; adj[n.id] = []; });
        wires.forEach(w => {
            adj[w.from].push(w.to);
            inDegree[w.to] = (inDegree[w.to] || 0) + 1;
        });

        const queue = nodes.filter(n => inDegree[n.id] === 0).map(n => n.id);
        const order = [];

        while (queue.length > 0) {
            const curr = queue.shift();
            order.push(curr);
            (adj[curr] || []).forEach(next => {
                inDegree[next]--;
                if (inDegree[next] === 0) queue.push(next);
            });
        }

        return order.length === nodes.length ? order : null; // null = cycle
    }

    function setNodeStatus(nodeId, status) {
        const el = canvas.querySelector(`[data-node-id="${nodeId}"]`);
        if (!el) return;
        const dot = el.querySelector('.cn-node-status');
        if (dot) { dot.className = 'cn-node-status ' + status; }
        el.classList.remove('running', 'done', 'error');
        if (status !== 'idle') el.classList.add(status);
    }

    function setWireStatus(nodeId, status) {
        wires.forEach((w, idx) => {
            if (w.from === nodeId) {
                const wireEl = svgLayer.querySelector(`[data-wire-idx="${idx}"]`);
                if (wireEl) {
                    wireEl.classList.remove('active', 'error');
                    if (status !== 'idle') wireEl.classList.add(status);
                }
            }
        });
    }

    function addExecLog(node, status, msg, resultData) {
        const reg = node ? (NODE_REGISTRY[node.type] || {}) : {};
        const entry = document.createElement('div');
        entry.className = 'cn-exec-entry ' + status;

        let resultHTML = '';
        if (resultData && status === 'done') {
            const items = formatResultItems(resultData);
            if (items.length > 0) {
                const preview = items.slice(0, 30).map(item =>
                    `<div style="padding: 2px 0; border-bottom: 1px solid rgba(255,255,255,0.04); word-break: break-all;">${esc(item)}</div>`
                ).join('');
                const moreText = items.length > 30 ? `<div style="color: var(--accent); padding-top: 4px;">... and ${items.length - 30} more</div>` : '';
                resultHTML = `
                    <div class="cn-exec-results" style="margin-top: 6px; max-height: 200px; overflow-y: auto; background: rgba(0,0,0,0.3); border-radius: 4px; padding: 6px 8px; font-size: 9.5px; color: var(--text-secondary);">
                        ${preview}${moreText}
                    </div>
                `;
            }
        }

        entry.innerHTML = `
            <div class="cn-exec-name">${node ? esc(reg.label || node.type) : 'Pipeline'}</div>
            <div class="cn-exec-detail">${esc(msg)}</div>
            ${resultHTML}
        `;
        execLog.appendChild(entry);
        execLog.scrollTop = execLog.scrollHeight;
    }

    function formatResultItems(data) {
        if (Array.isArray(data)) {
            return data.map(item => {
                if (typeof item === 'string') return item;
                if (item && item.url) return item.url;
                if (item && item.hostname) return item.hostname;
                if (item && item.subdomain) return item.subdomain;
                if (item && item.domain) return item.domain;
                if (item && item.name) return item.name;
                if (item && item.title) return item.title;
                return JSON.stringify(item);
            });
        } else if (typeof data === 'object' && data !== null) {
            return Object.entries(data).map(([k, v]) => `${k}: ${typeof v === 'object' ? JSON.stringify(v) : v}`);
        }
        return [String(data)];
    }

    function renderNodeResults(nodeId, data) {
        const el = canvas.querySelector(`[data-node-id="${nodeId}"]`);
        if (!el) return;

        // Remove any existing result preview
        const existing = el.querySelector('.cn-node-results');
        if (existing) existing.remove();

        const items = formatResultItems(data);
        if (items.length === 0) return;

        const resultsDiv = document.createElement('div');
        resultsDiv.className = 'cn-node-results';
        resultsDiv.style.cssText = 'max-height: 120px; overflow-y: auto; padding: 4px 12px 8px; font-family: var(--font-mono); font-size: 9.5px; border-top: 1px solid var(--border-color); color: var(--text-secondary);';

        const header = document.createElement('div');
        header.style.cssText = 'font-size: 9px; font-weight: 700; color: var(--safe); text-transform: uppercase; letter-spacing: 0.5px; margin-bottom: 4px; display: flex; justify-content: space-between;';
        header.innerHTML = `<span>✓ ${items.length} Results</span><span style="color: var(--text-muted); cursor: pointer;" class="cn-results-toggle">▼</span>`;
        resultsDiv.appendChild(header);

        const listDiv = document.createElement('div');
        listDiv.className = 'cn-results-list';
        items.slice(0, 20).forEach(item => {
            const row = document.createElement('div');
            row.style.cssText = 'padding: 2px 0; border-bottom: 1px solid rgba(255,255,255,0.04); word-break: break-all; cursor: pointer;';
            row.textContent = item;
            row.title = 'Click to copy';
            row.addEventListener('click', (e) => {
                e.stopPropagation();
                navigator.clipboard.writeText(item);
                row.style.color = 'var(--safe)';
                setTimeout(() => { row.style.color = ''; }, 600);
            });
            listDiv.appendChild(row);
        });
        if (items.length > 20) {
            const more = document.createElement('div');
            more.style.cssText = 'color: var(--accent); padding-top: 4px; font-size: 9px;';
            more.textContent = `... and ${items.length - 20} more`;
            listDiv.appendChild(more);
        }
        resultsDiv.appendChild(listDiv);

        // Toggle collapse
        header.querySelector('.cn-results-toggle').addEventListener('click', (e) => {
            e.stopPropagation();
            const isHidden = listDiv.style.display === 'none';
            listDiv.style.display = isHidden ? '' : 'none';
            e.target.textContent = isHidden ? '▼' : '▶';
        });

        // Insert before the footer (ports)
        const footer = el.querySelector('.cn-node-footer');
        if (footer) {
            el.insertBefore(resultsDiv, footer);
        } else {
            el.appendChild(resultsDiv);
        }
    }

    // ── Cross-populate regular sidebar tabs with CyberNode results ──
    function crossPopulateTab(nodeType, output, target) {
        try {
            if (nodeType === 'subdomain' && Array.isArray(output)) {
                const tbody = document.getElementById('subdomain-results-tbody');
                const prog = document.getElementById('subdomain-progress');
                const targetInput = document.getElementById('subdomain-target');
                if (!tbody) return;

                if (targetInput && target) targetInput.value = target;
                if (prog) prog.innerText = `Found ${output.length} subdomains (via CyberNode pipeline).`;

                tbody.innerHTML = '';
                output.forEach(sub => {
                    const subText = typeof sub === 'string' ? sub : (sub.hostname || sub.subdomain || JSON.stringify(sub));
                    const tr = document.createElement('tr');
                    tr.innerHTML = `
                        <td>${esc(subText)}</td>
                        <td style="font-family: var(--font-mono); font-weight: 500;">—</td>
                        <td><span class="badge safe">PASSIVE</span></td>
                    `;
                    tbody.appendChild(tr);
                });

                const wfBtn = document.getElementById('subdomain-workflow-btn');
                if (wfBtn) wfBtn.style.display = 'inline-block';
            }

            if (nodeType === 'headeranalyzer' && output) {
                const tbody = document.getElementById('header-results-tbody');
                if (tbody && typeof output === 'object') {
                    tbody.innerHTML = '';
                    const headers = output.headers || output;
                    Object.entries(headers).forEach(([k, v]) => {
                        const tr = document.createElement('tr');
                        tr.innerHTML = `<td>${esc(k)}</td><td>${esc(String(v))}</td>`;
                        tbody.appendChild(tr);
                    });
                }
            }

            if (nodeType === 'sslanalyzer' && output) {
                const box = document.getElementById('ssl-results-box');
                if (box) {
                    box.innerHTML = `<pre style="white-space: pre-wrap; font-size: 11px;">${esc(JSON.stringify(output, null, 2))}</pre>`;
                }
            }

            if (nodeType === 'wafdetect' && output) {
                const box = document.getElementById('waf-results-box');
                if (box) {
                    box.innerHTML = `<pre style="white-space: pre-wrap; font-size: 11px;">${esc(JSON.stringify(output, null, 2))}</pre>`;
                }
            }
        } catch (e) {
            console.warn('[CyberNode] Cross-populate failed for', nodeType, e);
        }
    }

    // ── Exec Panel close ────────────────────────────────────────────
    document.getElementById('cn-exec-close')?.addEventListener('click', () => {
        execPanel.style.display = 'none';
    });

    // ── Clear Canvas ────────────────────────────────────────────────
    document.getElementById('cn-clear-btn')?.addEventListener('click', () => {
        if (!confirm('Clear all nodes and connections?')) return;
        nodes = [];
        wires = [];
        canvas.innerHTML = '';
        svgLayer.innerHTML = '';
        updateMinimap();
    });

    // ── Export .hawkchain ────────────────────────────────────────────
    document.getElementById('cn-export-btn')?.addEventListener('click', () => {
        const data = {
            version: '1.0',
            created: new Date().toISOString(),
            nodes: nodes.map(n => ({ id: n.id, type: n.type, x: n.x, y: n.y, config: n.config })),
            wires: wires.map(w => ({ from: w.from, to: w.to }))
        };
        const blob = new Blob([JSON.stringify(data, null, 2)], { type: 'application/json' });
        const url = URL.createObjectURL(blob);
        const a = document.createElement('a');
        a.href = url;
        a.download = `pipeline-${Date.now()}.hawkchain`;
        a.click();
        URL.revokeObjectURL(url);
    });

    // ── Import .hawkchain ───────────────────────────────────────────
    const importBtn = document.getElementById('cn-import-btn');
    const importFile = document.getElementById('cn-import-file');
    if (importBtn && importFile) {
        importBtn.addEventListener('click', () => importFile.click());
        importFile.addEventListener('change', (e) => {
            const file = e.target.files[0];
            if (!file) return;
            const reader = new FileReader();
            reader.onload = (ev) => {
                try {
                    const data = JSON.parse(ev.target.result);
                    // Clear existing
                    nodes = [];
                    wires = [];
                    canvas.innerHTML = '';
                    svgLayer.innerHTML = '';

                    // Load nodes
                    let maxId = 0;
                    (data.nodes || []).forEach(n => {
                        const node = { id: n.id, type: n.type, x: n.x, y: n.y, config: n.config || {}, _result: null, _status: 'idle' };
                        nodes.push(node);
                        if (n.id > maxId) maxId = n.id;
                        const el = createNodeElement(node);
                        canvas.appendChild(el);
                    });
                    nextId = maxId + 1;

                    // Load wires
                    wires = (data.wires || []).map(w => ({ from: w.from, to: w.to }));
                    updateAllWires();
                    updatePortStyles();
                    updateMinimap();
                } catch (err) {
                    alert('Invalid .hawkchain file: ' + err.message);
                }
            };
            reader.readAsText(file);
            importFile.value = '';
        });
    }

    // ── Keyboard shortcuts ──────────────────────────────────────────
    document.addEventListener('keydown', (e) => {
        // Delete selected node
        if ((e.key === 'Delete' || e.key === 'Backspace') && selectedNode && document.activeElement.tagName !== 'INPUT' && document.activeElement.tagName !== 'TEXTAREA') {
            removeNode(selectedNode);
        }
    });

    // ── Add CyberNode to HawkSearch ─────────────────────────────────
    // (it will be auto-included via the nav-item data-target system)

    // ── Init ────────────────────────────────────────────────────────
    updateMinimap();

})();

// ═══════════════════════════════════════════════════════════════════
// Team Mode: Frontend Collaboration Client
// Architecture mirrors the backend:
//   team_engine.py (logic) <-> gui_bridge.py (transport)
//   TeamController (logic)  <-> TeamClient (transport via global socket)
// ═══════════════════════════════════════════════════════════════════
