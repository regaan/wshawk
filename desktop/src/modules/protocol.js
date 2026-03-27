(function initProtocolModule(global) {
    const modules = global.WSHawkModules = global.WSHawkModules || {};

    function esc(value) {
        const div = document.createElement('div');
        div.textContent = value == null ? '' : String(value);
        return div.innerHTML;
    }

    function hostFromUrl(raw) {
        if (!raw) return '';
        try {
            return new URL(raw).hostname;
        } catch (_) {
            return '';
        }
    }

    modules.protocol = {
        summarize(protocolSummary = {}, templates = []) {
            const families = (protocolSummary.message_families || []).slice(0, 5).map(item => item[0]).filter(Boolean);
            return {
                format: protocolSummary.format || 'unknown',
                injectableFields: protocolSummary.injectable_fields || [],
                recurringFields: protocolSummary.recurring_fields || [],
                families,
                templates: templates.slice(0, 10),
            };
        },

        initWSMap(ctx = {}) {
            const treeContainer = document.getElementById('wsmap-tree-container');
            const detailBody = document.getElementById('wsmap-detail-body');
            const detailTitle = document.getElementById('wsmap-detail-title');
            const liveBtn = document.getElementById('wsmap-live-btn');
            const discoverBtn = document.getElementById('wsmap-scan-btn');
            const testBtn = document.getElementById('wsmap-test-btn');
            const attackBtn = document.getElementById('wsmap-attack-btn');
            const navBtn = document.querySelector('.nav-item[data-target="wsmap"]');

            if (!treeContainer || treeContainer.dataset.protocolInitialized === '1') {
                return;
            }
            treeContainer.dataset.protocolInitialized = '1';

            let mode = 'discover';
            let endpoints = [];
            let protocolMap = null;
            let selection = null;

            const log = (type, message) => ctx.appendLog?.(type, message);
            const currentProject = () => ctx.getCurrentProject?.() || {};

            function setButtonsForMode() {
                if (liveBtn) {
                    liveBtn.classList.toggle('primary', mode === 'live');
                    liveBtn.classList.toggle('secondary', mode !== 'live');
                }
                if (discoverBtn) {
                    discoverBtn.classList.toggle('primary', mode === 'discover');
                    discoverBtn.classList.toggle('secondary', mode !== 'discover');
                }
                if (mode === 'live') {
                    testBtn.textContent = 'Refresh Map';
                    attackBtn.textContent = 'Load Target';
                } else {
                    testBtn.textContent = 'Probe Endpoint';
                    attackBtn.textContent = 'Scan This Target';
                }
            }

            function renderDiscoverTree() {
                if (!endpoints.length) {
                    treeContainer.innerHTML = '<div class="empty-state">No endpoints discovered yet.</div>';
                    return;
                }

                const groups = {};
                endpoints.forEach((endpoint) => {
                    const host = hostFromUrl(endpoint.url) || 'other';
                    groups[host] = groups[host] || [];
                    groups[host].push(endpoint);
                });

                let html = '';
                Object.entries(groups).forEach(([domain, items]) => {
                    html += `<div style="padding: 8px 12px; font-size: 10px; color: var(--text-muted); font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; background: rgba(255,255,255,0.02);">${esc(domain)}</div>`;
                    items.forEach((endpoint) => {
                        const active = selection?.kind === 'endpoint' && selection.url === endpoint.url ? 'active' : '';
                        html += `
                            <div class="wsmap-node ${active}" data-kind="endpoint" data-url="${esc(endpoint.url)}">
                                <div class="wsmap-node-url">${esc(endpoint.url)}</div>
                                <div class="wsmap-node-meta">
                                    <span class="wsmap-confidence ${(endpoint.confidence || 'medium').toLowerCase()}">${esc(endpoint.confidence || 'MEDIUM')}</span>
                                    <span style="color: var(--text-muted);">${esc(endpoint.source || '')}</span>
                                </div>
                            </div>
                        `;
                    });
                });

                treeContainer.innerHTML = html;
                treeContainer.querySelectorAll('.wsmap-node[data-kind="endpoint"]').forEach((node) => {
                    node.addEventListener('click', () => {
                        const endpoint = endpoints.find((item) => item.url === node.dataset.url);
                        if (!endpoint) return;
                        selection = { kind: 'endpoint', url: endpoint.url };
                        detailTitle.textContent = endpoint.url;
                        detailBody.innerHTML = `
                            <div class="wsmap-detail-row"><span class="label">URL</span><span class="value">${esc(endpoint.url)}</span></div>
                            <div class="wsmap-detail-row"><span class="label">Protocol</span><span class="value">${endpoint.url.startsWith('wss') ? 'WSS (Secure)' : 'WS (Insecure)'}</span></div>
                            <div class="wsmap-detail-row"><span class="label">Discovery Source</span><span class="value">${esc(endpoint.source || 'N/A')}</span></div>
                            <div class="wsmap-detail-row"><span class="label">Confidence</span><span class="value">${esc(endpoint.confidence || 'N/A')}</span></div>
                            <div class="wsmap-detail-row"><span class="label">Details</span><span class="value">${esc(endpoint.details || 'No additional details')}</span></div>
                            <div class="wsmap-detail-row"><span class="label">Status</span><span class="value" id="wsmap-probe-status">Not tested</span></div>
                        `;
                        testBtn.disabled = false;
                        attackBtn.disabled = false;
                        renderDiscoverTree();
                    });
                });
            }

            function renderLiveTree() {
                if (!protocolMap) {
                    treeContainer.innerHTML = '<div class="empty-state">No live protocol map available yet.</div>';
                    return;
                }

                const families = protocolMap.message_families || [];
                const connections = (protocolMap.nodes || []).filter((node) => node.type === 'connection');
                const correlations = protocolMap.correlation_groups || [];

                let html = `
                    <div style="padding: 10px 12px; border-bottom: 1px solid var(--border-color);">
                        <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; letter-spacing: 0.08em;">Live Graph</div>
                        <div style="margin-top: 6px; font-size: 12px; color: var(--text-primary);">
                            ${protocolMap.summary.connection_count || 0} connections •
                            ${protocolMap.summary.frame_count || 0} frames •
                            ${protocolMap.summary.family_count || 0} families •
                            ${protocolMap.summary.finding_count || 0} findings
                        </div>
                    </div>
                `;

                [
                    ['Correlation Groups', correlations.map((group) => ({
                        id: group.correlation_id,
                        title: group.correlation_id,
                        subtitle: `${group.summary.http_flow_count} HTTP / ${group.summary.ws_connection_count} WS / ${group.summary.browser_artifact_count} browser`,
                        kind: 'correlation',
                    }))],
                    ['Message Families', families.map((family) => ({
                        id: family.name,
                        title: family.name,
                        subtitle: `${family.count} observed • ${family.fields.length} fields`,
                        kind: 'family',
                    }))],
                    ['Connections', connections.map((connection) => ({
                        id: connection.id.replace(/^conn:/, ''),
                        title: connection.meta.url || connection.label,
                        subtitle: `${connection.meta.state || 'open'}${connection.meta.correlation_id ? ` • ${connection.meta.correlation_id}` : ''}`,
                        kind: 'connection',
                    }))],
                ].forEach(([title, items]) => {
                    html += `<div style="padding: 8px 12px; font-size: 10px; color: var(--text-muted); font-weight: 600; text-transform: uppercase; letter-spacing: 0.5px; background: rgba(255,255,255,0.02);">${esc(title)}</div>`;
                    if (!items.length) {
                        html += '<div style="padding: 10px 12px; color: var(--text-muted); font-size: 11px;">No data yet.</div>';
                        return;
                    }
                    items.forEach((item) => {
                        const active = selection?.kind === item.kind && selection.id === item.id ? 'active' : '';
                        html += `
                            <div class="wsmap-node ${active}" data-kind="${esc(item.kind)}" data-id="${esc(item.id)}">
                                <div class="wsmap-node-url">${esc(item.title)}</div>
                                <div class="wsmap-node-meta"><span style="color: var(--text-muted);">${esc(item.subtitle)}</span></div>
                            </div>
                        `;
                    });
                });

                treeContainer.innerHTML = html;
                treeContainer.querySelectorAll('.wsmap-node').forEach((node) => {
                    node.addEventListener('click', () => {
                        selection = { kind: node.dataset.kind, id: node.dataset.id };
                        renderLiveTree();
                        renderLiveDetail();
                    });
                });
            }

            function renderLiveDetail() {
                if (!protocolMap) {
                    detailTitle.textContent = 'Endpoint Details';
                    detailBody.innerHTML = '<div class="empty-state">Load a live protocol map to inspect captured state, transitions, and correlations.</div>';
                    testBtn.disabled = true;
                    attackBtn.disabled = true;
                    return;
                }

                const summary = protocolMap.summary || {};
                const protocolSummary = protocolMap.protocol_summary || {};
                const transitions = protocolMap.transitions || [];
                const templates = protocolMap.templates || [];
                const recommendations = protocolMap.recommended_attacks || [];
                const findingCategories = protocolMap.finding_categories || {};
                const targetPacks = protocolMap.target_packs || [];
                const playbookCandidates = protocolMap.playbook_candidates || [];

                if (!selection) {
                    detailTitle.textContent = 'Live Protocol Map';
                    detailBody.innerHTML = `
                        <div class="wsmap-detail-row"><span class="label">Observed Format</span><span class="value">${esc(protocolSummary.format || 'unknown')}</span></div>
                        <div class="wsmap-detail-row"><span class="label">Connections</span><span class="value">${summary.connection_count || 0}</span></div>
                        <div class="wsmap-detail-row"><span class="label">Frames</span><span class="value">${summary.frame_count || 0}</span></div>
                        <div class="wsmap-detail-row"><span class="label">Message Families</span><span class="value">${summary.family_count || 0}</span></div>
                        <div class="wsmap-detail-row"><span class="label">Recorded Findings</span><span class="value">${summary.finding_count || 0}</span></div>
                        <div class="wsmap-detail-row"><span class="label">Recurring Fields</span><span class="value">${esc((protocolSummary.recurring_fields || []).slice(0, 10).join(', ') || 'None')}</span></div>
                        <div style="margin-top: 14px;">
                            <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; margin-bottom: 8px;">Top Transitions</div>
                            ${(transitions.slice(0, 8).map((transition) => `
                                <div class="wsmap-detail-row">
                                    <span class="label">${esc(transition.source)} → ${esc(transition.target)}</span>
                                    <span class="value">${transition.count}</span>
                                </div>
                            `).join('')) || '<div class="empty-state" style="padding: 10px;">No transition chains captured yet.</div>'}
                        </div>
                        <div style="margin-top: 14px;">
                            <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; margin-bottom: 8px;">Reusable Templates</div>
                            ${(templates.slice(0, 6).map((template) => `
                                <div style="padding: 8px 0; border-bottom: 1px solid var(--border-color);">
                                    <div style="font-weight: 600; color: var(--text-primary);">${esc(template.name || 'template')}</div>
                                    <div style="font-size: 11px; color: var(--text-muted);">${template.count || 0} observed • fields: ${esc((template.fields || []).join(', ') || 'none')}</div>
                                    <div style="font-size: 10px; color: var(--text-muted); margin-top: 4px;">Editable: ${esc((template.editable_fields || []).map((field) => `${field.location || 'payload'}:${field.name}`).join(', ') || 'none')}</div>
                                </div>
                            `).join('')) || '<div class="empty-state" style="padding: 10px;">No protocol templates generated yet.</div>'}
                        </div>
                        <div style="margin-top: 14px;">
                            <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; margin-bottom: 8px;">Detected Target Packs</div>
                            ${(targetPacks.map((pack) => `
                                <div style="padding: 8px 10px; border: 1px solid var(--border-color); border-radius: 8px; margin-bottom: 8px; background: rgba(255,255,255,0.02);">
                                    <div style="display: flex; justify-content: space-between; gap: 8px; align-items: center;">
                                        <div style="font-weight: 600; color: var(--text-primary);">${esc(pack.title || pack.id)}</div>
                                        <span class="wsmap-confidence ${esc((pack.confidence || 'medium').toLowerCase())}">${esc((pack.confidence || 'medium').toUpperCase())}</span>
                                    </div>
                                    <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">${esc(pack.notes || '')}</div>
                                    <div style="font-size: 10px; color: var(--text-muted); margin-top: 6px;">Signals: ${esc((pack.signals || []).join(', ') || 'none')}</div>
                                    <div style="font-size: 10px; color: var(--text-muted); margin-top: 6px;">Operations: ${esc((pack.operations || []).map((op) => op.operation_name || op.root_field || op.event || op.target || op.command || op.action).filter(Boolean).slice(0, 6).join(', ') || 'none')}</div>
                                    <div style="font-size: 10px; color: var(--text-muted); margin-top: 4px;">Channels / Namespaces: ${esc([...(pack.channels || []), ...(pack.namespaces || [])].slice(0, 8).join(', ') || 'none')}</div>
                                    <div style="font-size: 10px; color: var(--text-muted); margin-top: 4px;">Identifiers: ${esc((pack.identifiers || []).slice(0, 8).join(', ') || 'none')}</div>
                                    <div style="margin-top: 8px;">
                                        ${(pack.attack_templates || []).slice(0, 3).map((template) => `
                                            <div style="padding: 6px 8px; border-radius: 6px; background: rgba(15, 23, 42, 0.38); margin-top: 6px;">
                                                <div style="font-size: 11px; font-weight: 600; color: var(--text-primary);">${esc(template.title || template.id || 'template')}</div>
                                                <div style="font-size: 10px; color: var(--text-muted); margin-top: 3px;">Fields: ${esc((template.fields || []).join(', ') || 'none')}</div>
                                            </div>
                                        `).join('')}
                                    </div>
                                </div>
                            `).join('')) || '<div class="empty-state" style="padding: 10px;">No known target packs matched the captured traffic yet.</div>'}
                        </div>
                        <div style="margin-top: 14px;">
                            <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; margin-bottom: 8px;">Recommended Attacks</div>
                            ${(recommendations.map((item) => `
                                <div style="padding: 8px 10px; border: 1px solid var(--border-color); border-radius: 8px; margin-bottom: 8px; background: rgba(255,255,255,0.02);">
                                    <div style="font-weight: 600; color: var(--text-primary);">${esc(item.title || item.id)}</div>
                                    <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">${esc(item.reason || '')}</div>
                                </div>
                            `).join('')) || '<div class="empty-state" style="padding: 10px;">No protocol-driven recommendations yet.</div>'}
                        </div>
                        <div style="margin-top: 14px;">
                            <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; margin-bottom: 8px;">Suggested Playbooks</div>
                            ${(playbookCandidates.map((item) => `
                                <div style="padding: 8px 10px; border: 1px solid var(--border-color); border-radius: 8px; margin-bottom: 8px; background: rgba(6,182,212,0.08);">
                                    <div style="font-weight: 600; color: var(--text-primary);">${esc(item.title || item.id)}</div>
                                    <div style="font-size: 10px; color: var(--accent); margin-top: 4px;">${esc(item.id || '')}</div>
                                    <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">${esc(item.reason || item.description || '')}</div>
                                </div>
                            `).join('')) || '<div class="empty-state" style="padding: 10px;">No workflow playbooks suggested yet.</div>'}
                        </div>
                        <div style="margin-top: 14px;">
                            <div style="font-size: 11px; color: var(--text-muted); text-transform: uppercase; margin-bottom: 8px;">Finding Categories</div>
                            ${Object.keys(findingCategories).length ? Object.entries(findingCategories).map(([name, count]) => `
                                <div class="wsmap-detail-row">
                                    <span class="label">${esc(name)}</span>
                                    <span class="value">${count}</span>
                                </div>
                            `).join('') : '<div class="empty-state" style="padding: 10px;">No findings linked to the current graph yet.</div>'}
                        </div>
                    `;
                    testBtn.disabled = false;
                    attackBtn.disabled = true;
                    return;
                }

                if (selection.kind === 'family') {
                    const family = (protocolMap.message_families || []).find((item) => item.name === selection.id);
                    detailTitle.textContent = family?.name || 'Message Family';
                    detailBody.innerHTML = family ? `
                        <div class="wsmap-detail-row"><span class="label">Observed Count</span><span class="value">${family.count}</span></div>
                        <div class="wsmap-detail-row"><span class="label">Fields</span><span class="value">${esc((family.fields || []).join(', ') || 'none')}</span></div>
                        <div class="wsmap-detail-row"><span class="label">Auth Fields</span><span class="value">${esc((family.auth_fields || []).join(', ') || 'none')}</span></div>
                        <div class="wsmap-detail-row"><span class="label">Identifiers</span><span class="value">${esc((family.identifier_fields || []).join(', ') || 'none')}</span></div>
                        <div style="margin-top: 14px; font-size: 11px; color: var(--text-muted); text-transform: uppercase;">Templates</div>
                        <div style="font-size: 11px; color: var(--text-secondary); white-space: pre-wrap;">${esc((templates || []).filter((item) => item.name === family.name).map((item) => (item.editable_fields || []).map((field) => `${field.location || 'payload'}:${field.name}`).join(', ') || 'no editable fields').join('\n') || 'No templates linked to this family yet.')}</div>
                        <div style="margin-top: 14px; font-size: 11px; color: var(--text-muted); text-transform: uppercase;">Sample</div>
                        <pre style="white-space: pre-wrap; word-break: break-word; font-size: 11px; color: var(--text-primary);">${esc(JSON.stringify(family.sample, null, 2))}</pre>
                    ` : '<div class="empty-state">Message family not found.</div>';
                    testBtn.disabled = false;
                    attackBtn.disabled = true;
                    return;
                }

                if (selection.kind === 'connection') {
                    const connection = (protocolMap.nodes || []).find((node) => node.id === `conn:${selection.id}`);
                    detailTitle.textContent = connection?.meta?.url || connection?.label || 'Connection';
                    detailBody.innerHTML = connection ? `
                        <div class="wsmap-detail-row"><span class="label">URL</span><span class="value">${esc(connection.meta.url || '')}</span></div>
                        <div class="wsmap-detail-row"><span class="label">State</span><span class="value">${esc(connection.meta.state || 'unknown')}</span></div>
                        <div class="wsmap-detail-row"><span class="label">Subprotocol</span><span class="value">${esc(connection.meta.subprotocol || 'none')}</span></div>
                        <div class="wsmap-detail-row"><span class="label">Accepted Subprotocol</span><span class="value">${esc(connection.meta.accepted_subprotocol || 'none')}</span></div>
                        <div class="wsmap-detail-row"><span class="label">Compression</span><span class="value">${connection.meta.compression_enabled ? 'enabled' : 'not negotiated'}</span></div>
                        <div class="wsmap-detail-row"><span class="label">Correlation</span><span class="value">${esc(connection.meta.correlation_id || 'unlinked')}</span></div>
                    ` : '<div class="empty-state">Connection not found.</div>';
                    testBtn.disabled = false;
                    attackBtn.disabled = !connection?.meta?.url;
                    return;
                }

                const group = (protocolMap.correlation_groups || []).find((item) => item.correlation_id === selection.id);
                detailTitle.textContent = selection.id;
                detailBody.innerHTML = group ? `
                    <div class="wsmap-detail-row"><span class="label">HTTP Bootstrap</span><span class="value">${group.summary.http_flow_count}</span></div>
                    <div class="wsmap-detail-row"><span class="label">WS Sessions</span><span class="value">${group.summary.ws_connection_count}</span></div>
                    <div class="wsmap-detail-row"><span class="label">Browser Artifacts</span><span class="value">${group.summary.browser_artifact_count}</span></div>
                    <div style="margin-top: 14px; font-size: 11px; color: var(--text-muted); text-transform: uppercase;">Linked Targets</div>
                    <div style="font-size: 12px; color: var(--text-primary); white-space: pre-wrap;">${esc([
                        ...(group.http_flows || []).map((item) => item.url),
                        ...(group.ws_connections || []).map((item) => item.url),
                        ...(group.browser_artifacts || []).map((item) => item.url)
                    ].filter(Boolean).slice(0, 12).join('\n') || 'No linked targets')}</div>
                ` : '<div class="empty-state">Correlation group not found.</div>';
                testBtn.disabled = false;
                attackBtn.disabled = !(group?.ws_connections || []).length;
            }

            async function loadDiscovery() {
                let target = ctx.targetUrlInput?.value.trim() || '';
                if (!target) {
                    log('vuln', 'Input Error: Enter a target URL to discover WebSocket endpoints.');
                    return;
                }

                if (target.startsWith('ws://')) target = target.replace('ws://', 'http://');
                else if (target.startsWith('wss://')) target = target.replace('wss://', 'https://');
                else if (!target.startsWith('http')) target = `https://${target}`;

                mode = 'discover';
                selection = null;
                setButtonsForMode();
                treeContainer.innerHTML = '<div class="empty-state">Scanning for WebSocket endpoints...</div>';
                detailTitle.textContent = 'Endpoint Details';
                detailBody.innerHTML = '<div class="empty-state">Discovery in progress...</div>';
                testBtn.disabled = true;
                attackBtn.disabled = true;
                log('info', `Endpoint discovery initiated for: ${target}`);

                try {
                    const res = await fetch('/discovery/scan', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ target }),
                    });
                    const data = await res.json().catch(() => ({}));
                    endpoints = data.endpoints || [];
                    if (endpoints.length > 0) {
                        log('success', `Discovered ${endpoints.length} WebSocket endpoint(s).`);
                    } else {
                        log('info', 'No WebSocket endpoints discovered on target.');
                    }
                } catch (error) {
                    endpoints = [];
                    log('vuln', `Discovery failed: ${error.message}`);
                }

                renderDiscoverTree();
            }

            async function loadLiveMap({ allowProjectBootstrap = false } = {}) {
                mode = 'live';
                selection = null;
                setButtonsForMode();

                let project = currentProject();
                if (!project.projectId && allowProjectBootstrap && typeof ctx.ensurePlatformProject === 'function' && ctx.targetUrlInput?.value.trim()) {
                    try {
                        project = await ctx.ensurePlatformProject('protocol_map', ctx.targetUrlInput.value.trim());
                    } catch (_) {
                        // fall through to empty state below
                    }
                }

                if (!project.projectId) {
                    protocolMap = null;
                    treeContainer.innerHTML = '<div class="empty-state">Live protocol mapping needs a platform project. Run a scan, replay a request, or save the current target first.</div>';
                    detailTitle.textContent = 'Live Protocol Map';
                    detailBody.innerHTML = '<div class="empty-state">No project-linked traffic available yet.</div>';
                    testBtn.disabled = true;
                    attackBtn.disabled = true;
                    return;
                }

                treeContainer.innerHTML = '<div class="empty-state">Building live protocol graph from captured WS traffic...</div>';
                detailTitle.textContent = 'Live Protocol Map';
                detailBody.innerHTML = '<div class="empty-state">Analyzing traffic, transitions, and correlation groups...</div>';
                testBtn.disabled = true;
                attackBtn.disabled = true;

                try {
                    const res = await fetch(`/platform/projects/${project.projectId}/protocol-map?limit=500`);
                    const data = await res.json().catch(() => ({}));
                    if (!res.ok) {
                        throw new Error(data.detail || `Protocol map load failed (${res.status})`);
                    }
                    protocolMap = data.protocol_map || null;
                    renderLiveTree();
                    renderLiveDetail();
                    log('info', `[Platform] Loaded live protocol map with ${protocolMap?.summary?.family_count || 0} message families.`);
                } catch (error) {
                    protocolMap = null;
                    treeContainer.innerHTML = `<div class="empty-state">${esc(error.message)}</div>`;
                    detailBody.innerHTML = '<div class="empty-state">Live protocol map unavailable.</div>';
                    log('vuln', `[Platform] Failed to load protocol map: ${error.message}`);
                }
            }

            async function handleProbeOrRefresh() {
                if (mode === 'live') {
                    await loadLiveMap({ allowProjectBootstrap: false });
                    return;
                }

                if (!selection?.url) return;
                const statusEl = document.getElementById('wsmap-probe-status');
                if (statusEl) statusEl.textContent = 'Probing...';

                try {
                    const res = await fetch('/discovery/probe', {
                        method: 'POST',
                        headers: { 'Content-Type': 'application/json' },
                        body: JSON.stringify({ url: selection.url }),
                    });
                    const data = await res.json().catch(() => ({}));
                    if (statusEl) {
                        statusEl.textContent = data.alive ? 'ALIVE' : 'UNREACHABLE';
                        statusEl.style.color = data.alive ? 'var(--safe)' : 'var(--danger)';
                    }
                } catch (error) {
                    if (statusEl) statusEl.textContent = `Error: ${error.message}`;
                }
            }

            function handleLoadTarget() {
                if (mode === 'discover') {
                    if (!selection?.url || !ctx.targetUrlInput) return;
                    ctx.targetUrlInput.value = selection.url;
                    document.querySelector('.nav-item[data-target="dashboard"]')?.click();
                    log('info', `Target updated to discovered endpoint: ${selection.url}`);
                    return;
                }

                let targetUrl = '';
                if (selection?.kind === 'connection') {
                    targetUrl = (protocolMap?.nodes || []).find((node) => node.id === `conn:${selection.id}`)?.meta?.url || '';
                } else if (selection?.kind === 'correlation') {
                    targetUrl = ((protocolMap?.correlation_groups || []).find((item) => item.correlation_id === selection.id)?.ws_connections || [])[0]?.url || '';
                }

                if (targetUrl && ctx.targetUrlInput) {
                    ctx.targetUrlInput.value = targetUrl;
                    document.querySelector('.nav-item[data-target="reqforge"]')?.click();
                    log('info', `[Platform] Loaded protocol-map target into Request Forge: ${targetUrl}`);
                }
            }

            liveBtn?.addEventListener('click', () => { void loadLiveMap({ allowProjectBootstrap: true }); });
            discoverBtn?.addEventListener('click', () => { void loadDiscovery(); });
            testBtn?.addEventListener('click', () => { void handleProbeOrRefresh(); });
            attackBtn?.addEventListener('click', () => handleLoadTarget());
            navBtn?.addEventListener('click', () => {
                if (currentProject().projectId) {
                    setTimeout(() => { void loadLiveMap({ allowProjectBootstrap: false }); }, 60);
                }
            });

            setButtonsForMode();
            renderLiveDetail();
        },
    };
})(window);
