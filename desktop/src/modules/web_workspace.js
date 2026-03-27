(function initWebWorkspace(global) {
    const modules = global.WSHawkModules = global.WSHawkModules || {};

    const TARGET_TO_WORKSPACE = {
        httpforge: 'requests',
        httpfuzzer: 'requests',
        jwtanalyzer: 'requests',
        dirscanner: 'discovery',
        headeranalyzer: 'discovery',
        subdomain: 'discovery',
        webcrawler: 'discovery',
        techfp: 'discovery',
        sslanalyzer: 'discovery',
        sensitivefinder: 'discovery',
        portscanner: 'discovery',
        dnslookup: 'discovery',
        wafdetect: 'attacks',
        vulnscanner: 'attacks',
        corstester: 'attacks',
        csrfforge: 'attacks',
        blindprobe: 'attacks',
        redirecthunter: 'attacks',
        protopolluter: 'attacks',
        hawkproxyca: 'attacks',
        attackchainer: 'attacks',
        cybernode: 'attacks',
        teammode: 'attacks',
        evidence: 'evidence',
        notes: 'evidence',
        scanhistory: 'evidence',
    };

    const WORKSPACES = {
        discovery: {
            title: 'Discovery Workspace',
            subtitle: 'Map authenticated surface area, bootstrap sessions, and turn captured HTTP traffic into reusable project intelligence.',
            chip: 'DISCOVERY WORKSPACE',
            quickHint: 'Recon, crawl, and surface mapping',
            feedTitle: 'Recent Surface',
            feedMeta: 'Targets and discovery-driven HTTP telemetry',
            guidance:
                'Start here when a target is new. Crawl first, enrich targets with headers, tech, SSL, and sensitive-data scans, then hand the strongest surface straight into Requests or Attacks without losing project context.',
            actions: [
                { target: 'webcrawler', title: 'Web Crawler', description: 'Discover pages, forms, APIs, and CSRF hints with project-backed journaling.' },
                { target: 'dirscanner', title: 'Dir Scanner', description: 'Enumerate hidden content and tie exposed paths directly to findings.' },
                { target: 'subdomain', title: 'Subdomain Finder', description: 'Expand the attack surface and push new hosts into the project target graph.' },
                { target: 'techfp', title: 'Tech Fingerprint', description: 'Profile frameworks and platform indicators before choosing attack paths.' },
                { target: 'sslanalyzer', title: 'SSL Analyzer', description: 'Inspect certificate posture, protocol support, and TLS hygiene.' },
                { target: 'sensitivefinder', title: 'Sensitive Finder', description: 'Mine captured responses for leaked secrets and bootstrap artifacts.' },
            ],
        },
        requests: {
            title: 'Requests Workspace',
            subtitle: 'Craft, replay, fuzz, and compare authenticated HTTP flows using stored identities and project correlation.',
            chip: 'REQUESTS WORKSPACE',
            quickHint: 'Replay and mutate real traffic',
            feedTitle: 'Recent HTTP Flows',
            feedMeta: 'Latest request/response telemetry stored for this project',
            guidance:
                'Use this workspace once you have a live session. Replay requests through the platform transport, preserve correlation IDs, and seed later attack modules with known-good authenticated flows.',
            actions: [
                { target: 'httpforge', title: 'HTTP Forge', description: 'Replay or craft exact requests with bridge-backed transport and evidence logging.' },
                { target: 'httpfuzzer', title: 'HTTP Fuzzer', description: 'Mutate parameters against live targets while writing every attempt into project history.' },
                { target: 'jwtanalyzer', title: 'JWT Analyzer', description: 'Inspect, tamper, and stage token hypotheses before replaying them.' },
                { target: 'headeranalyzer', title: 'Header Analyzer', description: 'Review trust boundaries and response posture on the same authenticated paths.' },
            ],
        },
        attacks: {
            title: 'Attacks Workspace',
            subtitle: 'Run exploit-focused web modules, then pivot into workflow abuse, replay, or WebSocket operations with shared project state.',
            chip: 'ATTACKS WORKSPACE',
            quickHint: 'Exploit-focused modules and chained abuse',
            feedTitle: 'Attack Runs & Findings',
            feedMeta: 'Offensive runs, evidence, and high-signal findings',
            guidance:
                'This is the offensive lane. Start from real requests, replay with identities, chain multi-step flows, and keep every exploit attempt tied to findings, evidence, and later WS pivots.',
            actions: [
                { target: 'vulnscanner', title: 'Web Vuln Scan', description: 'Run the project-backed orchestrator across crawl, fuzz, redirect, and sensitive flows.' },
                { target: 'corstester', title: 'CORS Tester', description: 'Probe origin handling and store exploitable responses as findings.' },
                { target: 'csrfforge', title: 'CSRF Forge', description: 'Generate or replay CSRF paths with live project identities.' },
                { target: 'blindprobe', title: 'Blind Probe', description: 'Test SSRF candidates while persisting each probe and response signal.' },
                { target: 'redirecthunter', title: 'Redirect Hunter', description: 'Hunt redirect abuse and pivot suspicious parameters into follow-on testing.' },
                { target: 'protopolluter', title: 'Proto Polluter', description: 'Exercise prototype pollution paths with recorded transport evidence.' },
                { target: 'attackchainer', title: 'Attack Chainer', description: 'Build multi-step authenticated workflows that reuse extracted values and project history.' },
            ],
        },
        evidence: {
            title: 'Evidence Workspace',
            subtitle: 'Review findings, exports, notes, and historical scans without leaving the web engagement context.',
            chip: 'EVIDENCE WORKSPACE',
            quickHint: 'Operator proof, notes, and exports',
            feedTitle: 'Evidence & Notes',
            feedMeta: 'Recent proof artifacts, operator notes, and stored findings',
            guidance:
                'Use this workspace to package what mattered. Review the strongest findings, export project bundles, and keep operator notes close to the web traffic and attack runs that produced them.',
            actions: [
                { target: 'evidence', title: 'Evidence Vault', description: 'Open the platform evidence workspace for artifacts, notes, and export management.' },
                { target: 'notes', title: 'Operator Notes', description: 'Capture hypotheses, operator observations, and replay guidance for the engagement.' },
                { target: 'scanhistory', title: 'Scan History', description: 'Compare historical web findings and diff regressions across runs.' },
                { action: 'export-json', title: 'Export JSON Bundle', description: 'Download the current project as a portable JSON evidence bundle.' },
            ],
        },
    };

    const state = {
        activeWorkspace: 'discovery',
        refreshPromise: null,
    };

    function esc(value) {
        const stringValue = String(value ?? '');
        return stringValue
            .replace(/&/g, '&amp;')
            .replace(/</g, '&lt;')
            .replace(/>/g, '&gt;')
            .replace(/"/g, '&quot;')
            .replace(/'/g, '&#39;');
    }

    function currentProject() {
        return typeof getCurrentProject === 'function' ? (getCurrentProject() || {}) : {};
    }

    function currentProjectId() {
        return currentProject().projectId || null;
    }

    function clickNav(target) {
        const visibleButton = Array.from(document.querySelectorAll(`.nav-item[data-target="${target}"]`)).find((button) => {
            const style = global.getComputedStyle(button);
            return style.display !== 'none' && style.visibility !== 'hidden';
        });
        (visibleButton || document.querySelector(`.nav-item[data-target="${target}"]`))?.click();
    }

    function targetWorkspace(target) {
        return TARGET_TO_WORKSPACE[target] || 'discovery';
    }

    function visibleWebButtons() {
        return Array.from(document.querySelectorAll('#web-menu .nav-item')).filter((button) => button.style.display !== 'none');
    }

    function refreshWebMenuLabels() {
        const children = Array.from(document.getElementById('web-menu')?.children || []);
        let activeLabel = null;
        let hasVisibleItems = false;

        children.forEach((child) => {
            if (child.id === 'web-workspace-switcher') {
                if (activeLabel && child.style.display !== 'none') {
                    hasVisibleItems = true;
                }
                return;
            }

            if (child.classList.contains('nav-label')) {
                if (activeLabel && !activeLabel.dataset.webStaticLabel) {
                    activeLabel.style.display = hasVisibleItems ? '' : 'none';
                }
                activeLabel = child;
                hasVisibleItems = false;
                if (child.dataset.webStaticLabel) {
                    child.style.display = '';
                }
                return;
            }

            if (child.classList.contains('nav-item') && child.style.display !== 'none') {
                hasVisibleItems = true;
            }
        });

        if (activeLabel && !activeLabel.dataset.webStaticLabel) {
            activeLabel.style.display = hasVisibleItems ? '' : 'none';
        }
    }

    function syncWorkspaceButtons() {
        document.querySelectorAll('.web-workspace-btn').forEach((button) => {
            const isActive = button.dataset.webWorkspace === state.activeWorkspace;
            button.classList.toggle('active', isActive);
            button.style.borderColor = isActive ? 'var(--accent)' : 'var(--border-color)';
            button.style.boxShadow = isActive ? '0 0 0 1px rgba(6,182,212,0.3)' : 'none';
        });

        const workspace = WORKSPACES[state.activeWorkspace];
        const chip = document.getElementById('web-workspace-active-chip');
        if (chip) {
            chip.textContent = workspace.chip;
            chip.className = `badge ${state.activeWorkspace === 'attacks' ? 'danger' : state.activeWorkspace === 'evidence' ? 'warning' : state.activeWorkspace === 'requests' ? 'standard' : 'safe'}`;
        }
    }

    function filterWebMenu() {
        document.querySelectorAll('#web-menu .nav-item').forEach((button) => {
            const target = button.dataset.target || '';
            if (target === 'webworkspace') {
                button.style.display = '';
                return;
            }

            const workspace = targetWorkspace(target);
            button.style.display = workspace === state.activeWorkspace ? '' : 'none';
        });

        refreshWebMenuLabels();
    }

    function metricCard(label, value, tone, detail) {
        const accent = tone === 'danger'
            ? 'var(--danger)'
            : tone === 'warning'
                ? 'var(--warning)'
                : tone === 'safe'
                    ? 'var(--safe)'
                    : 'var(--accent)';

        return `
            <div style="padding: 14px; border: 1px solid var(--border-color); border-radius: var(--radius-lg); background: var(--bg-secondary);">
                <div style="font-size: 10px; text-transform: uppercase; letter-spacing: 1px; color: var(--text-muted); margin-bottom: 8px;">${esc(label)}</div>
                <div style="font-size: 24px; font-weight: 700; color: ${accent}; margin-bottom: 6px;">${esc(value)}</div>
                <div style="font-size: 11px; color: var(--text-secondary); line-height: 1.5;">${esc(detail)}</div>
            </div>
        `;
    }

    function quickActionCard(action) {
        const label = action.action === 'export-json' ? 'Export' : 'Open';
        return `
            <div style="padding: 14px; border: 1px solid var(--border-color); border-radius: var(--radius-lg); background: linear-gradient(180deg, rgba(15,23,42,0.92), rgba(15,23,42,0.72)); display: flex; flex-direction: column; gap: 10px;">
                <div style="font-size: 13px; font-weight: 600; color: var(--text-primary);">${esc(action.title)}</div>
                <div style="font-size: 11px; line-height: 1.6; color: var(--text-secondary); flex: 1;">${esc(action.description)}</div>
                <button class="btn ${action.action === 'export-json' ? 'warning' : 'secondary'} small web-workspace-launch"
                    data-nav-target="${esc(action.target || '')}" data-web-action="${esc(action.action || '')}"
                    style="align-self: flex-start;">${esc(label)}</button>
            </div>
        `;
    }

    function listItem(title, meta, detail, tone = 'standard') {
        const border = tone === 'danger'
            ? 'var(--danger)'
            : tone === 'warning'
                ? 'var(--warning)'
                : tone === 'safe'
                    ? 'var(--safe)'
                    : 'var(--border-color)';
        return `
            <div style="padding: 12px; border: 1px solid ${border}; border-radius: var(--radius); background: rgba(15,23,42,0.55); margin-bottom: 8px;">
                <div style="display: flex; justify-content: space-between; gap: 8px; margin-bottom: 6px;">
                    <div style="font-size: 12px; font-weight: 600; color: var(--text-primary);">${esc(title)}</div>
                    <div style="font-size: 10px; color: var(--text-muted); white-space: nowrap;">${esc(meta)}</div>
                </div>
                <div style="font-size: 11px; color: var(--text-secondary); line-height: 1.55;">${esc(detail)}</div>
            </div>
        `;
    }

    function formatTargetSummary(target) {
        const detailParts = [];
        if (target.host) detailParts.push(target.host);
        if (target.kind) detailParts.push(target.kind);
        return listItem(target.url || 'Target', target.scheme || 'http', detailParts.join(' · ') || 'Stored target');
    }

    function formatHttpFlow(flow) {
        const status = flow.response_status || flow.error || 'pending';
        const tone = flow.error ? 'danger' : String(status).startsWith('2') ? 'safe' : String(status).startsWith('3') ? 'warning' : 'standard';
        return listItem(
            `${flow.method || 'GET'} ${flow.url || ''}`,
            status,
            `${flow.created_at || ''}${flow.correlation_id ? ` · ${flow.correlation_id}` : ''}`,
            tone,
        );
    }

    function formatAttackRun(run) {
        const summary = run.summary || {};
        const detail = Object.keys(summary).length
            ? Object.entries(summary).slice(0, 3).map(([key, value]) => `${key}=${value}`).join(' · ')
            : 'Attack run recorded in project store.';
        return listItem(run.attack_type || 'attack', run.status || 'running', detail, run.status === 'failed' ? 'danger' : 'warning');
    }

    function formatEvidenceItem(item) {
        return listItem(item.title || item.category || 'Evidence', item.severity || 'info', item.category || 'Stored evidence artifact', item.severity === 'high' || item.severity === 'critical' ? 'danger' : 'warning');
    }

    function formatNote(note) {
        return listItem(note.title || 'Operator note', note.updated_at || '', note.body || 'No note body yet.');
    }

    function workspaceMetrics(data) {
        const summary = data.projectPayload?.protocol_map_summary || {};
        const counts = {
            identities: (data.projectPayload?.identities || []).length,
            findings: (data.projectPayload?.findings || []).length,
            evidence: (data.projectPayload?.evidence || []).length,
            notes: (data.projectPayload?.notes || []).length,
            attackRuns: (data.projectPayload?.attack_runs || []).length,
            targets: data.targets.length,
            httpFlows: data.httpFlows.length,
            wsFamilies: summary.family_count || 0,
        };

        switch (state.activeWorkspace) {
            case 'requests':
                return [
                    metricCard('HTTP Flows', counts.httpFlows, 'accent', 'Stored request/response records available for replay and evidence.'),
                    metricCard('Identities', counts.identities, 'safe', 'Vault identities ready to drive authenticated web requests.'),
                    metricCard('Findings', counts.findings, 'warning', 'Request-driven anomalies promoted into the shared project findings list.'),
                    metricCard('Correlation Paths', counts.wsFamilies || 0, 'standard', 'Observed protocol families that can pivot from HTTP into WS workflows.'),
                ];
            case 'attacks':
                return [
                    metricCard('Attack Runs', counts.attackRuns, 'danger', 'Project-backed offensive runs stored with summaries and status.'),
                    metricCard('Findings', counts.findings, 'warning', 'Exploit-facing findings captured across web and realtime testing.'),
                    metricCard('Evidence', counts.evidence, 'accent', 'Artifacts available for operator proof and reporting.'),
                    metricCard('Identities', counts.identities, 'safe', 'Roles available for authenticated replay and chained abuse.'),
                ];
            case 'evidence':
                return [
                    metricCard('Evidence Items', counts.evidence, 'accent', 'Portable artifacts already captured for this web engagement.'),
                    metricCard('Notes', counts.notes, 'standard', 'Operator notes and workflow guidance tied to the project.'),
                    metricCard('Findings', counts.findings, 'warning', 'Findings ready to review, diff, and export.'),
                    metricCard('Attack Runs', counts.attackRuns, 'danger', 'Attack history retained for reproducibility.'),
                ];
            case 'discovery':
            default:
                return [
                    metricCard('Targets', counts.targets, 'accent', 'Hosts, paths, and correlated endpoints discovered so far.'),
                    metricCard('HTTP Flows', counts.httpFlows, 'safe', 'Discovery traffic already stored in the transport journal.'),
                    metricCard('Identities', counts.identities, 'warning', 'Captured roles available for authenticated mapping.'),
                    metricCard('Findings', counts.findings, 'danger', 'Discovery-led findings promoted directly into the project store.'),
                ];
        }
    }

    function workspaceFeedItems(data) {
        switch (state.activeWorkspace) {
            case 'requests':
                return data.httpFlows.slice(0, 6).map(formatHttpFlow);
            case 'attacks': {
                const attackRuns = (data.projectPayload?.attack_runs || []).slice(0, 4).map(formatAttackRun);
                const findings = (data.projectPayload?.findings || []).slice(0, 4).map((finding) =>
                    listItem(
                        finding.title || finding.category || 'Finding',
                        String(finding.severity || 'info').toUpperCase(),
                        finding.description || finding.category || 'Stored finding',
                        finding.severity === 'high' || finding.severity === 'critical' ? 'danger' : 'warning',
                    )
                );
                return attackRuns.concat(findings).slice(0, 8);
            }
            case 'evidence': {
                const evidenceItems = (data.projectPayload?.evidence || []).slice(0, 4).map(formatEvidenceItem);
                const noteItems = (data.projectPayload?.notes || []).slice(0, 3).map(formatNote);
                return evidenceItems.concat(noteItems).slice(0, 7);
            }
            case 'discovery':
            default:
                return data.targets.slice(0, 6).map(formatTargetSummary);
        }
    }

    function workspaceProjectLabel(projectPayload) {
        if (!projectPayload?.project) {
            return 'No platform project linked yet.';
        }
        const project = projectPayload.project;
        const name = project.name || project.id;
        const targetUrl = project.target_url || currentProject().url || 'Target unset';
        return `${name}\n${targetUrl}`;
    }

    async function exportProjectBundle(projectId) {
        const response = await fetch(`/platform/projects/${projectId}/exports/json`);
        if (!response.ok) {
            const failure = await response.text();
            throw new Error(failure || `Export failed (${response.status})`);
        }

        const blob = await response.blob();
        const filename = `wshawk-${projectId}-bundle.json`;
        const href = URL.createObjectURL(blob);
        const anchor = document.createElement('a');
        anchor.href = href;
        anchor.download = filename;
        document.body.appendChild(anchor);
        anchor.click();
        anchor.remove();
        URL.revokeObjectURL(href);
    }

    function bindQuickActions() {
        document.querySelectorAll('.web-workspace-launch').forEach((button) => {
            if (button.dataset.webWorkspaceBound === '1') {
                return;
            }
            button.dataset.webWorkspaceBound = '1';
            button.addEventListener('click', async () => {
                const navTarget = button.dataset.navTarget;
                const action = button.dataset.webAction;

                if (action === 'export-json') {
                    const projectId = currentProjectId();
                    if (!projectId) {
                        global.appendLog?.('vuln', '[Web Workspace] Create or sync a project before exporting evidence.');
                        return;
                    }
                    try {
                        await exportProjectBundle(projectId);
                        global.appendLog?.('success', '[Web Workspace] Exported JSON evidence bundle for the current project.');
                    } catch (error) {
                        global.appendLog?.('vuln', `[Web Workspace] Export failed: ${error.message}`);
                    }
                    return;
                }

                if (navTarget) {
                    clickNav(navTarget);
                }
            });
        });
    }

    async function renderBoard() {
        const workspace = WORKSPACES[state.activeWorkspace];
        const title = document.getElementById('web-workspace-title');
        const subtitle = document.getElementById('web-workspace-subtitle');
        const projectEl = document.getElementById('web-workspace-project');
        const summaryEl = document.getElementById('web-workspace-summary');
        const quickEl = document.getElementById('web-workspace-quickactions');
        const feedTitleEl = document.getElementById('web-workspace-feed-title');
        const feedMetaEl = document.getElementById('web-workspace-feed-meta');
        const guideEl = document.getElementById('web-workspace-guidance');
        const hintEl = document.getElementById('web-workspace-quick-hint');

        if (!title || !subtitle || !summaryEl || !quickEl || !guideEl) {
            return null;
        }

        title.textContent = workspace.title;
        subtitle.textContent = workspace.subtitle;
        feedTitleEl.textContent = workspace.feedTitle;
        feedMetaEl.textContent = workspace.feedMeta;
        hintEl.textContent = workspace.quickHint;
        guideEl.innerHTML = `
            <div style="font-size: 12px; line-height: 1.7; color: var(--text-secondary); margin-bottom: 12px;">${esc(workspace.guidance)}</div>
            <div style="display: flex; gap: 8px; flex-wrap: wrap;">
                <button class="btn secondary small web-workspace-launch" data-nav-target="reqforge">Request Forge</button>
                <button class="btn secondary small web-workspace-launch" data-nav-target="attacks">WS Attack Lab</button>
                <button class="btn secondary small web-workspace-launch" data-nav-target="wsmap">Protocol Map</button>
            </div>
        `;

        quickEl.innerHTML = workspace.actions.map(quickActionCard).join('');
        bindQuickActions();

        const projectId = currentProjectId();
        if (!projectId) {
            projectEl.textContent = 'No platform project linked yet.';
            summaryEl.innerHTML = [
                metricCard('Project', '0', 'standard', 'Create a project from the current target URL to unlock store-backed web operations.'),
                metricCard('HTTP Flows', '0', 'standard', 'Requests, crawler hits, and attack traffic will appear here once the project exists.'),
                metricCard('Findings', '0', 'standard', 'Web findings will be promoted here as soon as modules start writing to the project store.'),
                metricCard('Evidence', '0', 'standard', 'Exports, notes, and artifacts will accumulate under the Evidence workspace.'),
            ].join('');
            document.getElementById('web-workspace-recent').innerHTML = `
                <div class="empty-state" style="padding: 24px;">
                    <div style="margin-bottom: 12px;">Set a target URL, then create a project-backed web workspace.</div>
                    <button id="web-workspace-create-project" class="btn primary small">Create Project From Current Target</button>
                </div>
            `;
            document.getElementById('web-workspace-create-project')?.addEventListener('click', async () => {
                try {
                    if (typeof ensurePlatformProject === 'function') {
                        await ensurePlatformProject('web_workspace_bootstrap');
                        await renderBoard();
                        global.appendLog?.('success', '[Web Workspace] Platform project linked from current target.');
                    }
                } catch (error) {
                    global.appendLog?.('vuln', `[Web Workspace] Unable to create project: ${error.message}`);
                }
            });
            return null;
        }

        if (state.refreshPromise) {
            return state.refreshPromise;
        }

        state.refreshPromise = (async () => {
            const [projectRes, targetsRes, flowsRes] = await Promise.all([
                fetch(`/platform/projects/${projectId}`),
                fetch(`/platform/projects/${projectId}/targets?limit=24`),
                fetch(`/platform/projects/${projectId}/http-flows?limit=24`),
            ]);

            const projectPayload = await projectRes.json().catch(() => ({}));
            const targetsPayload = await targetsRes.json().catch(() => ({}));
            const flowsPayload = await flowsRes.json().catch(() => ({}));

            if (!projectRes.ok) {
                throw new Error(projectPayload.detail || `Project lookup failed (${projectRes.status})`);
            }

            const data = {
                projectPayload,
                targets: targetsPayload.targets || [],
                httpFlows: flowsPayload.http_flows || [],
            };

            projectEl.textContent = workspaceProjectLabel(projectPayload);
            summaryEl.innerHTML = workspaceMetrics(data).join('');

            const feedItems = workspaceFeedItems(data);
            document.getElementById('web-workspace-recent').innerHTML = feedItems.length
                ? feedItems.join('')
                : '<div class="empty-state">No project-backed telemetry yet for this workspace.</div>';

            bindQuickActions();
            return data;
        })();

        try {
            return await state.refreshPromise;
        } catch (error) {
            projectEl.textContent = `Project refresh failed\n${error.message}`;
            summaryEl.innerHTML = '<div class="empty-state">Unable to load project telemetry for this workspace.</div>';
            document.getElementById('web-workspace-recent').innerHTML = `<div class="empty-state">${esc(error.message)}</div>`;
            return null;
        } finally {
            state.refreshPromise = null;
        }
    }

    function setWorkspace(workspace, options = {}) {
        if (!WORKSPACES[workspace]) {
            return;
        }
        state.activeWorkspace = workspace;
        syncWorkspaceButtons();
        filterWebMenu();

        if (options.navigateBoard !== false) {
            clickNav('webworkspace');
        }

        void renderBoard();
    }

    function syncWorkspaceFromTarget(target) {
        if (!target || target === 'webworkspace') {
            return;
        }
        const workspace = targetWorkspace(target);
        if (workspace !== state.activeWorkspace) {
            state.activeWorkspace = workspace;
            syncWorkspaceButtons();
            filterWebMenu();
        }
    }

    function initSidebarBindings() {
        document.querySelectorAll('.web-workspace-btn').forEach((button) => {
            button.addEventListener('click', () => {
                setWorkspace(button.dataset.webWorkspace || 'discovery');
            });
        });

        document.querySelectorAll('#web-menu .nav-item').forEach((button) => {
            button.addEventListener('click', () => {
                syncWorkspaceFromTarget(button.dataset.target || '');
                if (button.dataset.target === 'webworkspace') {
                    void renderBoard();
                }
            });
        });

        document.getElementById('toggle-mode-btn')?.addEventListener('click', () => {
            setTimeout(() => {
                if (typeof getCurrentMode === 'function' && getCurrentMode() === 'web') {
                    clickNav('webworkspace');
                    void renderBoard();
                }
            }, 10);
        });
    }

    function bindProjectRefreshSignals() {
        if (typeof socket === 'undefined' || !socket) {
            return;
        }

        const refreshIfNeeded = (data) => {
            if (data?.project_id && data.project_id === currentProjectId()) {
                const activeView = document.querySelector('.view.active');
                if (activeView?.id === 'view-webworkspace') {
                    void renderBoard();
                }
            }
        };

        socket.on('platform_event', refreshIfNeeded);
        socket.on('platform_evidence', refreshIfNeeded);
    }

    function init() {
        if (!document.getElementById('view-webworkspace')) {
            return;
        }

        syncWorkspaceButtons();
        filterWebMenu();
        initSidebarBindings();
        bindProjectRefreshSignals();
        void renderBoard();
    }

    modules.webWorkspace = {
        init,
        refreshBoard: renderBoard,
        setWorkspace,
        getActiveWorkspace: () => state.activeWorkspace,
    };

    init();
})(window);
