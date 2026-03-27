(function initApiModule(global) {
    const modules = global.WSHawkModules = global.WSHawkModules || {};

    modules.api = {
        bridgeHttpBase(port) {
            return `http://127.0.0.1:${port}`;
        },

        bridgeWebSocketUrl(port, path) {
            const normalized = path.startsWith('/') ? path : `/${path}`;
            return `ws://127.0.0.1:${port}${normalized}`;
        },

        bridgeFetch(rawFetch, port, input, init = {}, legacyBase = 'http://127.0.0.1:8080') {
            let url = input;

            if (typeof input === 'string') {
                const httpBase = this.bridgeHttpBase(port);
                if (input.startsWith(legacyBase)) {
                    url = `${httpBase}${input.slice(legacyBase.length)}`;
                } else if (input.startsWith('/')) {
                    url = `${httpBase}${input}`;
                }
            }

            return rawFetch(url, init);
        },

        derivePlatformProjectName(url) {
            if (url) {
                try {
                    const host = new URL(url).hostname.replace(/^www\./, '').replace(/[^a-z0-9.-]+/gi, '-');
                    if (host) {
                        return `${host}-operation`;
                    }
                } catch (_) {
                    // Fall back to timestamp naming below.
                }
            }

            const stamp = new Date().toISOString().replace(/[:.]/g, '-');
            return `wshawk-${stamp}`;
        },

        applyProjectState(ctx, data) {
            const nextProject = data || {
                projectId: null,
                url: '',
                vulns: 0,
                msgs: 0,
                findings: [],
                logs: [],
                history: []
            };
            ctx.setCurrentProject(nextProject);
            ctx.targetUrlInput.value = nextProject.url || '';
            ctx.valVulns.innerText = nextProject.vulns || '0';
            ctx.valMsgs.innerText = nextProject.msgs || '0';
            ctx.setMsgCount(nextProject.msgs || 0);
            ctx.historyCount.innerText = `${ctx.getMsgCount()} frames`;

            ctx.clearFindingStore();
            ctx.findingsContainer.innerHTML = '';
            if (Array.isArray(nextProject.findings) && nextProject.findings.length) {
                nextProject.findings.forEach((finding, index) => {
                    ctx.addFinding(
                        {
                            type: finding.type || `Finding ${index + 1}`,
                            severity: finding.severity || 'LOW',
                            description: finding.description || '',
                            payload: finding.payload || '',
                        },
                        { findingId: finding.id || `saved-finding-${index}` }
                    );
                });
                const severityScore = { LOW: 1, MEDIUM: 2, HIGH: 3, CRITICAL: 4 };
                const highest = nextProject.findings.reduce((max, finding) => {
                    const level = String(finding.severity || 'LOW').toUpperCase();
                    return Math.max(max, severityScore[level] || 1);
                }, 0);
                if (highest >= 4) {
                    ctx.valRisk.innerText = 'COMPROMISED';
                    ctx.valRisk.className = 'metric-value text-danger';
                } else if (highest >= 3) {
                    ctx.valRisk.innerText = 'EXPOSED';
                    ctx.valRisk.className = 'metric-value text-warning';
                } else if (highest >= 2) {
                    ctx.valRisk.innerText = 'OBSERVED';
                    ctx.valRisk.className = 'metric-value text-info';
                } else {
                    ctx.valRisk.innerText = 'SECURE';
                    ctx.valRisk.className = 'metric-value text-safe';
                }
            } else {
                ctx.resetFindingsView();
                ctx.valRisk.innerText = 'SECURE';
                ctx.valRisk.className = 'metric-value text-safe';
                ctx.valProgress.style.width = '0%';
            }

            ctx.clearSystemLog();
            if (Array.isArray(nextProject.logs) && nextProject.logs.length) {
                nextProject.logs.forEach((entry) => {
                    ctx.appendLog(entry.type || 'info', entry.text || '');
                });
            } else {
                ctx.appendLog('text-muted', 'System initialization complete.');
            }

            if (Array.isArray(nextProject.history) && nextProject.history.length) {
                ctx.resetHistoryView();
                nextProject.history.forEach((entry, index) => {
                    ctx.addHistoryRow(entry.dir || 'INFO', entry.payload || '', {
                        rowId: entry.rowId || `saved-row-${index}`,
                        rowNumber: entry.rowNumber || (index + 1),
                        time: entry.time || '',
                        size: entry.size,
                    });
                });
            } else {
                ctx.resetHistoryView();
            }

            ctx.welcomeModal.style.display = 'none';
            ctx.mainApp.style.display = 'flex';
            void ctx.refreshReqForgeIdentities();
            if (nextProject.projectId) {
                ctx.startPlatformProjectAutoRefresh();
                void ctx.refreshPlatformProjectSummary({ silent: true });
            } else {
                ctx.stopPlatformProjectAutoRefresh();
            }
        },

        gatherProjectState(ctx) {
            return {
                projectId: ctx.getCurrentProject().projectId || null,
                projectName: ctx.getCurrentProject().projectName || '',
                url: ctx.targetUrlInput.value,
                vulns: parseInt(ctx.valVulns.innerText, 10) || 0,
                msgs: ctx.getMsgCount(),
                findings: Array.from(ctx.findingsContainer.querySelectorAll('.finding-card')).map((card, index) => {
                    const findingId = card.dataset.findingId || `saved-finding-${index}`;
                    const stored = ctx.globalVulns[findingId] || {};
                    return {
                        id: findingId,
                        type: stored.type || card.querySelector('.f-name')?.textContent || '',
                        severity: stored.severity || card.dataset.severity || 'LOW',
                        description: stored.description || card.querySelector('.f-desc')?.textContent || '',
                        payload: stored.payload || card.querySelector('.f-payload')?.textContent || '',
                    };
                }),
                logs: Array.from(ctx.systemLog.querySelectorAll('.log-line')).map((line) => {
                    const type = Array.from(line.classList).find((name) => name !== 'log-line') || 'info';
                    return { type, text: line.innerText || '' };
                }),
                history: Array.from(ctx.historyTbody.querySelectorAll('tr'))
                    .filter((row) => !row.classList.contains('empty-tr'))
                    .map((row, index) => {
                        const rowId = row.dataset.rowId || '';
                        return {
                            rowId,
                            rowNumber: parseInt((row.cells[0]?.textContent || '').replace(/[^0-9]/g, ''), 10) || (index + 1),
                            dir: row.cells[1]?.textContent || '',
                            time: row.cells[2]?.textContent || '',
                            size: parseInt((row.cells[3]?.textContent || '').replace(/[^0-9]/g, ''), 10) || 0,
                            payload: rowId && ctx.historyData[rowId] !== undefined
                                ? ctx.historyData[rowId]
                                : (row.cells[4]?.textContent || ''),
                        };
                    })
            };
        },

        async ensurePlatformProject(ctx, reason = 'operation', targetUrlOverride = '') {
            const currentProject = ctx.getCurrentProject();
            const targetUrl = targetUrlOverride || ctx.targetUrlInput.value.trim() || currentProject.url || '';
            if (!targetUrl && !currentProject.projectId) {
                throw new Error('Target URL is required before creating a platform project.');
            }

            if (ctx.platformState.syncPromise) {
                return ctx.platformState.syncPromise;
            }

            ctx.platformState.syncPromise = (async () => {
                const shouldForceNewProject = Boolean(ctx.platformState?.forceNewProject);
                const projectName = shouldForceNewProject
                    ? `wshawk-${new Date().toISOString().replace(/[:.]/g, '-')}`
                    : this.derivePlatformProjectName(targetUrl);
                const res = await fetch('/platform/projects', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        project_id: shouldForceNewProject ? null : (currentProject.projectId || null),
                        name: projectName,
                        target_url: targetUrl,
                        metadata: {
                            source: 'desktop',
                            mode: ctx.getCurrentMode(),
                            reason,
                            synced_at: new Date().toISOString(),
                        },
                    }),
                });

                if (!res.ok) {
                    const failure = await res.json().catch(() => ({}));
                    throw new Error(failure.detail || `Platform project sync failed (${res.status})`);
                }

                const data = await res.json();
                const project = data.project;
                ctx.setCurrentProject({
                    ...ctx.getCurrentProject(),
                    projectId: project.id,
                    projectName: project.name,
                    url: targetUrl || currentProject.url,
                });
                ctx.platformState.forceNewProject = false;

                if (ctx.platformState.lastAnnouncement !== project.id) {
                    ctx.appendLog('info', `[Platform] Linked current workflow to project ${project.name}.`);
                    ctx.platformState.lastAnnouncement = project.id;
                }

                await ctx.refreshReqForgeIdentities();
                ctx.startPlatformProjectAutoRefresh();
                ctx.queuePlatformProjectRefresh(150);
                return project;
            })();

            try {
                return await ctx.platformState.syncPromise;
            } finally {
                ctx.platformState.syncPromise = null;
            }
        },

        stopPlatformProjectAutoRefresh(ctx) {
            if (ctx.platformState.refreshTimer) {
                clearInterval(ctx.platformState.refreshTimer);
                ctx.platformState.refreshTimer = null;
            }
            if (ctx.platformState.refreshQueued) {
                clearTimeout(ctx.platformState.refreshQueued);
                ctx.platformState.refreshQueued = null;
            }
        },

        startPlatformProjectAutoRefresh(ctx) {
            this.stopPlatformProjectAutoRefresh(ctx);
            if (!ctx.getCurrentProject().projectId) return;

            ctx.platformState.refreshTimer = setInterval(() => {
                void ctx.refreshPlatformProjectSummary({ silent: true });
            }, 8000);
        },

        queuePlatformProjectRefresh(ctx, delay = 900) {
            if (!ctx.getCurrentProject().projectId) return;
            if (ctx.platformState.refreshQueued) {
                clearTimeout(ctx.platformState.refreshQueued);
            }

            ctx.platformState.refreshQueued = setTimeout(() => {
                ctx.platformState.refreshQueued = null;
                void ctx.refreshPlatformProjectSummary({ silent: true });
            }, delay);
        },

        async refreshPlatformProjectSummary(ctx, { silent = true } = {}) {
            const currentProject = ctx.getCurrentProject();
            if (!currentProject.projectId || ctx.platformState.refreshing) {
                return null;
            }

            ctx.platformState.refreshing = true;
            try {
                const [projectRes, eventsRes, evidenceRes] = await Promise.all([
                    fetch(`/platform/projects/${currentProject.projectId}`),
                    fetch(`/platform/projects/${currentProject.projectId}/events?limit=200`),
                    fetch(`/platform/projects/${currentProject.projectId}/evidence?limit=100`)
                ]);

                const projectData = await projectRes.json().catch(() => ({}));
                const eventsData = await eventsRes.json().catch(() => ({}));
                const evidenceData = await evidenceRes.json().catch(() => ({}));

                if (!projectRes.ok) {
                    throw new Error(projectData.detail || `Project sync failed (${projectRes.status})`);
                }

                const project = projectData.project || {};
                const events = eventsData.events || projectData.recent_events || [];
                const evidence = evidenceData.evidence || projectData.evidence || [];
                const attackRuns = projectData.attack_runs || [];
                const notes = projectData.notes || [];
                ctx.platformState.reqforgeIdentityCache = projectData.identities || ctx.platformState.reqforgeIdentityCache;
                ctx.renderReqForgeIdentities(ctx.platformState.reqforgeIdentityCache);

                if (ctx.platformState.reqforgeIdentityCache.length > 0) {
                    ctx.setReqForgePlatformStatus(
                        `Loaded ${ctx.platformState.reqforgeIdentityCache.length} project identity${ctx.platformState.reqforgeIdentityCache.length === 1 ? '' : 'ies'} for replay and AuthZ diff.`,
                        'success'
                    );
                } else {
                    ctx.setReqForgePlatformStatus(
                        'No stored identities yet. Record DOM auth, then store it here to unlock role-aware replay.',
                        'info'
                    );
                }

                if (project.target_url) {
                    ctx.setCurrentProject({
                        ...ctx.getCurrentProject(),
                        projectId: project.id,
                        projectName: project.name,
                        url: project.target_url,
                    });
                    if (!ctx.targetUrlInput.value.trim()) {
                        ctx.targetUrlInput.value = project.target_url;
                    }
                }

                ctx.renderPlatformEvidence(evidence);
                ctx.renderPlatformTimeline(events);
                ctx.renderAttackWorkspace(attackRuns, projectData.findings || []);
                ctx.renderEvidenceWorkspace(evidence, notes, projectData.timeline || {});

                if (!silent) {
                    ctx.appendLog('info', `[Platform] Synced project telemetry: ${events.length} events, ${evidence.length} evidence items, ${attackRuns.length} attack runs.`);
                }

                return { project, events, evidence, attackRuns, notes };
            } catch (error) {
                if (!silent) {
                    ctx.appendLog('vuln', `[Platform] Project sync failed: ${error.message}`);
                }
                return null;
            } finally {
                ctx.platformState.refreshing = false;
            }
        }
    };
})(window);
