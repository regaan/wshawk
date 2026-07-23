(function initAttacksModule(global) {
    const modules = global.WSHawkModules = global.WSHawkModules || {};

    function parsePayload(rawValue) {
        if (typeof rawValue !== 'string') {
            return rawValue;
        }
        const trimmed = rawValue.trim();
        if (!trimmed) {
            return '';
        }
        try {
            return JSON.parse(trimmed);
        } catch (_) {
            return rawValue;
        }
    }

    function parseList(rawValue) {
        return String(rawValue || '')
            .split(/[\n,]+/)
            .map(item => item.trim())
            .filter(Boolean);
    }

    function selectedIdentityIds(ctx) {
        const selectedIdentityId = document.getElementById('reqforge-identity-select')?.value || '';
        if (selectedIdentityId) {
            return [selectedIdentityId];
        }
        return (ctx.platformState?.reqforgeIdentityCache || []).map(identity => identity.id);
    }

    function summarizeSubscription(summary = {}) {
        return `Subscription abuse completed with ${summary.mutation_count || 0} mutation(s); ${summary.suspicious_attempt_count || 0} suspicious acceptance(s) observed.`;
    }

    function summarizeRace(summary = {}) {
        return `Race attack ${summary.mode || 'duplicate_action'} ran ${summary.attempt_count || 0} attempt(s) across ${summary.wave_count || 0} wave(s).`;
    }

    function esc(value) {
        const div = document.createElement('div');
        div.textContent = value == null ? '' : String(value);
        return div.innerHTML;
    }

    function renderWorkflowResults(data, resDiv, varsDiv) {
        const workflow = data.workflow || {};
        const results = workflow.results || [];
        const summary = workflow.summary || {};
        const esc = global.esc || ((value) => String(value));

        let html = `<div style="font-size: 11px; padding: 8px 0; color: var(--text-muted); margin-bottom: 8px;">
            ${summary.completed || 0}/${summary.total_steps || results.length || 0} completed · ${summary.skipped || 0} skipped · ${summary.errors || 0} errors
        </div>`;

        results.forEach((step) => {
            const statusColor = step.status === 'success' ? 'var(--accent)' :
                step.status === 'skipped' ? 'var(--warning)' : 'var(--danger)';
            const statusIcon = step.status === 'success' ? '✓' :
                step.status === 'skipped' ? '⏭' : '✗';
            html += `<div style="background: var(--bg-secondary); border-radius: 6px; padding: 12px; margin-bottom: 8px; border-left: 3px solid ${statusColor};">
                <div style="display: flex; justify-content: space-between; margin-bottom: 6px;">
                    <span style="font-weight: 600; font-size: 12px; color: ${statusColor};">
                        ${statusIcon} ${esc(step.name || `Step ${step.step || '?'}`)}
                    </span>
                    <span style="font-size: 10px; color: var(--text-muted);">
                        ${(step.method && step.http_status) ? `${esc(step.method)} ${esc(step.http_status)}` : esc(step.type || '')}
                        ${step.response_length ? ` · ${step.response_length} bytes` : ''}
                    </span>
                </div>`;

            if (step.url) {
                html += `<div style="font-family: var(--font-mono); font-size: 10px; color: var(--text-muted); margin-bottom: 4px;">${esc(step.url)}</div>`;
            }
            if (step.reason) {
                html += `<div style="font-size: 10px; color: var(--danger);">${esc(step.reason)}</div>`;
            }
            if (step.response_preview) {
                html += `<div style="margin-top: 6px; font-family: var(--font-mono); font-size: 10px; color: var(--text-primary); white-space: pre-wrap;">${esc(step.response_preview)}</div>`;
            }
            if (step.extracted && Object.keys(step.extracted).length > 0) {
                html += '<div style="margin-top: 6px;">';
                Object.entries(step.extracted).forEach(([key, value]) => {
                    html += `<div style="font-size: 10px;"><span style="color: var(--accent);">{{${esc(key)}}}</span> = <code style="background: var(--bg-tertiary); padding: 2px 4px; border-radius: 3px;">${esc(String(value).substring(0, 120))}</code></div>`;
                });
                html += '</div>';
            }
            html += '</div>';
        });

        resDiv.innerHTML = html;

        const variables = workflow.variables || {};
        if (Object.keys(variables).length === 0) {
            varsDiv.innerHTML = '<span style="opacity: 0.5;">No variables extracted yet.</span>';
            return;
        }

        varsDiv.innerHTML = Object.entries(variables)
            .map(([key, value]) => `<div style="margin-bottom: 4px;"><span style="color: var(--accent);">{{${esc(key)}}}</span> = ${esc(String(value))}</div>`)
            .join('');
    }

    function renderAttackWorkspace({ attackRuns = [], findings = [] }) {
        const summaryContainer = document.getElementById('attacks-summary');
        const runList = document.getElementById('attacks-run-list');
        const findingList = document.getElementById('attacks-findings-list');
        if (!summaryContainer || !runList || !findingList) return;

        const normalizedRuns = attackRuns.map(run => ({ ...run, ...(run.metadata || {}) }));
        const normalizedFindings = findings.map(finding => ({ ...finding, ...(finding.metadata || {}), title: finding.metadata?.title || finding.title || finding.name }));
        const totalRuns = normalizedRuns.length;
        const activeRuns = normalizedRuns.filter(run => run.status === 'running').length;
        const suspiciousFindings = normalizedFindings.filter(item => ['high', 'critical'].includes(String(item.severity || '').toLowerCase())).length;
        const attackTypes = [...new Set(normalizedRuns.map(run => run.attack_type).filter(Boolean))];

        summaryContainer.innerHTML = `
            <div style="display: grid; grid-template-columns: repeat(2, minmax(0, 1fr)); gap: 10px;">
                <div class="metric-card" style="padding: 12px;">
                    <div class="metric-title">Attack Runs</div>
                    <div class="metric-value" style="font-size: 22px;">${totalRuns}</div>
                </div>
                <div class="metric-card" style="padding: 12px;">
                    <div class="metric-title">High-Risk Finds</div>
                    <div class="metric-value text-danger" style="font-size: 22px;">${suspiciousFindings}</div>
                </div>
                <div class="metric-card" style="padding: 12px;">
                    <div class="metric-title">Active Jobs</div>
                    <div class="metric-value" style="font-size: 22px;">${activeRuns}</div>
                </div>
                <div class="metric-card" style="padding: 12px;">
                    <div class="metric-title">Attack Types</div>
                    <div class="metric-value" style="font-size: 18px;">${attackTypes.length}</div>
                </div>
            </div>
            <div style="margin-top: 10px; font-size: 11px; color: var(--text-muted);">
                ${attackTypes.length ? `Observed: ${esc(attackTypes.slice(0, 6).join(', '))}` : 'No project-backed attack runs recorded yet.'}
            </div>
        `;

        if (!normalizedRuns.length) {
            runList.innerHTML = '<div class="empty-state">Run replay, subscription abuse, race, or workflows to build the attack ledger.</div>';
        } else {
            runList.innerHTML = normalizedRuns.map((run) => {
                const summary = run.summary || {};
                const preview = [
                    summary.suspicious_attempt_count ? `${summary.suspicious_attempt_count} suspicious mutations` : '',
                    summary.suspicious_race_window ? 'race window flagged' : '',
                    summary.behavior_changed ? 'behavior changed' : '',
                    summary.completed ? `${summary.completed} complete` : '',
                ].filter(Boolean).join(' • ') || 'No summary details';
                return `
                    <div style="padding: 10px 0; border-bottom: 1px solid var(--border-color);">
                        <div style="display: flex; justify-content: space-between; gap: 8px;">
                            <div style="font-weight: 600; color: var(--text-primary);">${esc(run.attack_type || 'attack')}</div>
                            <span class="badge" style="background: rgba(255,255,255,0.08);">${esc(run.status || 'unknown')}</span>
                        </div>
                        <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">${esc(preview)}</div>
                        <div style="font-size: 10px; color: var(--text-muted); margin-top: 4px;">${esc(run.updated_at || run.created_at || '')}</div>
                    </div>
                `;
            }).join('');
        }

        if (!normalizedFindings.length) {
            findingList.innerHTML = '<div class="empty-state">No offensive findings yet. Suspicious replay, authz drift, and race results will appear here.</div>';
            return;
        }

        findingList.innerHTML = normalizedFindings.map((finding) => `
            <div data-finding-id="${esc(finding.id || '')}" style="padding: 12px; border-bottom: 1px solid var(--border-color);">
                <div style="display: flex; justify-content: space-between; gap: 8px; align-items: center;">
                    <div style="font-weight: 600; color: var(--text-primary);">${esc(finding.title || 'Untitled finding')}</div>
                    <span class="sev-badge sev-${esc(String(finding.severity || 'info').toUpperCase())}">${esc(String(finding.severity || 'info').toUpperCase())}</span>
                </div>
                <div style="font-size: 11px; color: var(--text-muted); margin-top: 6px;">${esc(finding.category || 'offensive')} Â· ${esc(String(finding.lifecycle_status || 'open').toUpperCase())}</div>
                <div style="font-size: 12px; color: var(--text-primary); margin-top: 6px;">${esc(finding.description || '')}</div>
                <div style="display:flex;gap:6px;flex-wrap:wrap;margin-top:9px;">
                    <button class="btn secondary small" data-finding-action="confirmed">Confirm</button>
                    <button class="btn secondary small" data-finding-action="rejected">Reject</button>
                    <button class="btn secondary small" data-finding-action="fixed">Mark Fixed</button>
                    ${['idor-bola', 'tenant-isolation', 'missing-authentication', 'vertical-privilege-escalation', 'broken-function-level-authorization', 'websocket-authorization'].includes(finding.type)
                        ? '<button class="btn secondary small" data-finding-action="retest">Retest</button>' : ''}
                </div>
            </div>
        `).join('');

		if (!findingList.dataset.lifecycleBound) {
			findingList.dataset.lifecycleBound = 'true';
			findingList.addEventListener('click', async (event) => {
				const button = event.target.closest('[data-finding-action]');
				if (!button) return;
				const findingId = button.closest('[data-finding-id]')?.dataset.findingId || '';
				const projectId = global.getCurrentProject?.()?.projectId || '';
				if (!findingId || !projectId) return;
				const action = button.dataset.findingAction;
				button.disabled = true;
				const original = button.textContent;
				button.textContent = action === 'retest' ? 'Retesting...' : 'Saving...';
				try {
					const response = await global.ipcRequest(`/platform/projects/${projectId}/findings/${encodeURIComponent(findingId)}${action === 'retest' ? '/retest' : ''}`, {
						method: action === 'retest' ? 'POST' : 'PATCH',
						headers: { 'Content-Type': 'application/json' },
						body: JSON.stringify(action === 'retest' ? {} : { lifecycle_status: action }),
					});
					const data = await response.json();
					if (!response.ok) throw new Error(data.detail || `Finding action failed (${response.status})`);
					global.queuePlatformProjectRefresh?.(100);
				} catch (error) {
					button.textContent = `Error: ${error.message}`;
					setTimeout(() => { button.textContent = original; button.disabled = false; }, 2500);
					return;
				}
				button.textContent = 'Saved';
				setTimeout(() => { button.textContent = original; button.disabled = false; }, 1200);
			});
		}
    }

    modules.attacks = {
        authzDiffLogMessage(summary = {}) {
            return `AuthZ diff completed across ${summary.identity_count || 0} identities with ${summary.behavior_group_count || 0} behavior group(s).`;
        },

        replayStatusMessage(result = {}) {
            const alias = result.identity_alias || 'selected identity';
            return `Replay completed as ${alias} (${result.status || 'unknown'}).`;
        },

        parsePayload,

        async runScan(ctx) {
            const url = ctx.targetUrlInput.value.trim();
            const authPayload = document.getElementById('auth-payload').value.trim();
            if (!url) {
                ctx.appendLog('vuln', 'Input Error: Target WebSocket URL is required.');
                return;
            }

            ctx.resetFindingsView('Analysis sequence engaged. Monitoring for vulnerabilities...');
            ctx.resetHistoryView('Awaiting scanner traffic...');
            ctx.valRisk.innerText = 'SCANNING';
            ctx.valRisk.className = 'metric-value';
            ctx.valProgress.style.width = '0%';
            ctx.valProgress.style.background = 'var(--text-primary)';
            ctx.scanBtn.disabled = true;
            ctx.scanBtn.innerText = 'Processing...';
            document.getElementById('scan-stop-btn').style.display = 'block';

            try {
                const project = await ctx.ensurePlatformProject('scan_start', url);
                await ipcRequest('/scan/start', {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        project_id: project.id,
                        url,
                        auth_payload: authPayload,
                        rate: 10
                    })
                });
                ctx.startScanTimer();
            } catch (_) {
                ctx.appendLog('vuln', 'Bridge Communication Failure. Is the Python sidecar running?');
                ctx.scanBtn.innerText = 'Run Analysis';
                ctx.scanBtn.disabled = false;
                document.getElementById('scan-stop-btn').style.display = 'none';
            }
        },

        async stopScan(ctx) {
            try {
                await ipcRequest('/scan/stop', { method: 'POST' });
                ctx.appendLog('info', 'Commanded background scan to HALT.');
                ctx.scanBtn.innerText = 'Run Analysis';
                ctx.scanBtn.disabled = false;
                document.getElementById('scan-stop-btn').style.display = 'none';
            } catch (e) {
                ctx.appendLog('vuln', 'Failed to stop scan: ' + e.message);
            }
        },

        async runRequestForge(ctx) {
            const payload = parsePayload(document.getElementById('reqforge-req').value);
            const responseBox = document.getElementById('reqforge-res');
            const targetUrl = ctx.targetUrlInput.value.trim();
            const selectedIdentityId = document.getElementById('reqforge-identity-select')?.value || '';
            if (!targetUrl) {
                responseBox.value = '[!] Input Error: Please configure Target URL above first.';
                ctx.appendLog('vuln', 'Configuration Error: Target URL missing for Request Forge operation.');
                return;
            }
            if (selectedIdentityId && ctx.isIntercepting()) {
                responseBox.value = '[!] Identity-backed replay is disabled while the interceptor is active.';
                ctx.appendLog('vuln', 'Disable the interceptor before using project identities in Request Forge.');
                return;
            }
            responseBox.value = 'Executing payload transmission...';

            const targetEndpoint = ctx.isIntercepting()
                ? ctx.bridgeWebSocketUrl(`/proxy?url=${encodeURIComponent(targetUrl)}`)
                : targetUrl;

            try {
                const project = await ctx.ensurePlatformProject('reqforge_replay', targetUrl);
                const endpoint = (!ctx.isIntercepting() && project?.id)
                    ? `/platform/projects/${project.id}/replay/ws`
                    : '/reqforge/send';
                const body = (!ctx.isIntercepting() && project?.id)
                    ? { url: targetEndpoint, payload, identity_id: selectedIdentityId || null, timeout: 10 }
                    : { project_id: ctx.getCurrentProject().projectId || null, url: targetEndpoint, payload };
                const res = await ipcRequest(endpoint, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify(body)
                });
                const data = await res.json();
                if (!res.ok) {
                    throw new Error(data.detail || data.msg || `Replay failed (${res.status})`);
                }
                responseBox.value = JSON.stringify(data, null, 2);
                ctx.queuePlatformProjectRefresh(150);
                if (selectedIdentityId && data.result?.status) {
                    ctx.appendLog('info', `[Platform] ${this.replayStatusMessage(data.result)}`);
                }
            } catch (e) {
                responseBox.value = '[ERR] Inter-process transit failed: ' + e.message;
                ctx.appendLog('vuln', `[Platform] Request Forge failed: ${e.message}`);
            }
        },

        async runAuthzDiff(ctx) {
            const responseBox = document.getElementById('reqforge-res');
            const payload = parsePayload(document.getElementById('reqforge-req').value);
            const targetUrl = ctx.targetUrlInput.value.trim();
            if (!targetUrl) {
                ctx.appendLog('vuln', 'Target URL is required before running AuthZ diff.');
                return;
            }
            if (ctx.isIntercepting()) {
                ctx.appendLog('vuln', 'Disable the interceptor before running project-backed AuthZ diff.');
                return;
            }

            try {
                const project = await ctx.ensurePlatformProject('authz_diff', targetUrl);
                const identities = await ctx.refreshReqForgeIdentities({ announceErrors: true });
                if (identities.length < 2) {
                    throw new Error('Store at least two identities before running AuthZ diff.');
                }
				const primaryIdentityId = document.getElementById('reqforge-identity-select')?.value || '';
				const ownerIdentityId = document.getElementById('reqforge-compare-identity-select')?.value || '';
				if (!primaryIdentityId || !ownerIdentityId || primaryIdentityId === ownerIdentityId) {
					throw new Error('Select different primary and comparison identities for WebSocket AuthZ diff.');
				}
				const policyMode = document.getElementById('reqforge-authz-policy')?.value || 'compare_only';

                responseBox.value = 'Running cross-identity replay comparison...';
                const res = await ipcRequest(`/platform/projects/${project.id}/attacks/authz-diff`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        url: targetUrl,
                        payload,
						identity_ids: [primaryIdentityId, ownerIdentityId],
						primary_identity_id: primaryIdentityId,
						owner_identity_id: ownerIdentityId,
						policy_mode: policyMode,
						evidence_mode: document.getElementById('reqforge-authz-evidence-mode')?.value || 'redacted',
                        timeout: 10,
                    })
                });
                const data = await res.json();
                if (!res.ok) {
                    throw new Error(data.detail || data.msg || `AuthZ diff failed (${res.status})`);
                }

                responseBox.value = JSON.stringify(data, null, 2);
                ctx.queuePlatformProjectRefresh(150);
                const summary = data.diff?.summary || {};
				const verdict = data.diff?.policy_evaluation?.verdict || 'comparison_only';
                ctx.appendLog(
					summary.finding_saved || summary.behavior_changed ? 'vuln' : 'info',
					`[Platform] ${this.authzDiffLogMessage(summary)} Policy verdict: ${verdict}${summary.finding_id ? `; saved ${summary.finding_id}` : ''}.`
                );
            } catch (error) {
                responseBox.value = `[ERR] AuthZ diff failed: ${error.message}`;
                ctx.appendLog('vuln', `[Platform] AuthZ diff failed: ${error.message}`);
            }
        },

		async runAuthzMatrix(ctx) {
			const responseBox = document.getElementById('reqforge-res');
			const targetUrl = ctx.targetUrlInput.value.trim();
			try {
				if (!targetUrl) throw new Error('Target URL is required before running a WebSocket authorization matrix.');
				if (ctx.isIntercepting()) throw new Error('Disable interception before the bounded authorization matrix.');
				const project = await ctx.ensurePlatformProject('ws_authz_matrix', targetUrl);
				const identities = await ctx.refreshReqForgeIdentities({ announceErrors: true });
				const primaryIdentityId = document.getElementById('reqforge-identity-select')?.value || '';
				const ownerIdentityId = document.getElementById('reqforge-compare-identity-select')?.value || '';
				if (identities.length < 2 || !primaryIdentityId || !ownerIdentityId || primaryIdentityId === ownerIdentityId) throw new Error('Select different primary and owner/control identities.');
				const fields = parseList(document.getElementById('reqforge-field-paths')?.value);
				const candidates = parseList(document.getElementById('reqforge-candidate-values')?.value);
				if (!fields.length || !candidates.length) throw new Error('Enter a room/channel/tenant/GraphQL variable field and at least two captured object candidates.');
				responseBox.value = 'Running bounded WebSocket identity/object authorization matrix...';
				const response = await ipcRequest(`/platform/projects/${project.id}/attacks/ws-authz-matrix`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({
					url: targetUrl, payload: parsePayload(document.getElementById('reqforge-req').value),
					identity_ids: identities.map(identity => identity.id), primary_identity_id: primaryIdentityId, owner_identity_id: ownerIdentityId,
					policy_mode: document.getElementById('reqforge-authz-policy')?.value || 'primary_denied_owner_allowed',
					object_field: fields[0], object_values: candidates.slice(0, 10), minimum_confirmations: Math.min(2, candidates.length), include_anonymous: true,
					evidence_mode: document.getElementById('reqforge-authz-evidence-mode')?.value || 'redacted', timeout: 10,
				}) });
				const data = await response.json(); if (!response.ok) throw new Error(data.detail || `WebSocket AuthZ matrix failed (${response.status})`);
				responseBox.value = JSON.stringify(data, null, 2);
				ctx.queuePlatformProjectRefresh(150);
				ctx.appendLog(data.matrix?.summary?.finding_saved ? 'vuln' : 'info', `[Platform] WebSocket authorization matrix: ${data.matrix?.evaluation?.verdict || 'inconclusive'} across ${data.matrix?.summary?.request_count || 0} cases.`);
			} catch (error) { responseBox.value = `[ERR] WebSocket AuthZ matrix failed: ${error.message}`; ctx.appendLog('vuln', `[Platform] ${error.message}`); }
		},

        async runSubscriptionAbuse(ctx) {
            const responseBox = document.getElementById('reqforge-res');
            const targetUrl = ctx.targetUrlInput.value.trim();
            if (!targetUrl) {
                ctx.appendLog('vuln', 'Target URL is required before running subscription abuse checks.');
                return;
            }
            if (ctx.isIntercepting()) {
                ctx.appendLog('vuln', 'Disable the interceptor before running project-backed subscription abuse probes.');
                return;
            }

            const payload = parsePayload(document.getElementById('reqforge-req').value);
            const fieldPaths = parseList(document.getElementById('reqforge-field-paths')?.value);
            const candidateValues = parseList(document.getElementById('reqforge-candidate-values')?.value);
            const maxMutations = parseInt(document.getElementById('reqforge-max-mutations')?.value || '24', 10) || 24;

            try {
                const project = await ctx.ensurePlatformProject('subscription_abuse', targetUrl);
                responseBox.value = 'Running channel / tenant / object mutation probes...';
                const res = await ipcRequest(`/platform/projects/${project.id}/attacks/subscription-abuse`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        url: targetUrl,
                        payload,
                        identity_ids: selectedIdentityIds(ctx),
                        field_paths: fieldPaths,
                        candidate_values: candidateValues,
                        max_mutations: maxMutations,
                        timeout: 10,
                    }),
                });
                const data = await res.json();
                if (!res.ok) {
                    throw new Error(data.detail || data.msg || `Subscription abuse failed (${res.status})`);
                }

                responseBox.value = JSON.stringify(data, null, 2);
                ctx.queuePlatformProjectRefresh(150);
                const summary = data.attack?.summary || {};
                ctx.appendLog(
                    summary.suspicious_attempt_count ? 'vuln' : 'info',
                    `[Platform] ${summarizeSubscription(summary)}`
                );
            } catch (error) {
                responseBox.value = `[ERR] Subscription abuse failed: ${error.message}`;
                ctx.appendLog('vuln', `[Platform] Subscription abuse failed: ${error.message}`);
            }
        },

        async runRaceAttack(ctx) {
            const responseBox = document.getElementById('reqforge-res');
            const targetUrl = ctx.targetUrlInput.value.trim();
            if (!targetUrl) {
                ctx.appendLog('vuln', 'Target URL is required before running race attacks.');
                return;
            }
            if (ctx.isIntercepting()) {
                ctx.appendLog('vuln', 'Disable the interceptor before running project-backed race attacks.');
                return;
            }

            const payload = parsePayload(document.getElementById('reqforge-req').value);
            const raceMode = document.getElementById('reqforge-race-mode')?.value || 'duplicate_action';
            const concurrency = parseInt(document.getElementById('reqforge-race-concurrency')?.value || '5', 10) || 5;
            const waves = parseInt(document.getElementById('reqforge-race-waves')?.value || '2', 10) || 2;
            const staggerMs = parseInt(document.getElementById('reqforge-race-stagger')?.value || '0', 10) || 0;
            const waveDelayMs = parseInt(document.getElementById('reqforge-race-wave-delay')?.value || '0', 10) || 0;

            try {
                const project = await ctx.ensurePlatformProject('race_attack', targetUrl);
                responseBox.value = 'Running concurrent replay windows...';
                const res = await ipcRequest(`/platform/projects/${project.id}/attacks/race`, {
                    method: 'POST',
                    headers: { 'Content-Type': 'application/json' },
                    body: JSON.stringify({
                        url: targetUrl,
                        payload,
                        identity_ids: selectedIdentityIds(ctx),
                        mode: raceMode,
                        concurrency,
                        waves,
                        stagger_ms: staggerMs,
                        wave_delay_ms: waveDelayMs,
                        timeout: 10,
                    }),
                });
                const data = await res.json();
                if (!res.ok) {
                    throw new Error(data.detail || data.msg || `Race attack failed (${res.status})`);
                }

                responseBox.value = JSON.stringify(data, null, 2);
                ctx.queuePlatformProjectRefresh(150);
                const summary = data.attack?.summary || {};
                ctx.appendLog(
                    summary.suspicious_race_window ? 'vuln' : 'info',
                    `[Platform] ${summarizeRace(summary)}`
                );
            } catch (error) {
                responseBox.value = `[ERR] Race attack failed: ${error.message}`;
                ctx.appendLog('vuln', `[Platform] Race attack failed: ${error.message}`);
            }
        },

        async runWorkflow(ctx, steps, options = {}) {
            const targetUrl = options.defaultUrl || ctx.targetUrlInput.value.trim();
            const identityId = document.getElementById('chain-identity-select')?.value || '';
            const body = {
                default_url: targetUrl,
                steps,
                variables: options.variables || {},
                timeout: options.timeout || 10,
                identity_id: identityId || null,
            };

            const project = await ctx.ensurePlatformProject('workflow_execution', targetUrl);
            const res = await ipcRequest(`/platform/projects/${project.id}/attacks/workflow`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify(body),
            });
            const data = await res.json();
            if (!res.ok) {
                throw new Error(data.detail || data.msg || `Workflow execution failed (${res.status})`);
            }
            ctx.queuePlatformProjectRefresh(150);
            return data;
        },

        renderWorkflowResults,
        renderAttackWorkspace,
        summarizeSubscription,
        summarizeRace,
        parseList,
        selectedIdentityIds,
        initWorkspace(ctx) {
            document.getElementById('attacks-refresh-btn')?.addEventListener('click', async () => {
                await ctx.refreshPlatformProjectSummary({ silent: false });
            });
            document.getElementById('attacks-open-reqforge-btn')?.addEventListener('click', () => {
                document.querySelector('.nav-item[data-target="reqforge"]')?.click();
            });
            document.getElementById('attacks-open-workflow-btn')?.addEventListener('click', () => {
                document.querySelector('.nav-item[data-target="attackchainer"]')?.click();
            });
        },
    };
})(window);
