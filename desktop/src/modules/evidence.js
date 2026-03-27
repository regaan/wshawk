(function initEvidenceModule(global) {
    const modules = global.WSHawkModules = global.WSHawkModules || {};

    function normalizeSeverity(value) {
        const severity = String(value || 'LOW').trim().toUpperCase();
        if (severity === 'CRITICAL') return 'HIGH';
        if (severity === 'MED') return 'MEDIUM';
        if (!['HIGH', 'MEDIUM', 'LOW', 'INFO'].includes(severity)) return 'LOW';
        return severity;
    }

    function severityScore(value) {
        const severity = normalizeSeverity(value);
        if (severity === 'HIGH') return 4;
        if (severity === 'MEDIUM') return 3;
        if (severity === 'LOW') return 2;
        return 1;
    }

    function summarizeEvidencePayload(payload = {}) {
        if (payload.finding) {
            return payload.finding.payload || payload.finding.value || payload.finding.description || payload.finding.detail || '';
        }
        if (payload.summary?.interesting_identities?.length) {
            const aliases = payload.summary.interesting_identities
                .map(item => item.identity_alias)
                .filter(Boolean)
                .slice(0, 4)
                .join(', ');
            return aliases
                ? `Behavior drift observed across identities: ${aliases}`
                : `Behavior drift observed across ${payload.summary.identity_count || 0} identities.`;
        }
        if (payload.result?.response_preview) {
            return payload.result.response_preview;
        }
        if (payload.response) {
            return payload.response;
        }
        return global.truncate ? global.truncate(payload, 140) : JSON.stringify(payload);
    }

    function esc(value) {
        const div = document.createElement('div');
        div.textContent = value == null ? '' : String(value);
        return div.innerHTML;
    }

    function renderEvidenceRecord(item) {
        return `
            <div style="padding: 12px; border-bottom: 1px solid var(--border-color);">
                <div style="display: flex; justify-content: space-between; gap: 8px; align-items: center;">
                    <div style="font-weight: 600; color: var(--text-primary);">${esc(item.title || 'Untitled evidence')}</div>
                    <span class="sev-badge sev-${normalizeSeverity(item.severity)}">${esc(normalizeSeverity(item.severity))}</span>
                </div>
                <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">${esc(item.category || 'note')} • ${esc(item.created_at || '')}</div>
                <div style="font-size: 12px; color: var(--text-primary); margin-top: 8px;">${esc(summarizeEvidencePayload(item.payload || {}))}</div>
            </div>
        `;
    }

    function renderReplayRecipe(recipe) {
        const title = recipe.type === 'http'
            ? `${recipe.method || 'GET'} ${recipe.url || ''}`
            : recipe.url || 'WebSocket replay recipe';
        const meta = recipe.type === 'http'
            ? `flow=${recipe.flow_id || 'n/a'}${recipe.correlation_id ? ` • ${recipe.correlation_id}` : ''}`
            : `conn=${recipe.connection_id || 'n/a'}${recipe.correlation_id ? ` • ${recipe.correlation_id}` : ''}`;
        const detail = recipe.type === 'http'
            ? (recipe.curl || 'No curl replay available')
            : `Payloads captured: ${(recipe.payloads || []).length} • Subprotocol: ${recipe.subprotocol || 'none'}`;
        return `
            <div style="padding: 12px; border-bottom: 1px solid var(--border-color);">
                <div style="font-weight: 600; color: var(--text-primary);">${esc(title)}</div>
                <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">${esc(meta)}</div>
                <div style="font-size: 11px; color: var(--text-secondary); margin-top: 8px; white-space: pre-wrap; word-break: break-word;">${esc(detail)}</div>
            </div>
        `;
    }

    function renderCorrelationChain(chain) {
        const summary = chain.summary || {};
        const detail = [
            `${summary.http_flow_count || 0} HTTP`,
            `${summary.ws_connection_count || 0} WS`,
            `${summary.browser_artifact_count || 0} browser`,
            `${(chain.attack_runs || []).length} runs`,
            `${(chain.findings || []).length} findings`,
        ].join(' • ');
        const targets = [...(chain.http_urls || []), ...(chain.ws_urls || [])].filter(Boolean).slice(0, 4).join('\n');
        return `
            <div style="padding: 12px; border-bottom: 1px solid var(--border-color);">
                <div style="font-weight: 600; color: var(--text-primary);">${esc(chain.correlation_id || 'correlation')}</div>
                <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">${esc(detail)}</div>
                <div style="font-size: 11px; color: var(--text-secondary); margin-top: 8px; white-space: pre-wrap;">${esc(targets || 'No linked targets')}</div>
            </div>
        `;
    }

    modules.evidence = {
        normalizeSeverity,
        severityScore,
        async exportProjectBundle({ projectId, format = 'json', appendLog }) {
            if (!projectId) return false;

            const res = await fetch(`/platform/projects/${projectId}/exports/${encodeURIComponent(format)}`);
            if (!res.ok) {
                const failure = await res.json().catch(() => ({}));
                throw new Error(failure.detail || `Project export failed (${res.status})`);
            }

            const content = await res.text();
            const disposition = res.headers.get('content-disposition') || '';
            const filenameMatch = disposition.match(/filename="([^"]+)"/i);
            const filename = filenameMatch ? filenameMatch[1] : `wshawk-project.${format === 'markdown' ? 'md' : format}`;
            const mime = res.headers.get('content-type') || (
                format === 'html' ? 'text/html' :
                    format === 'markdown' ? 'text/markdown' :
                        'application/json'
            );

            const blob = new Blob([content], { type: mime });
            const url = URL.createObjectURL(blob);
            const anchor = document.createElement('a');
            anchor.href = url;
            anchor.download = filename;
            anchor.click();
            URL.revokeObjectURL(url);

            appendLog?.('info', `Project evidence export downloaded: ${filename}`);
            return true;
        },

        clearFindingStore(globalVulns) {
            Object.keys(globalVulns).forEach(key => delete globalVulns[key]);
        },

        resetFindingsView({ findingsContainer, globalVulns, message = 'No vulnerabilities detected on the target.' }) {
            this.clearFindingStore(globalVulns);
            findingsContainer.innerHTML = `<div class="empty-state">${global.esc ? global.esc(message) : message}</div>`;
        },

        evidenceToFinding(evidence) {
            const finding = evidence.payload?.finding || {};
            let description = finding.description || finding.detail;
            if (!description && evidence.payload?.summary?.behavior_changed) {
                description = `Authorization or behavior drift detected in ${evidence.category || 'offensive workflow'}.`;
            }
            if (!description) {
                description = `Platform evidence recorded for ${evidence.category || 'offensive workflow'}.`;
            }
            return {
                type: finding.type || finding.title || evidence.title || evidence.category || 'Platform Evidence',
                severity: normalizeSeverity(finding.severity || evidence.severity),
                description,
                payload: summarizeEvidencePayload(evidence.payload || {}),
            };
        },

        updateRiskFromEvidence(valRisk, evidenceList = []) {
            const highest = evidenceList.reduce((max, evidence) => Math.max(max, severityScore(evidence.severity)), 0);
            if (highest >= 4) {
                valRisk.innerText = 'COMPROMISED';
                valRisk.className = 'metric-value text-danger';
            } else if (highest === 3) {
                valRisk.innerText = 'EXPOSED';
                valRisk.className = 'metric-value text-warning';
            } else if (highest === 2) {
                valRisk.innerText = 'OBSERVED';
                valRisk.className = 'metric-value text-info';
            } else {
                valRisk.innerText = 'SECURE';
                valRisk.className = 'metric-value text-safe';
            }
        },

        addFinding({ findingsContainer, globalVulns, vuln, options = {} }) {
            if (findingsContainer.querySelector('.empty-state')) {
                findingsContainer.innerHTML = '';
            }
            const vId = options.findingId || Math.random().toString(36).substr(2, 9);
            if (globalVulns[vId]) {
                return vId;
            }
            globalVulns[vId] = vuln;
            const esc = global.esc || ((value) => String(value));
            const severity = normalizeSeverity(vuln.severity || 'LOW');
            const html = `
                <div class="finding-card ${severity}" data-severity="${severity}" data-finding-id="${esc(vId)}">
                    <div class="f-title" style="display: flex; gap: 8px; align-items: center;">
                        <span class="f-name" style="flex: 1;">${esc(vuln.type)}</span>
                        <button class="f-copy-btn" data-action="copy-finding" data-finding-id="${esc(vId)}">Copy</button>
                        <button class="btn primary" style="background: var(--safe); font-size: 11px; padding: 4px 10px; border: none; cursor: pointer; border-radius: 4px;" data-action="export-poc" data-finding-id="${esc(vId)}">
                            <svg width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" style="vertical-align: middle; margin-right: 4px;">
                                <path d="M12 2v20M17 5H9.5a3.5 3.5 0 0 0 0 7h5a3.5 3.5 0 0 1 0 7H6"></path>
                            </svg>
                            Export PoC
                        </button>
                        <span class="sev-badge sev-${severity}">${esc(severity)}</span>
                    </div>
                    <div class="f-desc">${esc(vuln.description)}</div>
                    <div class="f-payload">${esc(vuln.payload)}</div>
                </div>
            `;
            findingsContainer.insertAdjacentHTML('afterbegin', html);
            return vId;
        },

        renderPlatformEvidence({ findingsContainer, globalVulns, evidenceList = [] }) {
            const ordered = [...(evidenceList || [])].sort((a, b) => {
                const severityDelta = severityScore(b.severity) - severityScore(a.severity);
                if (severityDelta !== 0) return severityDelta;
                return String(b.created_at || '').localeCompare(String(a.created_at || ''));
            });

            if (!ordered.length) {
                this.resetFindingsView({
                    findingsContainer,
                    globalVulns,
                    message: 'No project evidence yet. Run scans, replays, or AuthZ diffs to build the offensive record.'
                });
                return { count: 0, evidence: ordered };
            }

            this.clearFindingStore(globalVulns);
            findingsContainer.innerHTML = '';
            ordered.forEach(evidence => {
                this.addFinding({
                    findingsContainer,
                    globalVulns,
                    vuln: this.evidenceToFinding(evidence),
                    options: { findingId: `evidence-${evidence.id}` }
                });
            });
            return { count: ordered.length, evidence: ordered };
        },

        renderWorkspace({ evidenceList = [], notes = [], timeline = {} }) {
            const evidenceContainer = document.getElementById('evidence-records');
            const notesContainer = document.getElementById('evidence-notes-list');
            if (!evidenceContainer || !notesContainer) return;

            const replayRecipes = timeline.replay_recipes || [];
            const correlationChains = timeline.correlation_chains || [];
            const attackRuns = timeline.attack_runs || [];
            const findings = timeline.findings || [];

            evidenceContainer.innerHTML = `
                <div style="padding: 14px; border-bottom: 1px solid var(--border-color); background: rgba(255,255,255,0.02);">
                    <div style="display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 10px;">
                        <div><div style="font-size: 10px; text-transform: uppercase; color: var(--text-muted);">Evidence</div><div style="font-size: 20px; font-weight: 700; color: var(--accent);">${evidenceList.length}</div></div>
                        <div><div style="font-size: 10px; text-transform: uppercase; color: var(--text-muted);">Attack Runs</div><div style="font-size: 20px; font-weight: 700; color: var(--danger);">${attackRuns.length}</div></div>
                        <div><div style="font-size: 10px; text-transform: uppercase; color: var(--text-muted);">Replay Recipes</div><div style="font-size: 20px; font-weight: 700; color: var(--warning);">${replayRecipes.length}</div></div>
                        <div><div style="font-size: 10px; text-transform: uppercase; color: var(--text-muted);">Correlation Chains</div><div style="font-size: 20px; font-weight: 700; color: var(--safe);">${correlationChains.length}</div></div>
                    </div>
                    <div style="font-size: 11px; color: var(--text-secondary); margin-top: 10px;">
                        Findings: ${findings.length} • Evidence exports now carry replay recipes, correlation chains, and protocol-guided playbook hints.
                    </div>
                </div>
                <div style="padding: 10px 14px; font-size: 10px; text-transform: uppercase; letter-spacing: 1px; color: var(--text-muted);">Recorded Evidence</div>
                ${evidenceList.length ? evidenceList.map(renderEvidenceRecord).join('') : '<div class="empty-state" style="padding: 16px;">No evidence recorded yet. Scan, replay, or workflow results will appear here.</div>'}
                <div style="padding: 10px 14px; font-size: 10px; text-transform: uppercase; letter-spacing: 1px; color: var(--text-muted); border-top: 1px solid var(--border-color);">Replay Recipes</div>
                ${replayRecipes.length ? replayRecipes.slice(0, 12).map(renderReplayRecipe).join('') : '<div class="empty-state" style="padding: 16px;">No replay recipes captured yet.</div>'}
                <div style="padding: 10px 14px; font-size: 10px; text-transform: uppercase; letter-spacing: 1px; color: var(--text-muted); border-top: 1px solid var(--border-color);">Correlation Chains</div>
                ${correlationChains.length ? correlationChains.slice(0, 12).map(renderCorrelationChain).join('') : '<div class="empty-state" style="padding: 16px;">No correlation chains available yet.</div>'}
            `;

            if (!notes.length) {
                notesContainer.innerHTML = '<div class="empty-state">Saved notes for the current project will appear here.</div>';
                return;
            }

            notesContainer.innerHTML = notes.map((note) => `
                <div style="padding: 10px 0; border-bottom: 1px solid var(--border-color);">
                    <div style="font-weight: 600; color: var(--text-primary);">${esc(note.title || 'Untitled note')}</div>
                    <div style="font-size: 11px; color: var(--text-muted); margin-top: 4px;">${esc(note.updated_at || note.created_at || '')}</div>
                    <div style="font-size: 12px; color: var(--text-primary); margin-top: 6px; white-space: pre-wrap;">${esc(String(note.body || '').slice(0, 300) || 'No note body')}</div>
                </div>
            `).join('');
        },

        async exportPoC({ globalVulns, findingId, targetUrl, authPayload, invoke, appendLog }) {
            const vuln = globalVulns[findingId];
            if (!vuln) return;

            const url = targetUrl || 'wss://target.api.com/';
            const exploitCode = `#!/usr/bin/env python3
# WSHawk Automated Exploit PoC
# Target: ${url}
# Vulnerability: ${vuln.type}
# Severity: ${vuln.severity}

import asyncio
import websockets
import sys

TARGET = "${url}"
PAYLOAD = """${vuln.payload.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}"""
AUTH_PAYLOAD = """${authPayload.replace(/\\/g, '\\\\').replace(/"/g, '\\"')}""" if "${authPayload}" else None

async def exploit():
    print(f"[*] WSHawk Exploit Initialized")
    print(f"[*] Connecting to {TARGET}")
    try:
        async with websockets.connect(TARGET, ping_interval=None) as ws:
            print("[+] Connected successfully!")
            if AUTH_PAYLOAD:
                print("[*] Sending authentication sequence/skeleton key...")
                await ws.send(AUTH_PAYLOAD)
                await asyncio.sleep(0.5)
            print("[*] Sending malicious payload...")
            await ws.send(PAYLOAD)
            print("[*] Waiting for response...")
            while True:
                response = await asyncio.wait_for(ws.recv(), timeout=5.0)
                print("\\n[+] Exploit successful! Server responded:")
                print("-" * 40)
                print(response)
                print("-" * 40)
                break
    except asyncio.TimeoutError:
        print("[-] Exploit sent but no response received (could be a blind exploitation success or timeout).")
    except Exception as e:
        print(f"[-] Exploit failed or connection dropped: {e}")

if __name__ == "__main__":
    try:
        asyncio.run(exploit())
    except KeyboardInterrupt:
        print("\\n[!] Exploit aborted by user.")
        sys.exit(0)
`;

            const res = await invoke('dialog:exportExploit', exploitCode);
            if (res && res.success) {
                appendLog('success', `Exported Python PoC saved to ${res.path}`);
            } else if (res && !res.canceled) {
                appendLog('vuln', 'Failed to save exploit.');
            }
        },

        initWorkspace(ctx) {
            document.getElementById('evidence-export-json-btn')?.addEventListener('click', async () => {
                const projectId = ctx.getCurrentProject().projectId;
                if (!projectId) {
                    ctx.appendLog('vuln', 'Link a platform project before exporting evidence.');
                    return;
                }
                await this.exportProjectBundle({ projectId, format: 'json', appendLog: ctx.appendLog });
            });
            document.getElementById('evidence-export-markdown-btn')?.addEventListener('click', async () => {
                const projectId = ctx.getCurrentProject().projectId;
                if (!projectId) {
                    ctx.appendLog('vuln', 'Link a platform project before exporting evidence.');
                    return;
                }
                await this.exportProjectBundle({ projectId, format: 'markdown', appendLog: ctx.appendLog });
            });
            document.getElementById('evidence-export-html-btn')?.addEventListener('click', async () => {
                const projectId = ctx.getCurrentProject().projectId;
                if (!projectId) {
                    ctx.appendLog('vuln', 'Link a platform project before exporting evidence.');
                    return;
                }
                await this.exportProjectBundle({ projectId, format: 'html', appendLog: ctx.appendLog });
            });
            document.getElementById('evidence-open-notes-btn')?.addEventListener('click', () => {
                document.querySelector('.nav-item[data-target="notes"]')?.click();
            });
        },
    };
})(window);
