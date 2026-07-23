(function registerCoreViews() {
    'use strict';
    window.WSHawkViewRegistry.register('core', String.raw`
                <div id="view-dashboard" class="view slide-up active">
                    <div class="metrics-grid">
                        <div class="metric-card">
                            <div class="metric-title">Detected Threats</div>
                            <div class="metric-value" id="val-vulns">0</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-title">Frames Analyzed</div>
                            <div class="metric-value" id="val-msgs">0</div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-title">Posture</div>
                            <div class="metric-value text-safe" id="val-risk">SECURE</div>
                        </div>
                        <div class="metric-card progress-card">
                            <div class="metric-title">Scan Progress</div>
                            <div class="progress-bar-container">
                                <div class="progress-bar-fill" id="val-progress"></div>
                            </div>
                        </div>
                        <div class="metric-card">
                            <div class="metric-title">Severity Distribution</div>
                            <div class="severity-chart" id="severity-chart">
                                <div class="sev-bar-group">
                                    <div class="sev-bar sev-bar-high" id="sev-bar-high" style="height: 0%;"></div>
                                    <span class="sev-bar-label">HIGH</span>
                                    <span class="sev-bar-count" id="sev-count-high">0</span>
                                </div>
                                <div class="sev-bar-group">
                                    <div class="sev-bar sev-bar-medium" id="sev-bar-medium" style="height: 0%;"></div>
                                    <span class="sev-bar-label">MED</span>
                                    <span class="sev-bar-count" id="sev-count-medium">0</span>
                                </div>
                                <div class="sev-bar-group">
                                    <div class="sev-bar sev-bar-low" id="sev-bar-low" style="height: 0%;"></div>
                                    <span class="sev-bar-label">LOW</span>
                                    <span class="sev-bar-count" id="sev-count-low">0</span>
                                </div>
                            </div>
                        </div>
                    </div>

                    <div class="split-view">
                        <div class="panel">
                            <div class="panel-header glass-header flex-between">
                                <span class="title">Active Findings</span>
                                <div class="findings-toolbar">
                                    <input type="text" id="findings-search" placeholder="Search findings..."
                                        style="background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 11px; width: 140px; min-height: unset; height: 26px;">
                                    <div class="sev-filter-group">
                                        <button class="sev-filter-btn active" data-sev="all">All</button>
                                        <button class="sev-filter-btn" data-sev="HIGH">High</button>
                                        <button class="sev-filter-btn" data-sev="MEDIUM">Med</button>
                                        <button class="sev-filter-btn" data-sev="LOW">Low</button>
                                    </div>
                                </div>
                            </div>
                            <div class="panel-body custom-scroll" id="findings-container">
                                <div class="empty-state">No vulnerabilities detected on the target.</div>
                            </div>
                        </div>
                        <div class="panel">
                            <div class="panel-header glass-header">
                                <span class="title">Engine Telemetry</span>
                            </div>
                            <div class="panel-body console-body custom-scroll" id="system-log">
                                <div class="log-line text-muted">System initialization complete.</div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Scan History -->
                <div id="view-scanhistory" class="view slide-up">
                    <div class="split-pane horizontal">
                        <div class="pane flex-col panel" style="flex: 1;">
                            <div class="panel-header glass-header flex-between">
                                <span class="title">Saved Scans</span>
                                <button class="btn primary small" id="btn-refresh-history">Refresh</button>
                            </div>
                            <div class="panel-body no-padding custom-scroll" style="height: 250px;">
                                <table class="data-table" id="scanhistory-table">
                                    <thead>
                                        <tr>
                                            <th>Timestamp</th>
                                            <th>Target</th>
                                            <th>High</th>
                                            <th>Med</th>
                                            <th>Low</th>
                                            <th>Time (s)</th>
                                            <th>Compare</th>
                                        </tr>
                                    </thead>
                                    <tbody id="scanhistory-tbody">
                                        <!-- Populated via JS -->
                                    </tbody>
                                </table>
                            </div>
                        </div>
                        <div class="pane flex-col panel mt-4" style="flex: 2;">
                            <div class="panel-header glass-header flex-between">
                                <span class="title">Scan Details / PoC Generater</span>
                                <span class="badge" id="scanhistory-detail-title">Select a scan</span>
                            </div>
                            <div class="panel-body no-padding custom-scroll" style="background: rgba(0,0,0,0.2);">
                                <table class="data-table" id="scanhistory-vuln-table">
                                    <thead>
                                        <tr>
                                            <th>Severity</th>
                                            <th>Vuln Type</th>
                                            <th>Detail</th>
                                            <th>Value/Endpoint</th>
                                            <th>Action</th>
                                        </tr>
                                    </thead>
                                    <tbody id="scanhistory-vuln-tbody">
                                    </tbody>
                                </table>
                            </div>
                            <div class="panel-body mt-2 custom-scroll"
                                style="flex: 1; border-top: 1px solid var(--border-color); display: flex; flex-direction: column;">
                                <div class="nav-label" style="margin-bottom: 8px;">Proof of Concept (PoC)</div>
                                <textarea id="scanhistory-poc-box" class="code-area custom-scroll" style="flex: 1;"
                                    readonly placeholder="Select a vulnerability to generate its PoC logic."></textarea>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- History -->
                <div id="view-history" class="view slide-up">
                    <div class="panel full-height">
                        <div class="panel-header glass-header flex-between">
                            <div>
                                <span class="title">Traffic Chronicle</span>
                                <span class="subtitle" id="history-count" style="margin-left: 10px;">0 frames</span>
                            </div>
                            <input type="text" id="history-filter" class="code-area"
                                style="width: 200px; padding: 4px 8px; border-radius: 4px; min-height: unset; height: 30px;"
                                placeholder="Filter payloads...">
                        </div>
                        <div class="panel-body no-padding custom-scroll">
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th>ID</th>
                                        <th>DIR</th>
                                        <th>TIMING</th>
                                        <th>SIZE</th>
                                        <th>PAYLOAD</th>
                                        <th style="width: 60px;">ACTION</th>
                                    </tr>
                                </thead>
                                <tbody id="history-tbody">
                                    <tr class="empty-tr">
                                        <td colspan="6">Awaiting traffic capture...</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- WebSocket Request Forge -->
                <div id="view-reqforge" class="view slide-up">
                    <div class="reqforge-layout full-height">
                        <div class="split-view" style="flex: 1;">
                            <div class="panel">
                                <div class="panel-header glass-header flex-between">
                                    <span class="title">WebSocket Request Editor</span>
                                    <div style="display: flex; gap: 8px; align-items: center; flex-wrap: wrap; justify-content: flex-end;">
                                        <select id="reqforge-identity-select"
                                            style="background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 11px; min-height: unset; height: 30px; min-width: 190px;">
                                            <option value="">Anonymous Replay</option>
                                        </select>
                                        <select id="reqforge-compare-identity-select" title="Owner or privileged WebSocket control identity"
                                            style="background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 11px; min-height: unset; height: 30px; min-width: 190px;">
                                            <option value="">Comparison Identity</option>
                                        </select>
                                        <button id="reqforge-refresh-identities" class="btn secondary small">Refresh Identities</button>
                                        <button id="reqforge-store-dom-identity" class="btn secondary small">Store DOM Identity</button>
                                        <button id="reqforge-subscription-btn" class="btn secondary small">Subscription Abuse</button>
                                        <button id="reqforge-race-btn" class="btn secondary small">Race Attack</button>
                                        <button id="reqforge-authz-diff-btn" class="btn secondary small">AuthZ Diff</button>
										<button id="reqforge-authz-matrix-btn" class="btn secondary small">AuthZ Matrix</button>
                                        <button id="send-reqforge" class="btn secondary small">Fire Payload</button>
                                    </div>
                                </div>
                                <textarea id="reqforge-req" class="code-area custom-scroll"
                                    spellcheck="false">{"action": "ping", "data": "test"}</textarea>
                                <div style="padding: 10px 12px; border-top: 1px solid var(--border-color); display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 8px;">
                                    <select id="reqforge-authz-policy" title="Expected WebSocket authorization behavior"
                                        style="grid-column: span 2; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 11px; min-height: unset; height: 30px;">
                                        <option value="compare_only">AuthZ: compare behavior only</option>
                                        <option value="primary_denied_owner_allowed">AuthZ: primary denied; owner allowed</option>
                                        <option value="tenant_isolation">AuthZ: foreign tenant denied; member allowed</option>
                                        <option value="function_level_authorization">AuthZ: lower privilege denied; privileged allowed</option>
										<option value="admin_only_operation">AuthZ: non-admin denied; administrator allowed</option>
										<option value="ownership_transfer">AuthZ: unauthorized ownership transfer denied</option>
                                    </select>
                                    <select id="reqforge-authz-evidence-mode" title="WebSocket finding evidence retention"
                                        style="grid-column: span 2; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 11px; min-height: unset; height: 30px;">
                                        <option value="redacted">Evidence: redacted payloads</option>
                                        <option value="hash_only">Evidence: hashes only</option>
                                        <option value="full">Evidence: full payloads</option>
                                    </select>
                                    <input type="text" id="reqforge-field-paths" placeholder="Field paths: channel,tenant_id"
                                        style="background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 11px; min-height: unset; height: 30px;">
                                    <input type="text" id="reqforge-candidate-values" placeholder="Candidates: admin,*,root"
                                        style="background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 11px; min-height: unset; height: 30px;">
                                    <input type="number" id="reqforge-max-mutations" min="1" max="100" value="24"
                                        style="background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 11px; min-height: unset; height: 30px;"
                                        title="Max subscription mutations">
                                    <select id="reqforge-race-mode"
                                        style="background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 11px; min-height: unset; height: 30px;">
                                        <option value="duplicate_action">duplicate_action</option>
                                        <option value="replay_before_invalidation">replay_before_invalidation</option>
                                        <option value="stale_token_window">stale_token_window</option>
                                        <option value="parallel_socket_abuse">parallel_socket_abuse</option>
                                    </select>
                                    <input type="number" id="reqforge-race-concurrency" min="1" max="32" value="5"
                                        style="background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 11px; min-height: unset; height: 30px;"
                                        title="Race concurrency">
                                    <input type="number" id="reqforge-race-waves" min="1" max="16" value="2"
                                        style="background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 11px; min-height: unset; height: 30px;"
                                        title="Race waves">
                                    <input type="number" id="reqforge-race-stagger" min="0" max="5000" value="25"
                                        style="background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 11px; min-height: unset; height: 30px;"
                                        title="Stagger ms">
                                    <input type="number" id="reqforge-race-wave-delay" min="0" max="10000" value="0"
                                        style="background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 11px; min-height: unset; height: 30px;"
                                        title="Wave delay ms">
                                </div>
                                <div id="reqforge-platform-status"
                                    style="padding: 8px 12px; border-top: 1px solid var(--border-color); font-size: 11px; color: var(--text-muted);">
                                    WebSocket replay is ready. For HTTP requests, use HTTP Forge in Workspace Tools. Store identities from DOM auth and run the same payload across roles.
                                </div>
                            </div>
                            <div class="panel">
                                <div class="panel-header glass-header flex-between">
                                    <span class="title">Server Response</span>
                                    <button id="reqforge-copy-btn" class="btn secondary small"
                                        style="font-size: 11px;">Copy</button>
                                </div>
                                <textarea id="reqforge-res" class="code-area custom-scroll readonly" spellcheck="false"
                                    readonly>Awaiting execution...</textarea>
                            </div>
                        </div>
                        <div class="panel" style="flex: none; max-height: 180px;">
                            <div class="panel-header glass-header flex-between">
                                <span class="title">Regex Extractor</span>
                                <div style="display: flex; gap: 8px; align-items: center;">
                                    <input type="text" id="extractor-regex" placeholder="Pattern: token[=:]\s*(.+?)\b"
                                        style="background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 11px; font-family: var(--font-mono); width: 240px; min-height: unset; height: 26px;">
                                    <button id="extractor-run-btn" class="btn secondary small"
                                        style="font-size: 11px;">Extract</button>
                                </div>
                            </div>
                            <div class="panel-body custom-scroll" id="extractor-results"
                                style="font-size: 12px; font-family: var(--font-mono); padding: 10px;">
                                <div class="empty-state" style="padding: 10px;">Enter a regex pattern with capture
                                    groups
                                    and click Extract.</div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Attack Ops -->
                <div id="view-attacks" class="view slide-up">
                    <div class="split-view full-height">
                        <div class="panel" style="flex: 0 0 320px;">
                            <div class="panel-header glass-header flex-between">
                                <span class="title">Attack Runs</span>
                                <button id="attacks-refresh-btn" class="btn secondary small">Refresh</button>
                            </div>
                            <div class="panel-body custom-scroll" id="attacks-summary"
                                style="border-bottom: 1px solid var(--border-color); min-height: 120px;">
                                <div class="empty-state">No platform attack data yet.</div>
                            </div>
                            <div class="panel-body custom-scroll" id="attacks-run-list">
                                <div class="empty-state">Run replay, subscription abuse, race, or workflows to build the attack ledger.</div>
                            </div>
                        </div>
                        <div class="panel" style="flex: 1;">
                            <div class="panel-header glass-header flex-between">
                                <span class="title">Offensive Findings</span>
                                <div style="display: flex; gap: 8px;">
                                    <button id="attacks-open-reqforge-btn" class="btn secondary small">WS Forge</button>
                                    <button id="attacks-open-workflow-btn" class="btn secondary small">Workflow</button>
                                </div>
                            </div>
                            <div class="panel-body custom-scroll" id="attacks-findings-list">
                                <div class="empty-state">No offensive findings yet. Suspicious replay, authz drift, and race results will appear here.</div>
                            </div>
                        </div>
                    </div>
                </div>

				<!-- Findings Workspace -->
				<div id="view-findingsworkspace" class="view slide-up">
					<div class="panel full-height" style="display:flex;flex-direction:column;">
						<div class="panel-header glass-header flex-between" style="gap:8px;flex-wrap:wrap;">
							<span class="title">Findings Workspace</span>
							<div style="display:flex;gap:6px;align-items:center;flex-wrap:wrap;">
								<input id="findings-search" placeholder="Search title, endpoint, policy" style="width:220px;height:28px;">
								<select id="findings-status-filter"><option value="">All states</option><option>open</option><option>confirmed</option><option>rejected</option><option>fixed</option><option>inconclusive</option></select>
								<select id="findings-severity-filter"><option value="">All severities</option><option>CRITICAL</option><option>HIGH</option><option>MEDIUM</option><option>LOW</option><option>INFO</option></select>
								<select id="findings-export-format"><option value="json">JSON</option><option value="markdown">Markdown</option><option value="csv">CSV</option></select>
								<button id="findings-export-selected" class="btn secondary small">Export Selected</button>
								<button id="findings-refresh" class="btn secondary small">Refresh</button>
							</div>
						</div>
						<div id="findings-workspace-summary" style="padding:8px 12px;border-bottom:1px solid var(--border-color);font-size:11px;color:var(--text-muted);">No project findings loaded.</div>
						<div style="display:grid;grid-template-columns:minmax(560px,1.35fr) minmax(360px,1fr);min-height:0;flex:1;">
							<div class="custom-scroll" style="overflow:auto;border-right:1px solid var(--border-color);">
								<table style="width:100%;border-collapse:collapse;font-size:11px;"><thead><tr><th></th><th>Finding</th><th>Severity</th><th>Confidence</th><th>State</th><th>Last retest</th><th>Actions</th></tr></thead><tbody id="findings-workspace-body"></tbody></table>
							</div>
							<div class="custom-scroll" style="overflow:auto;padding:12px;">
								<div id="findings-evidence-preview" class="empty-state">Select a finding to preview sanitized evidence.</div>
							</div>
						</div>
					</div>
					<dialog id="finding-reveal-dialog" style="max-width:520px;background:var(--bg-panel);color:var(--text-primary);border:1px solid var(--border-color);border-radius:10px;padding:20px;">
						<h3 style="margin-top:0;">Reveal retained evidence?</h3><p style="font-size:12px;line-height:1.6;">Full response evidence can contain private application data. Reveal it only in an appropriate environment. Copy stays disabled until you explicitly reveal it.</p>
						<div style="display:flex;justify-content:flex-end;gap:8px;"><button id="finding-reveal-cancel" class="btn secondary small">Cancel</button><button id="finding-reveal-confirm" class="btn primary small">Reveal</button></div>
					</dialog>
				</div>

                <!-- AI Exploit Context Menu (for ReqForge right-click) -->
                <div id="ai-exploit-menu" class="ai-exploit-context-menu" style="display: none;">
                    <div class="ai-ctx-header">Generate AI Payloads</div>
                    <div class="ai-ctx-divider"></div>
                    <div class="ai-ctx-item" data-vuln="auto">
                        <span class="ai-ctx-icon">AI</span>
                        <span>Auto-Detect Vuln Type</span>
                    </div>
                    <div class="ai-ctx-divider"></div>
                    <div class="ai-ctx-item" data-vuln="sqli">
                        <span class="ai-ctx-icon">SQ</span>
                        <span>SQL Injection</span>
                    </div>
                    <div class="ai-ctx-item" data-vuln="xss">
                        <span class="ai-ctx-icon">XS</span>
                        <span>Cross-Site Scripting</span>
                    </div>
                    <div class="ai-ctx-item" data-vuln="idor">
                        <span class="ai-ctx-icon">ID</span>
                        <span>IDOR</span>
                    </div>
                    <div class="ai-ctx-item" data-vuln="cmdi">
                        <span class="ai-ctx-icon">CM</span>
                        <span>Command Injection</span>
                    </div>
                    <div class="ai-ctx-item" data-vuln="ssti">
                        <span class="ai-ctx-icon">ST</span>
                        <span>SSTI</span>
                    </div>
                    <div class="ai-ctx-item" data-vuln="nosql">
                        <span class="ai-ctx-icon">NQ</span>
                        <span>NoSQL Injection</span>
                    </div>
                    <div class="ai-ctx-item" data-vuln="lfi">
                        <span class="ai-ctx-icon">LF</span>
                        <span>Path Traversal / LFI</span>
                    </div>
                    <div class="ai-ctx-item" data-vuln="xxe">
                        <span class="ai-ctx-icon">XE</span>
                        <span>XXE</span>
                    </div>
                    <div class="ai-ctx-item" data-vuln="ssrf">
                        <span class="ai-ctx-icon">SR</span>
                        <span>SSRF</span>
                    </div>
                    <div class="ai-ctx-item" data-vuln="authn">
                        <span class="ai-ctx-icon">AU</span>
                        <span>Auth Bypass</span>
                    </div>
                </div>

                <!-- Intercept -->
                <div id="view-intercept" class="view slide-up">
                    <div class="split-view full-height">
                        <div class="panel" style="flex: 1;">
                            <div class="panel-header glass-header flex-between">
                                <span class="title" id="intercept-title">Interceptor: Idle</span>
                                <button id="toggle-intercept-btn" class="btn secondary small">Engage
                                    Interceptor</button>
                            </div>
                            <div class="panel-body no-padding custom-scroll"
                                style="height: 150px; flex: none; border-bottom: 1px solid var(--border-color);">
                                <table class="data-table">
                                    <thead>
                                        <tr>
                                            <th>DIR</th>
                                            <th>URL</th>
                                            <th>Preview</th>
                                        </tr>
                                    </thead>
                                    <tbody id="intercept-queue-tbody">
                                        <tr class="empty-tr">
                                            <td colspan="3">Interceptor is currently idle.</td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>
                            <div class="panel-header glass-header"
                                style="flex: none; border-top: 1px solid var(--border-color);">
                                <span class="title">Captured Handshakes (Extension)</span>
                            </div>
                            <div class="panel-body no-padding custom-scroll" style="height: 150px; flex: none;">
                                <table class="data-table">
                                    <thead>
                                        <tr>
                                            <th>Time</th>
                                            <th>URL</th>
                                            <th>Action</th>
                                        </tr>
                                    </thead>
                                    <tbody id="handshake-tbody">
                                        <tr class="empty-tr">
                                            <td colspan="3">Awaiting handshakes from WSHawk Extension...</td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>
                            <div class="panel-body flex-center" id="intercept-orb-container"
                                style="flex: 1; display: flex; flex-direction: column;">
                                <div class="intercept-visual" id="intercept-orb" style="animation: none;"></div>
                                <p class="text-muted">Awaiting connection through proxy
                                    through the private direct-IPC worker transport.</p>
                            </div>
                        </div>
                        <div class="panel" id="intercept-editor-panel"
                            style="flex: 1; opacity: 0.5; pointer-events: none;">
                            <div class="panel-header glass-header flex-between">
                                <span class="title">Frame Editor</span>
                                <div style="display: flex; gap: 8px;">
                                    <button id="btn-intercept-drop" class="btn secondary small"
                                        style="color: var(--danger);">Drop</button>
                                    <button id="btn-intercept-forward" class="btn primary small">Forward</button>
                                </div>
                            </div>
                            <textarea id="intercept-editor" class="code-area custom-scroll" spellcheck="false"
                                placeholder="Frame payload..."></textarea>
                        </div>
                    </div>
                </div>

                <!-- Payload Blaster -->
                <div id="view-blaster" class="view slide-up">
                    <div class="split-view full-height">
                        <div class="panel">
                            <div class="panel-header glass-header">
                                <span class="title">Payload Blaster Configuration</span>
                            </div>
                            <div class="panel-body custom-scroll">
                                <p class="text-muted mb-2" style="font-size: 13px;">1. Define base request template. Use
                                    <code style="color:var(--primary);">§</code> to mark injection points.
                                </p>
                                <textarea id="blaster-template" class="code-area custom-scroll"
                                    style="height: 120px; width: 100%; margin-bottom: 20px;" spellcheck="false"
                                    placeholder='{"action": "login", "username": "§inject§"}'></textarea>

                                <div class="flex-between mb-2">
                                    <p class="text-muted" style="font-size: 13px;">2. Define payload list (one per
                                        line).</p>
                                    <div style="display: flex; gap: 10px; align-items: center;">
                                        <span id="blaster-payload-count" class="text-muted"
                                            style="font-size: 12px; display: none;">0 payloads</span>
                                        <select id="blaster-payload-select" class="dropdown-select"
                                            style="background:var(--bg-panel); color:var(--text-primary); border:1px solid var(--border); border-radius:4px; padding:4px;">
                                            <option value="">-- Load The Arsenal --</option>
                                            <optgroup label="SQL Injection">
                                                <option value="sqli_all">All SQLi</option>
                                                <option value="sqli_time">SQLi - Time-Based</option>
                                                <option value="sqli_error">SQLi - Error-Based</option>
                                                <option value="sqli_boolean">SQLi - Boolean</option>
                                            </optgroup>
                                            <optgroup label="Cross-Site Scripting (XSS)">
                                                <option value="xss_all">All XSS</option>
                                                <option value="xss_ws">XSS - WS Context</option>
                                            </optgroup>
                                            <option value="cmd">Command Injection</option>
                                            <option value="lfi">Path Traversal</option>
                                            <option value="xxe">XML External Entity</option>
                                            <option value="ssti">Server-Side Template Inject</option>
                                            <option value="nosql">NoSQL Injection</option>
                                        </select>
                                    </div>
                                </div>
                                <div style="margin-bottom: 8px;">
                                    <label
                                        style="font-size: 12px; display: flex; align-items: center; gap: 6px; cursor: pointer;">
                                        <input type="checkbox" id="blaster-spe-checkbox" style="cursor: pointer;">
                                        Apply SPE mutation on these payloads (Smart Payload Evolution)
                                    </label>
                                </div>
                                <textarea id="blaster-payloads" class="code-area custom-scroll"
                                    style="height: 120px; width: 100%;" spellcheck="false"
                                    placeholder="alert(1);&#10;1' OR '1'='1&#10;../../../../etc/passwd"></textarea>
                                <div style="display: flex; gap: 8px; margin-top: 12px; width: 100%;">
                                    <button id="blaster-stop-btn" class="btn primary w-full"
                                        style="background: var(--danger); border-color: var(--danger); display: none;">STOP
                                        BLASTING</button>
                                    <button id="blaster-start-btn" class="btn primary w-full">COMMENCE FUZZING</button>
                                </div>

                                <!-- DOM Invader Controls -->
                                <div
                                    style="margin-top: 16px; padding: 12px; background: var(--bg-secondary); border-radius: 8px; border: 1px solid var(--border-color);">
                                    <div
                                        style="display: flex; align-items: center; justify-content: space-between; margin-bottom: 10px;">
                                        <span
                                            style="font-size: 11px; font-weight: 700; color: var(--primary); text-transform: uppercase; letter-spacing: 1px;">DOM
                                            Invader</span>
                                        <span id="dom-invader-status"
                                            class="dom-status-pill dom-status-unknown">Checking...</span>
                                    </div>
                                    <label
                                        style="font-size: 12px; display: flex; align-items: center; gap: 8px; cursor: pointer; margin-bottom: 10px;">
                                        <input type="checkbox" id="blaster-dom-verify" style="cursor: pointer;">
                                        Verify XSS execution in headless Chromium (eliminates false positives)
                                    </label>
                                    <div style="display: flex; gap: 8px;">
                                        <button id="dom-record-auth-btn" class="btn secondary small"
                                            style="flex: 1; font-size: 11px;">Record Auth Flow</button>
                                        <button id="dom-replay-auth-btn" class="btn secondary small"
                                            style="flex: 1; font-size: 11px; display: none;">Auth Flow Saved</button>
                                    </div>
                                    <div id="dom-auth-status"
                                        style="font-size: 11px; color: var(--text-muted); margin-top: 6px; display: none;">
                                    </div>
                                </div>
                            </div>
                        </div>
                        <div class="panel">
                            <div class="panel-header glass-header"
                                style="display:flex; justify-content:space-between; align-items:center;">
                                <span class="title">Blast Results</span>
                                <button id="blaster-clear-btn"
                                    style="background:none; border:none; color:var(--text-muted); cursor:pointer; font-size:12px;">Clear
                                    Results</button>
                            </div>
                            <div class="panel-body no-padding custom-scroll">
                                <table class="data-table">
                                    <thead>
                                        <tr>
                                            <th>Payload</th>
                                            <th>Status</th>
                                            <th>Length</th>
                                            <th>DOM Verified</th>
                                            <th>Diff</th>
                                            <th>Response Snippet</th>
                                        </tr>
                                    </thead>
                                    <tbody id="blaster-tbody">
                                        <tr class="empty-tr">
                                            <td colspan="6">Awaiting execution...</td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Codec -->
                <div id="view-codec" class="view slide-up">
                    <div class="codec-layout">
                        <div class="panel" style="flex: 1;">
                            <div class="panel-header glass-header flex-between">
                                <span class="title">Protocol Codec</span>
                                <div style="display: flex; gap: 8px;">
                                    <button id="codec-binary-analyze-btn" class="btn secondary small">Analyze Binary (Base64)</button>
                                    <button id="codec-smart-btn" class="btn secondary small">Smart Decode</button>
                                    <button id="codec-clear-btn" class="btn secondary small"
                                        style="color: var(--text-muted);">Clear</button>
                                </div>
                            </div>
                            <div class="panel-body custom-scroll" style="padding: 16px;">
                                <div class="codec-input-section">
                                    <label class="codec-label">Input</label>
                                    <textarea id="codec-input" class="code-area custom-scroll" spellcheck="false"
                                        style="height: 120px; width: 100%; border: 1px solid var(--border-color); border-radius: 6px;"
                                        placeholder="Paste data to encode/decode..."></textarea>
                                </div>

                                <div class="codec-controls">
                                    <div class="codec-row">
                                        <span class="codec-label">Transform:</span>
                                        <div class="codec-btn-grid">
                                            <button class="codec-op-btn" data-op="base64-encode">Base64
                                                Encode</button>
                                            <button class="codec-op-btn" data-op="base64-decode">Base64
                                                Decode</button>
                                            <button class="codec-op-btn" data-op="url-encode">URL Encode</button>
                                            <button class="codec-op-btn" data-op="url-decode">URL Decode</button>
                                            <button class="codec-op-btn" data-op="html-encode">HTML Encode</button>
                                            <button class="codec-op-btn" data-op="html-decode">HTML Decode</button>
                                            <button class="codec-op-btn" data-op="hex-encode">Hex Encode</button>
                                            <button class="codec-op-btn" data-op="hex-decode">Hex Decode</button>
                                            <button class="codec-op-btn" data-op="unicode-encode">Unicode
                                                Escape</button>
                                            <button class="codec-op-btn" data-op="unicode-decode">Unicode
                                                Unescape</button>
                                            <button class="codec-op-btn" data-op="gzip-decompress">Gzip
                                                Decompress</button>
                                        </div>
                                    </div>
                                    <div class="codec-row">
                                        <span class="codec-label">Hash:</span>
                                        <div class="codec-btn-grid">
                                            <button class="codec-op-btn hash-btn" data-op="md5">MD5</button>
                                            <button class="codec-op-btn hash-btn" data-op="sha1">SHA-1</button>
                                            <button class="codec-op-btn hash-btn" data-op="sha256">SHA-256</button>
                                            <button class="codec-op-btn hash-btn" data-op="sha512">SHA-512</button>
                                        </div>
                                    </div>
                                </div>

                                <div class="codec-output-section">
                                    <div class="flex-between" style="margin-bottom: 8px;">
                                        <label class="codec-label">Output</label>
                                        <div style="display: flex; gap: 8px; align-items: center;">
                                            <span class="codec-chain-badge" id="codec-chain-label"></span>
                                            <button id="codec-copy-btn" class="btn secondary small"
                                                style="font-size: 11px;">Copy</button>
                                            <button id="codec-swap-btn" class="btn secondary small"
                                                style="font-size: 11px;">↑ Use as Input</button>
                                        </div>
                                    </div>
                                    <textarea id="codec-output" class="code-area custom-scroll readonly"
                                        spellcheck="false"
                                        style="height: 120px; width: 100%; border: 1px solid var(--border-color); border-radius: 6px;"
                                        readonly placeholder="Result will appear here..."></textarea>
                                </div>

                                <div class="codec-chain-section" id="codec-chain-container">
                                    <label class="codec-label">Decode Chain (Auto-detected layers)</label>
                                    <div id="codec-chain-list" class="codec-chain-list"></div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Comparer -->
                <div id="view-comparer" class="view slide-up">
                    <div class="comparer-layout">
                        <div class="panel" style="flex: 1;">
                            <div class="panel-header glass-header flex-between">
                                <span class="title">Sample A</span>
                                <button id="comparer-paste-a" class="btn secondary small">Paste from Clipboard</button>
                            </div>
                            <textarea id="comparer-input-a" class="code-area custom-scroll" spellcheck="false"
                                placeholder="Paste first response here..."></textarea>
                        </div>
                        <div class="comparer-controls-center">
                            <button id="comparer-run-btn" class="btn primary small">Compare ⇄</button>
                            <button id="comparer-clear-btn" class="btn secondary small"
                                style="color: var(--text-muted); margin-top: 8px;">Clear</button>
                            <div class="comparer-stats" id="comparer-stats"></div>
                        </div>
                        <div class="panel" style="flex: 1;">
                            <div class="panel-header glass-header flex-between">
                                <span class="title">Sample B</span>
                                <button id="comparer-paste-b" class="btn secondary small">Paste from Clipboard</button>
                            </div>
                            <textarea id="comparer-input-b" class="code-area custom-scroll" spellcheck="false"
                                placeholder="Paste second response here..."></textarea>
                        </div>
                    </div>
                    <div class="panel" style="margin-top: 16px; flex: none; max-height: 280px;">
                        <div class="panel-header glass-header flex-between">
                            <span class="title">Diff Output</span>
                            <span class="subtitle" id="comparer-diff-count"></span>
                        </div>
                        <div class="panel-body custom-scroll" id="comparer-diff-output"
                            style="font-family: var(--font-mono); font-size: 12px; padding: 12px; overflow-y: auto;">
                            <div class="empty-state">Run a comparison to see differences.</div>
                        </div>
                    </div>
                </div>

                <!-- Notes -->
                <div id="view-notes" class="view slide-up">
                    <div class="split-view full-height">
                        <div class="panel" style="flex: 0 0 220px;">
                            <div class="panel-header glass-header flex-between">
                                <span class="title">Engagement Notes</span>
                                <button id="notes-add-btn" class="btn secondary small">+ New</button>
                            </div>
                            <div class="panel-body no-padding custom-scroll" id="notes-list-container">
                                <div class="empty-state" style="padding: 20px;">No notes yet. Click + New.</div>
                            </div>
                        </div>
                        <div class="panel" style="flex: 1;">
                            <div class="panel-header glass-header flex-between">
                                <span class="title" id="notes-editor-title">Select a note</span>
                                <div style="display: flex; gap: 8px;">
                                    <button id="notes-link-btn" class="btn secondary small"
                                        title="Link to current findings">Link Findings</button>
                                    <button id="notes-delete-btn" class="btn secondary small"
                                        style="color: var(--danger);">Delete</button>
                                </div>
                            </div>
                            <textarea id="notes-editor" class="code-area custom-scroll" spellcheck="true"
                                placeholder="Write your engagement notes here...&#10;&#10;Supports plain text. Findings can be auto-linked with the Link Findings button."
                                style="flex: 1;"></textarea>
                        </div>
                    </div>
                </div>

                <!-- Evidence Vault -->
                <div id="view-evidence" class="view slide-up">
                    <div class="split-view full-height">
                        <div class="panel" style="flex: 1;">
                            <div class="panel-header glass-header flex-between">
                                <span class="title">Evidence Vault</span>
                                <div style="display: flex; gap: 8px;">
                                    <button id="evidence-export-json-btn" class="btn secondary small">Export JSON</button>
                                    <button id="evidence-export-markdown-btn" class="btn secondary small">Export Markdown</button>
                                    <button id="evidence-export-html-btn" class="btn primary small">Export HTML</button>
                                </div>
                            </div>
                            <div class="panel-body custom-scroll" id="evidence-records">
                                <div class="empty-state">No evidence recorded yet. Scan, replay, or workflow results will appear here.</div>
                            </div>
                        </div>
                        <div class="panel" style="flex: 0 0 320px;">
                            <div class="panel-header glass-header flex-between">
                                <span class="title">Operator Notes</span>
                                <button id="evidence-open-notes-btn" class="btn secondary small">Open Notes</button>
                            </div>
                            <div class="panel-body custom-scroll" id="evidence-notes-list">
                                <div class="empty-state">Saved notes for the current project will appear here.</div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Endpoint Map -->
                <div id="view-wsmap" class="view slide-up">
                    <div class="split-view full-height">
                        <div class="panel" style="flex: 0 0 280px;">
                            <div class="panel-header glass-header flex-between">
                                <span class="title">Discovered Endpoints</span>
                                <div style="display: flex; gap: 8px;">
                                    <button id="wsmap-live-btn" class="btn secondary small">Live Map</button>
                                    <button id="wsmap-scan-btn" class="btn primary small">Discover</button>
                                </div>
                            </div>
                            <div class="panel-body custom-scroll" id="wsmap-tree-container">
                                <div class="empty-state">Enter a target HTTP URL above and click Discover to find
                                    WebSocket endpoints.</div>
                            </div>
                        </div>
                        <div class="panel" style="flex: 1;">
                            <div class="panel-header glass-header flex-between">
                                <span class="title" id="wsmap-detail-title">Endpoint Details</span>
                                <div style="display: flex; gap: 8px;">
                                    <button id="wsmap-test-btn" class="btn secondary small" disabled>Probe
                                        Endpoint</button>
                                    <button id="wsmap-attack-btn" class="btn primary small" disabled>Scan This
                                        Target</button>
                                </div>
                            </div>
                            <div class="panel-body custom-scroll" id="wsmap-detail-body">
                                <div class="empty-state">Select an endpoint from the tree to view details.</div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Auth Builder -->
                <div id="view-authbuilder" class="view slide-up">
                    <div class="split-view full-height">
                        <div class="panel" style="flex: 1;">
                            <div class="panel-header glass-header flex-between">
                                <span class="title">Authentication Sequence</span>
                                <div style="display: flex; gap: 8px;">
                                    <button id="auth-add-step" class="btn secondary small">+ Add Step</button>
                                    <button id="auth-clear-all" class="btn secondary small"
                                        style="color: var(--text-muted);">Clear All</button>
                                </div>
                            </div>
                            <div class="panel-body custom-scroll" id="auth-steps-container">
                                <div class="empty-state">Define multi-step authentication sequences.<br>Click + Add Step
                                    to begin.</div>
                            </div>
                            <div
                                style="padding: 12px; border-top: 1px solid var(--border-color); display: flex; gap: 8px;">
                                <button id="auth-test-btn" class="btn primary w-full">Test Full Sequence</button>
                                <button id="auth-save-btn" class="btn secondary w-full">Save as Preset</button>
                            </div>
                        </div>
                        <div class="panel" style="flex: 0 0 320px;">
                            <div class="panel-header glass-header flex-between">
                                <span class="title">Extraction Rules</span>
                                <button id="auth-add-rule" class="btn secondary small">+ Add Rule</button>
                            </div>
                            <div class="panel-body custom-scroll" id="auth-rules-container">
                                <div class="empty-state">Define token extraction rules.<br>Use regex or JSONPath to
                                    capture session tokens from responses.</div>
                            </div>
                            <div class="panel-header glass-header"
                                style="border-top: 1px solid var(--border-color); border-bottom: none;">
                                <span class="title">Test Output</span>
                            </div>
                            <textarea id="auth-test-output" class="code-area custom-scroll readonly"
                                style="height: 140px;" readonly
                                placeholder="Run the test sequence to see results here..."></textarea>
                        </div>
                    </div>
                </div>

                <!-- Scheduler -->
                <div id="view-scheduler" class="view slide-up">
                    <div class="split-view full-height">
                        <div class="panel" style="flex: 1;">
                            <div class="panel-header glass-header flex-between">
                                <span class="title">Scheduled Scans</span>
                                <button id="sched-add-btn" class="btn primary small">+ New Schedule</button>
                            </div>
                            <div class="panel-body no-padding custom-scroll">
                                <table class="data-table">
                                    <thead>
                                        <tr>
                                            <th>Target</th>
                                            <th>Interval</th>
                                            <th>Last Run</th>
                                            <th>Findings</th>
                                            <th>Status</th>
                                            <th>Actions</th>
                                        </tr>
                                    </thead>
                                    <tbody id="sched-tbody">
                                        <tr class="empty-tr">
                                            <td colspan="6">No scheduled scans configured.</td>
                                        </tr>
                                    </tbody>
                                </table>
                            </div>
                        </div>
                        <div class="panel" style="flex: 0 0 320px;">
                            <div class="panel-header glass-header">
                                <span class="title">Delta Report</span>
                            </div>
                            <div class="panel-body custom-scroll" id="sched-delta-container">
                                <div class="empty-state">Select a scheduled scan to view the delta report showing
                                    changes since the last run.</div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- OAST Callbacks -->
                <div id="view-oast" class="view slide-up">
                    <div class="split-view full-height">
                        <div class="panel" style="flex: 1;">
                            <div class="panel-header glass-header flex-between">
                                <span class="title">Out-of-Band Callbacks</span>
                                <div style="display: flex; gap: 8px;">
                                    <button id="oast-poll-btn" class="btn secondary small">Poll</button>
                                    <button id="oast-clear-btn" class="btn secondary small"
                                        style="color: var(--text-muted);">Clear</button>
                                </div>
                            </div>
                            <div class="panel-body custom-scroll" id="oast-list" style="padding: 0;">
                                <div class="empty-state">No callbacks received yet. Run a scan with OAST payloads to
                                    detect
                                    blind vulnerabilities.</div>
                            </div>
                        </div>
                        <div class="panel" style="flex: 1;">
                            <div class="panel-header glass-header">
                                <span class="title">Callback Detail</span>
                            </div>
                            <div class="panel-body custom-scroll" id="oast-detail" style="padding: 16px;">
                                <div class="empty-state">Select a callback to view details.</div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Mutation Lab -->
                <div id="view-mutationlab" class="view slide-up">
                    <div class="panel full-height">
                        <div class="panel-header glass-header flex-between">
                            <span class="title">Payload Mutation Lab (SPE)</span>
                            <div style="display: flex; gap: 8px; align-items: center;">
                                <select id="mutation-strategy"
                                    style="background: var(--bg-panel); color: var(--text-primary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; font-size: 12px;">
                                    <option value="all">All Strategies</option>
                                    <option value="case">Case Mutation</option>
                                    <option value="encode">Encoding</option>
                                    <option value="fragment">Fragmentation</option>
                                    <option value="comment">Comment Injection</option>
                                    <option value="unicode">Unicode Substitution</option>
                                    <option value="double">Double Encoding</option>
                                </select>
                                <input type="number" id="mutation-count" value="10" min="1" max="50"
                                    style="background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 12px; width: 60px; min-height: unset; height: 28px;"
                                    title="Number of mutations">
                                <button id="mutation-run-btn" class="btn primary small">Mutate</button>
                            </div>
                        </div>
                        <div class="panel-body custom-scroll" style="padding: 16px;">
                            <div style="margin-bottom: 16px;">
                                <label class="text-muted"
                                    style="font-size: 11px; display: block; margin-bottom: 4px;">Base
                                    Payload</label>
                                <textarea id="mutation-input" class="code-area"
                                    style="height: 60px; width: 100%; resize: none;" spellcheck="false"
                                    placeholder="&lt;script&gt;alert(1)&lt;/script&gt;"></textarea>
                            </div>
                            <div id="mutation-results">
                                <div class="empty-state">Enter a base payload and click Mutate to see SPE variations.
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- ═══════════════ WEB PENTEST VIEWS ═══════════════ -->

                <!-- Web Operations Board -->
    `);
})();
