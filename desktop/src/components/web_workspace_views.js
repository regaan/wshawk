(function registerWebWorkspaceViews() {
    'use strict';
    window.WSHawkViewRegistry.register('web-workspace', String.raw`
                <div id="view-webworkspace" class="view slide-up">
                    <div class="panel full-height">
                        <div class="panel-header glass-header flex-between">
                            <span class="title">Web Operations Board</span>
                            <div id="web-workspace-active-chip" class="badge standard">DISCOVERY WORKSPACE</div>
                        </div>
                        <div class="panel-body custom-scroll" style="padding: 16px;">
                            <div id="web-workspace-hero"
                                style="display: flex; justify-content: space-between; gap: 16px; align-items: flex-start; padding: 16px; border-radius: var(--radius-lg); border: 1px solid var(--border-color); background: linear-gradient(135deg, rgba(6,182,212,0.14), rgba(15,23,42,0.95)); margin-bottom: 14px;">
                                <div>
                                    <div id="web-workspace-title"
                                        style="font-size: 20px; font-weight: 700; color: var(--text-primary); margin-bottom: 6px;">
                                        Discovery Workspace
                                    </div>
                                    <div id="web-workspace-subtitle"
                                        style="font-size: 12px; color: var(--text-secondary); max-width: 720px; line-height: 1.6;">
                                        Map authenticated surface area, bootstrap sessions, and turn captured HTTP traffic into reusable project intelligence.
                                    </div>
                                </div>
                                <div id="web-workspace-project"
                                    style="font-size: 11px; color: var(--text-muted); text-align: right; min-width: 180px;">
                                    No platform project linked yet.
                                </div>
                            </div>

                            <div id="web-workspace-summary"
                                style="display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin-bottom: 14px;">
                            </div>

                            <div class="split-view" style="height: auto; gap: 12px; align-items: stretch;">
                                <div class="panel" style="flex: 1.1;">
                                    <div class="panel-header glass-header flex-between">
                                        <span class="title">Quick Launch</span>
                                        <span id="web-workspace-quick-hint"
                                            style="font-size: 10px; color: var(--text-muted);">Platform-backed actions</span>
                                    </div>
                                    <div class="panel-body custom-scroll" id="web-workspace-quickactions"
                                        style="padding: 14px; min-height: 260px;"></div>
                                </div>
                                <div class="panel" style="flex: 0.9;">
                                    <div class="panel-header glass-header flex-between">
                                        <span id="web-workspace-feed-title" class="title">Recent Activity</span>
                                        <span id="web-workspace-feed-meta"
                                            style="font-size: 10px; color: var(--text-muted);">Waiting for project telemetry</span>
                                    </div>
                                    <div class="panel-body custom-scroll" id="web-workspace-recent"
                                        style="padding: 14px; min-height: 260px;"></div>
                                </div>
                            </div>

                            <div class="panel" style="margin-top: 12px;">
                                <div class="panel-header glass-header flex-between">
                                    <span class="title">Workspace Guidance</span>
                                    <span style="font-size: 10px; color: var(--text-muted);">Cross-protocol aware</span>
                                </div>
                                <div class="panel-body" id="web-workspace-guidance" style="padding: 14px;"></div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- HTTP Forge -->
                <div id="view-httpforge" class="view slide-up">
                    <div class="split-view" style="height: 100%;">
                        <div class="panel" style="flex: 1;">
                            <div class="panel-header glass-header flex-between">
                                <span class="title">HTTP Request</span>
                                <div style="display: flex; gap: 6px; align-items: center;">
                                    <select id="http-method"
                                        style="background: var(--bg-panel); color: var(--accent); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; font-size: 12px; font-weight: 700;">
                                        <option>GET</option>
                                        <option>POST</option>
                                        <option>PUT</option>
                                        <option>DELETE</option>
                                        <option>PATCH</option>
                                        <option>HEAD</option>
                                        <option>OPTIONS</option>
                                    </select>
                                    <input type="text" id="http-url" placeholder="https://target.com/api/endpoint"
                                        style="flex: 1; min-width: 220px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 12px; min-height: unset; height: 28px;">
                                    <button id="http-send-btn" class="btn primary small">Send</button>
                                    <button id="http-template-btn" class="btn secondary small">Template</button>
                                    <button id="http-replay-btn" class="btn secondary small">Replay</button>
                                    <button id="http-authz-diff-btn" class="btn secondary small">AuthZ Diff</button>
                                    <button id="http-race-btn" class="btn secondary small">Race</button>
                                </div>
                            </div>
                            <div class="panel-body custom-scroll" style="padding: 0;">
                                <div style="padding: 8px 12px; border-bottom: 1px solid var(--border-color);">
                                    <label class="text-muted"
                                        style="font-size: 10px; display: block; margin-bottom: 4px;">Headers (one per
                                        line: Header: Value)</label>
                                    <textarea id="http-headers" class="code-area"
                                        style="height: 80px; width: 100%; resize: none;" spellcheck="false"
                                        placeholder="Content-Type: application/json&#10;Authorization: Bearer eyJ..."></textarea>
                                </div>
                                <div style="padding: 8px 12px;">
                                    <label class="text-muted"
                                        style="font-size: 10px; display: block; margin-bottom: 4px;">Body</label>
                                    <textarea id="http-body" class="code-area"
                                        style="height: 120px; width: 100%; resize: none;" spellcheck="false"
                                        placeholder='{"username": "admin", "password": "test"}'></textarea>
                                </div>
                                <div style="padding: 8px 12px; border-top: 1px solid var(--border-color); display: grid; grid-template-columns: repeat(3, minmax(0, 1fr)); gap: 8px;">
                                    <div style="grid-column: 1 / -1; display: flex; gap: 8px; align-items: center; flex-wrap: wrap;">
                                        <select id="http-identity-select"
                                            style="flex: 1 1 320px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 11px; min-height: unset; height: 30px;">
                                            <option value="">Current Headers / Anonymous</option>
                                        </select>
                                        <button id="http-refresh-identities-btn" class="btn secondary small" style="white-space: nowrap; flex: 0 0 auto;">Refresh Identities</button>
                                    </div>
                                    <input type="text" id="http-template-name" placeholder="Template name (optional)"
                                        style="background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 11px; min-height: unset; height: 30px;">
                                    <input type="text" id="http-template-vars" placeholder='Replay vars JSON: {"csrf":"token"}'
                                        style="background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 11px; min-height: unset; height: 30px; font-family: var(--font-mono);">
                                    <select id="http-race-mode"
                                        style="background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 11px; min-height: unset; height: 30px;">
                                        <option value="duplicate_action">duplicate_action</option>
                                        <option value="replay_before_invalidation">replay_before_invalidation</option>
                                        <option value="stale_token_window">stale_token_window</option>
                                        <option value="business_logic">business_logic</option>
                                    </select>
                                    <input type="number" id="http-race-concurrency" min="1" max="64" value="5"
                                        style="background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 11px; min-height: unset; height: 30px;"
                                        title="Race concurrency">
                                    <input type="number" id="http-race-waves" min="1" max="16" value="2"
                                        style="background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 11px; min-height: unset; height: 30px;"
                                        title="Race waves">
                                    <input type="number" id="http-race-stagger" min="0" max="5000" value="25"
                                        style="background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 11px; min-height: unset; height: 30px;"
                                        title="Stagger ms">
                                </div>
                                <div id="http-attack-status"
                                    style="padding: 8px 12px; border-top: 1px solid var(--border-color); font-size: 11px; color: var(--text-muted);">
                                    HTTP Forge is project-aware. Build a replay template, diff it across identities, or run concurrent race attempts.
                                </div>
                            </div>
                        </div>
                        <div class="panel" style="flex: 1;">
                            <div class="panel-header glass-header flex-between">
                                <span class="title">HTTP Response</span>
                                <div style="display: flex; gap: 6px; align-items: center;">
                                    <span id="http-status-badge" class="text-muted" style="font-size: 11px;">—</span>
                                    <span id="http-time-badge" class="text-muted" style="font-size: 11px;">—</span>
                                    <button id="http-copy-res-btn" class="btn secondary small"
                                        style="font-size: 10px;">Copy</button>
                                </div>
                            </div>
                            <div class="panel-body custom-scroll" style="padding: 0;">
                                <div style="padding: 8px 12px; border-bottom: 1px solid var(--border-color);">
                                    <label class="text-muted" style="font-size: 10px;">Response Headers</label>
                                    <pre id="http-res-headers"
                                        style="font-size: 11px; color: var(--text-secondary); white-space: pre-wrap; margin: 4px 0; max-height: 100px; overflow-y: auto;">—</pre>
                                </div>
                                <div style="padding: 8px 12px;">
                                    <label class="text-muted" style="font-size: 10px;">Response Body</label>
                                    <textarea id="http-res-body" class="code-area"
                                        style="height: 200px; width: 100%; resize: none;" readonly spellcheck="false"
                                        placeholder="Awaiting request..."></textarea>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- HTTP Fuzzer -->
                <div id="view-httpfuzzer" class="view slide-up">
                    <div class="panel full-height">
                        <div class="panel-header glass-header flex-between">
                            <span class="title">HTTP Parameter Fuzzer</span>
                            <div style="display: flex; gap: 6px; align-items: center;">
                                <select id="fuzz-method"
                                    style="background: var(--bg-panel); color: var(--text-primary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; font-size: 12px;">
                                    <option>GET</option>
                                    <option>POST</option>
                                    <option>PUT</option>
                                </select>
                                <input type="text" id="fuzz-url" placeholder="https://target.com/api?param=§FUZZ§"
                                    style="min-width: 280px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 12px; min-height: unset; height: 28px;">
                                <select id="fuzz-wordlist"
                                    style="background: var(--bg-panel); color: var(--text-primary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; font-size: 12px;">
                                    <option value="common">Common Params</option>
                                    <option value="sqli">SQLi Payloads</option>
                                    <option value="xss">XSS Payloads</option>
                                    <option value="dirs">Directories</option>
                                </select>
                                <input type="text" id="fuzz-custom-file"
                                    placeholder="Custom wordlist path e.g. /usr/share/wordlists/dirb/common.txt"
                                    style="width: 250px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 11px; min-height: unset; height: 28px;">
                                <select id="fuzz-encoder"
                                    style="background: var(--bg-secondary); border: 1px solid var(--border-color); color: var(--text-primary); padding: 4px 8px; border-radius: var(--radius); font-size: 11px; height: 28px;">
                                    <option value="none">No Encoding</option>
                                    <option value="url">URL Encode</option>
                                    <option value="base64">Base64 Encode</option>
                                    <option value="hex">Hex Encode</option>
                                </select>
                                <input type="text" id="fuzz-grep" placeholder="Regex Grep (e.g. SQL syntax.*error)"
                                    style="width: 150px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 11px; min-height: unset; height: 28px;">
                                <button id="fuzz-start-btn" class="btn primary small">Start Fuzz</button>
                                <button id="fuzz-stop-btn" class="btn secondary small"
                                    style="display: none;">Stop</button>
                            </div>
                        </div>
                        <div class="panel-body custom-scroll" style="padding: 0;">
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th>#</th>
                                        <th>Payload</th>
                                        <th>Status</th>
                                        <th>Length</th>
                                        <th>Time</th>
                                        <th>Notes</th>
                                    </tr>
                                </thead>
                                <tbody id="fuzz-results-tbody">
                                    <tr class="empty-tr">
                                        <td colspan="6">Configure target URL with §FUZZ§ markers and click Start.</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- Dir Scanner -->
                <div id="view-dirscanner" class="view slide-up">
                    <div class="panel full-height">
                        <div class="panel-header glass-header flex-between">
                            <span class="title">Directory & File Scanner</span>
                            <div style="display: flex; gap: 6px; align-items: center;">
                                <input type="text" id="dir-target" placeholder="https://target.com"
                                    style="min-width: 220px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 12px; min-height: unset; height: 28px;">
                                <input type="text" id="dir-extensions" placeholder="php,html,js,txt"
                                    value="php,html,js,txt,bak"
                                    style="width: 100px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 12px; min-height: unset; height: 28px;"
                                    title="Extensions to check">
                                <input type="text" id="dir-custom-file" placeholder="Custom wordlist path (optional)"
                                    style="width: 150px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 11px; min-height: unset; height: 28px;">
                                <input type="number" id="dir-throttle" placeholder="WAF Throttle MS" value="0"
                                    style="width: 100px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 11px; min-height: unset; height: 28px;">
                                <label
                                    style="display: flex; align-items: center; gap: 4px; font-size: 11px; color: var(--text-muted); cursor: pointer;">
                                    <input type="checkbox" id="dir-recursive" style="margin: 0;">
                                    Recursive
                                </label>
                                <button id="dir-start-btn" class="btn primary small">Scan</button>
                                <button id="dir-stop-btn" class="btn secondary small"
                                    style="display: none;">Stop</button>
                            </div>
                        </div>
                        <div class="panel-body custom-scroll" style="padding: 0;">
                            <div id="dir-progress"
                                style="padding: 10px 14px; border-bottom: 1px solid var(--border-color); font-size: 11px; color: var(--text-muted);">
                                Ready. Enter target URL and click Scan.
                            </div>
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th>Status</th>
                                        <th>Path</th>
                                        <th>Size</th>
                                        <th>Content-Type</th>
                                    </tr>
                                </thead>
                                <tbody id="dir-results-tbody">
                                    <tr class="empty-tr">
                                        <td colspan="4">No results yet.</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- Header Analyzer -->
                <div id="view-headeranalyzer" class="view slide-up">
                    <div class="panel full-height">
                        <div class="panel-header glass-header flex-between">
                            <span class="title">Security Header Analyzer</span>
                            <div style="display: flex; gap: 6px; align-items: center;">
                                <input type="text" id="header-target-url" placeholder="https://target.com"
                                    style="min-width: 300px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 12px; min-height: unset; height: 28px;">
                                <button id="header-analyze-btn" class="btn primary small">Analyze</button>
                            </div>
                        </div>
                        <div class="panel-body custom-scroll" style="padding: 16px;">
                            <div id="header-results">
                                <div class="empty-state">Enter a URL and click Analyze to check security headers.</div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- JWT Analyzer -->
                <div id="view-jwtanalyzer" class="view slide-up">
                    <div class="panel full-height">
                        <div class="panel-header glass-header flex-between">
                            <span class="title">JWT Token Analyzer</span>
                            <div style="display: flex; gap: 6px; align-items: center;">
                                <button id="jwt-decode-btn" class="btn primary small">Decode</button>
                                <button id="jwt-none-attack-btn" class="btn secondary small"
                                    title="alg: none attack">None Attack</button>
                                <button id="jwt-bruteforce-btn" class="btn secondary small"
                                    title="Bruteforce HS256 secret">Brute Secret</button>
                            </div>
                        </div>
                        <div class="panel-body custom-scroll" style="padding: 16px;">
                            <div style="margin-bottom: 16px;">
                                <label class="text-muted"
                                    style="font-size: 11px; display: block; margin-bottom: 4px;">JWT Token</label>
                                <textarea id="jwt-input" class="code-area"
                                    style="height: 60px; width: 100%; resize: none;" spellcheck="false"
                                    placeholder="eyJhbGciOiJIUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiIxMjM0NTY3ODkwIiwibmFtZSI6IkpvaG4gRG9lIiwiaWF0IjoxNTE2MjM5MDIyfQ.SflKxwRJSMeKKF2QT4fwpMeJf36POk6yJV_adQssw5c"></textarea>
                            </div>
                            <div class="split-view" style="gap: 12px;">
                                <div style="flex: 1;">
                                    <label class="text-muted"
                                        style="font-size: 11px; display: block; margin-bottom: 4px;">Header</label>
                                    <pre id="jwt-header"
                                        style="background: var(--bg-secondary); padding: 10px; border-radius: var(--radius); font-size: 12px; color: var(--danger); min-height: 60px; white-space: pre-wrap; word-break: break-all;">—</pre>
                                </div>
                                <div style="flex: 1;">
                                    <label class="text-muted"
                                        style="font-size: 11px; display: block; margin-bottom: 4px;">Payload</label>
                                    <pre id="jwt-payload"
                                        style="background: var(--bg-secondary); padding: 10px; border-radius: var(--radius); font-size: 12px; color: var(--accent); min-height: 60px; white-space: pre-wrap; word-break: break-all;">—</pre>
                                </div>
                            </div>
                            <div style="margin-top: 12px;">
                                <label class="text-muted"
                                    style="font-size: 11px; display: block; margin-bottom: 4px;">Signature &
                                    Verification</label>
                                <pre id="jwt-signature"
                                    style="background: var(--bg-secondary); padding: 10px; border-radius: var(--radius); font-size: 12px; color: var(--warning); white-space: pre-wrap; word-break: break-all;">—</pre>
                            </div>
                            <div id="jwt-attacks-output" style="margin-top: 12px;"></div>
                        </div>
                    </div>
                </div>

                <!-- Subdomain Finder -->
                <div id="view-subdomain" class="view slide-up">
                    <div class="panel full-height">
                        <div class="panel-header glass-header flex-between">
                            <span class="title">Subdomain Finder</span>
                            <div style="display: flex; gap: 6px; align-items: center;">
                                <input type="text" id="subdomain-target" placeholder="target.com"
                                    style="min-width: 220px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 12px; min-height: unset; height: 28px;">
                                <button id="subdomain-start-btn" class="btn primary small"
                                    style="box-shadow: 0 0 10px rgba(0, 198, 255, 0.4);">Find Subdomains</button>
                                <button id="subdomain-workflow-btn" class="btn warning small"
                                    style="display: none; box-shadow: 0 0 10px rgba(243, 156, 18, 0.4);">⚡ Vuln
                                    Auto-Orchestrate</button>
                                <button id="subdomain-export-btn" class="btn secondary small">Export/Copy</button>
                            </div>
                        </div>
                        <div class="panel-body custom-scroll" style="padding: 0;">
                            <div id="subdomain-progress"
                                style="padding: 10px 14px; border-bottom: 1px solid var(--border-color); font-size: 11px; color: var(--text-muted);">
                                Enter a domain and click Find Subdomains.
                            </div>
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th>Subdomain</th>
                                        <th>IP</th>
                                        <th>Status</th>
                                    </tr>
                                </thead>
                                <tbody id="subdomain-results-tbody">
                                    <tr class="empty-tr">
                                        <td colspan="3">No results yet.</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- Web Crawler -->
                <div id="view-webcrawler" class="view slide-up">
                    <div class="panel full-height">
                        <div class="panel-header glass-header flex-between">
                            <span class="title">Web Crawler</span>
                            <div style="display: flex; gap: 6px; align-items: center;">
                                <input type="text" id="crawl-target" placeholder="https://target.com"
                                    style="min-width: 250px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 12px; min-height: unset; height: 28px;">
                                <input type="number" id="crawl-depth" value="3" min="1" max="10"
                                    style="width: 55px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 11px; min-height: unset; height: 28px;"
                                    title="Max Depth">
                                <input type="number" id="crawl-max" value="100" min="10" max="500"
                                    style="width: 60px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 11px; min-height: unset; height: 28px;"
                                    title="Max Pages">
                                <label
                                    style="display: flex; align-items: center; gap: 4px; font-size: 10px; color: var(--text-muted); cursor: pointer;">
                                    <input type="checkbox" id="crawl-sensitive-toggle"
                                        style="accent-color: var(--accent);">
                                    + Sensitive Scan
                                </label>
                                <button id="crawl-start-btn" class="btn primary small">Crawl</button>
                            </div>
                        </div>
                        <div class="panel-body custom-scroll" style="padding: 0;">
                            <div id="crawl-stats"
                                style="padding: 10px 14px; border-bottom: 1px solid var(--border-color); font-size: 11px; color: var(--text-muted); display: flex; gap: 16px;">
                                <span>Pages: <strong id="crawl-stat-pages">0</strong></span>
                                <span>Forms: <strong id="crawl-stat-forms">0</strong></span>
                                <span>Scripts: <strong id="crawl-stat-scripts">0</strong></span>
                                <span>API Endpoints: <strong id="crawl-stat-apis">0</strong></span>
                            </div>
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th>URL</th>
                                        <th>Status</th>
                                        <th>Depth</th>
                                        <th>Size</th>
                                    </tr>
                                </thead>
                                <tbody id="crawl-results-tbody">
                                    <tr class="empty-tr">
                                        <td colspan="4">Enter a target URL and click Crawl to begin.</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- Vulnerability Scanner -->
    `);
})();
