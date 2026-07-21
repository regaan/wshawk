(function registerWebSecurityViews() {
    'use strict';
    window.WSHawkViewRegistry.register('web-security', String.raw`
                <div id="view-vulnscanner" class="view slide-up">
                    <div class="panel full-height">
                        <div class="panel-header glass-header flex-between">
                            <span class="title" style="color: var(--danger); font-weight: 700;">⚠ Vulnerability
                                Scanner</span>
                            <div style="display: flex; gap: 6px; align-items: center;">
                                <input type="text" id="vuln-target" placeholder="https://target.com"
                                    style="min-width: 280px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 12px; min-height: unset; height: 28px;">
                                <button id="vuln-start-btn" class="btn primary small"
                                    style="background: var(--danger); box-shadow: 0 0 12px rgba(239,68,68,0.4);">Launch
                                    Scan</button>
                                <button id="vuln-stop-btn" class="btn secondary small"
                                    style="display: none;">Stop</button>
                                <button id="vuln-export-btn" class="btn secondary small">Export Report</button>
                            </div>
                        </div>
                        <div class="panel-body custom-scroll" style="padding: 0;">
                            <!-- Phase Progress -->
                            <div id="vuln-phases"
                                style="padding: 12px 16px; border-bottom: 1px solid var(--border-color); display: flex; gap: 12px; flex-wrap: wrap;">
                                <span id="vuln-phase-crawl" class="badge standard" style="opacity: 0.4;">Crawl</span>
                                <span id="vuln-phase-headers" class="badge standard"
                                    style="opacity: 0.4;">Headers</span>
                                <span id="vuln-phase-dirscan" class="badge standard"
                                    style="opacity: 0.4;">DirScan</span>
                                <span id="vuln-phase-fuzz" class="badge standard" style="opacity: 0.4;">Fuzz</span>
                            </div>
                            <!-- Severity Chart + Summary -->
                            <div id="vuln-charts"
                                style="padding: 16px; border-bottom: 1px solid var(--border-color); display: none;">
                                <div style="display: flex; gap: 20px; align-items: center;">
                                    <canvas id="vuln-pie-chart" width="120" height="120"
                                        style="flex-shrink: 0;"></canvas>
                                    <div style="flex: 1;">
                                        <div
                                            style="font-size: 11px; text-transform: uppercase; letter-spacing: 1px; color: var(--text-muted); margin-bottom: 8px; font-weight: 600;">
                                            Severity Breakdown</div>
                                        <div style="display: flex; gap: 16px; flex-wrap: wrap;">
                                            <div style="text-align: center;">
                                                <div id="vuln-count-high"
                                                    style="font-size: 22px; font-weight: 700; color: var(--danger);">0
                                                </div>
                                                <div
                                                    style="font-size: 9px; text-transform: uppercase; color: var(--text-muted);">
                                                    High</div>
                                            </div>
                                            <div style="text-align: center;">
                                                <div id="vuln-count-medium"
                                                    style="font-size: 22px; font-weight: 700; color: var(--warning);">0
                                                </div>
                                                <div
                                                    style="font-size: 9px; text-transform: uppercase; color: var(--text-muted);">
                                                    Medium</div>
                                            </div>
                                            <div style="text-align: center;">
                                                <div id="vuln-count-low"
                                                    style="font-size: 22px; font-weight: 700; color: var(--accent);">0
                                                </div>
                                                <div
                                                    style="font-size: 9px; text-transform: uppercase; color: var(--text-muted);">
                                                    Low</div>
                                            </div>
                                            <div style="text-align: center;">
                                                <div id="vuln-count-info"
                                                    style="font-size: 22px; font-weight: 700; color: var(--text-muted);">
                                                    0</div>
                                                <div
                                                    style="font-size: 9px; text-transform: uppercase; color: var(--text-muted);">
                                                    Info</div>
                                            </div>
                                        </div>
                                        <div id="vuln-scan-time"
                                            style="margin-top: 10px; font-size: 10px; color: var(--text-muted);"></div>
                                    </div>
                                </div>
                            </div>
                            <!-- Live Log -->
                            <div id="vuln-log"
                                style="padding: 10px 14px; border-bottom: 1px solid var(--border-color); max-height: 140px; overflow-y: auto; font-size: 11px; font-family: var(--font-mono); color: var(--text-muted); background: var(--bg-secondary);">
                                Waiting for scan to start...
                            </div>
                            <!-- Findings Table -->
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th>#</th>
                                        <th>Severity</th>
                                        <th>Type</th>
                                        <th>Title</th>
                                        <th>Detail</th>
                                    </tr>
                                </thead>
                                <tbody id="vuln-findings-tbody">
                                    <tr class="empty-tr">
                                        <td colspan="5">No findings yet. Enter a target and click Launch Scan.</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- Tech Fingerprint -->
                <div id="view-techfp" class="view slide-up">
                    <div class="panel full-height">
                        <div class="panel-header glass-header flex-between">
                            <span class="title">Tech Stack Fingerprinter</span>
                            <div style="display: flex; gap: 6px; align-items: center;">
                                <input type="text" id="techfp-target" placeholder="https://target.com"
                                    style="min-width: 300px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 12px; min-height: unset; height: 28px;">
                                <button id="techfp-start-btn" class="btn primary small">Detect</button>
                            </div>
                        </div>
                        <div class="panel-body custom-scroll" style="padding: 16px;">
                            <div id="techfp-results">
                                <div class="empty-state">Enter a URL and click Detect to identify the technology stack.
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- SSL/TLS Analyzer -->
                <div id="view-sslanalyzer" class="view slide-up">
                    <div class="panel full-height">
                        <div class="panel-header glass-header flex-between">
                            <span class="title">SSL/TLS Certificate Analyzer</span>
                            <div style="display: flex; gap: 6px; align-items: center;">
                                <input type="text" id="ssl-target" placeholder="example.com"
                                    style="min-width: 250px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 12px; min-height: unset; height: 28px;">
                                <input type="number" id="ssl-port" value="443" min="1" max="65535"
                                    style="width: 65px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 11px; min-height: unset; height: 28px;">
                                <button id="ssl-start-btn" class="btn primary small">Analyze</button>
                            </div>
                        </div>
                        <div class="panel-body custom-scroll" style="padding: 16px;">
                            <div id="ssl-results">
                                <div class="empty-state">Enter a hostname and click Analyze to inspect SSL/TLS
                                    configuration.</div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Sensitive Data Finder -->
                <div id="view-sensitivefinder" class="view slide-up">
                    <div class="panel full-height">
                        <div class="panel-header glass-header flex-between">
                            <span class="title">Sensitive Data Finder</span>
                            <div style="display: flex; gap: 6px; align-items: center;">
                                <input type="text" id="sensitive-target" placeholder="https://target.com/page"
                                    style="min-width: 300px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 12px; min-height: unset; height: 28px;">
                                <button id="sensitive-start-btn" class="btn primary small">Scan</button>
                            </div>
                        </div>
                        <div class="panel-body custom-scroll" style="padding: 0;">
                            <div id="sensitive-progress"
                                style="padding: 10px 14px; border-bottom: 1px solid var(--border-color); font-size: 11px; color: var(--text-muted);">
                                Enter a URL to scan for leaked API keys, tokens, credentials, and sensitive data.
                            </div>
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th>Severity</th>
                                        <th>Type</th>
                                        <th>Value (Masked)</th>
                                    </tr>
                                </thead>
                                <tbody id="sensitive-results-tbody">
                                    <tr class="empty-tr">
                                        <td colspan="3">No findings yet.</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- WAF Detector -->
                <div id="view-wafdetect" class="view slide-up">
                    <div class="panel full-height">
                        <div class="panel-header glass-header flex-between">
                            <span class="title">WAF Detector</span>
                            <div style="display: flex; gap: 6px; align-items: center;">
                                <input type="text" id="waf-target" placeholder="https://target.com"
                                    style="min-width: 300px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 12px; min-height: unset; height: 28px;">
                                <button id="waf-start-btn" class="btn primary small">Detect</button>
                            </div>
                        </div>
                        <div class="panel-body custom-scroll" style="padding: 16px;">
                            <div id="waf-results">
                                <div class="empty-state">Enter a URL and click Detect to identify WAFs.</div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- CORS Tester -->
                <div id="view-corstester" class="view slide-up">
                    <div class="panel full-height">
                        <div class="panel-header glass-header flex-between">
                            <span class="title">CORS Misconfiguration Tester</span>
                            <div style="display: flex; gap: 6px; align-items: center;">
                                <input type="text" id="cors-target" placeholder="https://target.com/api"
                                    style="min-width: 300px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 12px; min-height: unset; height: 28px;">
                                <button id="cors-start-btn" class="btn primary small">Test</button>
                            </div>
                        </div>
                        <div class="panel-body custom-scroll" style="padding: 0;">
                            <div id="cors-summary"
                                style="padding: 10px 14px; border-bottom: 1px solid var(--border-color); font-size: 11px; color: var(--text-muted);">
                                Enter a URL to test for CORS misconfigurations.
                            </div>
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th>Severity</th>
                                        <th>Test</th>
                                        <th>Origin Sent</th>
                                        <th>ACAO Response</th>
                                        <th>Credentials</th>
                                    </tr>
                                </thead>
                                <tbody id="cors-results-tbody">
                                    <tr class="empty-tr">
                                        <td colspan="5">No results yet.</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- Port Scanner -->
                <div id="view-portscanner" class="view slide-up">
                    <div class="panel full-height">
                        <div class="panel-header glass-header flex-between">
                            <span class="title">TCP Port Scanner</span>
                            <div style="display: flex; gap: 6px; align-items: center;">
                                <input type="text" id="port-target" placeholder="target.com"
                                    style="min-width: 200px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 12px; min-height: unset; height: 28px;">
                                <select id="port-preset"
                                    style="background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 11px; height: 28px;">
                                    <option value="top100">Top 100</option>
                                    <option value="web">Web Ports</option>
                                    <option value="database">Database</option>
                                    <option value="full">Full 1-1024</option>
                                </select>
                                <input type="text" id="port-custom" placeholder="Custom: 80,443,8000-8100"
                                    style="width: 160px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 11px; min-height: unset; height: 28px;">
                                <button id="port-start-btn" class="btn primary small">Scan</button>
                            </div>
                        </div>
                        <div class="panel-body custom-scroll" style="padding: 0;">
                            <div id="port-stats"
                                style="padding: 10px 14px; border-bottom: 1px solid var(--border-color); font-size: 11px; color: var(--text-muted); display: flex; gap: 16px;">
                                <span>Open: <strong id="port-stat-open">0</strong></span>
                                <span>Scanned: <strong id="port-stat-total">0</strong></span>
                                <span>Elapsed: <strong id="port-stat-time">—</strong></span>
                            </div>
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th>Port</th>
                                        <th>State</th>
                                        <th>Service</th>
                                        <th>Banner</th>
                                    </tr>
                                </thead>
                                <tbody id="port-results-tbody">
                                    <tr class="empty-tr">
                                        <td colspan="4">Enter a host and click Scan.</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- DNS / WHOIS -->
                <div id="view-dnslookup" class="view slide-up">
                    <div class="panel full-height">
                        <div class="panel-header glass-header flex-between">
                            <span class="title">DNS / WHOIS Lookup</span>
                            <div style="display: flex; gap: 6px; align-items: center;">
                                <input type="text" id="dns-target" placeholder="example.com"
                                    style="min-width: 280px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 12px; min-height: unset; height: 28px;">
                                <button id="dns-start-btn" class="btn primary small">Lookup</button>
                            </div>
                        </div>
                        <div class="panel-body custom-scroll" style="padding: 16px;">
                            <div id="dns-results">
                                <div class="empty-state">Enter a domain to query DNS records and WHOIS data.</div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- CSRF Forge -->
                <div id="view-csrfforge" class="view slide-up">
                    <div class="panel full-height">
                        <div class="panel-header glass-header flex-between">
                            <span class="title" style="color: var(--warning);">⚡ CSRF Forge</span>
                            <div style="display: flex; gap: 6px; align-items: center;">
                                <select id="csrf-method"
                                    style="background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 11px; height: 28px;">
                                    <option>POST</option>
                                    <option>GET</option>
                                    <option>PUT</option>
                                    <option>DELETE</option>
                                </select>
                                <input type="text" id="csrf-url" placeholder="https://target.com/action"
                                    style="min-width: 280px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 12px; min-height: unset; height: 28px;">
                                <button id="csrf-gen-btn" class="btn primary small"
                                    style="background: var(--warning); color: #111;">Generate</button>
                            </div>
                        </div>
                        <div class="panel-body custom-scroll" style="padding: 0;">
                            <div style="display: flex; height: 100%;">
                                <div
                                    style="flex: 1; border-right: 1px solid var(--border-color); display: flex; flex-direction: column;">
                                    <div
                                        style="padding: 8px 12px; font-size: 10px; text-transform: uppercase; letter-spacing: 1px; color: var(--text-muted); border-bottom: 1px solid var(--border-color);">
                                        Request Body / Form Data</div>
                                    <textarea id="csrf-body"
                                        placeholder="username=admin&password=pass123&#10;OR JSON:&#10;{&quot;action&quot;: &quot;delete&quot;, &quot;id&quot;: 1}"
                                        style="flex: 1; background: var(--bg-secondary); border: none; padding: 12px; font-family: var(--font-mono); font-size: 12px; color: var(--text-primary); resize: none;"></textarea>
                                    <div
                                        style="padding: 8px 12px; font-size: 10px; text-transform: uppercase; letter-spacing: 1px; color: var(--text-muted); border-top: 1px solid var(--border-color); border-bottom: 1px solid var(--border-color);">
                                        Headers (optional)</div>
                                    <textarea id="csrf-headers"
                                        placeholder="Content-Type: application/x-www-form-urlencoded"
                                        style="height: 80px; background: var(--bg-secondary); border: none; padding: 12px; font-family: var(--font-mono); font-size: 11px; color: var(--text-muted); resize: none;"></textarea>
                                </div>
                                <div style="flex: 1; display: flex; flex-direction: column;">
                                    <div
                                        style="padding: 8px 12px; font-size: 10px; text-transform: uppercase; letter-spacing: 1px; color: var(--accent); border-bottom: 1px solid var(--border-color); display: flex; justify-content: space-between; align-items: center;">
                                        Generated PoC
                                        <button id="csrf-copy-btn" class="btn secondary small"
                                            style="font-size: 9px; padding: 2px 8px;">Copy HTML</button>
                                    </div>
                                    <div id="csrf-results" style="flex: 1; padding: 12px; overflow-y: auto;">
                                        <div class="empty-state">Fill in the request details and click Generate.</div>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Blind Probe (SSRF) -->
                <div id="view-blindprobe" class="view slide-up">
                    <div class="panel full-height">
                        <div class="panel-header glass-header flex-between">
                            <span class="title" style="color: var(--danger);">Blind Probe (SSRF)</span>
                            <div style="display: flex; gap: 6px; align-items: center;">
                                <input type="text" id="ssrf-url" placeholder="https://target.com/fetch?url=VALUE"
                                    style="min-width: 300px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 12px; min-height: unset; height: 28px;">
                                <input type="text" id="ssrf-param" placeholder="param (auto)"
                                    style="width: 90px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 11px; min-height: unset; height: 28px;">
                                <button id="ssrf-start-btn" class="btn primary small"
                                    style="background: var(--danger);">Probe</button>
                            </div>
                        </div>
                        <div class="panel-body custom-scroll" style="padding: 0;">
                            <div id="ssrf-stats"
                                style="padding: 10px 14px; border-bottom: 1px solid var(--border-color); font-size: 11px; color: var(--text-muted); display: flex; gap: 16px;">
                                <span>Payloads: <strong id="ssrf-stat-sent">0</strong></span>
                                <span>Findings: <strong id="ssrf-stat-findings"
                                        style="color: var(--danger);">0</strong></span>
                                <span>Params: <strong id="ssrf-stat-params">—</strong></span>
                            </div>
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th>Severity</th>
                                        <th>Category</th>
                                        <th>Param</th>
                                        <th>Payload</th>
                                        <th>Status</th>
                                        <th>Indicators</th>
                                    </tr>
                                </thead>
                                <tbody id="ssrf-results-tbody">
                                    <tr class="empty-tr">
                                        <td colspan="6">Enter a URL with parameters and click Probe to test for SSRF.
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- Redirect Hunter -->
                <div id="view-redirecthunter" class="view slide-up">
                    <div class="panel full-height">
                        <div class="panel-header glass-header flex-between">
                            <span class="title">↗ Redirect Hunter</span>
                            <div style="display: flex; gap: 6px; align-items: center;">
                                <input type="text" id="redirect-url" placeholder="https://target.com/login?next=VALUE"
                                    style="min-width: 320px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 12px; min-height: unset; height: 28px;">
                                <input type="text" id="redirect-param" placeholder="param (auto)"
                                    style="width: 90px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 11px; min-height: unset; height: 28px;">
                                <button id="redirect-start-btn" class="btn primary small">Hunt</button>
                            </div>
                        </div>
                        <div class="panel-body custom-scroll" style="padding: 0;">
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th>Severity</th>
                                        <th>Technique</th>
                                        <th>Param</th>
                                        <th>Payload</th>
                                        <th>Redirect Type</th>
                                        <th>Destination</th>
                                    </tr>
                                </thead>
                                <tbody id="redirect-results-tbody">
                                    <tr class="empty-tr">
                                        <td colspan="6">Enter a URL with redirect parameters and click Hunt.</td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- Proto Polluter -->
                <div id="view-protopolluter" class="view slide-up">
                    <div class="panel full-height">
                        <div class="panel-header glass-header flex-between">
                            <span class="title" style="color: var(--warning);">Proto Polluter</span>
                            <div style="display: flex; gap: 6px; align-items: center;">
                                <input type="text" id="proto-url" placeholder="https://target.com/api/settings"
                                    style="min-width: 300px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 12px; min-height: unset; height: 28px;">
                                <select id="proto-method"
                                    style="background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 11px; height: 28px;">
                                    <option>GET</option>
                                    <option>POST</option>
                                    <option>PUT</option>
                                </select>
                                <button id="proto-start-btn" class="btn primary small"
                                    style="background: var(--warning); color: #111;">Pollute</button>
                            </div>
                        </div>
                        <div class="panel-body custom-scroll" style="padding: 0;">
                            <div id="proto-stats"
                                style="padding: 10px 14px; border-bottom: 1px solid var(--border-color); font-size: 11px; color: var(--text-muted); display: flex; gap: 16px;">
                                <span>Tests: <strong id="proto-stat-tests">0</strong></span>
                                <span>Findings: <strong id="proto-stat-findings"
                                        style="color: var(--warning);">0</strong></span>
                                <span>Baseline: <strong id="proto-stat-baseline">—</strong></span>
                            </div>
                            <table class="data-table">
                                <thead>
                                    <tr>
                                        <th>Severity</th>
                                        <th>Vector</th>
                                        <th>Payload</th>
                                        <th>Status</th>
                                        <th>Response Δ</th>
                                        <th>Indicators</th>
                                    </tr>
                                </thead>
                                <tbody id="proto-results-tbody">
                                    <tr class="empty-tr">
                                        <td colspan="6">Enter a URL and click Pollute to test for prototype pollution.
                                        </td>
                                    </tr>
                                </tbody>
                            </table>
                        </div>
                    </div>
                </div>

                <!-- Proxy CA -->
                <div id="view-hawkproxyca" class="view slide-up">
                    <div class="panel full-height">
                        <div class="panel-header glass-header flex-between">
                            <span class="title" style="color: var(--accent);">Proxy CA</span>
                            <div style="display: flex; gap: 6px; align-items: center;">
                                <button id="ca-generate-btn" class="btn primary small">Generate CA</button>
                                <input type="text" id="ca-host-input" placeholder="hostname for cert"
                                    style="min-width: 180px; background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 12px; min-height: unset; height: 28px;">
                                <button id="ca-host-btn" class="btn secondary small">Host Cert</button>
                            </div>
                        </div>
                        <div class="panel-body custom-scroll" style="padding: 16px;">
                            <div id="ca-results">
                                <div class="empty-state">Click "Generate CA" to create the WSHawk root certificate
                                    authority.</div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Attack Chainer -->
                <div id="view-attackchainer" class="view slide-up">
                    <div class="panel full-height">
                        <div class="panel-header glass-header flex-between">
                            <span class="title" style="color: var(--danger);">⛓ Attack Chainer</span>
                            <div style="display: flex; gap: 6px; align-items: center;">
                                <select id="chain-identity-select"
                                    style="background: var(--bg-secondary); border: 1px solid var(--border-color); border-radius: var(--radius); padding: 4px 8px; color: var(--text-primary); font-size: 11px; min-height: unset; height: 30px; min-width: 190px;">
                                    <option value="">Workflow Default Identity</option>
                                </select>
                                <button id="chain-add-step" class="btn secondary small">+ Step</button>
                                <button id="chain-exec-btn" class="btn primary small"
                                    style="background: var(--danger);">Execute Workflow</button>
                            </div>
                        </div>
                        <div class="panel-body custom-scroll" style="padding: 0;">
                            <div style="display: flex; height: 100%;">
                                <!-- Step Builder -->
                                <div
                                    style="flex: 1; border-right: 1px solid var(--border-color); display: flex; flex-direction: column;">
                                    <div
                                        style="padding: 8px 12px; font-size: 10px; text-transform: uppercase; letter-spacing: 1px; color: var(--text-muted); border-bottom: 1px solid var(--border-color); display: flex; justify-content: space-between;">
                                        Steps (JSON)
                                        <span style="font-size: 9px; opacity: 0.5;">Use {{var}} for injection</span>
                                    </div>
                                    <textarea id="chain-steps-editor" placeholder='[
  {
    "name": "Step 1 — Get Login Page",
    "method": "GET",
    "url": "https://target.com/login",
    "headers": {},
    "body": "",
    "extract": [
      {
        "var": "csrf",
        "from": "body",
        "regex": "name=\"csrf_token\" value=\"([^\"]+)\""
      }
    ]
  },
  {
    "name": "Step 2 — Submit Login with Token",
    "method": "POST",
    "url": "https://target.com/login",
    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
    "body": "username=admin&password=pass&csrf_token={{csrf}}",
    "extract": [
      {
        "var": "session",
        "from": "cookies",
        "regex": "session=([^;]+)"
      }
    ]
  }
]' style="flex: 1; background: var(--bg-secondary); border: none; padding: 12px; font-family: var(--font-mono); font-size: 11px; color: var(--text-primary); resize: none; line-height: 1.6;"></textarea>
                                </div>
                                <!-- Results -->
                                <div style="flex: 1; display: flex; flex-direction: column;">
                                    <div
                                        style="padding: 8px 12px; font-size: 10px; text-transform: uppercase; letter-spacing: 1px; color: var(--accent); border-bottom: 1px solid var(--border-color);">
                                        Chain Results
                                    </div>
                                    <div id="chain-results" style="flex: 1; padding: 12px; overflow-y: auto;">
                                        <div class="empty-state">Define attack steps and click Execute Chain.</div>
                                    </div>
                                    <div
                                        style="padding: 8px 12px; font-size: 10px; text-transform: uppercase; letter-spacing: 1px; color: var(--text-muted); border-top: 1px solid var(--border-color);">
                                        Variables
                                    </div>
                                    <div id="chain-variables"
                                        style="padding: 8px 12px; font-size: 11px; font-family: var(--font-mono); color: var(--text-muted); max-height: 100px; overflow-y: auto;">
                                        <span style="opacity: 0.5;">No variables extracted yet.</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- ═══════════════════════════════════════════════════════════ -->
                <!-- CyberNode: Visual Attack Pipeline Canvas                   -->
                <!-- ═══════════════════════════════════════════════════════════ -->
    `);
})();
