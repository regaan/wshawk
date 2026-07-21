(function registerCollaborationViews() {
    'use strict';
    window.WSHawkViewRegistry.register('collaboration', String.raw`
                <div id="view-cybernode" class="view slide-up">
                    <div class="panel full-height" style="display: flex; flex-direction: column;">
                        <div class="panel-header glass-header flex-between">
                            <span class="title" style="color: var(--accent);">
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                                    stroke-width="2" style="vertical-align: -2px; margin-right: 4px;">
                                    <circle cx="6" cy="6" r="3"></circle>
                                    <circle cx="18" cy="6" r="3"></circle>
                                    <circle cx="6" cy="18" r="3"></circle>
                                    <circle cx="18" cy="18" r="3"></circle>
                                    <line x1="9" y1="6" x2="15" y2="6"></line>
                                    <line x1="6" y1="9" x2="6" y2="15"></line>
                                </svg>
                                CyberNode Pipeline
                            </span>
                            <div style="display: flex; gap: 6px; align-items: center;">
                                <button id="cn-clear-btn" class="btn secondary small">Clear Canvas</button>
                                <button id="cn-export-btn" class="btn secondary small">Export .hawkchain</button>
                                <button id="cn-import-btn" class="btn secondary small">Import</button>
                                <input type="file" id="cn-import-file" accept=".hawkchain,.json" style="display: none;">
                                <button id="cn-exec-btn" class="btn primary small"
                                    style="background: linear-gradient(135deg, var(--accent), var(--danger));">
                                    ▶ Execute Pipeline
                                </button>
                            </div>
                        </div>
                        <div class="panel-body" style="padding: 0; flex: 1; display: flex; overflow: hidden;">
                            <!-- Node Toolbox Palette -->
                            <div id="cn-toolbox" class="cn-toolbox custom-scroll">
                                <div class="cn-toolbox-header">NODES</div>

                                <div class="cn-toolbox-section">RECON</div>
                                <div class="cn-tool-node" data-node-type="subdomain" data-node-color="#06b6d4"
                                    draggable="true">
                                    <span class="cn-tool-icon">SD</span> Subdomain Finder
                                </div>
                                <div class="cn-tool-node" data-node-type="crawler" data-node-color="#8b5cf6"
                                    draggable="true">
                                    <span class="cn-tool-icon">WC</span> Web Crawler
                                </div>
                                <div class="cn-tool-node" data-node-type="techfp" data-node-color="#f59e0b"
                                    draggable="true">
                                    <span class="cn-tool-icon">TF</span> Tech Fingerprint
                                </div>
                                <div class="cn-tool-node" data-node-type="dnslookup" data-node-color="#14b8a6"
                                    draggable="true">
                                    <span class="cn-tool-icon">DN</span> DNS / WHOIS
                                </div>
                                <div class="cn-tool-node" data-node-type="portscan" data-node-color="#6366f1"
                                    draggable="true">
                                    <span class="cn-tool-icon">PS</span> Port Scanner
                                </div>

                                <div class="cn-toolbox-section">SCAN</div>
                                <div class="cn-tool-node" data-node-type="dirscan" data-node-color="#22c55e"
                                    draggable="true">
                                    <span class="cn-tool-icon">DS</span> Dir Scanner
                                </div>
                                <div class="cn-tool-node" data-node-type="headeranalyzer" data-node-color="#a855f7"
                                    draggable="true">
                                    <span class="cn-tool-icon">HA</span> Header Analyzer
                                </div>
                                <div class="cn-tool-node" data-node-type="sslanalyzer" data-node-color="#3b82f6"
                                    draggable="true">
                                    <span class="cn-tool-icon">SS</span> SSL/TLS Analyzer
                                </div>
                                <div class="cn-tool-node" data-node-type="sensitivefinder" data-node-color="#ef4444"
                                    draggable="true">
                                    <span class="cn-tool-icon">SF</span> Sensitive Finder
                                </div>
                                <div class="cn-tool-node" data-node-type="vulnscan" data-node-color="#dc2626"
                                    draggable="true">
                                    <span class="cn-tool-icon">VS</span> Vuln Scanner
                                </div>
                                <div class="cn-tool-node" data-node-type="wafdetect" data-node-color="#f97316"
                                    draggable="true">
                                    <span class="cn-tool-icon">WF</span> WAF Detector
                                </div>

                                <div class="cn-toolbox-section">EXPLOIT</div>
                                <div class="cn-tool-node" data-node-type="httpfuzzer" data-node-color="#e11d48"
                                    draggable="true">
                                    <span class="cn-tool-icon">FZ</span> HTTP Fuzzer
                                </div>
                                <div class="cn-tool-node" data-node-type="corstester" data-node-color="#d946ef"
                                    draggable="true">
                                    <span class="cn-tool-icon">CR</span> CORS Tester
                                </div>
                                <div class="cn-tool-node" data-node-type="csrfforge" data-node-color="#f43f5e"
                                    draggable="true">
                                    <span class="cn-tool-icon">XF</span> CSRF Forge
                                </div>
                                <div class="cn-tool-node" data-node-type="ssrfprobe" data-node-color="#be123c"
                                    draggable="true">
                                    <span class="cn-tool-icon">BP</span> Blind Probe
                                </div>
                                <div class="cn-tool-node" data-node-type="redirect" data-node-color="#fb923c"
                                    draggable="true">
                                    <span class="cn-tool-icon">RH</span> Redirect Hunter
                                </div>
                                <div class="cn-tool-node" data-node-type="protopollute" data-node-color="#7c3aed"
                                    draggable="true">
                                    <span class="cn-tool-icon">PP</span> Proto Polluter
                                </div>

                                <div class="cn-toolbox-section">LOGIC</div>
                                <div class="cn-tool-node" data-node-type="filter" data-node-color="#64748b"
                                    draggable="true">
                                    <span class="cn-tool-icon">FG</span> Filter / Grep
                                </div>
                                <div class="cn-tool-node" data-node-type="note" data-node-color="#475569"
                                    draggable="true">
                                    <span class="cn-tool-icon">NT</span> Note / Label
                                </div>
                            </div>

                            <!-- Canvas Area -->
                            <div id="cn-canvas-wrap" class="cn-canvas-wrap">
                                <svg id="cn-svg-layer" class="cn-svg-layer"></svg>
                                <div id="cn-canvas" class="cn-canvas"></div>
                                <!-- Minimap -->
                                <div id="cn-minimap" class="cn-minimap">
                                    <canvas id="cn-minimap-canvas" width="180" height="120"></canvas>
                                </div>
                                <!-- Zoom controls -->
                                <div class="cn-zoom-controls">
                                    <button id="cn-zoom-in" class="cn-zoom-btn">+</button>
                                    <span id="cn-zoom-level" class="cn-zoom-level">100%</span>
                                    <button id="cn-zoom-out" class="cn-zoom-btn">−</button>
                                    <button id="cn-zoom-fit" class="cn-zoom-btn" title="Fit to view">⊞</button>
                                </div>
                            </div>

                            <!-- Execution Log Panel -->
                            <div id="cn-exec-panel" class="cn-exec-panel" style="display: none;">
                                <div class="cn-exec-header">
                                    <span>Pipeline Execution Log</span>
                                    <button id="cn-exec-close" class="btn-icon" style="font-size: 14px;">✕</button>
                                </div>
                                <div id="cn-exec-log" class="cn-exec-log custom-scroll"></div>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- ═══════════════════════════════════════════════════════════ -->
                <!-- Team Mode: Multiplayer Collaboration Panel                 -->
                <!-- ═══════════════════════════════════════════════════════════ -->
                <div id="view-teammode" class="view slide-up">
                    <div class="panel full-height" style="display: flex; flex-direction: column;">
                        <div class="panel-header glass-header flex-between">
                            <span class="title" style="color: var(--safe);">
                                <svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor"
                                    stroke-width="2" style="vertical-align: -2px; margin-right: 4px;">
                                    <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path>
                                    <circle cx="9" cy="7" r="4"></circle>
                                    <path d="M23 21v-2a4 4 0 0 0-3-3.87"></path>
                                </svg>
                                Team Mode
                            </span>
                            <div id="team-room-badge"
                                style="display: none; background: rgba(16, 185, 129, 0.15); border: 1px solid rgba(16, 185, 129, 0.3); padding: 4px 10px; border-radius: 6px; font-family: var(--font-mono); font-size: 12px; font-weight: 700; color: var(--safe); letter-spacing: 2px;">
                            </div>
                        </div>
                        <div class="panel-body custom-scroll"
                            style="padding: 0; flex: 1; display: flex; overflow: hidden;">
                            <!-- Left: Room Management + Roster -->
                            <div
                                style="width: 320px; min-width: 320px; border-right: 1px solid var(--border-color); display: flex; flex-direction: column;">
                                <!-- Connection Section -->
                                <div id="team-connect-section" style="padding: 20px;">
                                    <div
                                        style="font-size: 10px; font-weight: 700; color: var(--text-muted); letter-spacing: 1.5px; margin-bottom: 16px;">
                                        CREATE OR JOIN A ROOM</div>

                                    <div style="margin-bottom: 12px;">
                                        <label
                                            style="font-size: 11px; color: var(--text-secondary); display: block; margin-bottom: 4px;">Your
                                            Name</label>
                                        <input type="text" id="team-operator-name" placeholder="e.g. Regaan"
                                            style="width: 100%; background: var(--bg-card); border: 1px solid var(--border-highlight); color: var(--text-primary); padding: 8px 12px; border-radius: 6px; font-size: 13px; outline: none;">
                                    </div>

                                    <button id="team-create-btn" class="btn primary"
                                        style="width: 100%; margin-bottom: 12px;">
                                        Create New Room
                                    </button>

                                    <div style="display: flex; align-items: center; gap: 8px; margin-bottom: 12px;">
                                        <div style="flex: 1; height: 1px; background: var(--border-color);"></div>
                                        <span style="font-size: 10px; color: var(--text-muted);">OR</span>
                                        <div style="flex: 1; height: 1px; background: var(--border-color);"></div>
                                    </div>

                                    <div style="display: flex; gap: 6px;">
                                        <input type="text" id="team-join-code" placeholder="Room Code (e.g. X9K3M2)"
                                            maxlength="6"
                                            style="flex: 1; background: var(--bg-card); border: 1px solid var(--border-highlight); color: var(--text-primary); padding: 8px 12px; border-radius: 6px; font-family: var(--font-mono); font-size: 14px; letter-spacing: 3px; text-transform: uppercase; text-align: center; outline: none;">
                                        <button id="team-join-btn" class="btn secondary">Join</button>
                                    </div>
                                </div>

                                <!-- Connected Section (hidden by default) -->
                                <div id="team-connected-section"
                                    style="display: none; flex: 1; display: flex; flex-direction: column;">
                                    <div
                                        style="padding: 12px 16px; border-bottom: 1px solid var(--border-color); display: flex; justify-content: space-between; align-items: center;">
                                        <div>
                                            <div
                                                style="font-size: 10px; font-weight: 700; color: var(--text-muted); letter-spacing: 1px;">
                                                ROOM CODE</div>
                                            <div id="team-active-code"
                                                style="font-family: var(--font-mono); font-size: 20px; font-weight: 700; color: var(--safe); letter-spacing: 4px;">
                                            </div>
                                        </div>
                                        <button id="team-leave-btn" class="btn secondary small"
                                            style="border-color: var(--danger); color: var(--danger);">Leave</button>
                                    </div>

                                    <!-- Operator Roster -->
                                    <div style="padding: 12px 16px; border-bottom: 1px solid var(--border-color);">
                                        <div
                                            style="font-size: 10px; font-weight: 700; color: var(--text-muted); letter-spacing: 1px; margin-bottom: 8px;">
                                            OPERATORS ONLINE</div>
                                        <div id="team-roster" style="display: flex; flex-direction: column; gap: 6px;">
                                        </div>
                                    </div>

                                    <!-- Quick Share -->
                                    <div style="padding: 12px 16px;">
                                        <div
                                            style="font-size: 10px; font-weight: 700; color: var(--text-muted); letter-spacing: 1px; margin-bottom: 8px;">
                                            QUICK SHARE</div>
                                        <button id="team-share-room" class="btn secondary small"
                                            style="width: 100%; margin-bottom: 6px;">Copy Room Code</button>
                                        <div style="font-size: 10px; color: var(--text-muted); text-align: center;">
                                            Share this code with your team members</div>
                                    </div>
                                </div>
                            </div>

                            <!-- Right: Activity Feed -->
                            <div style="flex: 1; display: flex; flex-direction: column;">
                                <div
                                    style="padding: 10px 16px; border-bottom: 1px solid var(--border-color); font-size: 10px; font-weight: 700; color: var(--text-muted); letter-spacing: 1.5px;">
                                    TEAM ACTIVITY FEED
                                </div>
                                <div id="team-activity-feed" class="custom-scroll"
                                    style="flex: 1; overflow-y: auto; padding: 12px 16px;">
                                    <div class="empty-state" style="flex-direction: column; gap: 8px;">
                                        <svg width="40" height="40" viewBox="0 0 24 24" fill="none"
                                            stroke="currentColor" stroke-width="1.5" style="opacity: 0.3;">
                                            <path d="M17 21v-2a4 4 0 0 0-4-4H5a4 4 0 0 0-4 4v2"></path>
                                            <circle cx="9" cy="7" r="4"></circle>
                                            <path d="M23 21v-2a4 4 0 0 0-3-3.87"></path>
                                            <path d="M16 3.13a4 4 0 0 1 0 7.75"></path>
                                        </svg>
                                        <span>Create or join a room to start collaborating.</span>
                                        <span style="font-size: 11px; opacity: 0.5;">All scans, findings, and notes will
                                            be shared in real-time.</span>
                                    </div>
                                </div>
                            </div>
                        </div>
                    </div>
                </div>
    `);
})();
