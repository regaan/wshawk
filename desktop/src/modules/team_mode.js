(function TeamModeEngine() {
    'use strict';

    const BRIDGE_URL = 'http://127.0.0.1:8080';

    // ── Guard: only initialize if the Team Mode panel exists ────────
    const connectSection = document.getElementById('team-connect-section');
    if (!connectSection) return;

    // ── Utility ─────────────────────────────────────────────────────
    function esc(s) { const d = document.createElement('div'); d.textContent = s; return d.innerHTML; }
    function log(type, msg) { if (typeof window.appendLog === 'function') window.appendLog(type, msg); }

    // ─────────────────────────────────────────────────────────────────
    // TeamClient: Transport layer
    // Wraps REST calls (via gui_bridge) and Socket.IO events
    // using the EXISTING global `socket` from connectBridge().
    // ─────────────────────────────────────────────────────────────────
    const TeamClient = {
        // Returns the global bridge socket (created in connectBridge)
        _socket() {
            return window.socket || null;
        },

        // REST: Create a new room on the backend engine
        async createRoom(operatorName, target) {
            const res = await fetch(`${BRIDGE_URL}/team/create`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ name: operatorName, target })
            });
            return res.json();
        },

        // REST: Validate room exists before Socket.IO join
        async validateRoom(roomCode) {
            const res = await fetch(`${BRIDGE_URL}/team/join`, {
                method: 'POST',
                headers: { 'Content-Type': 'application/json' },
                body: JSON.stringify({ room_code: roomCode })
            });
            if (!res.ok) {
                const err = await res.json().catch(() => ({}));
                throw new Error(err.detail || 'Room not found');
            }
            return res.json();
        },

        // REST: Get room diagnostics
        async getStats() {
            const res = await fetch(`${BRIDGE_URL}/team/stats`);
            return res.json();
        },

        // Socket.IO: Join room for real-time sync
        emitJoin(roomCode, name) {
            const s = this._socket();
            if (s) s.emit('team_join', { room_code: roomCode, name });
        },

        // Socket.IO: Leave room
        emitLeave() {
            const s = this._socket();
            if (s) s.emit('team_leave', {});
        },

        // Socket.IO: Broadcast notes update
        emitNotesUpdate(content, cursorPos) {
            const s = this._socket();
            if (s) s.emit('team_notes_update', { content, cursor_pos: cursorPos });
        },

        // Socket.IO: Broadcast cursor position
        emitCursorMove(position, tab) {
            const s = this._socket();
            if (s) s.emit('team_cursor_move', { position, tab });
        },

        // Socket.IO: Broadcast scan event
        emitScanEvent(scanType, target, status, resultsCount) {
            const s = this._socket();
            if (s) s.emit('team_scan_event', { scan_type: scanType, target, status, results_count: resultsCount || 0 });
        },

        // Socket.IO: Broadcast finding
        emitFinding(finding) {
            const s = this._socket();
            if (s) s.emit('team_finding', { finding });
        },

        // Socket.IO: Broadcast endpoint discovery
        emitEndpoint(endpoint) {
            const s = this._socket();
            if (s) s.emit('team_endpoint_add', { endpoint });
        },

        // Register all team event listeners on the global socket
        registerListeners(handlers) {
            const s = this._socket();
            if (!s) {
                console.warn('[Team] Global socket not available yet. Retrying in 1s...');
                setTimeout(() => this.registerListeners(handlers), 1000);
                return;
            }

            s.on('team_roster', handlers.onRoster);
            s.on('team_activity', handlers.onActivity);
            s.on('team_state', handlers.onState);
            s.on('team_notes_sync', handlers.onNotesSync);
            s.on('team_endpoint_sync', handlers.onEndpointSync);
            s.on('team_cursor_sync', handlers.onCursorSync);
            s.on('team_error', handlers.onError);
        },
    };

    // ─────────────────────────────────────────────────────────────────
    // TeamUI: DOM rendering
    // Pure rendering functions — no transport or state logic.
    // ─────────────────────────────────────────────────────────────────
    const TeamUI = {
        refs: {
            connectSection: connectSection,
            connectedSection: document.getElementById('team-connected-section'),
            activeCode: document.getElementById('team-active-code'),
            roster: document.getElementById('team-roster'),
            activityFeed: document.getElementById('team-activity-feed'),
            roomBadge: document.getElementById('team-room-badge'),
            onlineDot: document.getElementById('team-online-dot'),
            nameInput: document.getElementById('team-operator-name'),
        },

        showConnected(roomCode) {
            this.refs.connectSection.style.display = 'none';
            this.refs.connectedSection.style.display = 'flex';
            this.refs.activeCode.textContent = roomCode;
            if (this.refs.roomBadge) { this.refs.roomBadge.style.display = 'block'; this.refs.roomBadge.textContent = roomCode; }
            if (this.refs.onlineDot) this.refs.onlineDot.style.display = 'block';
            this.refs.activityFeed.innerHTML = '';
        },

        showDisconnected() {
            this.refs.connectSection.style.display = 'block';
            this.refs.connectedSection.style.display = 'none';
            if (this.refs.roomBadge) this.refs.roomBadge.style.display = 'none';
            if (this.refs.onlineDot) this.refs.onlineDot.style.display = 'none';
            this.refs.roster.innerHTML = '';
            this.refs.activityFeed.innerHTML = '<div class="empty-state" style="flex-direction: column; gap: 8px;"><span>Create or join a room to start collaborating.</span></div>';
        },

        renderRoster(operators, myName) {
            const el = this.refs.roster;
            if (!el) return;
            el.innerHTML = '';

            operators.forEach(op => {
                const row = document.createElement('div');
                row.style.cssText = 'display: flex; align-items: center; gap: 10px; padding: 8px 10px; background: var(--bg-card); border-radius: 8px; border: 1px solid var(--border-color);';
                const isMe = op.name === myName;
                row.innerHTML = `
                    <div style="width: 32px; height: 32px; border-radius: 50%; background: ${op.color}; display: flex; align-items: center; justify-content: center; font-weight: 700; font-size: 13px; color: #fff; flex-shrink: 0;">
                        ${esc(op.name.charAt(0).toUpperCase())}
                    </div>
                    <div style="flex: 1; min-width: 0;">
                        <div style="font-size: 12px; font-weight: 600; color: var(--text-primary); overflow: hidden; text-overflow: ellipsis; white-space: nowrap;">
                            ${esc(op.name)} ${isMe ? '<span style="font-size: 9px; color: var(--accent); font-weight: 400;">(you)</span>' : ''}
                        </div>
                        <div style="font-size: 10px; color: var(--text-muted);">Online</div>
                    </div>
                    <div style="width: 8px; height: 8px; border-radius: 50%; background: var(--safe); flex-shrink: 0;"></div>
                `;
                el.appendChild(row);
            });
        },

        addActivityEntry(data) {
            const feed = this.refs.activityFeed;
            if (!feed) return;

            const emptyState = feed.querySelector('.empty-state');
            if (emptyState) emptyState.remove();

            const entry = document.createElement('div');
            entry.style.cssText = 'display: flex; gap: 10px; padding: 10px 0; border-bottom: 1px solid var(--border-color); animation: slideUp 0.3s ease;';

            const time = data.time ? new Date(data.time).toLocaleTimeString() : '';
            let icon = '-';
            let message = '';

            switch (data.type) {
                case 'join':
                    icon = '+'; message = `<strong>${esc(data.operator)}</strong> joined the room`; break;
                case 'leave':
                    icon = '-'; message = `<strong>${esc(data.operator)}</strong> left the room`; break;
                case 'scan':
                    icon = data.status === 'started' ? '>' : 'ok';
                    message = `<strong>${esc(data.operator)}</strong> ${data.status === 'started' ? 'started' : 'completed'} <span style="color: var(--accent);">${esc(data.scan_type)}</span> on ${esc(data.target)}`;
                    if (data.results_count) message += ` (${data.results_count} results)`;
                    break;
                case 'finding':
                    icon = '!!';
                    const sev = data.finding?.severity || 'INFO';
                    const sevColor = sev === 'CRITICAL' ? 'var(--danger)' : sev === 'HIGH' ? '#f97316' : 'var(--warning)';
                    message = `<strong>${esc(data.operator)}</strong> found <span style="color: ${sevColor};">[${sev}]</span> ${esc(data.finding?.title || 'vulnerability')}`;
                    break;
                case 'endpoint':
                    icon = 'ep';
                    message = `<strong>${esc(data.operator)}</strong> discovered endpoint: <span style="color: var(--accent); font-family: var(--font-mono);">${esc(data.endpoint?.url || data.endpoint || '')}</span>`;
                    break;
                case 'system':
                    icon = '--'; message = data.message || 'System event'; break;
                default:
                    message = `<strong>${esc(data.operator || 'Unknown')}</strong>: ${data.type || 'event'}`;
            }

            entry.innerHTML = `
                <div style="width: 24px; height: 24px; border-radius: 50%; background: ${data.color || '#333'}; display: flex; align-items: center; justify-content: center; font-size: 9px; font-weight: 700; flex-shrink: 0; color: #fff; font-family: var(--font-mono);">
                    ${icon}
                </div>
                <div style="flex: 1; min-width: 0;">
                    <div style="font-size: 12px; color: var(--text-secondary); line-height: 1.5;">${message}</div>
                    <div style="font-size: 10px; color: var(--text-muted); margin-top: 2px;">${time}</div>
                </div>
            `;

            feed.appendChild(entry);
            feed.scrollTop = feed.scrollHeight;
        },
    };

    // ─────────────────────────────────────────────────────────────────
    // TeamController: Coordinates TeamClient and TeamUI
    // Manages state, wires events, handles user actions.
    // ─────────────────────────────────────────────────────────────────
    const state = {
        connected: false,
        roomCode: null,
        operatorName: '',
        operators: [],
    };

    // Register Socket.IO event listeners on the existing global socket
    TeamClient.registerListeners({
        onRoster(data) {
            state.operators = data.operators || [];
            TeamUI.renderRoster(state.operators, state.operatorName);
            // Update status bar operator count
            const el = document.getElementById('status-schedulers');
            if (el && state.connected) el.textContent = `${state.operators.length} operators`;
        },

        onActivity(data) {
            TeamUI.addActivityEntry(data);
        },

        onState(data) {
            // Sync shared state when first joining a room
            if (data.shared_notes) {
                const editor = document.getElementById('notes-editor');
                if (editor) editor.value = data.shared_notes;
            }
        },

        onNotesSync(data) {
            const editor = document.getElementById('notes-editor');
            if (editor) {
                const pos = editor.selectionStart;
                editor.value = data.content;
                editor.selectionStart = pos;
                editor.selectionEnd = pos;
            }
        },

        onEndpointSync(data) {
            TeamUI.addActivityEntry({
                type: 'endpoint',
                operator: data.operator,
                color: data.color,
                endpoint: data.endpoint,
                time: new Date().toISOString(),
            });
        },

        onCursorSync(data) {
            // Future: render remote cursors on the notes editor
        },

        onError(data) {
            log('vuln', `[Team] Error: ${data.error || 'Unknown error'}`);
        },
    });

    // ── Create Room ─────────────────────────────────────────────────
    document.getElementById('team-create-btn')?.addEventListener('click', async () => {
        const name = TeamUI.refs.nameInput?.value?.trim() || 'Operator';
        state.operatorName = name;

        try {
            const data = await TeamClient.createRoom(name, document.getElementById('target-url')?.value || '');
            if (data.status === 'success') {
                enterRoom(data.room_code, name);
            }
        } catch (e) {
            log('vuln', `[Team] Failed to create room: ${e.message}`);
        }
    });

    // ── Join Room ───────────────────────────────────────────────────
    document.getElementById('team-join-btn')?.addEventListener('click', async () => {
        const code = document.getElementById('team-join-code')?.value?.trim().toUpperCase();
        const name = TeamUI.refs.nameInput?.value?.trim() || 'Operator';
        if (!code || code.length < 4) return;

        state.operatorName = name;

        try {
            const data = await TeamClient.validateRoom(code);
            if (data.status === 'success') {
                enterRoom(data.room_code, name);
            }
        } catch (e) {
            log('vuln', `[Team] ${e.message}`);
        }
    });

    function enterRoom(roomCode, name) {
        state.connected = true;
        state.roomCode = roomCode;

        TeamUI.showConnected(roomCode);
        TeamClient.emitJoin(roomCode, name);
        hookNotesSync();
        log('info', `[Team] Joined room ${roomCode} as ${name}`);
    }

    // ── Leave Room ──────────────────────────────────────────────────
    document.getElementById('team-leave-btn')?.addEventListener('click', () => {
        TeamClient.emitLeave();
        state.connected = false;
        state.roomCode = null;
        state.operators = [];
        TeamUI.showDisconnected();
        log('info', '[Team] Left the team room.');
    });

    // ── Copy Room Code ──────────────────────────────────────────────
    document.getElementById('team-share-room')?.addEventListener('click', () => {
        if (!state.roomCode) return;
        navigator.clipboard.writeText(state.roomCode);
        const btn = document.getElementById('team-share-room');
        const orig = btn.textContent;
        btn.textContent = 'Copied';
        btn.style.color = 'var(--safe)';
        setTimeout(() => { btn.textContent = orig; btn.style.color = ''; }, 1500);
    });

    // ── Notes Real-Time Sync ────────────────────────────────────────
    let _notesHooked = false;
    function hookNotesSync() {
        if (_notesHooked) return;
        _notesHooked = true;

        const editor = document.getElementById('notes-editor');
        if (!editor) return;

        let debounce = null;
        editor.addEventListener('input', () => {
            if (!state.connected) return;
            clearTimeout(debounce);
            debounce = setTimeout(() => {
                TeamClient.emitNotesUpdate(editor.value, editor.selectionStart);
            }, 300);
        });
    }

    // ── Public API: expose to other modules ─────────────────────────
    // Other tools (CyberNode, scanners, etc.) call these to broadcast
    // events to the team without knowing about Socket.IO internals.
    window.WSHawkTeam = {
        isConnected: () => state.connected,
        broadcastScanEvent: (scanType, target, status, resultsCount) => {
            if (!state.connected) return;
            TeamClient.emitScanEvent(scanType, target, status, resultsCount);
        },
        broadcastFinding: (finding) => {
            if (!state.connected) return;
            TeamClient.emitFinding(finding);
        },
        broadcastEndpoint: (endpoint) => {
            if (!state.connected) return;
            TeamClient.emitEndpoint(endpoint);
        },
    };

})();
