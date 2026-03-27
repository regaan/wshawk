(function initTrafficModule(global) {
    const modules = global.WSHawkModules = global.WSHawkModules || {};

    modules.traffic = {
        clearHistoryStore(historyData) {
            Object.keys(historyData).forEach(key => delete historyData[key]);
        },

        resetHistoryView({ historyTbody, historyData, message = 'Awaiting traffic capture...' }) {
            this.clearHistoryStore(historyData);
            historyTbody.innerHTML = `<tr class="empty-tr"><td colspan="6">${global.esc ? global.esc(message) : message}</td></tr>`;
        },

        addHistoryRow({ historyTbody, historyData, dir, data, options = {} }) {
            if (historyTbody.querySelector('.empty-tr')) {
                historyTbody.innerHTML = '';
            }

            const rowId = options.rowId || `h${Date.now()}${Math.random().toString(16).slice(2, 8)}`;
            if (historyData[rowId]) {
                return rowId;
            }

            historyData[rowId] = typeof data === 'string' ? data : JSON.stringify(data);
            const rowNumber = options.rowNumber || Object.keys(historyData).length;
            const time = options.time || new Date().toLocaleTimeString('en-US', { hour12: false });
            const size = options.size ?? (typeof data === 'string' ? new Blob([data]).size : JSON.stringify(data).length);
            const truncate = global.truncate || ((value) => String(value));
            const esc = global.esc || ((value) => String(value));
            const html = `
                <tr data-row-id="${esc(rowId)}">
                    <td>#${rowNumber}</td>
                    <td class="dir-${String(dir || 'info').toLowerCase()}">${esc(dir)}</td>
                    <td>${esc(time)}</td>
                    <td>${size}B</td>
                    <td>${esc(truncate(data, 90))}</td>
                    <td><button class="history-replay-btn" data-action="send-to-forge" data-row-id="${esc(rowId)}">→ Forge</button></td>
                </tr>
            `;
            historyTbody.insertAdjacentHTML('afterbegin', html);
            return rowId;
        },

        eventToHistoryMessage(event) {
            const payload = event.payload || {};
            if (payload.message !== undefined) {
                return typeof payload.message === 'string' ? payload.message : JSON.stringify(payload.message);
            }
            if (payload.response !== undefined) {
                return typeof payload.response === 'string' ? payload.response : JSON.stringify(payload.response);
            }
            if (payload.result) {
                if (payload.result.response) return payload.result.response;
                if (payload.result.error) return payload.result.error;
                if (payload.result.payload) return payload.result.payload;
                if (payload.result.status) return payload.result.status;
            }
            if (payload.payload !== undefined) {
                return typeof payload.payload === 'string' ? payload.payload : JSON.stringify(payload.payload);
            }
            return typeof payload === 'string' ? payload : JSON.stringify(payload);
        },

        renderPlatformTimeline({ historyTbody, historyData, events = [] }) {
            const trafficEvents = (events || []).filter(event => {
                if (event.direction === 'in' || event.direction === 'out') return true;
                return [
                    'ws_platform_replay_error',
                    'ws_platform_replay_timeout',
                    'http_request_replayed',
                    'ws_authz_diff_result',
                ].includes(event.event_type);
            });

            if (!trafficEvents.length) {
                this.resetHistoryView({ historyTbody, historyData, message: 'Project timeline is ready. Run scans, replays, or proxy traffic to populate it.' });
                return 0;
            }

            this.clearHistoryStore(historyData);
            historyTbody.innerHTML = '';

            [...trafficEvents].reverse().forEach((event, index) => {
                const direction = event.direction ? event.direction.toUpperCase() : 'INFO';
                this.addHistoryRow({
                    historyTbody,
                    historyData,
                    dir: direction,
                    data: this.eventToHistoryMessage(event),
                    options: {
                        rowId: event.id,
                        rowNumber: index + 1,
                        time: new Date(event.created_at).toLocaleTimeString('en-US', { hour12: false }),
                    }
                });
            });

            return trafficEvents.length;
        }
    };
})(window);
