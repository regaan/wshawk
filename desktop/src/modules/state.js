(function createRendererState(global) {
    'use strict';

    const state = {
        bridge: { port: 8080, ready: false, connectRequested: false },
        mode: { current: 'standard', advanced: false },
        project: {
            projectId: null,
            url: '',
            vulns: 0,
            msgs: 0,
            findings: [],
            logs: [],
            history: [],
        },
        platform: {
            syncPromise: null,
            refreshTimer: null,
            refreshQueued: null,
            refreshing: false,
            reqforgeIdentityCache: [],
            lastAnnouncement: null,
        },
        counters: { messages: 0, handshakes: 0, history: 1 },
    };

    global.WSHawkRendererState = state;
})(window);
