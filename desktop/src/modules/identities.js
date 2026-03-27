(function initIdentitiesModule(global) {
    const modules = global.WSHawkModules = global.WSHawkModules || {};

    function populateIdentitySelect(select, identities = [], placeholder = 'Anonymous Replay') {
        if (!select) return;

        const previousValue = select.value;
        select.innerHTML = '';
        const placeholderOption = document.createElement('option');
        placeholderOption.value = '';
        placeholderOption.textContent = placeholder;
        select.appendChild(placeholderOption);

        identities.forEach(identity => {
            const option = document.createElement('option');
            option.value = identity.id;
            option.textContent = `${identity.alias} · ${identity.source || 'manual'}`;
            select.appendChild(option);
        });

        if (previousValue && identities.some(identity => identity.id === previousValue)) {
            select.value = previousValue;
        }
    }

    modules.identities = {
        setReqForgePlatformStatus(message, tone = 'muted') {
            const status = document.getElementById('reqforge-platform-status');
            if (!status) return;

            const colors = {
                muted: 'var(--text-muted)',
                info: 'var(--accent)',
                success: 'var(--success)',
                danger: 'var(--danger)',
            };

            status.textContent = message;
            status.style.color = colors[tone] || colors.muted;
        },

        renderReqForgeIdentities(identities = []) {
            const reqforgeSelect = document.getElementById('reqforge-identity-select');
            const httpSelect = document.getElementById('http-identity-select');
            const previousReqforge = reqforgeSelect?.value || '';
            const previousHttp = httpSelect?.value || '';

            populateIdentitySelect(reqforgeSelect, identities, 'Anonymous Replay');
            populateIdentitySelect(httpSelect, identities, 'Current Headers / Anonymous');
            populateIdentitySelect(document.getElementById('chain-identity-select'), identities, 'Workflow Default Identity');

            const preferred = previousHttp || previousReqforge;
            if (preferred && identities.some(identity => identity.id === preferred)) {
                if (reqforgeSelect && !reqforgeSelect.value) reqforgeSelect.value = preferred;
                if (httpSelect && !httpSelect.value) httpSelect.value = preferred;
            }
        },

        async refreshReqForgeIdentities(ctx, { announceErrors = false } = {}) {
            const currentProject = ctx.getCurrentProject();
            if (!currentProject.projectId) {
                ctx.platformState.reqforgeIdentityCache = [];
                this.renderReqForgeIdentities([]);
                this.setReqForgePlatformStatus(
                    ctx.targetUrlInput.value.trim()
                        ? 'Project-backed replay will start automatically on first operation.'
                        : 'Set a target URL to create a project-backed offensive workspace.',
                    'muted'
                );
                return [];
            }

            try {
                const res = await fetch(`/platform/projects/${currentProject.projectId}/identities`);
                const data = await res.json();
                ctx.platformState.reqforgeIdentityCache = data.identities || [];
                this.renderReqForgeIdentities(ctx.platformState.reqforgeIdentityCache);

                if (ctx.platformState.reqforgeIdentityCache.length > 0) {
                    this.setReqForgePlatformStatus(
                        `Loaded ${ctx.platformState.reqforgeIdentityCache.length} project identity${ctx.platformState.reqforgeIdentityCache.length === 1 ? '' : 'ies'} for replay and AuthZ diff.`,
                        'success'
                    );
                } else {
                    this.setReqForgePlatformStatus(
                        'No stored identities yet. Record DOM auth, then store it here to unlock role-aware replay.',
                        'info'
                    );
                }
                return ctx.platformState.reqforgeIdentityCache;
            } catch (error) {
                ctx.platformState.reqforgeIdentityCache = [];
                this.renderReqForgeIdentities([]);
                this.setReqForgePlatformStatus('Identity vault unavailable for the current project.', 'danger');
                if (announceErrors) {
                    ctx.appendLog('vuln', `[Platform] Failed to load identities: ${error.message}`);
                }
                return [];
            }
        }
    };
})(window);
