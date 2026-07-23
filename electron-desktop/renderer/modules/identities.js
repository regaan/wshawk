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
            const recordedUser = identity.storage?.auth_user
                || identity.storage?.username
                || identity.tokens?.auth_user
                || identity.tokens?.username
                || '';
            const storedAlias = identity.alias
                || identity.name
                || '';
            const alias = (recordedUser && /^captured-user(?:-|$)/i.test(storedAlias) ? recordedUser : storedAlias)
                || recordedUser
                || (identity.id ? `identity-${String(identity.id).slice(-8)}` : 'captured-identity');
            option.textContent = `${alias} · ${identity.source || identity.metadata?.source || 'manual'}`;
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
            const reqforgeCompareSelect = document.getElementById('reqforge-compare-identity-select');
            const httpSelect = document.getElementById('http-identity-select');
            const httpCompareSelect = document.getElementById('http-compare-identity-select');
            const previousReqforge = reqforgeSelect?.value || '';
            const previousReqforgeCompare = reqforgeCompareSelect?.value || '';
            const previousHttp = httpSelect?.value || '';
            const previousHttpCompare = httpCompareSelect?.value || '';

            populateIdentitySelect(reqforgeSelect, identities, 'Anonymous Replay');
            populateIdentitySelect(reqforgeCompareSelect, identities, 'Comparison Identity');
            populateIdentitySelect(httpSelect, identities, 'Current Headers / Anonymous');
            populateIdentitySelect(httpCompareSelect, identities, 'Choose comparison identity');
            populateIdentitySelect(document.getElementById('chain-identity-select'), identities, 'Workflow Default Identity');

            const preferred = previousHttp || previousReqforge;
            if (preferred && identities.some(identity => identity.id === preferred)) {
                if (reqforgeSelect && !reqforgeSelect.value) reqforgeSelect.value = preferred;
                if (httpSelect && !httpSelect.value) httpSelect.value = preferred;
            }

            if (httpCompareSelect) {
                if (previousHttpCompare && identities.some(identity => identity.id === previousHttpCompare)) {
                    httpCompareSelect.value = previousHttpCompare;
                }
                if (!httpCompareSelect.value || httpCompareSelect.value === httpSelect?.value) {
                    httpCompareSelect.value = identities.find(identity => identity.id !== httpSelect?.value)?.id || '';
                }
            }

			if (reqforgeCompareSelect) {
				if (previousReqforgeCompare && identities.some(identity => identity.id === previousReqforgeCompare)) reqforgeCompareSelect.value = previousReqforgeCompare;
				if (!reqforgeCompareSelect.value || reqforgeCompareSelect.value === reqforgeSelect?.value) {
					reqforgeCompareSelect.value = identities.find(identity => identity.id !== reqforgeSelect?.value)?.id || '';
				}
			}

            if (httpSelect && httpCompareSelect && !httpSelect.dataset.diffPairBound) {
                httpSelect.dataset.diffPairBound = 'true';
                const chooseDifferentComparison = () => Array.from(httpCompareSelect.options)
                    .find(option => option.value && option.value !== httpSelect.value)?.value || '';
                httpSelect.addEventListener('change', () => {
                    if (!httpCompareSelect.value || httpCompareSelect.value === httpSelect.value) {
                        httpCompareSelect.value = chooseDifferentComparison();
                    }
                });
                httpCompareSelect.addEventListener('change', () => {
                    if (httpCompareSelect.value && httpCompareSelect.value === httpSelect.value) {
                        httpCompareSelect.value = chooseDifferentComparison();
                    }
                });
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
                const res = await ipcRequest(`/platform/projects/${currentProject.projectId}/identities`);
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
