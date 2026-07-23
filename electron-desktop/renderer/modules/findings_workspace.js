(function findingsWorkspace(global) {
	'use strict';
	const state = { items: [], selectedId: '', selected: new Set(), revealed: new Set() };
	const byId = id => state.items.find(item => item.id === id);
	const projectId = () => global.getCurrentProject?.()?.projectId || '';

	function element(name, text = '', attributes = {}) {
		const node = document.createElement(name);
		if (text !== '') node.textContent = text;
		for (const [key, value] of Object.entries(attributes)) {
			if (key === 'class') node.className = value;
			else if (key === 'title') node.title = value;
			else node.setAttribute(key, value);
		}
		return node;
	}

	function filtered() {
		const query = String(document.getElementById('findings-search')?.value || '').toLowerCase();
		const status = document.getElementById('findings-status-filter')?.value || '';
		const severity = document.getElementById('findings-severity-filter')?.value || '';
		return state.items.filter(item => {
			const metadata = item.metadata || {};
			const search = [metadata.title, item.name, metadata.url, metadata.policy_mode, metadata.type].join(' ').toLowerCase();
			return (!query || search.includes(query)) && (!status || metadata.lifecycle_status === status) && (!severity || String(metadata.severity).toUpperCase() === severity);
		});
	}

	async function updateFinding(id, update) {
		const response = await global.ipcRequest(`/platform/projects/${projectId()}/findings/${encodeURIComponent(id)}`, { method: 'PATCH', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify(update) });
		const data = await response.json();
		if (!response.ok) throw new Error(data.detail || `Finding update failed (${response.status})`);
		await load();
	}

	async function retest(id) {
		const response = await global.ipcRequest(`/platform/projects/${projectId()}/findings/${encodeURIComponent(id)}/retest`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: '{}' });
		const data = await response.json();
		if (!response.ok) throw new Error(data.detail || `Finding retest failed (${response.status})`);
		await load();
	}

	function selectEditor(values, current, onChange) {
		const select = element('select');
		select.style.cssText = 'font-size:10px;height:26px;';
		for (const value of values) { const option = element('option', value); option.value = value; option.selected = String(current).toLowerCase() === value.toLowerCase(); select.appendChild(option); }
		select.addEventListener('change', () => onChange(select.value));
		return select;
	}

	function renderTable() {
		const body = document.getElementById('findings-workspace-body');
		if (!body) return;
		body.replaceChildren();
		for (const item of filtered()) {
			const metadata = item.metadata || {}; const row = element('tr'); row.dataset.findingId = item.id;
			row.style.cssText = `border-bottom:1px solid var(--border-color);${state.selectedId === item.id ? 'background:rgba(0,255,170,.06);' : ''}`;
			const checkboxCell = element('td'); const checkbox = element('input'); checkbox.type = 'checkbox'; checkbox.checked = state.selected.has(item.id); checkbox.addEventListener('change', () => { checkbox.checked ? state.selected.add(item.id) : state.selected.delete(item.id); }); checkboxCell.appendChild(checkbox); row.appendChild(checkboxCell);
			const titleCell = element('td'); titleCell.style.cssText = 'padding:8px;max-width:260px;cursor:pointer;'; titleCell.appendChild(element('div', metadata.title || item.name || 'Untitled', { class: 'text-primary' })); titleCell.appendChild(element('div', metadata.url || metadata.type || '', { class: 'text-muted' })); if (metadata.duplicate_count) titleCell.appendChild(element('span', `deduplicated ×${metadata.duplicate_count + 1}`, { class: 'badge' })); titleCell.addEventListener('click', () => { state.selectedId = item.id; renderTable(); renderPreview(); }); row.appendChild(titleCell);
			const severityCell = element('td'); severityCell.appendChild(selectEditor(['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL'], metadata.severity || 'INFO', value => updateFinding(item.id, { severity: value }).catch(showError))); row.appendChild(severityCell);
			const confidenceCell = element('td'); confidenceCell.appendChild(selectEditor(['none', 'low', 'medium', 'high', 'confirmed'], metadata.confidence || 'medium', value => updateFinding(item.id, { confidence: value }).catch(showError))); row.appendChild(confidenceCell);
			const statusCell = element('td'); statusCell.appendChild(selectEditor(['open', 'confirmed', 'rejected', 'fixed', 'inconclusive'], metadata.lifecycle_status || 'open', value => updateFinding(item.id, { lifecycle_status: value }).catch(showError))); row.appendChild(statusCell);
			row.appendChild(element('td', metadata.last_retest_classification || 'not retested'));
			const actionCell = element('td'); const button = element('button', 'Retest', { class: 'btn secondary small' }); button.disabled = !metadata.category?.includes('authorization'); button.addEventListener('click', async () => { button.disabled = true; button.textContent = 'Retesting…'; try { await retest(item.id); } catch (error) { showError(error); } }); actionCell.appendChild(button); row.appendChild(actionCell);
			body.appendChild(row);
		}
		const counts = state.items.reduce((map, item) => { const key = item.metadata?.lifecycle_status || 'open'; map[key] = (map[key] || 0) + 1; return map; }, {});
		document.getElementById('findings-workspace-summary').textContent = `${state.items.length} findings · ${Object.entries(counts).map(([key, value]) => `${key} ${value}`).join(' · ')} · ${state.selected.size} selected`;
	}

	function evidenceValue(item) { try { return JSON.parse(item.value || '{}'); } catch (_) { return { raw: item.value || '' }; } }

	function renderPreview() {
		const container = document.getElementById('findings-evidence-preview'); const item = byId(state.selectedId);
		if (!container) return; container.replaceChildren();
		if (!item) { container.appendChild(element('div', 'Select a finding to preview sanitized evidence.', { class: 'empty-state' })); return; }
		const metadata = item.metadata || {}; const evidence = evidenceValue(item); const revealed = state.revealed.has(item.id);
		container.appendChild(element('h3', metadata.title || item.name));
		container.appendChild(element('p', `${metadata.type || 'finding'} · ${metadata.severity || 'INFO'} · ${metadata.confidence || 'unknown'} confidence · ${metadata.lifecycle_status || 'open'}`, { class: 'text-muted' }));
		const overview = element('pre'); overview.style.cssText = 'white-space:pre-wrap;font-size:10px;'; overview.textContent = JSON.stringify({ endpoint: evidence.endpoint || metadata.url, policy: evidence.policy, attacker: evidence.attacker, owner_control: evidence.owner_control, evidence_mode: evidence.evidence_mode, tested_at: evidence.tested_at, wshawk_version: evidence.wshawk_version, target_fingerprint: evidence.target_fingerprint, response_hashes: metadata.response_hashes, curl_reproduction: evidence.curl_reproduction }, null, 2); container.appendChild(overview);
		const controls = element('div'); controls.style.cssText = 'display:flex;gap:8px;margin:10px 0;';
		const reveal = element('button', revealed ? 'Evidence Revealed' : 'Reveal Evidence', { class: 'btn secondary small' }); reveal.disabled = revealed; reveal.addEventListener('click', () => confirmReveal(item.id)); controls.appendChild(reveal);
		const copy = element('button', 'Copy Evidence', { class: 'btn secondary small' }); copy.disabled = !revealed; copy.addEventListener('click', () => navigator.clipboard.writeText(JSON.stringify(evidence, null, 2)).catch(showError)); controls.appendChild(copy); container.appendChild(controls);
		if (revealed) { const full = element('pre'); full.style.cssText = 'white-space:pre-wrap;font-size:10px;border:1px solid var(--border-color);padding:8px;'; full.textContent = JSON.stringify(evidence, null, 2); container.appendChild(full); }
	}

	function confirmReveal(id) {
		const dialog = document.getElementById('finding-reveal-dialog');
		if (!dialog?.showModal) return;
		document.getElementById('finding-reveal-cancel').onclick = () => dialog.close();
		document.getElementById('finding-reveal-confirm').onclick = () => { state.revealed.add(id); dialog.close(); renderPreview(); };
		dialog.showModal();
	}

	function showError(error) { document.getElementById('findings-workspace-summary').textContent = `Error: ${error.message || error}`; }

	async function load() {
		if (!projectId()) { state.items = []; renderTable(); renderPreview(); return; }
		const response = await global.ipcRequest(`/platform/projects/${projectId()}/findings?limit=5000`); const data = await response.json();
		if (!response.ok) throw new Error(data.detail || `Findings load failed (${response.status})`);
		state.items = data.findings || data.items || [];
		if (state.selectedId && !byId(state.selectedId)) state.selectedId = '';
		renderTable(); renderPreview();
	}

	async function exportSelected() {
		if (!state.selected.size) throw new Error('Select at least one finding before export.');
		const format = document.getElementById('findings-export-format').value;
		const response = await global.ipcRequest(`/platform/projects/${projectId()}/findings/export-selected`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ finding_ids: [...state.selected], format }) });
		const data = await response.json(); if (!response.ok) throw new Error(data.detail || `Export failed (${response.status})`);
		await global.WSHawkIPC.invoke('dialog.report.save', { content: data.content, extension: format === 'markdown' ? 'md' : format });
	}

	document.getElementById('findings-refresh')?.addEventListener('click', () => load().catch(showError));
	document.getElementById('findings-export-selected')?.addEventListener('click', () => exportSelected().catch(showError));
	for (const id of ['findings-search', 'findings-status-filter', 'findings-severity-filter']) document.getElementById(id)?.addEventListener(id === 'findings-search' ? 'input' : 'change', renderTable);
	document.querySelector('.nav-item[data-target="findingsworkspace"]')?.addEventListener('click', () => load().catch(showError));
	global.WSHawkFindingsWorkspace = Object.freeze({ load });
})(window);
