'use strict';

(() => {
    const subscriptions = new Map();
    let lastConnectionId = '';
    let lastOperationId = '';
	let lastProjectId = '';
	let activeBlaster = null;
	let activeVulnerabilityScan = null;

    class IPCHeaders {
        constructor(values = {}) { this.values = values; }
        get(name) {
            const key = Object.keys(this.values).find(item => item.toLowerCase() === String(name).toLowerCase());
            const value = key ? this.values[key] : undefined;
            return Array.isArray(value) ? value.join(', ') : (value ?? null);
        }
        *entries() {
            for (const [key, value] of Object.entries(this.values)) {
                yield [key, Array.isArray(value) ? value.join(', ') : String(value)];
            }
        }
    }

    class IPCResponse {
        constructor(status, data, headers = {}) {
            this.status = status;
            this.ok = status >= 200 && status < 300;
            this.statusText = this.ok ? 'OK' : 'IPC Error';
            this.data = data;
            this.headers = new IPCHeaders(headers);
        }
        async json() { return this.data; }
        async text() { return typeof this.data === 'string' ? this.data : JSON.stringify(this.data); }
		async blob() { return new Blob([await this.text()], { type: this.headers.get('content-type') || 'application/octet-stream' }); }
    }

    function parseBody(init = {}) {
        if (init.body === undefined || init.body === null || init.body === '') return {};
        if (typeof init.body === 'object') return init.body;
        try { return JSON.parse(init.body); } catch (_) { return { body: String(init.body) }; }
    }

    function normalizeHeaders(value) {
        if (!value) return {};
        if (typeof value === 'object' && !Array.isArray(value)) return value;
        const result = {};
        for (const line of String(value).split(/\r?\n/)) {
            const index = line.indexOf(':');
            if (index > 0) result[line.slice(0, index).trim()] = line.slice(index + 1).trim();
        }
        return result;
    }

	function escapeHTML(value) {
		return String(value ?? '').replace(/[&<>"']/g, char => ({ '&': '&amp;', '<': '&lt;', '>': '&gt;', '"': '&quot;', "'": '&#39;' })[char]);
	}

	function titleSeverity(value) {
		return String(value || 'info').replace(/^./, char => char.toUpperCase());
	}

	function boundedInteger(value, fallback, minimum, maximum) {
		return Math.min(maximum, Math.max(minimum, Number(value) || fallback));
	}

	function responseHeader(headers, name) {
		const values = headers || {};
		const key = Object.keys(values).find(item => item.toLowerCase() === String(name).toLowerCase());
		if (!key) return '';
		const value = values[key];
		return Array.isArray(value) ? value.join(', ') : String(value ?? '');
	}

	function substituteVariables(value, variables = {}) {
		return String(value ?? '').replace(/\{\{([A-Za-z_][A-Za-z0-9_.-]{0,127})\}\}/g, (match, name) => Object.hasOwn(variables, name) ? String(variables[name]) : match);
	}

	function expandIdentity(entity) {
		const metadata = entity?.metadata && typeof entity.metadata === 'object' ? entity.metadata : {};
		const tokens = metadata.tokens && typeof metadata.tokens === 'object' ? metadata.tokens : {};
		const storage = metadata.storage && typeof metadata.storage === 'object' ? metadata.storage : {};
		const recordedUser = storage.auth_user || storage.username || tokens.auth_user || tokens.username || '';
		const storedAlias = metadata.alias
			|| entity?.alias
			|| entity?.name;
		const alias = (recordedUser && /^captured-user(?:-|$)/i.test(storedAlias || '') ? recordedUser : storedAlias)
			|| recordedUser
			|| (entity?.id ? `identity-${String(entity.id).slice(-8)}` : 'captured-identity');
		return {
			...metadata,
			id: entity?.id || metadata.id || '',
			alias,
			source: metadata.source || entity?.source || 'manual',
			created_at: entity?.created_at || metadata.created_at || '',
			updated_at: entity?.updated_at || metadata.updated_at || '',
		};
	}

	function identityHeaders(identity) {
		const headers = normalizeHeaders(identity?.headers || {});
		const tokens = identity?.tokens || {};
		const bearer = tokens.session_token || tokens.access_token || tokens.jwt || tokens.token;
		if (bearer && !Object.keys(headers).some(key => key.toLowerCase() === 'authorization')) headers.Authorization = `Bearer ${bearer}`;
		const cookies = Array.isArray(identity?.cookies) ? identity.cookies.filter(item => item?.name).map(item => `${item.name}=${item.value || ''}`).join('; ') : '';
		if (cookies && !Object.keys(headers).some(key => key.toLowerCase() === 'cookie')) headers.Cookie = cookies;
		return headers;
	}

	function authFlowHeaders(flow) {
		const headers = normalizeHeaders(flow?.ws_headers || flow?.headers || {});
		const cookies = Array.isArray(flow?.cookies)
			? flow.cookies.filter(item => item?.name).map(item => `${item.name}=${item.value || ''}`).join('; ')
			: '';
		if (cookies && !Object.keys(headers).some(key => key.toLowerCase() === 'cookie')) headers.Cookie = cookies;
		const tokens = flow?.extracted_tokens || {};
		const bearer = tokens.access_token || tokens.session_token || tokens.jwt || tokens.token;
		if (bearer && !Object.keys(headers).some(key => key.toLowerCase() === 'authorization')) headers.Authorization = `Bearer ${bearer}`;
		return headers;
	}

	function applyBlasterTemplate(template, payload) {
		const source = String(template || '§inject§');
		if (source.includes('§inject§')) return source.split('§inject§').join(payload);
		if (source.includes('§')) return source.split('§').join(payload);
		if (source.includes('{{payload}}')) return source.split('{{payload}}').join(payload);
		if (source.includes('FUZZ')) return source.split('FUZZ').join(payload);
		return payload;
	}

	function tokenLikeStorage(storage = {}) {
		const result = {};
		for (const [key, value] of Object.entries(storage)) {
			if (/(token|jwt|auth|session)/i.test(key) && typeof value === 'string' && value.length <= 16_384) result[key] = value;
		}
		return result;
	}

	async function loadIdentity(id) {
		if (!id) return null;
		const result = await invoke('entities.get', { kind: 'identities', id });
		return expandIdentity(result.item);
	}

	function requestFromTemplate(template = {}, variables = {}, identity = null, projectId = '') {
		const headers = { ...normalizeHeaders(template.headers), ...identityHeaders(identity) };
		for (const [key, value] of Object.entries(headers)) headers[key] = substituteVariables(value, variables);
		return { project_id: projectId, method: template.method || 'GET', url: substituteVariables(template.url, variables), headers, body: substituteVariables(template.body, variables), timeout_ms: 20_000, follow_redirects: false };
	}

	function anonymousRequestFromTemplate(template = {}, variables = {}, projectId = '') {
		const request = requestFromTemplate(template, variables, null, projectId);
		for (const key of Object.keys(request.headers || {})) {
			if (/^(authorization|cookie|proxy-authorization|x-api-key)$/i.test(key)) delete request.headers[key];
		}
		return request;
	}

	function setObjectPath(document, path, value) {
		const parts = String(path || '').split('.').filter(Boolean);
		let current = document;
		for (const part of parts.slice(0, -1)) {
			if (!current[part] || typeof current[part] !== 'object') current[part] = {};
			current = current[part];
		}
		if (parts.length) current[parts.at(-1)] = value;
		return document;
	}

	function mutateAuthorizationTemplate(template = {}, location = 'none', field = '', candidate = '') {
		const result = { ...template, headers: { ...normalizeHeaders(template.headers) } };
		const mutationLocation = String(location || 'none').toLowerCase();
		if (mutationLocation === 'none' || candidate === '') return result;
		if (mutationLocation === 'path') {
			const parsed = new URL(result.url);
			if (parsed.pathname.includes('{{object}}')) parsed.pathname = parsed.pathname.replaceAll('{{object}}', encodeURIComponent(candidate));
			else if (parsed.pathname.includes('$OBJECT')) parsed.pathname = parsed.pathname.replaceAll('$OBJECT', encodeURIComponent(candidate));
			else if (/^path\.\d+$/.test(field)) {
				const segments = parsed.pathname.split('/');
				const index = Number(field.slice(5));
				if (index < 0 || index >= segments.length || !segments[index]) throw Object.assign(new Error('The selected URL path object no longer exists'), { status: 400 });
				segments[index] = encodeURIComponent(candidate);
				parsed.pathname = segments.join('/');
			}
			else if (field && parsed.pathname.includes(field)) parsed.pathname = parsed.pathname.replaceAll(field, encodeURIComponent(candidate));
			else {
				const segments = parsed.pathname.split('/');
				const index = segments.map(item => item.trim()).findLastIndex(Boolean);
				if (index < 0) throw Object.assign(new Error('The URL has no path object to mutate'), { status: 400 });
				segments[index] = encodeURIComponent(candidate);
				parsed.pathname = segments.join('/');
			}
			result.url = parsed.toString();
			return result;
		}
		if (mutationLocation === 'query') {
			if (!field) throw Object.assign(new Error('A query parameter name is required for authorization mutation'), { status: 400 });
			const parsed = new URL(result.url);
			parsed.searchParams.set(field, candidate);
			result.url = parsed.toString();
			return result;
		}
		if (mutationLocation === 'json' || mutationLocation === 'graphql') {
			if (!field) throw Object.assign(new Error('A JSON or GraphQL field path is required for authorization mutation'), { status: 400 });
			let document;
			try { document = JSON.parse(result.body || '{}'); }
			catch (_) { throw Object.assign(new Error('The request body must be valid JSON for authorization mutation'), { status: 400 }); }
			const path = mutationLocation === 'graphql' && !field.startsWith('variables.') ? `variables.${field}` : field;
			setObjectPath(document, path, candidate);
			result.body = JSON.stringify(document);
			result.headers['Content-Type'] = 'application/json';
			return result;
		}
		throw Object.assign(new Error(`Unsupported authorization mutation location: ${mutationLocation}`), { status: 400 });
	}

	function looksLikeObjectKey(value) {
		return /(^|_)(id|uuid|key|account|tenant|user|owner|order|document|resource|channel|room)(_|$)/i.test(String(value || ''));
	}

	function looksLikeObjectValue(value) {
		const text = String(value ?? '').trim();
		return /^\d{1,18}$/.test(text)
			|| /^[0-9a-f]{8}-[0-9a-f]{4}-[1-5][0-9a-f]{3}-[89ab][0-9a-f]{3}-[0-9a-f]{12}$/i.test(text)
			|| /^[0-9a-f]{24}$/i.test(text)
			|| /^[0-9A-HJKMNP-TV-Z]{26}$/i.test(text)
			|| /^[a-z][a-z0-9_-]{2,63}-(?:[a-z0-9_-]{1,64})$/i.test(text);
	}

	function neighboringObjectValues(value) {
		const text = String(value ?? '').trim();
		const candidates = [text];
		if (/^\d{1,15}$/.test(text)) {
			const numeric = Number(text);
			if (numeric > 0) candidates.push(String(numeric - 1));
			candidates.push(String(numeric + 1));
		}
		return candidates;
	}

	function collectDocumentObjectFields(value, prefix = '', output = []) {
		if (Array.isArray(value)) {
			value.forEach((child, index) => collectDocumentObjectFields(child, prefix ? `${prefix}.${index}` : String(index), output));
			return output;
		}
		if (!value || typeof value !== 'object') return output;
		for (const [key, child] of Object.entries(value)) {
			const path = prefix ? `${prefix}.${key}` : key;
			if ((looksLikeObjectKey(key) || looksLikeObjectValue(child)) && ['string', 'number'].includes(typeof child)) output.push({ field: path, value: String(child) });
			else collectDocumentObjectFields(child, path, output);
		}
		return output;
	}

	function discoverAuthorizationObjects(template = {}, capturedTemplates = []) {
		const discoveries = [];
		const add = (location, field, currentValue, source = 'current') => {
			if (!currentValue) return;
			let item = discoveries.find(entry => entry.location === location && entry.field === field);
			if (!item) {
				item = { location, field, current_value: String(currentValue), candidates: [], sources: [] };
				discoveries.push(item);
			}
			item.candidates.push(...neighboringObjectValues(currentValue));
			item.sources.push(source);
		};
		const inspect = (candidate, source) => {
			try {
				const parsed = new URL(candidate.url);
				const segments = parsed.pathname.split('/');
				segments.forEach((segment, index) => {
					const decoded = decodeURIComponent(segment || '');
					if (decoded && looksLikeObjectValue(decoded)) add('path', `path.${index}`, decoded, source);
				});
				for (const [key, value] of parsed.searchParams.entries()) if (looksLikeObjectKey(key) || looksLikeObjectValue(value)) add('query', key, value, source);
			} catch (_) { /* invalid captured URLs are ignored */ }
			try {
				const document = JSON.parse(candidate.body || '');
				for (const entry of collectDocumentObjectFields(document)) {
					const graphql = entry.field.startsWith('variables.');
					add(graphql ? 'graphql' : 'json', graphql ? entry.field.slice(10) : entry.field, entry.value, source);
				}
			} catch (_) { /* non-JSON bodies are ignored */ }
		};
		inspect(template, 'current');
		for (const captured of capturedTemplates.slice(0, 200)) inspect(captured, 'captured');
		for (const item of discoveries) {
			item.candidates = [...new Set(item.candidates)].slice(0, 10);
			item.sources = [...new Set(item.sources)];
		}
		return discoveries.slice(0, 40);
	}

	function redactEvidenceText(value) {
		let text = String(value ?? '');
		try {
			const redact = input => {
				if (Array.isArray(input)) return input.map(redact);
				if (!input || typeof input !== 'object') return input;
				const output = {};
				for (const [key, child] of Object.entries(input)) {
					output[key] = /(password|passwd|secret|token|authorization|cookie|session|csrf|api[_-]?key|email|balance|note|owner|tenant)/i.test(key) ? '[REDACTED]' : redact(child);
				}
				return output;
			};
			text = JSON.stringify(redact(JSON.parse(text)));
		} catch (_) {
			text = text
				.replace(/Bearer\s+[A-Za-z0-9._~+/=-]+/gi, 'Bearer [REDACTED]')
				.replace(/((?:token|secret|password|session|cookie|csrf|api[_-]?key|email|balance|note|owner|tenant)["'\s:=]+)[^\s,"'}]+/gi, '$1[REDACTED]');
		}
		return text;
	}

	function responseEvidence(response = {}, mode = 'redacted', retentionBytes = 65_536) {
		const rawBody = response.body || response.body_base64 || '';
		const retained = String(rawBody).slice(0, boundedInteger(retentionBytes, 65_536, 0, 1_048_576));
		return {
			status: response.status,
			status_text: response.status_text,
			body: mode === 'hash_only' ? '' : (mode === 'full' ? retained : redactEvidenceText(retained)),
			body_encoding: response.body_encoding,
			body_bytes: response.body_bytes,
			body_omitted: mode === 'hash_only',
			body_redacted: mode === 'redacted',
			body_retention_truncated: String(rawBody).length > retained.length,
			sha256: response.sha256,
			semantic_sha256: response.semantic_sha256 || '',
			flow_id: response.flow_id,
		};
	}

	function sanitizeAuthorizationTemplate(template = {}, evidenceMode = 'redacted') {
		const headers = { ...normalizeHeaders(template.headers) };
		for (const key of Object.keys(headers)) {
			if (/^(authorization|cookie|proxy-authorization|x-api-key)$/i.test(key)) headers[key] = '[IDENTITY APPLIED AT REPLAY]';
		}
		return { method: template.method || 'GET', url: template.url, headers, body: evidenceMode === 'full' ? String(template.body || '') : redactEvidenceText(template.body || '') };
	}

	function authorizationFindingProfile(mode) {
		return ({
			anonymous_denied_authenticated_allowed: { type: 'missing-authentication', title: 'Missing authentication on protected resource', cwe: 'CWE-306', owasp: 'API2:2023 Broken Authentication' },
			lower_privilege_denied_privileged_allowed: { type: 'vertical-privilege-escalation', title: 'Potential vertical privilege escalation', cwe: 'CWE-269', owasp: 'API5:2023 Broken Function Level Authorization' },
			tenant_isolation: { type: 'tenant-isolation', title: 'Potential cross-tenant authorization bypass', cwe: 'CWE-639', owasp: 'API1:2023 Broken Object Level Authorization' },
			function_level_authorization: { type: 'broken-function-level-authorization', title: 'Potential broken function-level authorization', cwe: 'CWE-862', owasp: 'API5:2023 Broken Function Level Authorization' },
			admin_only_operation: { type: 'admin-only-authorization', title: 'Potential admin-only operation bypass', cwe: 'CWE-269', owasp: 'API5:2023 Broken Function Level Authorization' },
			ownership_transfer: { type: 'ownership-transfer', title: 'Potential unauthorized ownership transfer', cwe: 'CWE-639', owasp: 'API1:2023 Broken Object Level Authorization' },
			primary_denied_owner_allowed: { type: 'idor-bola', title: 'Potential IDOR/BOLA', cwe: 'CWE-639', owasp: 'API1:2023 Broken Object Level Authorization' },
		})[mode] || { type: 'authorization-policy', title: 'Authorization policy violation', cwe: 'CWE-862', owasp: 'OWASP Authorization' };
	}

	async function sha256Text(value) {
		const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(String(value ?? '')));
		return Array.from(new Uint8Array(digest), byte => byte.toString(16).padStart(2, '0')).join('');
	}

	function sanitizedCurl(template = {}) {
		const parts = ['curl', '-i', '-X', String(template.method || 'GET').toUpperCase()];
		for (const [key, value] of Object.entries(normalizeHeaders(template.headers))) {
			const safe = /^(authorization|cookie|proxy-authorization|x-api-key)$/i.test(key) ? '[IDENTITY APPLIED AT REPLAY]' : String(value).replaceAll("'", "'\\''");
			parts.push('-H', `'${key}: ${safe}'`);
		}
		if (template.body) parts.push('--data-raw', `'${redactEvidenceText(template.body).replaceAll("'", "'\\''")}'`);
		parts.push(`'${String(template.url || '').replaceAll("'", "%27")}'`);
		return parts.join(' ');
	}

	function authorizationRetestClassification(evaluation = {}, results = []) {
		if (evaluation.finding === true) return 'still_vulnerable';
		if (evaluation.verdict === 'access_control_enforced') return 'fixed';
		if (evaluation.verdict === 'invalid_identity' || results.some(item => item.semantic?.state === 'unauthenticated')) return 'authentication_expired';
		if (results.length && results.every(item => item.response?.status === 404)) return 'endpoint_changed';
		return 'inconclusive';
	}

	function websocketSemantic(result = {}) {
		if (result.status !== 'received') {
			const message = String(result.error || 'connection failed');
			if (/401|unauthenticated|authentication/i.test(message)) return { state: 'unauthenticated', reason: message };
			if (/403|forbidden|denied|not authorized/i.test(message)) return { state: 'denied', reason: message };
			return { state: 'inconclusive', reason: message };
		}
		const payload = result.exchange?.response?.payload || result.exchange?.response?.payload_base64 || '';
		try {
			const document = JSON.parse(payload);
			if (document.type === 'error' || /forbidden|denied|unauthorized/i.test(String(document.code || document.error || document.message || ''))) return { state: 'denied', reason: 'WebSocket application response denied access', semantic_sha256: '' };
		} catch (_) {
			if (/forbidden|denied|not authorized/i.test(String(payload))) return { state: 'denied', reason: 'WebSocket payload contained a denial marker' };
		}
		return { state: 'allowed', reason: 'WebSocket connected and returned a non-denial event' };
	}

	async function saveAuthorizationFinding(projectId, evidence, metadata, existingFinding = null, retention = {}) {
		const fingerprintSource = [metadata.type, metadata.method, metadata.url, metadata.policy_mode, metadata.attacker_identity_id, metadata.owner_identity_id, evidence.recipe?.object_location, evidence.recipe?.object_field].join('|').toLowerCase();
		const fingerprint = await sha256Text(fingerprintSource);
		let target = existingFinding;
		if (!target) {
			const listed = await invoke('entities.list', { kind: 'findings', project_id: projectId, limit: 5000 });
			target = (listed.items || []).find(item => item.metadata?.fingerprint === fingerprint) || null;
		}
		const duplicateCount = Number(target?.metadata?.duplicate_count || 0) + (target ? 1 : 0);
		const saved = await invoke('entities.save', {
			kind: 'findings', project_id: projectId, id: target?.id || '', name: evidence.title,
			value: JSON.stringify(evidence), metadata: { ...(target?.metadata || {}), ...metadata, fingerprint, duplicate_count: duplicateCount },
		});
		const maxFindings = boundedInteger(retention.max_findings, 500, 10, 5000);
		const maxAgeDays = boundedInteger(retention.days, 90, 1, 3650);
		const listed = await invoke('entities.list', { kind: 'findings', project_id: projectId, limit: 5000 });
		const expiry = Date.now() - maxAgeDays * 86_400_000;
		const removable = (listed.items || []).filter((item, index) => item.id !== saved.item.id && (index >= maxFindings || Date.parse(item.updated_at || item.created_at || 0) < expiry));
		for (const item of removable.slice(0, 200)) await invoke('entities.delete', { kind: 'findings', id: item.id }).catch(() => {});
		return { item: saved.item, deduplicated: Boolean(target), pruned: removable.length };
	}

    function entityKind(segment) {
        return ({
            targets: 'targets', notes: 'notes', evidence: 'evidence', identities: 'identities',
            sessions: 'sessions', 'http-flows': 'http_flows', 'ws-connections': 'ws_connections',
            'ws-frames': 'ws_frames', events: 'timeline', 'protocol-map': 'protocol_maps',
            'attack-runs': 'attack_runs', findings: 'findings',
			'http-templates': 'sessions',
        })[segment];
    }

    async function invoke(method, params = {}) {
        return window.wshawk.invoke(method, params);
    }

	async function executeHTTPAuthzMatrix(projectId, body = {}, existingFinding = null) {
		const requestedIdentityIds = [...new Set(body.identity_ids || [])].slice(0, 8);
		const primaryIdentityId = body.primary_identity_id || requestedIdentityIds[0] || '';
		const ownerIdentityId = body.owner_identity_id || requestedIdentityIds[1] || '';
		if (!primaryIdentityId || !ownerIdentityId || primaryIdentityId === ownerIdentityId) {
			throw Object.assign(new Error('Different primary/attacker and owner/control identities are required'), { status: 400 });
		}
		if (!requestedIdentityIds.includes(primaryIdentityId)) requestedIdentityIds.unshift(primaryIdentityId);
		if (!requestedIdentityIds.includes(ownerIdentityId)) requestedIdentityIds.push(ownerIdentityId);
		const identities = await Promise.all([...new Set(requestedIdentityIds)].slice(0, 8).map(loadIdentity));
		const primaryIdentity = identities.find(item => item.id === primaryIdentityId);
		const ownerIdentity = identities.find(item => item.id === ownerIdentityId);
		if (!primaryIdentity || !ownerIdentity) throw Object.assign(new Error('A selected authorization identity no longer exists'), { status: 400 });
		const canonicalAuth = identity => JSON.stringify(Object.entries(identityHeaders(identity)).sort(([left], [right]) => left.toLowerCase().localeCompare(right.toLowerCase())));
		if (canonicalAuth(primaryIdentity) === canonicalAuth(ownerIdentity)) {
			throw Object.assign(new Error('The primary and owner identities contain identical authentication material'), { status: 400 });
		}

		const template = body.template || body.request || {};
		const variables = body.variables || {};
		const policyMode = body.policy_mode || body.policy?.mode || 'primary_denied_owner_allowed';
		const objectValues = (Array.isArray(body.object_values) ? body.object_values : [])
			.map(value => String(value).trim()).filter(Boolean).slice(0, 10);
		if (!objectValues.length) objectValues.push('current-object');
		const minimumConfirmations = Math.min(objectValues.length, boundedInteger(body.minimum_confirmations, objectValues.length > 1 ? 2 : 1, 1, 10));
		const evidenceMode = ['full', 'redacted', 'hash_only'].includes(body.evidence_mode) ? body.evidence_mode : 'redacted';
		const retentionBodyBytes = boundedInteger(body.retention_body_bytes, 65_536, 0, 1_048_576);
		const includeAnonymous = body.include_anonymous !== false;
		const writeMode = ['dry_run', 'execute', 'execute_with_rollback'].includes(body.write_mode)
			? body.write_mode : (body.safe_write_confirmed === true ? 'execute' : 'dry_run');
		const cases = [];
		for (const objectValue of objectValues) {
			const candidate = objectValue === 'current-object' ? '' : objectValue;
			const mutatedTemplate = mutateAuthorizationTemplate(template, body.object_location || 'none', body.object_field || '', candidate);
			for (const identity of identities) {
				let expectation = 'observe';
				if (policyMode !== 'compare_only') {
					if (identity.id === ownerIdentityId) expectation = 'allow';
					else if (identity.id === primaryIdentityId && policyMode !== 'anonymous_denied_authenticated_allowed') expectation = 'deny';
				}
				const auxiliary = key => {
					if (!body[key]?.url) return undefined;
					const candidateTemplate = body[key].mutate_object === false ? body[key] : mutateAuthorizationTemplate(body[key], body.object_location || 'none', body.object_field || '', candidate);
					return requestFromTemplate(candidateTemplate, variables, identity, projectId);
				};
				cases.push({
					id: `${objectValue}:${identity.id}`, identity_id: identity.id, alias: identity.alias,
					role: identity.storage?.auth_role || identity.role || 'authenticated', expectation,
					object_value: objectValue, request: requestFromTemplate(mutatedTemplate, variables, identity, projectId),
					before_request: auxiliary('before_template'), after_request: auxiliary('after_template'), cleanup_request: auxiliary('cleanup_template'),
				});
			}
			if (includeAnonymous) {
				const anonymousAuxiliary = key => {
					if (!body[key]?.url) return undefined;
					const candidateTemplate = body[key].mutate_object === false ? body[key] : mutateAuthorizationTemplate(body[key], body.object_location || 'none', body.object_field || '', candidate);
					return anonymousRequestFromTemplate(candidateTemplate, variables, projectId);
				};
				cases.push({
					id: `${objectValue}:anonymous`, alias: 'Anonymous', role: 'anonymous',
					expectation: policyMode === 'compare_only' ? 'observe' : 'deny', object_value: objectValue,
					request: anonymousRequestFromTemplate(mutatedTemplate, variables, projectId),
					before_request: anonymousAuxiliary('before_template'), after_request: anonymousAuxiliary('after_template'), cleanup_request: anonymousAuxiliary('cleanup_template'),
				});
			}
		}

		const policy = {
			mode: policyMode, minimum_confirmations: minimumConfirmations,
			denial_markers: Array.isArray(body.denial_markers) ? body.denial_markers.slice(0, 20) : [],
			success_markers: Array.isArray(body.success_markers) ? body.success_markers.slice(0, 20) : [],
		};
		const matrix = await invoke('scanner.authz_matrix', {
			cases, policy, safe_write_confirmed: body.safe_write_confirmed === true,
			write_mode: writeMode,
			max_requests: 80, authorization_confirmed: true,
		});
		const evaluation = matrix.evaluation || {};
		const profile = authorizationFindingProfile(policyMode);
		const testedAt = new Date().toISOString();
		const recipe = {
			version: 1, template: sanitizeAuthorizationTemplate(template, 'full'), variables,
			identity_ids: identities.map(item => item.id), primary_identity_id: primaryIdentityId,
			owner_identity_id: ownerIdentityId, policy_mode: policyMode,
			object_values: objectValues, object_location: body.object_location || 'none', object_field: body.object_field || '',
			minimum_confirmations: minimumConfirmations, include_anonymous: includeAnonymous,
			evidence_mode: evidenceMode, denial_markers: policy.denial_markers, success_markers: policy.success_markers,
			safe_write_confirmed: body.safe_write_confirmed === true, write_mode: writeMode,
			before_template: body.before_template || null, after_template: body.after_template || null, cleanup_template: body.cleanup_template || null,
			retention_body_bytes: retentionBodyBytes, retention_days: boundedInteger(body.retention_days, 90, 1, 3650), retention_max_findings: boundedInteger(body.retention_max_findings, 500, 10, 5000),
		};
		const results = (matrix.results || []).map(item => ({
			case_id: item.case_id, identity_id: item.identity_id, identity_alias: item.identity_alias,
			role: item.role, expectation: item.expectation, expectation_met: item.expectation_met,
			policy_violation: item.policy_violation, object_value: item.object_value,
			request: item.request, semantic: item.semantic,
			response: responseEvidence({ ...item.response, semantic_sha256: item.semantic?.semantic_sha256 }, evidenceMode, retentionBodyBytes),
			write_evidence: item.write_evidence,
		}));
		const endpointList = [...new Set(results.map(item => item.request?.url).filter(Boolean))];
		const priorHistory = Array.isArray(existingFinding?.metadata?.lifecycle_history) ? existingFinding.metadata.lifecycle_history : [];
		let lifecycleStatus = existingFinding?.metadata?.lifecycle_status || 'open';
		if (existingFinding) {
			if (evaluation.finding === true) lifecycleStatus = lifecycleStatus === 'fixed' ? 'reopened' : lifecycleStatus;
			else if (evaluation.verdict === 'access_control_enforced') lifecycleStatus = 'fixed';
			else lifecycleStatus = 'inconclusive';
		}
		const retestClassification = existingFinding ? authorizationRetestClassification(evaluation, results) : '';
		const lifecycleHistory = priorHistory.concat({ at: testedAt, action: existingFinding ? 'retest' : 'detected', verdict: evaluation.verdict, status: lifecycleStatus, classification: retestClassification || undefined }).slice(-50);
		let targetOrigin = template.url;
		try { targetOrigin = new URL(template.url).origin; } catch (_) { /* retained as entered */ }
		const targetFingerprint = await sha256Text(`${targetOrigin}|${results.map(item => item.response?.sha256 || '').join('|')}`);
		let screenshot = null;
		if (body.capture_screenshot === true && /^https?:/i.test(template.url || '')) {
			screenshot = await invoke('browser.evidence.capture', { url: template.url, cookies: primaryIdentity.cookies || [], timeoutMs: 10_000, waitUntil: 'domcontentloaded' }).catch(error => ({ error: error.message }));
		}
		const evidence = {
			version: 3, type: profile.type, title: profile.title, endpoint: template.url,
			endpoints: endpointList, method: template.method || 'GET', policy: evaluation,
			attacker: { id: primaryIdentity.id, alias: primaryIdentity.alias },
			owner_control: { id: ownerIdentity.id, alias: ownerIdentity.alias },
			identity_expiration: results.map(item => ({ identity_id: item.identity_id || 'anonymous', alias: item.identity_alias, state: item.semantic?.state, expired: item.semantic?.state === 'unauthenticated' })),
			evidence_mode: evidenceMode, results, recipe, tested_at: testedAt,
			wshawk_version: '4.0.4', target_fingerprint: targetFingerprint,
			replay_instructions: 'Refresh stored identities, open HTTP Forge, load the sanitized request, then run the saved authorization matrix recipe.',
			curl_reproduction: sanitizedCurl(sanitizeAuthorizationTemplate(template, 'redacted')),
			screenshot,
		};
		let finding = null;
		if (evaluation.finding === true || existingFinding) {
			const metadata = {
				...(existingFinding?.metadata || {}), type: profile.type,
				title: profile.title, category: 'authorization', description: evaluation.detail,
				severity: existingFinding?.metadata?.severity || String(evaluation.severity || 'high').toUpperCase(), confidence: existingFinding?.metadata?.confidence || evaluation.confidence || 'medium',
				url: template.url, method: template.method || 'GET', detail: evaluation.detail,
				cwe: profile.cwe, owasp: profile.owasp, policy_mode: policyMode,
				attacker_identity_id: primaryIdentity.id, attacker_alias: primaryIdentity.alias,
				owner_identity_id: ownerIdentity.id, owner_alias: ownerIdentity.alias,
				confirmation_count: evaluation.confirmation_count || 0,
				required_confirmations: evaluation.required_confirmations || minimumConfirmations,
				lifecycle_status: lifecycleStatus, lifecycle_history: lifecycleHistory,
				first_seen: existingFinding?.metadata?.first_seen || testedAt, last_tested: testedAt,
				response_hashes: results.map(item => item.response.sha256).filter(Boolean),
				target_fingerprint: targetFingerprint, wshawk_version: '4.0.4',
				last_retest_classification: retestClassification || existingFinding?.metadata?.last_retest_classification || '',
			};
			const saved = await saveAuthorizationFinding(projectId, evidence, metadata, existingFinding, { max_findings: recipe.retention_max_findings, days: recipe.retention_days });
			finding = { id: saved.item.id, ...evidence, metadata };
			finding.deduplicated = saved.deduplicated;
		}
		const attackRun = await invoke('entities.save', {
			kind: 'attack_runs', project_id: projectId, name: 'authorization-matrix', value: evaluation.verdict || 'completed',
			metadata: { attack_type: 'authorization-matrix', status: 'completed', target: template.url, policy_mode: policyMode, summary: matrix.summary, finding_id: finding?.id || '', tested_at: testedAt },
		});
		return { matrix: { ...matrix, finding, attack_run_id: attackRun.item.id, summary: { ...(matrix.summary || {}), finding_saved: evaluation.finding === true && Boolean(finding), finding_id: finding?.id || '', lifecycle_status: lifecycleStatus, retest_classification: retestClassification } } };
	}

    async function projectRoute(path, method, body, search) {
        const parts = path.split('/').filter(Boolean);
        if (parts.length === 2) {
            if (method === 'POST') {
				const result = await invoke('projects.save', {
                    id: body.project_id || body.id || '', name: body.name,
                    target_url: body.target_url || body.url || '', metadata: body.metadata || {},
                });
				lastProjectId = result.project.id;
				return result;
            }
            return invoke('projects.list', { limit: Number(search.get('limit')) || 100 });
        }
        const projectId = parts[2];
        if (parts.length === 3) {
            if (method === 'DELETE') return invoke('projects.delete', { id: projectId });
			lastProjectId = projectId;
			const snapshot = await invoke('projects.get', { id: projectId });
			return {
				...snapshot,
				identities: Array.isArray(snapshot.identities) ? snapshot.identities.map(expandIdentity) : [],
			};
        }
        const action = parts[3];
		lastProjectId = projectId;
		if (action === 'exports') {
			const format = decodeURIComponent(parts[4] || 'json').toLowerCase();
			const report = await invoke('reports.generate', { project_id: projectId, format });
			return report.content;
		}
		if (action === 'protocol-map') return invoke('protocol.map', { project_id: projectId });
        if (action === 'replay' && parts[4] === 'http') {
			const identity = await loadIdentity(body.identity_id);
			const request = requestFromTemplate(body.template || body.request || body, body.variables || {}, identity, projectId);
			const result = await invoke('http.request', request);
			const response = result.response;
			return { replay: { http_status: response.status, status: response.status, timing_ms: response.duration_ms, headers: response.headers, body: response.body || response.body_base64 || '', flow_id: response.flow_id, identity_alias: identity?.alias || '' } };
        }
		if (action === 'replay' && parts[4] === 'ws') {
			const identity = await loadIdentity(body.identity_id);
			const headers = { ...normalizeHeaders(body.headers), ...identityHeaders(identity) };
			const connected = await invoke('ws.connect', { project_id: projectId, url: body.url, headers, timeout_ms: (body.timeout || 10) * 1000 });
			try {
				const exchange = await invoke('ws.probe', { connection_id: connected.connection_id, message_type: body.binary ? 'binary' : 'text', payload: typeof body.payload === 'string' ? body.payload : JSON.stringify(body.payload), payload_base64: body.payload_base64 || '', timeout_ms: (body.timeout || 10) * 1000 });
				return { status: 'success', result: { status: 'received', identity_alias: identity?.alias || '', exchange } };
			} finally {
				await invoke('ws.disconnect', { connection_id: connected.connection_id }).catch(() => {});
            }
		}
		if (action === 'attacks' && parts[4] === 'http-authz-discover') {
			const listed = await invoke('entities.list', { kind: 'http_flows', project_id: projectId, limit: 500 });
			const captured = [];
			for (const item of listed.items || []) {
				try {
					const flow = JSON.parse(item.value || '{}');
					if (flow.request?.url) captured.push(flow.request);
				} catch (_) { /* malformed historical flows are ignored */ }
			}
			const discoveries = discoverAuthorizationObjects(body.template || body.request || body, captured);
			return { status: 'success', discoveries, captured_flow_count: captured.length, candidate_count: discoveries.reduce((sum, item) => sum + item.candidates.length, 0) };
		}
		if (action === 'attacks' && parts[4] === 'http-authz-matrix') {
			return executeHTTPAuthzMatrix(projectId, body);
		}
		if (action === 'attacks' && parts[4] === 'http-authz-diff') {
			const requestedIdentityIds = (body.identity_ids || []).slice(0, 2);
			if (requestedIdentityIds.length < 2 || requestedIdentityIds[0] === requestedIdentityIds[1]) {
				throw Object.assign(new Error('Two different stored identities are required'), { status: 400 });
			}
			const identities = await Promise.all(requestedIdentityIds.map(loadIdentity));
			const leftAuthHeaders = identityHeaders(identities[0]);
			const rightAuthHeaders = identityHeaders(identities[1]);
			const canonicalAuth = headers => JSON.stringify(Object.entries(headers).sort(([left], [right]) => left.toLowerCase().localeCompare(right.toLowerCase())));
			if (canonicalAuth(leftAuthHeaders) === canonicalAuth(rightAuthHeaders)) {
				throw Object.assign(new Error('The selected identities contain identical authentication material'), { status: 400 });
			}
			const left = requestFromTemplate(body.template, body.variables || {}, identities[0], projectId);
			const right = requestFromTemplate(body.template, body.variables || {}, identities[1], projectId);
			const policyMode = body.policy_mode || body.policy?.mode || 'compare_only';
			const comparison = await invoke('scanner.authz_diff', { left, right, policy: { mode: policyMode }, authorization_confirmed: true });
			const policyEvaluation = comparison.policy_evaluation || { mode: policyMode, verdict: 'comparison_only', finding: false };
			let finding = null;
			if (policyEvaluation.finding === true) {
				const evidenceMode = ['full', 'redacted', 'hash_only'].includes(body.evidence_mode) ? body.evidence_mode : 'redacted';
				const testedAt = new Date().toISOString();
				const evidence = {
					version: 2,
					type: 'idor-bola',
					title: 'Potential IDOR/BOLA: primary identity accessed an owner-controlled object',
					endpoint: left.url,
					method: left.method,
					policy: policyEvaluation,
					attacker: { id: identities[0].id, alias: identities[0].alias },
					owner_control: { id: identities[1].id, alias: identities[1].alias },
					responses: {
						attacker: responseEvidence(comparison.left, evidenceMode),
						owner_control: responseEvidence(comparison.right, evidenceMode),
					},
					evidence_mode: evidenceMode,
					recipe: { version: 1, template: sanitizeAuthorizationTemplate(body.template || {}, 'full'), variables: body.variables || {}, identity_ids: requestedIdentityIds, primary_identity_id: requestedIdentityIds[0], owner_identity_id: requestedIdentityIds[1], policy_mode: policyMode, object_values: [], object_location: 'none', object_field: '', minimum_confirmations: 1, include_anonymous: false, evidence_mode: evidenceMode, safe_write_confirmed: false },
					tested_at: testedAt,
				};
				const saved = await invoke('entities.save', {
					kind: 'findings',
					project_id: projectId,
					name: 'Potential IDOR/BOLA',
					value: JSON.stringify(evidence),
					metadata: {
						type: 'idor-bola',
						title: 'Potential IDOR/BOLA: primary identity accessed an owner-controlled object',
						category: 'authorization',
						description: policyEvaluation.detail,
						severity: String(policyEvaluation.severity || 'high').toUpperCase(),
						confidence: policyEvaluation.confidence || 'medium',
						url: left.url,
						method: left.method,
						detail: policyEvaluation.detail,
						cwe: 'CWE-639',
						owasp: 'API1:2023 Broken Object Level Authorization',
						policy_mode: policyMode,
						attacker_identity_id: identities[0].id,
						attacker_alias: identities[0].alias,
						owner_identity_id: identities[1].id,
						owner_alias: identities[1].alias,
						attacker_status: comparison.left.status,
						owner_status: comparison.right.status,
						attacker_response_sha256: comparison.left.sha256,
						owner_response_sha256: comparison.right.sha256,
						lifecycle_status: 'open',
						lifecycle_history: [{ at: testedAt, action: 'detected', verdict: policyEvaluation.verdict, status: 'open' }],
						first_seen: testedAt,
						last_tested: testedAt,
					},
				});
				finding = { id: saved.item.id, ...evidence };
				policyEvaluation.finding_id = saved.item.id;
			}
			const changed = comparison.authorization_difference !== 'none';
			return { diff: { ...comparison, results: [
				{ identity_id: identities[0].id, identity_alias: identities[0].alias, response: comparison.left },
				{ identity_id: identities[1].id, identity_alias: identities[1].alias, response: comparison.right },
			], finding, summary: { behavior_changed: changed, identity_count: 2, behavior_group_count: changed ? 2 : 1, policy_verdict: policyEvaluation.verdict, finding_saved: Boolean(finding), finding_id: finding?.id || '', compared_identities: [
				{ id: identities[0].id, alias: identities[0].alias },
				{ id: identities[1].id, alias: identities[1].alias },
			], http_status_breakdown: { [comparison.left.status]: 1, [comparison.right.status]: (comparison.left.status === comparison.right.status ? 2 : 1) } } } };
		}
		if (action === 'attacks' && parts[4] === 'ws-authz-matrix') {
			const identityIds = [...new Set(body.identity_ids || [])].slice(0, 8);
			const primaryId = body.primary_identity_id || identityIds[0];
			const ownerId = body.owner_identity_id || identityIds[1];
			if (!primaryId || !ownerId || primaryId === ownerId) throw Object.assign(new Error('Different primary and owner WebSocket identities are required'), { status: 400 });
			const identities = await Promise.all(identityIds.map(loadIdentity));
			const objectValues = [...new Set((body.object_values || body.candidate_values || []).map(String).filter(Boolean))].slice(0, 10);
			if (!objectValues.length) objectValues.push('current-object');
			const minimum = Math.min(objectValues.length, boundedInteger(body.minimum_confirmations, objectValues.length > 1 ? 2 : 1, 1, 10));
			const field = String(body.object_field || body.field_paths?.[0] || 'room');
			const allActors = identities.map(identity => ({ identity, id: identity.id, alias: identity.alias, headers: identityHeaders(identity) }));
			if (body.include_anonymous !== false) allActors.push({ identity: null, id: 'anonymous', alias: 'Anonymous', headers: {} });
			if (allActors.length * objectValues.length > 80) throw Object.assign(new Error('WebSocket authorization matrix exceeds 80 requests'), { status: 400 });
			const results = [];
			for (const objectValue of objectValues) {
				for (const actor of allActors) {
					let url = String(body.url || ''); let payload = body.payload;
					const candidate = objectValue === 'current-object' ? '' : objectValue;
					if (candidate) {
						if (field.startsWith('url.')) { const parsed = new URL(url); parsed.searchParams.set(field.slice(4), candidate); url = parsed.toString(); }
						else { let document; try { document = structuredClone(typeof payload === 'object' ? payload : JSON.parse(payload || '{}')); } catch (_) { document = {}; } payload = JSON.stringify(setObjectPath(document, field, candidate)); }
					}
					let connection; const observed = { identity_id: actor.id === 'anonymous' ? '' : actor.id, identity_alias: actor.alias, role: actor.identity?.storage?.auth_role || (actor.id === 'anonymous' ? 'anonymous' : 'authenticated'), object_value: objectValue };
					try {
						connection = await invoke('ws.connect', { project_id: projectId, url, headers: actor.headers, timeout_ms: boundedInteger(body.timeout, 10, 1, 30) * 1000 });
						observed.exchange = await invoke('ws.probe', { connection_id: connection.connection_id, message_type: 'text', payload: typeof payload === 'string' ? payload : JSON.stringify(payload), timeout_ms: boundedInteger(body.timeout, 10, 1, 30) * 1000 });
						observed.status = 'received';
					} catch (error) { observed.status = 'error'; observed.error = error.message; }
					finally { if (connection?.connection_id) await invoke('ws.disconnect', { connection_id: connection.connection_id }).catch(() => {}); }
					observed.semantic = websocketSemantic(observed);
					observed.expectation = actor.id === ownerId ? 'allow' : (actor.id === primaryId || actor.id === 'anonymous' ? 'deny' : 'observe');
					observed.policy_violation = observed.expectation === 'deny' && observed.semantic.state === 'allowed';
					observed.expectation_met = observed.expectation === 'observe' || (observed.expectation === 'allow' ? observed.semantic.state === 'allowed' : observed.semantic.state !== 'allowed');
					results.push(observed);
				}
			}
			const confirmed = objectValues.filter(value => results.some(item => item.object_value === value && item.identity_id === primaryId && item.policy_violation) && results.some(item => item.object_value === value && item.identity_id === ownerId && item.semantic.state === 'allowed'));
			const invalidControl = results.some(item => item.identity_id === ownerId && item.semantic.state !== 'allowed');
			const profile = authorizationFindingProfile(body.policy_mode || 'primary_denied_owner_allowed');
			let evaluation = { mode: body.policy_mode || 'primary_denied_owner_allowed', verdict: 'access_control_enforced', finding: false, severity: 'info', confidence: 'high', confirmation_count: confirmed.length, required_confirmations: minimum, confirmed_objects: confirmed, detail: 'Expected WebSocket authorization boundaries were enforced.' };
			if (invalidControl) evaluation = { ...evaluation, verdict: 'invalid_control', severity: 'warning', finding: false, detail: 'The owner/control WebSocket identity was not allowed for one or more objects.' };
			else if (confirmed.length >= minimum) evaluation = { ...evaluation, verdict: `potential_${profile.type.replaceAll('-', '_')}`, finding: true, severity: profile.type.includes('tenant') || profile.type.includes('ownership') ? 'critical' : 'high', detail: `WebSocket ${profile.title.toLowerCase()} confirmed across ${confirmed.length} foreign objects.` };
			else if (confirmed.length) evaluation = { ...evaluation, verdict: 'insufficient_confirmation', finding: false, severity: 'warning', confidence: 'medium', detail: `${confirmed.length} object(s) violated policy; ${minimum} are required.` };
			const testedAt = new Date().toISOString(); const evidenceMode = ['full', 'redacted', 'hash_only'].includes(body.evidence_mode) ? body.evidence_mode : 'redacted';
			const evidenceResults = [];
			for (const item of results) {
				const raw = JSON.stringify(item.exchange?.response || item.error || item.status);
				evidenceResults.push({ ...item, exchange: undefined, body: evidenceMode === 'hash_only' ? '' : (evidenceMode === 'full' ? raw : redactEvidenceText(raw)), sha256: await sha256Text(raw) });
			}
			const recipe = { version: 2, url: body.url, payload: body.payload, identity_ids: identityIds, primary_identity_id: primaryId, owner_identity_id: ownerId, policy_mode: body.policy_mode || 'primary_denied_owner_allowed', object_field: field, object_values: objectValues, minimum_confirmations: minimum, include_anonymous: body.include_anonymous !== false, timeout: body.timeout || 10, evidence_mode: evidenceMode };
			let finding = null;
			if (evaluation.finding) {
				const evidence = { version: 3, type: 'websocket-authorization', subtype: profile.type, title: `WebSocket ${profile.title}`, endpoint: body.url, policy: evaluation, results: evidenceResults, recipe, tested_at: testedAt, wshawk_version: '4.0.4', target_fingerprint: await sha256Text(body.url), replay_instructions: 'Replay this bounded WebSocket identity/object matrix after refreshing the stored sessions.' };
				const primary = identities.find(item => item.id === primaryId); const owner = identities.find(item => item.id === ownerId);
				const metadata = { type: 'websocket-authorization', subtype: profile.type, title: evidence.title, category: 'authorization', description: evaluation.detail, severity: String(evaluation.severity).toUpperCase(), confidence: evaluation.confidence, url: body.url, policy_mode: evaluation.mode, attacker_identity_id: primaryId, attacker_alias: primary?.alias, owner_identity_id: ownerId, owner_alias: owner?.alias, lifecycle_status: 'open', first_seen: testedAt, last_tested: testedAt, response_hashes: evidenceResults.map(item => item.sha256) };
				const saved = await saveAuthorizationFinding(projectId, evidence, metadata, null, { max_findings: body.retention_max_findings, days: body.retention_days }); finding = { id: saved.item.id, ...evidence };
			}
			return { matrix: { results, evaluation, finding, summary: { request_count: results.length, finding_saved: Boolean(finding), finding_id: finding?.id || '', confirmation_count: confirmed.length, required_confirmations: minimum } } };
		}
		if (action === 'attacks' && parts[4] === 'authz-diff') {
			const requestedIdentityIds = [...new Set(body.identity_ids || [])].slice(0, 10);
			const identities = await Promise.all(requestedIdentityIds.map(loadIdentity));
			const results = [];
			for (const identity of identities) {
				let connection;
				try {
					connection = await invoke('ws.connect', { project_id: projectId, url: body.url, headers: identityHeaders(identity), timeout_ms: (body.timeout || 10) * 1000 });
					const exchange = await invoke('ws.probe', { connection_id: connection.connection_id, message_type: 'text', payload: typeof body.payload === 'string' ? body.payload : JSON.stringify(body.payload), timeout_ms: (body.timeout || 10) * 1000 });
					const observed = { identity_id: identity.id, identity_alias: identity.alias, status: 'received', exchange };
					observed.semantic = websocketSemantic(observed); results.push(observed);
				} catch (error) { results.push({ identity_id: identity.id, identity_alias: identity.alias, status: 'error', error: error.message }); }
				finally { if (connection?.connection_id) await invoke('ws.disconnect', { connection_id: connection.connection_id }).catch(() => {}); }
			}
			for (const item of results) if (!item.semantic) item.semantic = websocketSemantic(item);
			const signatures = new Set(results.map(item => JSON.stringify(item.exchange?.response || item.error || item.status)));
			const policyMode = body.policy_mode || 'compare_only';
			let evaluation = { mode: policyMode, verdict: 'comparison_only', finding: false, severity: 'info', confidence: 'none', detail: 'WebSocket behavior was compared without an expected authorization policy.' };
			let finding = null;
			if (policyMode !== 'compare_only') {
				const primaryId = body.primary_identity_id || requestedIdentityIds[0];
				const ownerId = body.owner_identity_id || requestedIdentityIds[1];
				const primary = results.find(item => item.identity_id === primaryId);
				const owner = results.find(item => item.identity_id === ownerId);
				if (!primary || !owner || primaryId === ownerId) throw Object.assign(new Error('Different primary and owner WebSocket identities are required'), { status: 400 });
				if (owner.semantic?.state !== 'allowed') evaluation = { ...evaluation, verdict: owner.semantic?.state === 'unauthenticated' ? 'invalid_identity' : 'invalid_control', severity: 'warning', confidence: 'high', detail: 'The owner/control identity was not semantically allowed to receive the WebSocket event.' };
				else if (primary.semantic?.state !== 'allowed') evaluation = { ...evaluation, verdict: 'access_control_enforced', confidence: 'high', detail: 'The primary identity was rejected while the owner/control identity received the WebSocket event.' };
				else {
					evaluation = { ...evaluation, verdict: 'potential_websocket_authorization_bypass', finding: true, severity: 'high', confidence: signatures.size === 1 ? 'high' : 'medium', detail: 'The primary identity connected and received a response where the owner/control policy expected denial.' };
					const evidenceMode = ['full', 'redacted', 'hash_only'].includes(body.evidence_mode) ? body.evidence_mode : 'redacted';
					const responseValue = item => JSON.stringify(item.exchange?.response || item.error || item.status);
					const primaryRaw = responseValue(primary);
					const ownerRaw = responseValue(owner);
					const evidence = {
						version: 2, type: 'websocket-authorization', title: 'Potential WebSocket authorization bypass',
						endpoint: body.url, policy: evaluation,
						attacker: { id: primary.identity_id, alias: primary.identity_alias },
						owner_control: { id: owner.identity_id, alias: owner.identity_alias },
						responses: {
							attacker: { status: primary.status, body: evidenceMode === 'hash_only' ? '' : (evidenceMode === 'full' ? primaryRaw : redactEvidenceText(primaryRaw)), sha256: await sha256Text(primaryRaw) },
							owner_control: { status: owner.status, body: evidenceMode === 'hash_only' ? '' : (evidenceMode === 'full' ? ownerRaw : redactEvidenceText(ownerRaw)), sha256: await sha256Text(ownerRaw) },
						},
						recipe: { version: 1, url: body.url, payload: body.payload, identity_ids: requestedIdentityIds, primary_identity_id: primaryId, owner_identity_id: ownerId, policy_mode: policyMode, timeout: body.timeout || 10, evidence_mode: evidenceMode },
					};
					const saved = await invoke('entities.save', { kind: 'findings', project_id: projectId, name: evidence.title, value: JSON.stringify(evidence), metadata: { type: evidence.type, title: evidence.title, category: 'authorization', description: evaluation.detail, severity: 'HIGH', confidence: evaluation.confidence, url: body.url, cwe: 'CWE-862', owasp: 'API5:2023 Broken Function Level Authorization', attacker_alias: primary.identity_alias, owner_alias: owner.identity_alias, lifecycle_status: 'open', first_seen: new Date().toISOString(), last_tested: new Date().toISOString() } });
					finding = { id: saved.item.id, ...evidence };
				}
			}
			return { diff: { results, policy_evaluation: evaluation, finding, summary: { behavior_changed: signatures.size > 1, identity_count: results.length, behavior_group_count: signatures.size, policy_verdict: evaluation.verdict, finding_saved: Boolean(finding), finding_id: finding?.id || '' } } };
        }
        if (action === 'attacks' && (parts[4] === 'http-race' || parts[4] === 'race')) {
			const attempts = Math.min(50, (body.count || body.concurrency || 5) * (body.waves || 1));
			if (parts[4] === 'http-race' || body.request?.url || body.template?.url || body.url?.startsWith?.('http')) {
				const identity = await loadIdentity(body.identity_id);
				const request = requestFromTemplate(body.template || body.request || body, body.variables || {}, identity, projectId);
				const result = await invoke('scanner.race', { request, count: attempts, authorization_confirmed: true });
				return { attack: { results: result.responses, summary: { mode: body.mode || 'duplicate_action', attempt_count: result.responses.length, wave_count: body.waves || 1, suspicious_race_window: result.possible_race, distinct_outcomes: result.distinct_outcomes } } };
			}
			if (!lastConnectionId) { const identity = await loadIdentity((body.identity_ids || [])[0]); const connected = await invoke('ws.connect', { project_id: projectId, url: body.url, headers: identityHeaders(identity) }); lastConnectionId = connected.connection_id; }
			const result = await invoke('ws.race', { connection_id: body.connection_id || lastConnectionId, message_type: 'text', payload: typeof body.payload === 'string' ? body.payload : JSON.stringify(body.payload || {}), count: attempts, authorization_confirmed: true });
			return { attack: { results: result.responses, summary: { mode: body.mode || 'duplicate_action', attempt_count: result.sent, wave_count: body.waves || 1, suspicious_race_window: result.received !== result.sent } } };
        }
		if (action === 'attacks' && parts[4] === 'subscription-abuse') {
			const identity = await loadIdentity((body.identity_ids || [])[0]);
			if (!lastConnectionId) { const connected = await invoke('ws.connect', { project_id: projectId, url: body.url, headers: identityHeaders(identity) }); lastConnectionId = connected.connection_id; }
			const attempts = [];
			for (const field of (body.field_paths || []).slice(0, 12)) for (const value of (body.candidate_values || []).slice(0, 12)) {
				if (attempts.length >= (body.max_mutations || 24)) break;
				let document; try { document = structuredClone(typeof body.payload === 'object' ? body.payload : JSON.parse(body.payload)); } catch (_) { document = {}; }
				const payload = JSON.stringify(setObjectPath(document, field, value));
				const result = await invoke('scanner.subscription_abuse', { project_id: projectId, connection_id: lastConnectionId, payload, authorization_confirmed: true });
				attempts.push({ field, value, payload, ...result });
			}
			const suspicious = attempts.filter(item => item.possible_subscription_abuse).length;
			return { attack: { attempts, summary: { mutation_count: attempts.length, suspicious_attempt_count: suspicious } } };
		}
		if (action === 'attacks' && parts[4] === 'workflow') return invoke('workflow.run', { ...body, project_id: projectId, authorization_confirmed: true });
		if (action === 'findings' && parts[4] === 'export-selected' && method === 'POST') {
			const ids = new Set((body.finding_ids || []).map(String).slice(0, 500));
			const listed = await invoke('entities.list', { kind: 'findings', project_id: projectId, limit: 5000 });
			const items = (listed.items || []).filter(item => ids.has(item.id));
			const format = String(body.format || 'json').toLowerCase();
			let content;
			if (format === 'csv') {
				const quote = value => `"${String(value ?? '').replaceAll('"', '""')}"`;
				content = ['id,title,type,severity,confidence,status,url,last_tested', ...items.map(item => [item.id, item.metadata?.title || item.name, item.metadata?.type, item.metadata?.severity, item.metadata?.confidence, item.metadata?.lifecycle_status, item.metadata?.url, item.metadata?.last_tested].map(quote).join(','))].join('\n');
			} else if (format === 'markdown' || format === 'md') {
				content = `# WSHawk Selected Findings\n\nGenerated ${new Date().toISOString()}\n\n` + items.map(item => `## ${item.metadata?.title || item.name}\n\n- ID: ${item.id}\n- Severity: ${item.metadata?.severity || 'INFO'}\n- Confidence: ${item.metadata?.confidence || 'unknown'}\n- Status: ${item.metadata?.lifecycle_status || 'open'}\n- Endpoint: ${item.metadata?.url || ''}\n\n${item.metadata?.description || ''}\n`).join('\n');
			} else content = JSON.stringify({ format: 'wshawk-selected-findings', version: 1, generated_at: new Date().toISOString(), findings: items }, null, 2);
			return { status: 'success', format, count: items.length, content };
		}
		if (action === 'findings' && parts[4]) {
			const findingId = decodeURIComponent(parts[4]);
			const current = await invoke('entities.get', { kind: 'findings', id: findingId });
			if (current.item.project_id !== projectId) throw Object.assign(new Error('Finding does not belong to this project'), { status: 404 });
			if (method === 'DELETE') return invoke('entities.delete', { kind: 'findings', id: findingId });
			if (method === 'POST' && parts[5] === 'retest') {
				let evidence;
				try { evidence = JSON.parse(current.item.value || '{}'); }
				catch (_) { throw Object.assign(new Error('Finding has no valid replay recipe'), { status: 400 }); }
				if (!evidence.recipe) throw Object.assign(new Error('Finding has no authorization retest recipe'), { status: 400 });
				if (evidence.type === 'websocket-authorization') {
					const matrixRecipe = Array.isArray(evidence.recipe?.object_values);
					const rerun = await projectRoute(`/platform/projects/${projectId}/attacks/${matrixRecipe ? 'ws-authz-matrix' : 'authz-diff'}`, 'POST', evidence.recipe, new URLSearchParams());
					const rerunResult = matrixRecipe ? rerun.matrix : rerun.diff;
					const evaluation = matrixRecipe ? (rerunResult?.evaluation || {}) : (rerunResult?.policy_evaluation || {});
					const generatedId = rerunResult?.summary?.finding_id || '';
					if (generatedId && generatedId !== findingId) await invoke('entities.delete', { kind: 'findings', id: generatedId }).catch(() => {});
					const at = new Date().toISOString();
					const lifecycleStatus = evaluation.finding === true
						? (current.item.metadata?.lifecycle_status === 'fixed' ? 'reopened' : (current.item.metadata?.lifecycle_status || 'open'))
						: (evaluation.verdict === 'access_control_enforced' ? 'fixed' : 'inconclusive');
					const classification = evaluation.finding === true ? 'still_vulnerable'
						: (evaluation.verdict === 'access_control_enforced' ? 'fixed'
							: (evaluation.verdict === 'invalid_identity' ? 'authentication_expired'
								: (rerunResult?.results?.length && rerunResult.results.every(item => item.status === 'error' || /404|not found/i.test(item.error || '')) ? 'endpoint_changed' : 'inconclusive')));
					const history = (Array.isArray(current.item.metadata?.lifecycle_history) ? current.item.metadata.lifecycle_history : [])
						.concat({ at, action: 'retest', verdict: evaluation.verdict, status: lifecycleStatus, classification }).slice(-50);
					const nextEvidence = rerunResult?.finding ? { ...rerunResult.finding, id: undefined, tested_at: at } : { ...evidence, tested_at: at, last_retest: evaluation };
					const saved = await invoke('entities.save', { kind: 'findings', project_id: projectId, id: findingId, name: current.item.name, value: JSON.stringify(nextEvidence), metadata: { ...current.item.metadata, lifecycle_status: lifecycleStatus, lifecycle_history: history, last_tested: at, confidence: evaluation.confidence || current.item.metadata?.confidence, last_retest_classification: classification } });
					const responseKey = matrixRecipe ? 'matrix' : 'diff';
					return { [responseKey]: { ...rerunResult, finding: evaluation.finding === true ? { id: findingId, ...nextEvidence } : null, summary: { ...(rerunResult?.summary || {}), finding_saved: evaluation.finding === true, finding_id: findingId, lifecycle_status: lifecycleStatus, retest_classification: classification } }, finding: saved.item };
				}
				try {
					return await executeHTTPAuthzMatrix(projectId, evidence.recipe, current.item);
				} catch (error) {
					const at = new Date().toISOString();
					const classification = /connect|refused|dns|no such host|not found|404|invalid url|operation failed|security test failed/i.test(error.message || '') ? 'endpoint_changed' : 'inconclusive';
					const history = (Array.isArray(current.item.metadata?.lifecycle_history) ? current.item.metadata.lifecycle_history : []).concat({ at, action: 'retest', verdict: 'request_failed', status: 'inconclusive', classification, error: String(error.message || '').slice(0, 500) }).slice(-50);
					const saved = await invoke('entities.save', { kind: 'findings', project_id: projectId, id: findingId, name: current.item.name, value: current.item.value, metadata: { ...current.item.metadata, lifecycle_status: 'inconclusive', lifecycle_history: history, last_tested: at, last_retest_classification: classification } });
					return { matrix: { evaluation: { verdict: 'request_failed', finding: false, detail: error.message }, results: [], summary: { finding_saved: false, finding_id: findingId, lifecycle_status: 'inconclusive', retest_classification: classification } }, finding: saved.item };
				}
			}
			if (method === 'PATCH' || method === 'POST') {
				const allowedStatuses = new Set(['open', 'confirmed', 'rejected', 'fixed', 'inconclusive']);
				const requestedStatus = String(body.lifecycle_status || body.status || '').toLowerCase();
				const status = requestedStatus || current.item.metadata?.lifecycle_status || 'open';
				if (!allowedStatuses.has(status)) throw Object.assign(new Error('Finding status must be open, confirmed, rejected, fixed, or inconclusive'), { status: 400 });
				const allowedSeverities = new Set(['INFO', 'LOW', 'MEDIUM', 'HIGH', 'CRITICAL']);
				const severity = String(body.severity || current.item.metadata?.severity || 'INFO').toUpperCase();
				if (!allowedSeverities.has(severity)) throw Object.assign(new Error('Finding severity is invalid'), { status: 400 });
				const allowedConfidence = new Set(['none', 'low', 'medium', 'high', 'confirmed']);
				const confidence = String(body.confidence || current.item.metadata?.confidence || 'medium').toLowerCase();
				if (!allowedConfidence.has(confidence)) throw Object.assign(new Error('Finding confidence is invalid'), { status: 400 });
				const at = new Date().toISOString();
				const history = (Array.isArray(current.item.metadata?.lifecycle_history) ? current.item.metadata.lifecycle_history : [])
					.concat({ at, action: 'status_change', status, note: String(body.note || '').slice(0, 1000) }).slice(-50);
				const saved = await invoke('entities.save', {
					kind: 'findings', project_id: projectId, id: findingId, name: current.item.name, value: current.item.value,
					metadata: { ...current.item.metadata, lifecycle_status: status, severity, confidence, lifecycle_history: history, last_reviewed: at },
				});
				return { status: 'success', finding: saved.item };
			}
			return { status: 'success', finding: current.item };
		}
		if (action === 'identities') {
			if (method === 'POST') { const saved = await invoke('entities.save', { kind: 'identities', project_id: projectId, id: body.id || '', name: body.alias || body.name || 'identity', value: '', metadata: body }); return { status: 'success', identity: expandIdentity(saved.item), item: saved.item }; }
			const listed = await invoke('entities.list', { kind: 'identities', project_id: projectId, limit: Number(search.get('limit')) || 200 });
			return { status: 'success', identities: listed.items.map(expandIdentity), items: listed.items };
		}
		if (action === 'http-templates') {
			if (method === 'POST') {
				const template = { method: body.method || 'GET', url: body.url, headers: normalizeHeaders(body.headers), body: body.body || '', name: body.name || 'HTTP template', editable_fields: [...String(body.url || '').matchAll(/\{\{([^}]+)\}\}/g)].map(match => match[1]) };
				const saved = await invoke('entities.save', { kind: 'sessions', project_id: projectId, name: template.name, value: JSON.stringify(template), metadata: { type: 'http-template' } });
				return { status: 'success', template: { ...template, id: saved.item.id } };
			}
			const listed = await invoke('entities.list', { kind: 'sessions', project_id: projectId, limit: Number(search.get('limit')) || 200 });
			return { status: 'success', templates: listed.items.filter(item => item.metadata?.type === 'http-template').map(item => ({ id: item.id, ...JSON.parse(item.value || '{}') })) };
		}
		const kind = entityKind(action);
        if (kind) {
            if (method === 'POST') {
                return invoke('entities.save', {
                    kind, project_id: projectId, id: body.id || '',
                    name: body.name || body.alias || body.title || body.type || action,
                    value: typeof body.value === 'string' ? body.value : JSON.stringify(body),
                    metadata: body,
				}).then(result => ({ status: 'success', [action.replace(/-([a-z])/g, (_, c) => c.toUpperCase()).replace(/s$/, '')]: result.item, item: result.item }));
            }
            return invoke('entities.list', { kind, project_id: projectId, limit: Number(search.get('limit')) || 200 })
				.then(result => ({ status: 'success', [action.replace(/-/g, '_')]: result.items, items: result.items }));
        }
        throw Object.assign(new Error(`Unsupported project action: ${action}`), { status: 501 });
    }

    function toWebRequest(body) {
        return {
            project_id: body.project_id || body.projectId || '', url: body.url,
            method: body.method || 'GET', headers: normalizeHeaders(body.headers),
            body: body.body || '', timeout_ms: body.timeout_ms || 20_000,
            tls_skip_verify: body.tls_skip_verify === true, follow_redirects: body.follow_redirects !== false,
			restrict_redirect_origin: body.restrict_redirect_origin === true,
        };
    }

    async function dispatch(input, init = {}) {
        const raw = typeof input === 'string' ? input : String(input?.url || input);
        const url = new URL(raw, 'http://wshawk.internal');
        const path = url.pathname;
        const method = String(init.method || 'GET').toUpperCase();
        const body = parseBody(init);

        if (path.startsWith('/platform/projects')) return projectRoute(path, method, body, url.searchParams);
        if (path === '/web/request') {
            const result = await invoke('http.request', toWebRequest(body));
            const response = result.response;
            return { ...response, headers: Object.entries(response.headers || {}).map(([key, value]) => `${key}: ${Array.isArray(value) ? value.join(', ') : value}`).join('\n'), body: response.body || response.body_base64 || '', flow_id: response.flow_id };
        }
		if (path === '/web/dirscan') {
			const operationId = body.operation_id || `dir_${Date.now()}_${Math.random().toString(16).slice(2, 10)}`;
			const result = await invoke('web.dirscan', {
				operation_id: operationId, project_id: body.project_id || lastProjectId, url: body.url,
				words: Array.isArray(body.words) ? body.words : undefined,
				concurrency: boundedInteger(body.concurrency, 4, 1, 16),
				timeout_ms: boundedInteger(body.timeout_ms, 5000, 1000, 15000),
				operation_timeout_ms: boundedInteger(body.operation_timeout_ms, 30000, 5000, 120000),
			});
			const active = createEventSocket();
			for (const item of result.found || []) {
				let itemPath = item.url;
				try { itemPath = new URL(item.url).pathname; } catch (_) {}
				active.deliver('dir_result', { path: itemPath, status: item.status, length: item.bytes, type: 'endpoint', variant_paths: [] });
			}
			active.deliver('dir_done', { findings_count: result.found?.length || 0, checked: result.checked || 0, suppressed_soft_404: result.soft_404_filtered || 0, wildcard_detected: result.wildcard_detected === true });
			return result;
		}
		if (path === '/web/vulnscan') {
			if (activeVulnerabilityScan && !activeVulnerabilityScan.cancelRequested) {
				throw Object.assign(new Error('A vulnerability scan is already running'), { code: 'scan_already_running', status: 409 });
			}
			const active = createEventSocket();
			const projectId = body.project_id || lastProjectId;
			const started = performance.now();
			const findings = [];
			const bounded = (value, fallback, minimum, maximum) => Math.min(maximum, Math.max(minimum, Number(value) || fallback));
			const operation = { id: `vuln_${Date.now()}_${Math.random().toString(16).slice(2, 10)}`, cancelRequested: false };
			activeVulnerabilityScan = operation;
			lastOperationId = operation.id;
			const requestTimeoutMS = bounded(body.request_timeout_ms || body.timeout_ms, 5000, 1000, 15000);
			const operationTimeoutMS = bounded(body.operation_timeout_ms, 60000, 5000, 120000);
			let currentPhase = 'crawl';
			const phase = (name, status, message) => {
				currentPhase = name;
				active.deliver('vuln_phase', { phase: name, status });
				if (message) active.deliver('vuln_log', { level: status === 'error' ? 'error' : 'info', msg: message });
			};
			const assertActive = () => {
				if (operation.cancelRequested) throw Object.assign(new Error('Vulnerability scan cancelled by the operator'), { code: 'operation_cancelled', status: 499 });
			};
			try {
				phase('crawl', 'running', 'Crawling same-origin application pages (bounded to 20 pages by default).');
				const crawl = await invoke('web.crawl', { operation_id: operation.id, project_id: projectId, url: body.url, max_pages: bounded(body.max_pages, 20, 1, 50), depth: bounded(body.depth, 1, 1, 3), timeout_ms: requestTimeoutMS, operation_timeout_ms: operationTimeoutMS });
				assertActive();
				phase('crawl', 'done', `Crawl completed: ${crawl.visited || 0} pages, ${(crawl.endpoints || []).length} endpoints.`);
				phase('headers', 'running', 'Analyzing response headers and passive response indicators.');
				const scanRequest = toWebRequest({ ...body, project_id: projectId, timeout_ms: requestTimeoutMS, follow_redirects: false });
				const analysis = await invoke('web.analyze', { operation_id: operation.id, operation_timeout_ms: Math.min(operationTimeoutMS, 20000), request: scanRequest });
				assertActive();
				for (const item of analysis.findings || []) {
					const finding = { ...item, severity: titleSeverity(item.severity), title: String(item.type || 'finding').replace(/-/g, ' ') };
					findings.push(finding);
					await invoke('entities.save', { kind: 'findings', project_id: projectId, name: item.type || 'web-finding', value: item.detail || '', metadata: finding });
				}
				phase('headers', 'done', `Passive analysis completed: ${(analysis.findings || []).length} findings.`);
				phase('dirscan', 'running', 'Checking a bounded high-value directory list.');
				let directoryBase = body.url;
				try { directoryBase = new URL('/', body.url).toString(); } catch (_) {}
				const directory = await invoke('web.dirscan', { operation_id: operation.id, project_id: projectId, url: directoryBase, words: body.words, concurrency: bounded(body.concurrency, 8, 1, 16), timeout_ms: requestTimeoutMS, operation_timeout_ms: Math.min(operationTimeoutMS, 30000) });
				assertActive();
				phase('dirscan', 'done', `Directory scan completed: ${directory.checked || 0} paths checked, ${(directory.found || []).length} responses found.`);
				phase('fuzz', 'running', 'Running bounded active mutation probes with four concurrent requests.');
				let parameter = body.parameter || 'q';
				try { parameter = body.parameter || [...new URL(body.url).searchParams.keys()][0] || 'q'; } catch (_) {}
				const scan = await invoke('scanner.run', { operation_id: operation.id, project_id: projectId, request: scanRequest, parameter, location: body.location || 'query', categories: body.categories || [], oast_url: body.oast_url || '', authorization_confirmed: true, max_requests: bounded(body.max_requests, 50, 1, 100), concurrency: bounded(body.scan_concurrency, 4, 1, 8), operation_timeout_ms: operationTimeoutMS });
				assertActive();
				for (const item of scan.findings || []) findings.push({ ...item, severity: titleSeverity(item.severity), title: String(item.type || 'finding').replace(/-/g, ' ') });
				phase('fuzz', 'done', `Active mutation completed: ${scan.completed || 0} probes.`);
				const report = { status: 'completed', operation_id: operation.id, target: body.url, elapsed: ((performance.now() - started) / 1000).toFixed(2), total_findings: findings.length, findings, crawl, directory, active_scan: scan };
				active.deliver('vuln_complete', report);
				return report;
			} catch (error) {
				const cancelled = operation.cancelRequested || error?.code === 'operation_cancelled' || /context canceled/i.test(String(error?.detail || error?.message || ''));
				const message = cancelled ? 'Vulnerability scan cancelled.' : `Vulnerability scan failed during ${currentPhase}: ${error.message}`;
				phase(currentPhase, 'error', message);
				active.deliver('vuln_error', { operation_id: operation.id, phase: currentPhase, cancelled, code: error?.code || 'scan_failed', message });
				if (cancelled && !error.status) error.status = 499;
				throw error;
			} finally {
				if (activeVulnerabilityScan === operation) activeVulnerabilityScan = null;
				if (lastOperationId === operation.id) lastOperationId = '';
			}
		}
        if (path === '/web/fuzz' || path === '/web/ssrf' || path === '/web/redirect' || path === '/web/proto') {
            lastOperationId = `scan_${Date.now()}`;
			const categoryByRoute = { '/web/ssrf': ['ssrf'], '/web/redirect': ['redirect'], '/web/proto': ['prototype_pollution'] };
			const categoryByWordlist = { sqli: ['sqli'], xss: ['xss'], cmd: ['command_injection'], command: ['command_injection'], nosql: ['nosql_injection'], path_traversal: ['path_traversal'], lfi: ['path_traversal'], xxe: ['xxe'] };
			const categories = body.categories || categoryByRoute[path] || (path === '/web/fuzz' ? categoryByWordlist[String(body.wordlist || '').toLowerCase()] : []) || [];
			let parameter = body.parameter || body.param || 'q';
			try {
				for (const [name, value] of new URL(body.url).searchParams) if (String(value).includes('FUZZ')) { parameter = name; break; }
			} catch (_) {}
			const result = await invoke('scanner.run', {
				operation_id: lastOperationId, project_id: body.project_id || lastProjectId,
				request: toWebRequest({ ...(body.request || body), timeout_ms: body.timeout_ms || 5000, follow_redirects: false }), parameter,
				location: body.location || 'query', categories,
                oast_url: body.oast_url || '', authorization_confirmed: true, max_requests: body.max_requests || 100,
				concurrency: Math.min(Math.max(Number(body.concurrency) || 4, 1), 8), operation_timeout_ms: Math.min(Math.max(Number(body.operation_timeout_ms) || 60000, 5000), 120000),
            });
			if (path === '/web/redirect') return { ...result, total_findings: result.findings.length, elapsed: result.elapsed, findings: result.findings.map(item => ({ ...item, severity: titleSeverity(item.severity), payload_name: item.type, param: parameter, redirect_type: 'external', redirect_to: item.redirect_to || '' })) };
			if (path === '/web/proto') return { ...result, tests_run: result.completed, total_findings: result.findings.length, elapsed: result.elapsed, baseline_length: result.baseline?.body_bytes || 0, findings: result.findings.map(item => ({ ...item, severity: titleSeverity(item.severity), vector: 'JSON prototype key', response_diff: 0, indicators: [item.detail] })) };
			if (path === '/web/ssrf') return { ...result, total_findings: result.findings.length, payloads_sent: result.completed };
			return result;
        }
		if (path === '/web/crawl' || path === '/web/crawl-sensitive') {
			return invoke('web.crawl', {
				operation_id: body.operation_id || `crawl_${Date.now()}_${Math.random().toString(16).slice(2, 10)}`,
				project_id: body.project_id || lastProjectId, url: body.url,
				max_pages: boundedInteger(body.max_pages, 20, 1, 50),
				depth: boundedInteger(body.max_depth || body.depth, 1, 1, 3),
				timeout_ms: boundedInteger(body.timeout_ms, 5000, 1000, 15000),
				operation_timeout_ms: boundedInteger(body.operation_timeout_ms, 60000, 5000, 120000),
			});
		}
        if (['/web/headers', '/web/cors', '/web/waf', '/web/sensitive', '/web/csrf', '/web/fingerprint'].includes(path)) {
			const canaryOrigin = body.origin || 'https://wshawk.invalid';
			const requestBody = path === '/web/cors'
				? { ...body, headers: { ...normalizeHeaders(body.headers), Origin: canaryOrigin } }
				: body;
			const result = await invoke('web.analyze', {
				request: toWebRequest({
					...requestBody,
					timeout_ms: boundedInteger(body.timeout_ms, 10000, 1000, 15000),
					follow_redirects: false,
					restrict_redirect_origin: true,
				}),
			});
			if (path === '/web/fingerprint') {
				const technologies = result.findings.filter(item => item.type === 'technology-disclosure').map(item => ({ name: item.detail, category: 'Server', confidence: 'High' }));
				return { status: 'success', technologies, count: technologies.length };
			}
			if (path === '/web/sensitive') {
				const findings = result.findings.filter(item => item.type.startsWith('sensitive-')).map(item => ({ type: item.type.replace('sensitive-', ''), severity: titleSeverity(item.severity), value: item.detail }));
				return { status: 'success', findings, total: findings.length };
			}
			if (path === '/web/waf') {
				const matches = result.findings.filter(item => item.type === 'waf-detected');
				const detected = matches.map(item => ({ name: item.detail.split(':').pop().trim(), matched_via: ['response signature'], method: 'passive' }));
				return { status: 'success', detected, waf_count: detected.length, blocked: result.response.status === 403, evidence: matches.map(item => item.detail) };
			}
			if (path === '/web/cors') {
				const matches = result.findings.filter(item => item.type.startsWith('cors-'));
				const allowOrigin = responseHeader(result.response.headers, 'Access-Control-Allow-Origin');
				const allowCredentials = responseHeader(result.response.headers, 'Access-Control-Allow-Credentials').trim().toLowerCase() === 'true';
				if (allowCredentials && allowOrigin === canaryOrigin && !matches.some(item => item.type === 'cors-reflected-origin-credentials')) {
					matches.push({ type: 'cors-reflected-origin-credentials', severity: 'high', detail: 'CORS reflects an untrusted origin while allowing credentials' });
				}
				const findings = matches.map(item => ({ severity: titleSeverity(item.severity), test: item.type, origin_sent: canaryOrigin, acao_received: allowOrigin || 'Missing', credentials: allowCredentials, detail: item.detail || '' }));
				return { status: 'success', findings, total: findings.length, risk_score: findings.some(item => item.severity === 'High') ? 'High' : 'Safe' };
			}
			if (path === '/web/csrf') {
				const requestHeaders = normalizeHeaders(body.headers);
				const protectedRequest = /csrf|xsrf/i.test(`${body.body || ''}\n${JSON.stringify(requestHeaders)}`);
				const methodName = String(body.method || 'POST').toUpperCase();
				const fields = [...new URLSearchParams(body.body || '')].map(([name, value]) => `<input type="hidden" name="${escapeHTML(name)}" value="${escapeHTML(value)}">`).join('\n');
				const poc = `<!doctype html><form method="${escapeHTML(methodName)}" action="${escapeHTML(body.url)}">${fields}<button>Submit request</button></form>`;
				return { status: 'success', exploitable: !protectedRequest && result.response.status < 400, poc_type: 'HTML form', poc_html: poc, warnings: protectedRequest ? ['A CSRF token-like value was present; verify server-side validation manually.'] : [] };
			}
			const values = result.response.headers || {};
			const getHeader = name => { const key = Object.keys(values).find(item => item.toLowerCase() === name.toLowerCase()); return key ? values[key].join(', ') : 'Missing'; };
			const headers = {};
			for (const [name, missingType, risk] of [['Content-Security-Policy', 'missing-csp', 'High'], ['X-Content-Type-Options', 'missing-nosniff', 'Medium'], ['Referrer-Policy', 'missing-referrer-policy', 'Low'], ['Strict-Transport-Security', 'missing-hsts', 'Medium']]) {
				const value = getHeader(name); const missing = result.findings.some(item => item.type === missingType);
				headers[name] = { value, risk: missing ? risk : 'Safe', msg: missing ? `${name} is absent.` : `${name} is present.` };
			}
			return { status: 'success', headers };
        }
		if (path === '/web/ssl') {
			const target = body.url || `https://${body.host}${body.port ? `:${body.port}` : ''}`;
			const result = await invoke('tls.inspect', { url: target, skip_verify: body.skip_verify === true });
			const notAfter = result.not_after ? new Date(result.not_after) : null;
			const issues = [];
			if (result.expired) issues.push({ severity: 'High', msg: 'Certificate is expired.' });
			return { status: 'success', risk_score: issues.length ? 'High' : 'Safe', certificate: { subject: result.subject, issuer: result.issuer, not_before: result.not_before, not_after: result.not_after, days_remaining: notAfter ? Math.floor((notAfter - Date.now()) / 86400000) : null, protocol: result.version, cipher: result.cipher_suite, cipher_bits: null, san: result.dns_names || [] }, protocols: [{ name: result.version, supported: true }], issues };
		}
        if (path === '/web/chain') {
			return invoke('workflow.run', { ...body, project_id: body.project_id || lastProjectId, authorization_confirmed: true });
        }
		if (path === '/web/subdomains') {
			const result = await invoke('network.subdomains', { target: body.target || body.domain || body.url, names: Array.isArray(body.names) ? body.names : [] });
			return {
				...result,
				status: 'success',
				subdomain_details: result.subdomains || [],
				subdomains: (result.subdomains || []).map(item => item.name),
				ambiguous_details: result.ambiguous || [],
				ambiguous: (result.ambiguous || []).map(item => item.name),
			};
		}
		if (path === '/web/dns') { const result = await invoke('network.dns', { target: body.target || body.domain || body.url }); return { status: 'success', dns_records: { A_AAAA: result.addresses || [], CNAME: result.cname ? [result.cname] : [], MX: result.mx || [], NS: result.ns || [], TXT: result.txt || [] }, whois: {}, elapsed: 0 }; }
		if (path === '/web/portscan') {
			const result = await invoke('network.portscan', { target: body.target || body.host || body.url, ports: body.ports || '', timeout_ms: body.timeout_ms || 1000, authorization_confirmed: true });
			const active = createEventSocket();
			for (const item of result.open_ports || []) active.deliver('port_found', item);
			active.deliver('portscan_done', { open_count: result.open_ports?.length || 0, total_scanned: result.ports_scanned || 0, elapsed: 0 });
			return result;
		}
        if (path === '/scan/start') {
            if (/^wss?:/i.test(body.url || '')) {
                const result = await invoke('ws.connect', { project_id: body.project_id, url: body.url, headers: body.headers || {}, timeout_ms: 15_000, reconnect_attempts: 2 });
                lastConnectionId = result.connection_id;
                return { ...result, vulnerabilities_count: 0 };
            }
            lastOperationId = `scan_${Date.now()}`;
            const result = await invoke('scanner.run', { operation_id: lastOperationId, project_id: body.project_id, request: toWebRequest({ ...body, timeout_ms: body.timeout_ms || 5000, follow_redirects: false }), parameter: body.parameter || 'q', location: body.location || 'query', authorization_confirmed: true, concurrency: 4, operation_timeout_ms: 60000 });
            return { ...result, vulnerabilities_count: result.findings?.length || 0 };
        }
        if (path === '/blaster/stop') {
			if (!activeBlaster) return { cancelled: false };
			activeBlaster.cancelled = true;
			if (activeBlaster.connectionId) await invoke('ws.disconnect', { connection_id: activeBlaster.connectionId }).catch(() => {});
			return { cancelled: true };
		}
        if (path === '/web/vulnscan/stop') {
            if (!activeVulnerabilityScan) return { cancelled: false, reason: 'No vulnerability scan is running' };
			activeVulnerabilityScan.cancelRequested = true;
			const operationId = activeVulnerabilityScan.id;
			const result = await invoke('operation.cancel', { operation_id: operationId }).catch(() => ({ cancelled: false }));
			return { ...result, operation_id: operationId, cancelled: true, accepted: true };
		}
        if (path === '/scan/stop') {
            if (lastOperationId) return invoke('operation.cancel', { operation_id: lastOperationId });
            if (lastConnectionId) return invoke('ws.disconnect', { connection_id: lastConnectionId });
            return { cancelled: false };
        }
        if (path === '/reqforge/send') {
            if (!lastConnectionId) { const connected = await invoke('ws.connect', { project_id: body.project_id, url: body.url, headers: body.headers || {} }); lastConnectionId = connected.connection_id; }
            return invoke('ws.send', { connection_id: lastConnectionId, message_type: body.binary ? 'binary' : 'text', payload: typeof body.payload === 'string' ? body.payload : JSON.stringify(body.payload), payload_base64: body.payload_base64 || '' });
        }
		if (path === '/auth/test') return invoke('scanner.auth_test', { project_id: body.project_id || lastProjectId, url: body.url, authenticated_headers: body.headers || {}, authorization_confirmed: true });
        if (path === '/interceptor/toggle') return invoke('ws.intercept.set', { connection_id: lastConnectionId, enabled: body.enabled === true });
        if (path === '/interceptor/action') return invoke('ws.intercept.action', { intercept_id: body.id || body.intercept_id, action: body.action, payload: body.payload || '', payload_base64: body.payload_base64 || '' });
        if (path.startsWith('/blaster/payloads/')) {
			const result = await invoke('scanner.catalog');
			const category = path.split('/').pop();
			const aliases = { sqli_all: 'sqli', sqli_time: 'sqli', sqli_error: 'sqli', sqli_boolean: 'sqli', xss_all: 'xss', xss_ws: 'xss', cmd: 'command_injection', lfi: 'path_traversal' };
			const wanted = aliases[category] || category;
			const payloads = result.payloads.filter(item => item.category === wanted).map(item => item.value);
			return { status: 'success', payloads, count: payloads.length };
		}
		if (path === '/blaster/start') {
			if (activeBlaster && !activeBlaster.cancelled) throw Object.assign(new Error('A payload blast is already running'), { status: 409 });
			let payloads = (Array.isArray(body.payloads) ? body.payloads : []).map(String).map(item => item.trim()).filter(Boolean).slice(0, 100);
			if (!payloads.length) throw Object.assign(new Error('At least one non-empty payload is required'), { status: 400 });
			if (body.spe === true) {
				const evolved = [];
				for (const payload of payloads) {
					evolved.push(payload);
					const result = await invoke('scanner.mutate', { payload, strategy: 'auto', count: 2 });
					for (const mutation of result.mutations || []) if (!evolved.includes(mutation)) evolved.push(mutation);
					if (evolved.length >= 100) break;
				}
				payloads = evolved.slice(0, 100);
			}
			const active = createEventSocket();
			const token = { cancelled: false, connectionId: '' };
			activeBlaster = token;
			const results = [];
			try {
				if (/^wss?:/i.test(body.url || '')) {
					const connected = await invoke('ws.connect', { project_id: body.project_id || lastProjectId, url: body.url, headers: { ...authFlowHeaders(body.auth_flow), ...normalizeHeaders(body.headers) }, timeout_ms: 15_000, reconnect_attempts: 1 });
					token.connectionId = connected.connection_id;
					lastConnectionId = connected.connection_id;
					for (const payload of payloads) {
						if (token.cancelled) break;
						const message = applyBlasterTemplate(body.template, payload);
						active.deliver('blaster_progress', { payload, status: 'running' });
						try {
							const exchange = await invoke('ws.probe', { connection_id: connected.connection_id, message_type: 'text', payload: message, timeout_ms: 10_000 });
							const response = exchange.response?.payload || exchange.response?.payload_base64 || '';
							const item = { payload, status: 'success', length: String(response).length, response: String(response).slice(0, 2_000), dom_verified: false, dom_evidence: body.dom_verify ? 'DOM execution was not claimed for an isolated WebSocket frame. Use the DOM verifier with the application page and a selector.' : '' };
							results.push(item); active.deliver('blaster_result', item);
						} catch (error) {
							if (token.cancelled) break;
							const item = { payload, status: 'error', length: 0, response: error.message, dom_verified: false, dom_evidence: '' };
							results.push(item); active.deliver('blaster_result', item);
						}
					}
				} else if (/^https?:/i.test(body.url || '')) {
					for (const payload of payloads) {
						if (token.cancelled) break;
						active.deliver('blaster_progress', { payload, status: 'running' });
						try {
							const response = (await invoke('http.request', { project_id: body.project_id || lastProjectId, url: body.url, method: body.method || 'POST', headers: { ...authFlowHeaders(body.auth_flow), ...normalizeHeaders(body.headers) }, body: applyBlasterTemplate(body.template, payload), timeout_ms: 10_000, follow_redirects: false })).response;
							const responseBody = response.body || response.body_base64 || '';
							const item = { payload, status: response.status < 500 ? 'success' : 'error', length: response.body_bytes || String(responseBody).length, response: String(responseBody).slice(0, 2_000), dom_verified: false, dom_evidence: body.dom_verify ? 'DOM verification requires an explicit page selector and is available through the DOM verifier IPC method.' : '' };
							results.push(item); active.deliver('blaster_result', item);
						} catch (error) {
							const item = { payload, status: 'error', length: 0, response: error.message, dom_verified: false, dom_evidence: '' };
							results.push(item); active.deliver('blaster_result', item);
						}
					}
				} else throw Object.assign(new Error('Blaster target must use ws://, wss://, http://, or https://'), { status: 400 });
				return { status: token.cancelled ? 'cancelled' : 'success', sent: results.length, results };
			} finally {
				if (token.connectionId) await invoke('ws.disconnect', { connection_id: token.connectionId }).catch(() => {});
				if (activeBlaster === token) activeBlaster = null;
				active.deliver('blaster_completed', { cancelled: token.cancelled, sent: results.length });
			}
		}
        if (path === '/dom/status') {
			const result = await invoke('browser.status');
			return { ...result, status: 'success', playwright_installed: result.available === true && result.browserReady === true };
		}
		if (path === '/dom/auth/record') {
			const recorded = await invoke('browser.auth.record', { url: body.login_url || body.url, visible: true, timeoutMs: body.timeout_ms || (Number(body.timeout_s) || 120) * 1000, waitForURL: body.wait_for_url });
			const local = recorded.storage?.localStorage || {};
			const session = recorded.storage?.sessionStorage || {};
			return { status: 'success', flow: { url: recorded.url, cookies: recorded.cookies || [], local_storage: local, session_storage: session, storage: recorded.storage || {}, extracted_tokens: { ...tokenLikeStorage(local), ...tokenLikeStorage(session) }, ws_headers: {}, screenshot_base64: recorded.screenshotBase64 || '' } };
		}
		if (path === '/dom/auth/replay') {
			const flow = body.flow || body.auth_flow || {};
			const result = await invoke('browser.auth.replay', { url: body.url || flow.url, cookies: flow.cookies || [], storage: flow.storage || { localStorage: flow.local_storage || {}, sessionStorage: flow.session_storage || {} }, timeoutMs: body.timeout_ms || 30_000 });
			return { status: 'success', replay: result };
		}
		if (path === '/dom/xss/verify') {
			const result = await invoke('browser.dom_xss.verify', { url: body.url, selector: body.selector, submitSelector: body.submit_selector, payload: body.payload, marker: body.marker, timeoutMs: body.timeout_ms, ignoreHTTPSErrors: body.ignore_tls_errors === true, authorizationConfirmed: body.authorization_confirmed === true });
			return { status: 'success', verification: result };
		}
		if (path === '/discovery/scan') { const result = await invoke('web.crawl', { project_id: body.project_id || lastProjectId, url: body.url || body.target, max_pages: body.max_pages || 50, depth: body.depth || 2 }); return { endpoints: result.endpoints.filter(item => /^wss?:/i.test(item)).map(item => ({ url: item, source: 'crawler', confidence: 'medium' })), crawl: result }; }
		if (path === '/discovery/probe') { const result = await invoke('ws.connect', { project_id: body.project_id || lastProjectId, url: body.url, headers: body.headers || {}, timeout_ms: body.timeout_ms || 10_000 }); lastConnectionId = result.connection_id; return { ...result, alive: true }; }
		if (path === '/oast/poll') return invoke('oast.poll', { project_id: body.project_id, url: body.url || body.poll_url || '', headers: body.headers || {} });
		if (path === '/binary/analyze') return invoke('scanner.binary_analyze', { payload_base64: body.payload_base64 }).then(analysis => ({ status: 'success', analysis }));
		if (path === '/mutate') {
			const result = await invoke('scanner.mutate', { payload: body.payload, strategy: body.strategy || 'auto', count: Math.min(Number(body.count) || 10, 100) });
			return { status: 'success', ...result };
		}
		if (path === '/ai/context-exploit') {
			const catalog = await invoke('scanner.catalog');
			const aliases = { command: 'command_injection', cmd: 'command_injection', lfi: 'path_traversal', nosql: 'nosql_injection', proto: 'prototype_pollution' };
			const requested = new Set((body.vuln_types || []).map(item => aliases[String(item).toLowerCase()] || String(item).toLowerCase()));
			const candidates = catalog.payloads.filter(item => !requested.size || requested.has(item.category));
			const payloads = [];
			for (const item of candidates) {
				payloads.push(item.value);
				if (payloads.length >= Math.min(Number(body.count) || 12, 50)) break;
				const evolved = await invoke('scanner.mutate', { payload: item.value, strategy: 'auto', count: 2 });
				for (const mutation of evolved.mutations || []) {
					if (!payloads.includes(mutation)) payloads.push(mutation);
					if (payloads.length >= Math.min(Number(body.count) || 12, 50)) break;
				}
				if (payloads.length >= Math.min(Number(body.count) || 12, 50)) break;
			}
			const fullText = String(body.full_text || '');
			const start = Math.max(0, Math.min(Number(body.cursor_pos) || 0, fullText.length));
			const selection = String(body.selection || '');
			const end = Math.min(fullText.length, start + selection.length);
			let format = 'raw';
			try { JSON.parse(fullText); format = 'json'; } catch (_) { if (/^\s*</.test(fullText)) format = 'xml'; }
			const before = fullText.slice(0, start);
			const keyMatch = before.match(/["']?([A-Za-z_][\w.-]*)["']?\s*[:=]\s*["']?$/);
			return { status: 'success', payloads, blaster_template: `${fullText.slice(0, start)}§inject§${fullText.slice(end)}`, context: { format, key: keyMatch?.[1] || '', data_type: typeof body.selection }, vuln_labels: [...new Set(candidates.map(item => item.category))] };
		}
		if (path === '/config/get') return { status: 'success', ...JSON.parse(localStorage.getItem('wshawk.direct.config') || '{}') };
		if (path === '/config/save') {
			const safe = Object.fromEntries(Object.entries(body).filter(([key]) => !/(token|api.?key|secret|password)/i.test(key)));
			localStorage.setItem('wshawk.direct.config', JSON.stringify(safe));
			return { status: 'success', saved: true, secrets_persisted: false };
		}
		if (path === '/session/save') {
			lastProjectId = body.project_id || lastProjectId;
			if (!lastProjectId) throw Object.assign(new Error('Select or create a project before saving a workspace session'), { status: 400 });
			const result = await invoke('entities.save', { kind: 'sessions', project_id: lastProjectId, name: body.name, value: JSON.stringify(body.session || {}), metadata: { type: 'workspace-session', created: new Date().toISOString() } });
			return { status: 'success', name: body.name, project_id: lastProjectId, path: result.item.id };
		}
		if (path === '/session/list') {
			const requestedProjectId = url.searchParams.get('project_id') || '';
			let projects = [];
			if (requestedProjectId) {
				projects = [{ id: requestedProjectId, name: '' }];
			} else {
				const result = await invoke('projects.list', { limit: 200 });
				projects = Array.isArray(result.projects) ? result.projects : [];
			}

			const sessionGroups = await Promise.all(projects.map(async project => {
				try {
					const result = await invoke('entities.list', { kind: 'sessions', project_id: project.id, limit: 200 });
					return (result.items || []).filter(item => {
						if (item.metadata?.type) return item.metadata.type === 'workspace-session';
						try {
							const value = JSON.parse(item.value || '{}');
							return Boolean(value.snapshots || value.target);
						} catch (_) {
							return false;
						}
					}).map(item => ({
						id: item.id,
						name: item.name,
						created: item.created_at,
						project_id: project.id,
						project_name: project.name || '',
					}));
				} catch (_) {
					return [];
				}
			}));
			const sessions = sessionGroups.flat().sort((left, right) => String(right.created || '').localeCompare(String(left.created || '')));
			return { sessions };
		}
		if (path === '/session/load') {
			lastProjectId = body.project_id || lastProjectId;
			if (!lastProjectId) throw Object.assign(new Error('Select a project before loading a workspace session'), { status: 400 });
			const result = await invoke('entities.list', { kind: 'sessions', project_id: lastProjectId, limit: 200 });
			const item = result.items.find(candidate => {
				const requested = body.id ? candidate.id === body.id : candidate.name === body.name;
				return requested && candidate.metadata?.type !== 'http-template';
			});
			if (!item) throw Object.assign(new Error('Session was not found'), { status: 404 });
			return { status: 'success', project_id: lastProjectId, session: { id: item.id, name: item.name, data: JSON.parse(item.value || '{}') } };
		}
        if (path.startsWith('/team/')) return { status: 'local-only', members: 1, room_code: body.room_code || 'LOCAL' };
        if (path === '/proxy/ca/generate') return invoke('cert.ca.generate', { common_name: body.common_name, valid_days: body.valid_days });
        if (path === '/proxy/ca/host') return invoke('cert.host.generate', { ca_certificate_pem: body.ca_certificate_pem, ca_key_pem: body.ca_key_pem, hostname: body.hostname, valid_days: body.valid_days });
		if (path === '/web/report') {
			const report = await invoke('reports.generate', { project_id: body.project_id || lastProjectId, format: body.format || 'html' });
			const saved = await invoke('dialog.report.save', { content: report.content, extension: report.extension });
			return { status: saved.canceled ? 'cancelled' : 'success', path: saved.path || '', report };
		}
		if (path === '/extension/pairing/approve') return { status: 'unavailable', detail: 'The Electron + Go edition does not expose a network pairing endpoint.' };
		if (path === '/history') {
			if (!lastProjectId) return { status: 'success', history: [] };
			const result = await invoke('entities.list', { kind: 'attack_runs', project_id: lastProjectId, limit: 200 });
			return { status: 'success', history: result.items.map(item => ({ id: item.id, target: item.metadata?.target || '', timestamp: item.created_at, elapsed: item.metadata?.elapsed || 0, findings: item.metadata?.findings || [] })) };
		}
		if (path.startsWith('/history/compare/')) {
			const [, , , currentId, previousId] = path.split('/');
			const [current, previous] = await Promise.all([
				invoke('entities.get', { kind: 'attack_runs', id: currentId }),
				invoke('entities.get', { kind: 'attack_runs', id: previousId }),
			]);
			const currentFindings = current.item.metadata?.findings || [];
			const previousFindings = previous.item.metadata?.findings || [];
			const key = item => JSON.stringify([item.type || item.category || '', item.url || '', item.parameter || '']);
			const currentKeys = new Set(currentFindings.map(key));
			const previousKeys = new Set(previousFindings.map(key));
			const fixed = previousFindings.filter(item => !currentKeys.has(key(item)));
			const newVulns = currentFindings.filter(item => !previousKeys.has(key(item)));
			return { status: 'success', diff: { fixed_count: fixed.length, new_count: newVulns.length, fixed, new_vulns: newVulns } };
		}
		if (path.startsWith('/history/')) {
			const id = path.split('/').pop();
			const result = await invoke('entities.get', { kind: 'attack_runs', id });
			return { status: 'success', scan: { id, target: result.item.metadata?.target || '', timestamp: result.item.created_at, findings: result.item.metadata?.findings || [] } };
		}
        throw Object.assign(new Error(`No direct IPC mapping for ${path}`), { status: 501 });
    }

    async function ipcRequest(input, init = {}) {
        try {
            const data = await dispatch(input, init);
            return new IPCResponse(200, data, data?.response?.headers || {});
        } catch (error) {
            return new IPCResponse(error.status || 500, { code: error.code || 'ipc_error', message: error.message, detail: error.detail || error.message });
        }
    }

    class EventSocket {
        constructor() {
            this.listeners = new Map();
            this.io = this;
            this.connected = true;
            queueMicrotask(() => this.deliver('connect', {}));
        }
        on(name, callback) {
            if (typeof callback !== 'function') return this;
            const values = this.listeners.get(name) || new Set(); values.add(callback); this.listeners.set(name, values); return this;
        }
        off(name, callback) { this.listeners.get(name)?.delete(callback); return this; }
        emit(name, data) { this.deliver(name, data); return this; }
        deliver(name, data) { for (const callback of this.listeners.get(name) || []) { try { callback(data); } catch (error) { console.error(error); } } }
        removeAllListeners() { this.listeners.clear(); }
        disconnect() { this.connected = false; this.deliver('disconnect', { reason: 'renderer disconnect' }); }
    }

    let socket;
    function createEventSocket() { if (!socket || !socket.connected) socket = new EventSocket(); return socket; }

    window.wshawk.subscribe('worker:event', (message) => {
        const event = message?.event || '';
        const data = message?.data || {};
        const active = createEventSocket();
        active.deliver(event, data);
        active.deliver('platform_event', data);
        if (event === 'ws.frame') active.deliver('message_sent', data.direction === 'inbound' ? { response: data.payload || data.payload_base64 } : { msg: data.payload || data.payload_base64 });
        if (event === 'ws.intercepted') active.deliver('intercepted_frame', data);
        if (event === 'scan.progress') active.deliver('scan_progress', { ...data, progress: data.total ? Math.round(data.completed * 100 / data.total) : 0, phase: data.category });
		if (event === 'scan.progress') active.deliver('vuln_phase', { phase: 'fuzz', status: 'running' });
		if (event === 'scan.response') active.deliver('fuzz_result', { ...data, grepped: data.matched === true });
		if (event === 'scan.finding') active.deliver('vulnerability_found', data);
		if (event === 'scan.finding' && data.type === 'ssrf') active.deliver('ssrf_finding', { ...data, severity: titleSeverity(data.severity), category: 'SSRF', param: '', status: data.status, indicators: [data.detail] });
		if (event === 'scan.completed') {
			active.deliver('scan_update', { status: 'completed', vulnerabilities_count: data.findings?.length || 0 });
			active.deliver('fuzz_done', { findings_count: data.findings?.length || 0 });
			active.deliver('vuln_phase', { phase: 'fuzz', status: 'done' });
			if (!activeVulnerabilityScan || data.operation_id !== activeVulnerabilityScan.id) {
				active.deliver('vuln_complete', { ...data, findings: (data.findings || []).map(item => ({ ...item, severity: String(item.severity || 'info').replace(/^./, char => char.toUpperCase()), title: item.title || item.type })), total_findings: data.findings?.length || 0 });
			}
		}
		if (event === 'crawl_page') active.deliver('crawl_page', { ...data, content_length: data.bytes || 0 });
		if (event === 'crawl_complete') active.deliver('crawl_done', { pages_crawled: data.visited || 0, forms_found: 0, scripts_found: 0, api_endpoints_found: data.endpoints?.length || 0, errors_count: (data.pages || []).filter(item => item.error).length, elapsed_seconds: 0 });
    });

    window.ipcRequest = ipcRequest;
    window.WSHawkIPC = Object.freeze({ invoke, request: ipcRequest, createEventSocket });
    window.api = Object.freeze({
        send(channel) {
            const method = ({ 'window:minimize': 'window.minimize', 'window:maximize': 'window.maximize', 'window:close': 'window.close' })[channel];
            if (method) void invoke(method);
        },
        receive(channel, callback) {
            if (channel === 'bridge-ready') queueMicrotask(() => callback(true));
            if (channel === 'bridge-port') queueMicrotask(() => callback(0));
            return () => {};
        },
        async invoke(channel, value) {
            if (channel === 'dialog:openProject') {
                const result = await invoke('dialog.project.open');
                if (result.canceled) return { canceled: true };
                const project = result.project || {};
                return { success: true, data: { projectId: project.id, projectName: project.name, url: project.target_url, findings: [], logs: [], history: [] } };
            }
            if (channel === 'dialog:saveProject') {
                const saved = await invoke('projects.save', { id: value.projectId || '', name: value.projectName || 'WSHawk Project', target_url: value.url || '', metadata: { desktop_state: value } });
                const result = await invoke('dialog.project.export', { project_id: saved.project.id });
                return { success: !result.canceled, canceled: result.canceled, path: saved.project.name };
            }
            if (channel === 'dialog:exportReport') {
                const result = await invoke('dialog.report.save', { content: String(value || ''), extension: 'html' });
                return { success: !result.canceled, canceled: result.canceled };
            }
            throw new Error(`Unsupported desktop dialog: ${channel}`);
        },
    });
})();
