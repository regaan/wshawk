import asyncio
import json
import re
from typing import Any, Awaitable, Callable, Dict, List, Optional

from wshawk.db_manager import WSHawkDatabase
from wshawk.store import ProjectStore
from wshawk.transport import WSHawkHTTPProxy

from .authz_diff import WebSocketAuthzDiffService
from .common import build_ws_headers, normalize_ws_message, serialize_ws_payload
from .http_authz_diff import HTTPAuthzDiffService
from .http_common import merge_http_identity
from .http_race import HTTPRaceService
from .race import WebSocketRaceService
from .replay import WebSocketReplayService, replay_websocket_message


EventCallback = Optional[Callable[[Dict[str, Any]], Awaitable[None]]]


class WorkflowExecutionService:
    """Execute project-backed offensive workflows across HTTP, WS, and attack services."""

    PLAYBOOKS: Dict[str, Dict[str, Any]] = {
        "login_bootstrap": {
            "title": "Login Bootstrap",
            "description": "Bootstrap a browser/login flow, extract CSRF/session material, and record a note for follow-on replay.",
            "variables": ["http_login_url", "http_auth_url", "login_body", "csrf_regex", "session_regex"],
        },
        "csrf_session_capture": {
            "title": "CSRF / Session Capture",
            "description": "Fetch an authenticated page, extract CSRF/session values, and persist them for follow-on HTTP or WS abuse.",
            "variables": ["http_page_url", "csrf_regex", "session_regex"],
        },
        "http_replay": {
            "title": "HTTP Replay",
            "description": "Replay an authenticated HTTP request using workflow variables, then extract follow-on values from the response.",
            "variables": ["http_method", "http_target_url", "http_body"],
        },
        "ws_privilege_escalation": {
            "title": "WS Privilege Escalation",
            "description": "Use a browser/bootstrap token to replay a WebSocket action and capture authorization drift signals.",
            "variables": ["ws_target_url", "ws_payload"],
        },
        "stale_token_reuse": {
            "title": "Stale Token Reuse",
            "description": "Replay a stale HTTP or WS action and then race it to detect replay-before-invalidation windows.",
            "variables": ["http_target_url", "http_method", "http_body", "ws_target_url", "ws_payload"],
        },
        "tenant_hopping": {
            "title": "Tenant Hopping",
            "description": "Run HTTP and WS authorization diffs across tenant-scoped requests to detect object or tenant boundary drift.",
            "variables": ["tenant_value", "http_target_url", "ws_target_url", "ws_payload"],
        },
    }

    def __init__(
        self,
        db: Optional[WSHawkDatabase] = None,
        store: Optional[ProjectStore] = None,
        http_proxy: Optional[WSHawkHTTPProxy] = None,
    ):
        self.db = db or WSHawkDatabase()
        self.store = store or ProjectStore(self.db)
        self.http_proxy = http_proxy or WSHawkHTTPProxy(self.store)
        self.http_authz_diff_service = HTTPAuthzDiffService(store=self.store, http_proxy=self.http_proxy)
        self.http_race_service = HTTPRaceService(store=self.store, http_proxy=self.http_proxy)
        self.ws_replay_service = WebSocketReplayService(store=self.store)
        self.ws_authz_diff_service = WebSocketAuthzDiffService(store=self.store)
        self.ws_race_service = WebSocketRaceService(store=self.store)

    @classmethod
    def list_playbooks(cls) -> List[Dict[str, Any]]:
        return [
            {"id": name, **meta}
            for name, meta in sorted(cls.PLAYBOOKS.items(), key=lambda item: item[0])
        ]

    @staticmethod
    def _inject_vars(value: Any, variables: Dict[str, Any]) -> Any:
        if isinstance(value, str):
            whole_match = re.fullmatch(r"\{\{(\w+)\}\}", value)
            if whole_match:
                key = whole_match.group(1)
                if key in variables:
                    return variables[key]

            def replace(match):
                key = match.group(1)
                return str(variables.get(key, match.group(0)))

            return re.sub(r"\{\{(\w+)\}\}", replace, value)
        if isinstance(value, dict):
            return {key: WorkflowExecutionService._inject_vars(item, variables) for key, item in value.items()}
        if isinstance(value, list):
            return [WorkflowExecutionService._inject_vars(item, variables) for item in value]
        return value

    @staticmethod
    def _extract_by_rule(rule: Dict[str, Any], source_map: Dict[str, Any]) -> Optional[Any]:
        source_name = str(rule.get("from", "body"))
        source_value = source_map.get(source_name)
        if source_value is None:
            return None

        json_path = rule.get("path")
        if json_path:
            current = source_value
            for part in str(json_path).split("."):
                if isinstance(current, dict):
                    current = current.get(part)
                else:
                    return None
            return current

        regex = rule.get("regex", "")
        if regex:
            search_text = source_value if isinstance(source_value, str) else json.dumps(source_value)
            match = re.search(regex, search_text, re.IGNORECASE)
            if match:
                return match.group(1) if match.lastindex else match.group(0)
        return None

    def _resolve_identity(self, project_id: str, step: Dict[str, Any], default_identity: Optional[Dict[str, Any]] = None):
        if step.get("identity_id"):
            identity = self.db.get_identity(step["identity_id"])
            if identity and identity.get("project_id") == project_id:
                return identity
        if step.get("identity_alias"):
            return self.db.get_identity_by_alias(project_id, step["identity_alias"])
        return default_identity

    def _resolve_identities(
        self,
        project_id: str,
        step: Dict[str, Any],
        default_identity: Optional[Dict[str, Any]] = None,
    ) -> List[Dict[str, Any]]:
        resolved: List[Dict[str, Any]] = []
        seen = set()

        for identity_id in step.get("identity_ids") or []:
            identity = self.db.get_identity(identity_id)
            if identity and identity.get("project_id") == project_id and identity["id"] not in seen:
                resolved.append(identity)
                seen.add(identity["id"])

        for alias in step.get("identity_aliases") or []:
            identity = self.db.get_identity_by_alias(project_id, alias)
            if identity and identity["id"] not in seen:
                resolved.append(identity)
                seen.add(identity["id"])

        if not resolved and default_identity:
            resolved.append(default_identity)
        if not resolved:
            resolved = self.db.list_identities(project_id)
        return resolved

    def _source_map_from_http_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        body = result.get("body", "") or result.get("response", "") or ""
        parsed_json: Dict[str, Any] = {}
        if str(body).strip().startswith(("{", "[")):
            try:
                parsed_json = json.loads(body)
            except Exception:
                parsed_json = {}
        return {
            "body": body,
            "response": body,
            "headers": result.get("headers", {}),
            "http_status": result.get("http_status", result.get("status", "")),
            "status": result.get("status", ""),
            "json": parsed_json,
            "summary": result.get("summary", {}),
            "result": result,
        }

    def _source_map_from_ws_result(self, result: Dict[str, Any]) -> Dict[str, Any]:
        response = result.get("response", "")
        parsed_json: Dict[str, Any] = {}
        if str(response).strip().startswith(("{", "[")):
            try:
                parsed_json = json.loads(response)
            except Exception:
                parsed_json = {}
        return {
            "response": response,
            "body": response,
            "status": result.get("status", ""),
            "json": parsed_json,
            "summary": result.get("summary", {}),
            "result": result,
        }

    def _apply_extractions(
        self,
        *,
        step: Dict[str, Any],
        source_map: Dict[str, Any],
        variables: Dict[str, Any],
    ) -> Dict[str, Any]:
        extracted: Dict[str, Any] = {}
        for rule in step.get("extract", []) or []:
            var_name = rule.get("var")
            if not var_name:
                continue
            value = self._extract_by_rule(rule, source_map)
            if value is not None:
                variables[var_name] = value
                extracted[var_name] = value
        return extracted

    def _playbook_steps(
        self,
        *,
        playbook: str,
        default_url: str = "",
        default_ws_url: str = "",
    ) -> List[Dict[str, Any]]:
        if playbook not in self.PLAYBOOKS:
            raise ValueError(f"Unknown workflow playbook: {playbook}")

        http_url = default_url or "{{http_target_url}}"
        ws_url = default_ws_url or "{{ws_target_url}}"
        login_url = default_url or "{{http_login_url}}"
        auth_url = default_url or "{{http_auth_url}}"
        page_url = default_url or "{{http_page_url}}"
        csrf_regex = '(?i)(?:csrf|xsrf|authenticity)[^>\\s"\']*[=:]"?([^"\'\\s>]+)'
        session_regex = "(?i)(?:session|token|access_token|jwt)[^\"'\\s=:>]*[=:]\"?([^\"'\\s>]+)"

        if playbook == "login_bootstrap":
            return [
                {
                    "name": "Fetch Login Page",
                    "type": "http",
                    "method": "GET",
                    "url": login_url,
                    "extract": [
                        {"var": "csrf_token", "from": "body", "regex": csrf_regex},
                    ],
                },
                {
                    "name": "Submit Credentials",
                    "type": "http",
                    "method": "POST",
                    "url": auth_url,
                    "headers": {"Content-Type": "application/x-www-form-urlencoded"},
                    "body": "{{login_body}}",
                    "extract": [
                        {"var": "session_token", "from": "headers", "regex": session_regex},
                        {"var": "auth_response_token", "from": "body", "regex": session_regex},
                    ],
                },
                {
                    "name": "Capture Bootstrap Note",
                    "type": "note",
                    "title": "Login bootstrap captured",
                    "body": "Workflow captured CSRF/session material and prepared the project for follow-on HTTP or WS replay.",
                },
            ]

        if playbook == "csrf_session_capture":
            return [
                {
                    "name": "Fetch Authenticated Page",
                    "type": "http",
                    "method": "GET",
                    "url": page_url,
                    "extract": [
                        {"var": "csrf_token", "from": "body", "regex": csrf_regex},
                        {"var": "session_token", "from": "headers", "regex": session_regex},
                    ],
                },
                {
                    "name": "Record Captured State",
                    "type": "note",
                    "title": "CSRF/session capture",
                    "body": "Captured CSRF/session material for follow-on abuse.",
                },
            ]

        if playbook == "http_replay":
            return [
                {
                    "name": "Replay HTTP Request",
                    "type": "http",
                    "method": "{{http_method}}",
                    "url": http_url,
                    "body": "{{http_body}}",
                    "headers": {"Content-Type": "{{http_content_type}}"},
                    "extract": [
                        {"var": "http_status", "from": "http_status", "regex": r"(.+)"},
                    ],
                },
            ]

        if playbook == "ws_privilege_escalation":
            return [
                {
                    "name": "Replay Bootstrap HTTP Request",
                    "type": "http",
                    "method": "{{http_method}}",
                    "url": http_url,
                    "body": "{{http_body}}",
                    "continue_on_error": True,
                },
                {
                    "name": "Replay Privileged WS Action",
                    "type": "ws",
                    "url": ws_url,
                    "payload": "{{ws_payload}}",
                    "extract": [{"var": "ws_result", "from": "response", "regex": r"(.+)"}],
                },
            ]

        if playbook == "stale_token_reuse":
            return [
                {
                    "name": "Prime Stale State",
                    "type": "http",
                    "method": "{{http_method}}",
                    "url": http_url,
                    "body": "{{http_body}}",
                    "continue_on_error": True,
                },
                {"name": "Wait For Replay Window", "type": "sleep", "duration_ms": 500},
                {
                    "name": "Race Stale Replay",
                    "type": "http_race",
                    "method": "{{http_method}}",
                    "url": http_url,
                    "body": "{{http_body}}",
                    "mode": "replay_before_invalidation",
                    "concurrency": 4,
                    "waves": 2,
                    "stagger_ms": 15,
                },
            ]

        if playbook == "tenant_hopping":
            return [
                {
                    "name": "HTTP Tenant Diff",
                    "type": "http_authz_diff",
                    "method": "{{http_method}}",
                    "url": http_url,
                    "body": "{{http_body}}",
                    "headers": {"X-Tenant": "{{tenant_value}}"},
                },
                {
                    "name": "WS Tenant Diff",
                    "type": "ws_authz_diff",
                    "url": ws_url,
                    "payload": "{{ws_payload}}",
                },
            ]

        raise ValueError(f"Unhandled workflow playbook: {playbook}")

    async def _emit_result(self, event_callback: EventCallback, result: Dict[str, Any]):
        if event_callback:
            await event_callback(result)

    async def execute(
        self,
        *,
        project_id: str,
        steps: Optional[List[Dict[str, Any]]] = None,
        playbook: str = "",
        initial_vars: Optional[Dict[str, Any]] = None,
        default_url: str = "",
        default_ws_url: str = "",
        default_identity: Optional[Dict[str, Any]] = None,
        timeout: float = 8.0,
        default_headers: Optional[Dict[str, Any]] = None,
        default_cookies: Optional[Dict[str, Any]] = None,
        correlation_id: str = "",
        attack_run_id: Optional[str] = None,
        event_callback: EventCallback = None,
    ) -> Dict[str, Any]:
        steps = list(steps or [])
        if playbook:
            steps = self._playbook_steps(playbook=playbook, default_url=default_url, default_ws_url=default_ws_url) + steps
        if not steps:
            raise ValueError("At least one workflow step is required")

        created_run = None
        run_id = attack_run_id
        if not run_id:
            created_run = self.store.start_attack_run(
                project_id=project_id,
                attack_type="workflow",
                identity_id=default_identity.get("id") if default_identity else None,
                parameters={
                    "step_count": len(steps),
                    "default_url": default_url,
                    "default_ws_url": default_ws_url,
                    "playbook": playbook,
                },
            )
            run_id = created_run["id"]

        variables = dict(initial_vars or {})
        results: List[Dict[str, Any]] = []
        active_correlation_id = correlation_id or f"workflow-{run_id[:12]}"

        for index, raw_step in enumerate(steps, start=1):
            step = self._inject_vars(raw_step, variables)
            step_type = step.get("type") or ("http" if step.get("method") else "ws" if step.get("payload") is not None else "note")
            step_name = step.get("name") or f"Step {index}"
            identity = self._resolve_identity(project_id, step, default_identity=default_identity)
            extracted: Dict[str, Any] = {}

            if step.get("condition"):
                condition_name = str(step["condition"])
                if condition_name not in variables:
                    result = {
                        "step": index,
                        "name": step_name,
                        "type": step_type,
                        "status": "skipped",
                        "reason": f"Variable '{condition_name}' not set",
                    }
                    results.append(result)
                    await self._emit_result(event_callback, result)
                    continue

            if step_type == "sleep":
                duration_ms = int(step.get("duration_ms", 500))
                await asyncio.sleep(duration_ms / 1000.0)
                result = {"step": index, "name": step_name, "type": "sleep", "status": "success", "duration_ms": duration_ms}
                results.append(result)
                await self._emit_result(event_callback, result)
                continue

            if step_type == "set":
                new_vars = step.get("variables") or {}
                variables.update(new_vars)
                result = {"step": index, "name": step_name, "type": "set", "status": "success", "variables": new_vars}
                results.append(result)
                await self._emit_result(event_callback, result)
                continue

            if step_type == "note":
                note = self.store.save_note(
                    project_id=project_id,
                    title=step.get("title") or step_name,
                    body=str(step.get("body", "")),
                )
                result = {"step": index, "name": step_name, "type": "note", "status": "success", "note_id": note["id"]}
                results.append(result)
                await self._emit_result(event_callback, result)
                continue

            if step_type in {"http", "http_replay"}:
                url = step.get("url") or default_url
                headers, cookies = merge_http_identity(
                    identity=identity,
                    headers={**(default_headers or {}), **(step.get("headers") or {})},
                    cookies=default_cookies or {},
                )
                result = await self.http_proxy.send_request(
                    method=step.get("method", "GET"),
                    url=url,
                    headers=headers,
                    body=str(step.get("body", "")),
                    cookies=cookies,
                    project_id=project_id,
                    correlation_id=active_correlation_id,
                    attack_run_id=run_id,
                    metadata={"source": "workflow", "step": index, "name": step_name, "identity_alias": identity.get("alias") if identity else ""},
                    allow_redirects=bool(step.get("allow_redirects", False)),
                    timeout_s=int(step.get("timeout_s", timeout) or timeout),
                    verify_ssl=bool(step.get("verify_ssl", True)),
                )
                source_map = self._source_map_from_http_result(
                    {
                        "status": "error" if result.get("error") else "received",
                        "http_status": result.get("status", ""),
                        "body": result.get("body", ""),
                        "headers": result.get("headers_dict") or {},
                        "summary": {"flow_id": result.get("flow_id"), "correlation_id": active_correlation_id},
                    }
                )
                extracted = self._apply_extractions(step=step, source_map=source_map, variables=variables)
                step_result = {
                    "step": index,
                    "name": step_name,
                    "type": step_type,
                    "status": "success" if not result.get("error") else "error",
                    "method": step.get("method", "GET"),
                    "url": url,
                    "http_status": result.get("status", ""),
                    "response_length": len(result.get("body", "")),
                    "response_preview": result.get("body", "")[:300],
                    "flow_id": result.get("flow_id"),
                    "extracted": extracted,
                }
                results.append(step_result)
                await self._emit_result(event_callback, step_result)
                if result.get("error") and not step.get("continue_on_error", True):
                    break
                continue

            if step_type == "http_authz_diff":
                identities = self._resolve_identities(project_id, step, default_identity=default_identity)
                diff_result = await self.http_authz_diff_service.compare(
                    project_id=project_id,
                    identities=identities,
                    method=step.get("method", "GET"),
                    url=step.get("url") or default_url,
                    headers={**(default_headers or {}), **(step.get("headers") or {})},
                    body=step.get("body", ""),
                    cookies=default_cookies or {},
                    variables=variables,
                    correlation_id=active_correlation_id,
                    timeout_s=int(step.get("timeout_s", timeout) or timeout),
                )
                extracted = self._apply_extractions(
                    step=step,
                    source_map={"summary": diff_result.get("summary", {}), "result": diff_result, "json": diff_result},
                    variables=variables,
                )
                step_result = {
                    "step": index,
                    "name": step_name,
                    "type": step_type,
                    "status": "success",
                    "url": diff_result.get("url", ""),
                    "summary": diff_result.get("summary", {}),
                    "attack_run_id": diff_result.get("attack_run_id"),
                    "extracted": extracted,
                }
                results.append(step_result)
                await self._emit_result(event_callback, step_result)
                continue

            if step_type == "http_race":
                identities = self._resolve_identities(project_id, step, default_identity=default_identity)
                race_result = await self.http_race_service.run(
                    project_id=project_id,
                    identities=identities,
                    method=step.get("method", "GET"),
                    url=step.get("url") or default_url,
                    headers={**(default_headers or {}), **(step.get("headers") or {})},
                    body=step.get("body", ""),
                    cookies=default_cookies or {},
                    variables=variables,
                    correlation_id=active_correlation_id,
                    timeout_s=int(step.get("timeout_s", timeout) or timeout),
                    concurrency=int(step.get("concurrency", 5) or 5),
                    waves=int(step.get("waves", 2) or 2),
                    wave_delay_ms=int(step.get("wave_delay_ms", 0) or 0),
                    stagger_ms=int(step.get("stagger_ms", 0) or 0),
                    mode=str(step.get("mode") or "duplicate_action"),
                )
                extracted = self._apply_extractions(
                    step=step,
                    source_map={"summary": race_result.get("summary", {}), "result": race_result, "json": race_result},
                    variables=variables,
                )
                step_result = {
                    "step": index,
                    "name": step_name,
                    "type": step_type,
                    "status": "success",
                    "url": race_result.get("url", ""),
                    "summary": race_result.get("summary", {}),
                    "attack_run_id": race_result.get("attack_run_id"),
                    "extracted": extracted,
                }
                results.append(step_result)
                await self._emit_result(event_callback, step_result)
                continue

            if step_type in {"ws", "ws_replay"}:
                url = step.get("url") or default_ws_url or default_url
                payload = step.get("payload")
                headers = step.get("headers") or {}
                result = await replay_websocket_message(
                    url=url,
                    payload=payload,
                    identity=identity,
                    headers=headers,
                    timeout=float(step.get("timeout", timeout)),
                    receive_response=bool(step.get("receive_response", True)),
                )
                conn = self.store.open_ws_connection(
                    project_id=project_id,
                    url=url,
                    attack_run_id=run_id,
                    correlation_id=active_correlation_id,
                    handshake_headers=build_ws_headers(identity=identity, override_headers=headers),
                    metadata={"source": "workflow", "step": index, "name": step_name},
                )
                self.store.add_ws_frame(
                    project_id=project_id,
                    connection_id=conn["id"],
                    direction="out",
                    payload=serialize_ws_payload(payload),
                    metadata={"attack_run_id": run_id, "step": index, "name": step_name},
                )
                if result.get("response"):
                    self.store.add_ws_frame(
                        project_id=project_id,
                        connection_id=conn["id"],
                        direction="in",
                        payload=result["response"],
                        metadata={"attack_run_id": run_id, "step": index, "name": step_name},
                    )
                self.store.close_ws_connection(
                    conn["id"],
                    state=result.get("status", "unknown"),
                    metadata={"step": index, "name": step_name, "timing_ms": result.get("timing_ms"), "error": result.get("error", "")},
                )
                extracted = self._apply_extractions(step=step, source_map=self._source_map_from_ws_result(result), variables=variables)
                step_result = {
                    "step": index,
                    "name": step_name,
                    "type": step_type,
                    "status": result.get("status", "unknown"),
                    "url": url,
                    "response_length": result.get("response_length", 0),
                    "response_preview": result.get("response_preview", ""),
                    "connection_id": conn["id"],
                    "extracted": extracted,
                }
                results.append(step_result)
                await self._emit_result(event_callback, step_result)
                if result.get("status") == "error" and not step.get("continue_on_error", True):
                    break
                continue

            if step_type == "ws_authz_diff":
                identities = self._resolve_identities(project_id, step, default_identity=default_identity)
                diff_result = await self.ws_authz_diff_service.compare(
                    project_id=project_id,
                    url=step.get("url") or default_ws_url or default_url,
                    payload=step.get("payload"),
                    identities=identities,
                    headers=step.get("headers") or {},
                    timeout=float(step.get("timeout", timeout)),
                )
                extracted = self._apply_extractions(
                    step=step,
                    source_map={"summary": diff_result.get("summary", {}), "result": diff_result, "json": diff_result},
                    variables=variables,
                )
                step_result = {
                    "step": index,
                    "name": step_name,
                    "type": step_type,
                    "status": "success",
                    "url": diff_result.get("url", ""),
                    "summary": diff_result.get("summary", {}),
                    "attack_run_id": diff_result.get("attack_run_id"),
                    "extracted": extracted,
                }
                results.append(step_result)
                await self._emit_result(event_callback, step_result)
                continue

            if step_type == "ws_race":
                identities = self._resolve_identities(project_id, step, default_identity=default_identity)
                race_result = await self.ws_race_service.run(
                    project_id=project_id,
                    url=step.get("url") or default_ws_url or default_url,
                    payload=step.get("payload"),
                    identities=identities,
                    headers=step.get("headers") or {},
                    timeout=float(step.get("timeout", timeout)),
                    concurrency=int(step.get("concurrency", 5) or 5),
                    waves=int(step.get("waves", 2) or 2),
                    wave_delay_ms=int(step.get("wave_delay_ms", 0) or 0),
                    stagger_ms=int(step.get("stagger_ms", 0) or 0),
                    receive_response=bool(step.get("receive_response", True)),
                    mode=str(step.get("mode") or "duplicate_action"),
                    pre_payloads=step.get("pre_payloads") or [],
                )
                extracted = self._apply_extractions(
                    step=step,
                    source_map={"summary": race_result.get("summary", {}), "result": race_result, "json": race_result},
                    variables=variables,
                )
                step_result = {
                    "step": index,
                    "name": step_name,
                    "type": step_type,
                    "status": "success",
                    "url": race_result.get("url", ""),
                    "summary": race_result.get("summary", {}),
                    "attack_run_id": race_result.get("attack_run_id"),
                    "extracted": extracted,
                }
                results.append(step_result)
                await self._emit_result(event_callback, step_result)
                continue

            step_result = {
                "step": index,
                "name": step_name,
                "type": step_type,
                "status": "error",
                "reason": f"Unsupported step type: {step_type}",
            }
            results.append(step_result)
            await self._emit_result(event_callback, step_result)
            if not step.get("continue_on_error", True):
                break

        completed_statuses = {"success", "received", "sent"}
        summary = {
            "total_steps": len(steps),
            "completed": sum(1 for item in results if item.get("status") in completed_statuses),
            "skipped": sum(1 for item in results if item.get("status") == "skipped"),
            "errors": sum(1 for item in results if item.get("status") == "error"),
            "variable_count": len(variables),
            "playbook": playbook,
            "correlation_id": active_correlation_id,
        }

        if created_run:
            self.store.update_attack_run(created_run["id"], status="completed", summary=summary, completed=True)

        return {
            "attack_run_id": run_id,
            "results": results,
            "variables": variables,
            "summary": summary,
            "playbook": playbook or None,
            "playbooks": self.list_playbooks(),
        }
