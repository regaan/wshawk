import copy
import json
import re
from typing import Any, Dict, Iterable, List, Optional, Tuple

from .common import build_ws_headers, serialize_ws_payload, ws_result_effective_success
from .replay import replay_websocket_message
from wshawk.store import ProjectStore


_FIELD_HINTS = (
    "channel",
    "topic",
    "room",
    "stream",
    "subscription",
    "tenant",
    "workspace",
    "org",
    "project",
    "account",
    "user",
    "member",
    "object",
    "resource",
    "entity",
    "id",
)

_SENSITIVE_VALUE_RE = re.compile(r"(admin|root|internal|private|audit|debug|all|\*)", re.I)


def _walk_mutable_paths(value: Any, prefix: Tuple[Any, ...] = ()) -> Iterable[Tuple[Tuple[Any, ...], Any]]:
    if isinstance(value, dict):
        for key, nested in value.items():
            path = prefix + (key,)
            key_text = str(key).lower()
            if any(hint in key_text for hint in _FIELD_HINTS):
                yield path, nested
            yield from _walk_mutable_paths(nested, path)
    elif isinstance(value, list):
        for index, nested in enumerate(value):
            yield from _walk_mutable_paths(nested, prefix + (index,))


def _normalize_field_path(path: Any) -> Tuple[Any, ...]:
    if isinstance(path, (list, tuple)):
        return tuple(path)
    if isinstance(path, str):
        normalized: List[Any] = []
        for part in path.split("."):
            if part.isdigit():
                normalized.append(int(part))
            else:
                normalized.append(part)
        return tuple(normalized)
    raise ValueError(f"Unsupported field path: {path!r}")


def _path_to_string(path: Tuple[Any, ...]) -> str:
    return ".".join(str(part) for part in path)


def _get_path(payload: Any, path: Tuple[Any, ...]) -> Any:
    current = payload
    for part in path:
        if isinstance(current, dict) and part in current:
            current = current[part]
        elif isinstance(current, list) and isinstance(part, int) and 0 <= part < len(current):
            current = current[part]
        else:
            return None
    return current


def _set_path(payload: Any, path: Tuple[Any, ...], value: Any) -> None:
    current = payload
    for part in path[:-1]:
        current = current[part]
    current[path[-1]] = value


def _dedupe(values: Iterable[Any]) -> List[Any]:
    seen = set()
    ordered = []
    for value in values:
        try:
            key = json.dumps(value, sort_keys=True)
        except Exception:
            key = str(value)
        if key in seen:
            continue
        seen.add(key)
        ordered.append(value)
    return ordered


def _sensitive_candidate(value: Any) -> bool:
    if isinstance(value, (int, float)):
        return value in {-1, 0, 1, 9999, 99999}
    return bool(_SENSITIVE_VALUE_RE.search(str(value)))


def _default_candidates(field_name: str, original: Any) -> List[Any]:
    field_name = field_name.lower()
    candidates: List[Any] = []

    if any(token in field_name for token in ("channel", "topic", "room", "stream", "subscription")):
        candidates.extend(["admin", "admins", "private", "internal", "audit", "debug", "*", "all"])
    if any(token in field_name for token in ("tenant", "workspace", "org", "project", "account")):
        candidates.extend(["global", "root", "all-tenants", "tenant-0", "internal"])
    if any(token in field_name for token in ("user", "member", "object", "resource", "entity", "id")):
        candidates.extend(["0", "1", "999999", "admin", "root", "other-user"])

    if isinstance(original, bool):
        candidates.extend([not original, True])
    elif isinstance(original, int):
        candidates.extend([0, 1, -1, original + 1, 999999])
    elif isinstance(original, str) and original.isdigit():
        numeric = int(original)
        candidates.extend([str(item) for item in [0, 1, -1, numeric + 1, 999999]])
    elif isinstance(original, str) and original:
        candidates.extend([f"{original}-admin", f"{original}-shadow"])

    return _dedupe(candidates)


def _mutation_paths(payload: Any, field_paths: Optional[List[Any]] = None) -> List[Tuple[Any, ...]]:
    if field_paths:
        return [_normalize_field_path(path) for path in field_paths]
    return [path for path, _ in _walk_mutable_paths(payload)]


def generate_subscription_mutations(
    payload: Any,
    *,
    field_paths: Optional[List[Any]] = None,
    candidate_values: Optional[List[Any]] = None,
    max_mutations: int = 24,
) -> List[Dict[str, Any]]:
    if isinstance(payload, str):
        try:
            parsed_payload = json.loads(payload)
        except Exception:
            return []
    else:
        parsed_payload = copy.deepcopy(payload)

    if not isinstance(parsed_payload, (dict, list)):
        return []

    mutations: List[Dict[str, Any]] = []
    for path in _mutation_paths(parsed_payload, field_paths=field_paths):
        original = _get_path(parsed_payload, path)
        if original is None:
            continue
        field_name = str(path[-1])
        values = _dedupe([*(candidate_values or []), *_default_candidates(field_name, original)])
        for candidate in values:
            if candidate == original:
                continue
            mutated = copy.deepcopy(parsed_payload)
            _set_path(mutated, path, candidate)
            mutations.append(
                {
                    "field_path": _path_to_string(path),
                    "field_name": field_name,
                    "original_value": original,
                    "candidate_value": candidate,
                    "payload": mutated,
                    "sensitive_candidate": _sensitive_candidate(candidate),
                }
            )
            if len(mutations) >= max_mutations:
                return mutations
    return mutations


def _response_fingerprint(result: Dict[str, Any]) -> str:
    return json.dumps(
        {
            "status": result.get("status"),
            "response": result.get("response", ""),
            "error": result.get("error", ""),
        },
        sort_keys=True,
    )


class WebSocketSubscriptionAbuseService:
    """Probe channel/object/tenant tampering against live WebSocket actions."""

    def __init__(self, store: Optional[ProjectStore] = None):
        self.store = store

    async def probe(
        self,
        *,
        project_id: str,
        url: str,
        payload: Any,
        identities: Optional[List[Optional[Dict[str, Any]]]] = None,
        headers: Optional[Dict[str, Any]] = None,
        timeout: float = 8.0,
        field_paths: Optional[List[Any]] = None,
        candidate_values: Optional[List[Any]] = None,
        max_mutations: int = 24,
    ) -> Dict[str, Any]:
        identities = identities or [None]
        mutations = generate_subscription_mutations(
            payload,
            field_paths=field_paths,
            candidate_values=candidate_values,
            max_mutations=max_mutations,
        )
        target = self.store.ensure_target(project_id, url, kind="websocket") if self.store else None
        run = self.store.start_attack_run(
            project_id=project_id,
            attack_type="ws_subscription_abuse",
            target_id=target["id"] if target else None,
            parameters={
                "url": url,
                "headers": headers or {},
                "field_paths": field_paths or [],
                "candidate_values": candidate_values or [],
                "max_mutations": max_mutations,
            },
        ) if self.store else None

        baseline_results: List[Dict[str, Any]] = []
        attempts: List[Dict[str, Any]] = []
        suspicious_attempts: List[Dict[str, Any]] = []

        for identity in identities:
            baseline = await replay_websocket_message(
                url=url,
                payload=payload,
                identity=identity,
                headers=headers or {},
                timeout=timeout,
            )
            baseline["kind"] = "baseline"
            baseline_results.append(baseline)

            baseline_fp = _response_fingerprint(baseline)

            if self.store and run:
                baseline_conn = self.store.open_ws_connection(
                    project_id=project_id,
                    url=url,
                    attack_run_id=run["id"],
                    handshake_headers=build_ws_headers(identity=identity, override_headers=headers or {}),
                    metadata={"source": "ws_subscription_abuse", "identity_alias": identity.get("alias") if identity else ""},
                )
                self.store.add_ws_frame(
                    project_id=project_id,
                    connection_id=baseline_conn["id"],
                    direction="out",
                    payload=serialize_ws_payload(payload),
                    metadata={"attack_run_id": run["id"], "kind": "baseline"},
                )
                if baseline.get("response"):
                    self.store.add_ws_frame(
                        project_id=project_id,
                        connection_id=baseline_conn["id"],
                        direction="in",
                        payload=baseline["response"],
                        metadata={"attack_run_id": run["id"], "kind": "baseline"},
                    )
                self.store.close_ws_connection(
                    baseline_conn["id"],
                    state=baseline.get("status", "unknown"),
                    metadata={"timing_ms": baseline.get("timing_ms"), "error": baseline.get("error", "")},
                )

            for mutation in mutations:
                result = await replay_websocket_message(
                    url=url,
                    payload=mutation["payload"],
                    identity=identity,
                    headers=headers or {},
                    timeout=timeout,
                )
                result.update(
                    {
                        "kind": "mutation",
                        "field_path": mutation["field_path"],
                        "field_name": mutation["field_name"],
                        "original_value": mutation["original_value"],
                        "candidate_value": mutation["candidate_value"],
                        "candidate_sensitive": mutation["sensitive_candidate"],
                        "baseline_status": baseline.get("status"),
                        "baseline_response_preview": baseline.get("response_preview", ""),
                    }
                )
                result["behavior_changed"] = _response_fingerprint(result) != baseline_fp
                result["accepted_mutation"] = ws_result_effective_success(result)
                if result["accepted_mutation"] and (result["behavior_changed"] or mutation["sensitive_candidate"]):
                    suspicious_attempts.append(result)
                attempts.append(result)

                if self.store and run:
                    conn = self.store.open_ws_connection(
                        project_id=project_id,
                        url=url,
                        attack_run_id=run["id"],
                        handshake_headers=build_ws_headers(identity=identity, override_headers=headers or {}),
                        metadata={
                            "source": "ws_subscription_abuse",
                            "identity_alias": identity.get("alias") if identity else "",
                            "field_path": mutation["field_path"],
                            "candidate_value": mutation["candidate_value"],
                        },
                    )
                    self.store.add_ws_frame(
                        project_id=project_id,
                        connection_id=conn["id"],
                        direction="out",
                        payload=serialize_ws_payload(mutation["payload"]),
                        metadata={
                            "attack_run_id": run["id"],
                            "kind": "mutation",
                            "field_path": mutation["field_path"],
                            "candidate_value": mutation["candidate_value"],
                        },
                    )
                    if result.get("response"):
                        self.store.add_ws_frame(
                            project_id=project_id,
                            connection_id=conn["id"],
                            direction="in",
                            payload=result["response"],
                            metadata={
                                "attack_run_id": run["id"],
                                "kind": "mutation",
                                "field_path": mutation["field_path"],
                                "candidate_value": mutation["candidate_value"],
                            },
                        )
                    self.store.close_ws_connection(
                        conn["id"],
                        state=result.get("status", "unknown"),
                        metadata={
                            "timing_ms": result.get("timing_ms"),
                            "error": result.get("error", ""),
                            "candidate_value": mutation["candidate_value"],
                            "behavior_changed": result["behavior_changed"],
                        },
                    )

        field_summary: Dict[str, Dict[str, Any]] = {}
        for attempt in attempts:
            entry = field_summary.setdefault(
                attempt["field_path"],
                {
                    "field_name": attempt["field_name"],
                    "attempts": 0,
                    "suspicious_attempts": 0,
                    "accepted_attempts": 0,
                    "values": [],
                },
            )
            entry["attempts"] += 1
            entry["accepted_attempts"] += 1 if attempt["accepted_mutation"] else 0
            entry["suspicious_attempts"] += 1 if attempt in suspicious_attempts else 0
            if len(entry["values"]) < 10:
                entry["values"].append(attempt["candidate_value"])

        summary = {
            "identity_count": len(identities),
            "baseline_count": len(baseline_results),
            "mutation_count": len(attempts),
            "accepted_mutation_count": sum(1 for attempt in attempts if attempt["accepted_mutation"]),
            "suspicious_attempt_count": len(suspicious_attempts),
            "behavior_change_count": sum(1 for attempt in attempts if attempt["behavior_changed"]),
            "field_summary": list(field_summary.values()),
            "recommended_severity": (
                "high"
                if any(attempt.get("candidate_sensitive") and attempt.get("accepted_mutation") for attempt in suspicious_attempts)
                else "medium"
                if suspicious_attempts
                else "info"
            ),
        }

        if self.store and run:
            self.store.update_attack_run(
                run["id"],
                status="completed",
                summary=summary,
                completed=True,
            )

        return {
            "attack_run_id": run["id"] if run else None,
            "baseline_results": baseline_results,
            "mutations": mutations,
            "attempts": attempts,
            "suspicious_attempts": suspicious_attempts,
            "summary": summary,
        }
