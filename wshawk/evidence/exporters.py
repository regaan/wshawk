import json
from collections import Counter
from datetime import datetime
from html import escape
from typing import Any, Dict

from .bundles import EvidenceBundleBuilder
from .integrity import EvidenceIntegrityService
from .redaction import (
    SECRET_KEY_HINTS,
    mask_secret_value,
    sanitize_jsonable,
    sanitize_mapping,
    sanitize_payload,
    sanitize_text,
)


class EvidenceExportService:
    """Render project evidence bundles into operator-friendly export formats."""

    def __init__(self, bundle_builder: EvidenceBundleBuilder, protocol_graph=None):
        self.bundle_builder = bundle_builder
        self.protocol_graph = protocol_graph
        self.integrity = EvidenceIntegrityService()

    def _bundle_with_protocol(self, project_id: str) -> Dict[str, Any]:
        bundle = self.bundle_builder.build(project_id)
        if self.protocol_graph is not None:
            protocol_map = self.protocol_graph.build_project_map(project_id)
            bundle_finding_categories = Counter(
                finding.get("category", "unknown")
                for finding in (bundle.get("timeline", {}) or {}).get("findings", [])
                if finding.get("category")
            )
            if bundle_finding_categories:
                protocol_map["finding_categories"] = dict(bundle_finding_categories)
                protocol_map.setdefault("summary", {})["finding_count"] = len(
                    (bundle.get("timeline", {}) or {}).get("findings", [])
                )
            bundle["protocol_map"] = protocol_map
        return bundle

    def _sanitize_project(self, project: Dict[str, Any]) -> Dict[str, Any]:
        sanitized = dict(project or {})
        if "target_url" in sanitized:
            sanitized["target_url"] = sanitize_text(sanitized.get("target_url", ""))
        if "metadata" in sanitized:
            sanitized["metadata"] = sanitize_payload(sanitized.get("metadata") or {})
        return sanitized

    def _sanitize_identity(self, identity: Dict[str, Any]) -> Dict[str, Any]:
        sanitized = dict(identity or {})
        if "cookies" in sanitized:
            sanitized["cookies"] = sanitize_payload(sanitized.get("cookies") or [])
        if "headers" in sanitized:
            sanitized["headers"] = sanitize_mapping(sanitized.get("headers") or {})
        if "tokens" in sanitized:
            sanitized["tokens"] = sanitize_payload(sanitized.get("tokens") or {})
        if "storage" in sanitized:
            sanitized["storage"] = sanitize_payload(sanitized.get("storage") or {})
        if "notes" in sanitized:
            sanitized["notes"] = sanitize_text(sanitized.get("notes", ""))
        return sanitized

    def _sanitize_event(self, event: Dict[str, Any]) -> Dict[str, Any]:
        sanitized = dict(event or {})
        if "payload" in sanitized:
            sanitized["payload"] = sanitize_payload(sanitized.get("payload") or {})
        if "target" in sanitized:
            sanitized["target"] = sanitize_text(sanitized.get("target", ""))
        return sanitized

    def _sanitize_evidence(self, evidence: Dict[str, Any]) -> Dict[str, Any]:
        sanitized = dict(evidence or {})
        if "payload" in sanitized:
            sanitized["payload"] = sanitize_payload(sanitized.get("payload") or {})
        return sanitized

    def _sanitize_http_flow(self, flow: Dict[str, Any]) -> Dict[str, Any]:
        sanitized = dict(flow or {})
        sanitized["url"] = sanitize_text(sanitized.get("url", ""))
        sanitized["request_headers"] = sanitize_mapping(sanitized.get("request_headers") or {})
        sanitized["response_headers"] = sanitize_mapping(sanitized.get("response_headers") or {})
        sanitized["request_body"] = sanitize_text(sanitized.get("request_body", ""))
        sanitized["response_body"] = sanitize_text(sanitized.get("response_body", ""))
        sanitized["error"] = sanitize_text(sanitized.get("error", ""))
        sanitized["metadata"] = sanitize_payload(sanitized.get("metadata") or {})
        return sanitized

    def _sanitize_target(self, target: Dict[str, Any]) -> Dict[str, Any]:
        sanitized = dict(target or {})
        sanitized["url"] = sanitize_text(sanitized.get("url", ""))
        sanitized["metadata"] = sanitize_payload(sanitized.get("metadata") or {})
        return sanitized

    def _sanitize_ws_connection(self, connection: Dict[str, Any]) -> Dict[str, Any]:
        sanitized = dict(connection or {})
        sanitized["url"] = sanitize_text(sanitized.get("url", ""))
        sanitized["handshake_headers"] = sanitize_mapping(sanitized.get("handshake_headers") or {})
        sanitized["metadata"] = sanitize_payload(sanitized.get("metadata") or {})
        return sanitized

    def _sanitize_ws_frame(self, frame: Dict[str, Any]) -> Dict[str, Any]:
        sanitized = dict(frame or {})
        sanitized["payload_text"] = sanitize_text(sanitized.get("payload_text", ""))
        sanitized["metadata"] = sanitize_payload(sanitized.get("metadata") or {})
        return sanitized

    def _sanitize_browser_artifact(self, artifact: Dict[str, Any]) -> Dict[str, Any]:
        sanitized = dict(artifact or {})
        sanitized["url"] = sanitize_text(sanitized.get("url", ""))
        sanitized["payload"] = sanitize_payload(sanitized.get("payload") or {})
        return sanitized

    def _sanitize_attack_run(self, run: Dict[str, Any]) -> Dict[str, Any]:
        sanitized = dict(run or {})
        sanitized["parameters"] = sanitize_payload(sanitized.get("parameters") or {})
        sanitized["summary"] = sanitize_payload(sanitized.get("summary") or {})
        return sanitized

    def _sanitize_finding(self, finding: Dict[str, Any]) -> Dict[str, Any]:
        sanitized = dict(finding or {})
        sanitized["description"] = sanitize_text(sanitized.get("description", ""))
        sanitized["payload"] = sanitize_payload(sanitized.get("payload") or {})
        return sanitized

    def _sanitize_note(self, note: Dict[str, Any]) -> Dict[str, Any]:
        sanitized = dict(note or {})
        sanitized["body"] = sanitize_text(sanitized.get("body", ""))
        return sanitized

    def _sanitize_timeline(self, timeline: Dict[str, Any]) -> Dict[str, Any]:
        timeline = timeline or {}
        return {
            "targets": [self._sanitize_target(item) for item in timeline.get("targets", [])],
            "http_flows": [self._sanitize_http_flow(item) for item in timeline.get("http_flows", [])],
            "ws_connections": [self._sanitize_ws_connection(item) for item in timeline.get("ws_connections", [])],
            "ws_frames": [self._sanitize_ws_frame(item) for item in timeline.get("ws_frames", [])],
            "browser_artifacts": [self._sanitize_browser_artifact(item) for item in timeline.get("browser_artifacts", [])],
            "attack_runs": [self._sanitize_attack_run(item) for item in timeline.get("attack_runs", [])],
            "findings": [self._sanitize_finding(item) for item in timeline.get("findings", [])],
            "correlation_groups": sanitize_jsonable(timeline.get("correlation_groups", [])),
            "correlation_chains": sanitize_jsonable(timeline.get("correlation_chains", [])),
            "replay_recipes": sanitize_jsonable(timeline.get("replay_recipes", [])),
        }

    def _sanitize_bundle(self, bundle: Dict[str, Any]) -> Dict[str, Any]:
        return {
            "generated_at": bundle.get("generated_at"),
            "project": self._sanitize_project(bundle.get("project") or {}),
            "timeline": self._sanitize_timeline(bundle.get("timeline") or {}),
            "identities": [self._sanitize_identity(item) for item in bundle.get("identities", [])],
            "events": [self._sanitize_event(item) for item in bundle.get("events", [])],
            "evidence": [self._sanitize_evidence(item) for item in bundle.get("evidence", [])],
            "notes": [self._sanitize_note(item) for item in bundle.get("notes", [])],
            "statistics": dict(bundle.get("statistics") or {}),
            "sanitized_preview": sanitize_jsonable(bundle.get("sanitized_preview", {})),
            "protocol_map": self._sanitize_protocol_map(bundle.get("protocol_map", {})),
        }

    @staticmethod
    def _path_is_sensitive(path: str) -> bool:
        lowered = str(path or "").lower()
        if lowered.endswith(("_reused", "_present", "_supported")):
            return False
        return any(hint in lowered for hint in SECRET_KEY_HINTS)

    def _sanitize_sample_for_path(self, path: str, value: Any) -> Any:
        if self._path_is_sensitive(path):
            if isinstance(value, str):
                return mask_secret_value(value, keep=4)
            return sanitize_payload(value)
        return sanitize_payload(value)

    def _sanitize_protocol_map(self, protocol_map: Dict[str, Any]) -> Dict[str, Any]:
        protocol_map = dict(protocol_map or {})

        field_profiles = []
        for item in protocol_map.get("protocol_summary", {}).get("field_profiles", []):
            path = item.get("path", "")
            field_profiles.append(
                {
                    "path": path,
                    "count": item.get("count", 0),
                    "types": dict(item.get("types") or {}),
                    "samples": [self._sanitize_sample_for_path(path, sample) for sample in (item.get("samples") or [])],
                    "keys": list(item.get("keys") or []),
                }
            )

        templates = []
        for template in protocol_map.get("templates", []):
            editable_fields = []
            for field in template.get("editable_fields", []):
                path = field.get("path", "")
                editable_fields.append(
                    {
                        "path": path,
                        "current_value": self._sanitize_sample_for_path(path, field.get("current_value")),
                        "suggested_variable": field.get("suggested_variable", ""),
                    }
                )
            templates.append(
                {
                    "name": template.get("name", ""),
                    "count": template.get("count", 0),
                    "sample": sanitize_payload(template.get("sample")),
                    "fields": list(template.get("fields") or []),
                    "editable_fields": editable_fields,
                    "directions": dict(template.get("directions") or {}),
                    "metadata_hints": list(template.get("metadata_hints") or []),
                    "replay_template": sanitize_payload(template.get("replay_template") or {}),
                }
            )

        message_families = []
        for family in protocol_map.get("message_families", []):
            sample = family.get("sample")
            message_families.append(
                {
                    "name": family.get("name", ""),
                    "count": family.get("count", 0),
                    "fields": list(family.get("fields") or []),
                    "auth_fields": list(family.get("auth_fields") or []),
                    "identifier_fields": list(family.get("identifier_fields") or []),
                    "sample": sanitize_payload(sample),
                }
            )

        sanitized = sanitize_jsonable(protocol_map)
        sanitized["finding_categories"] = dict(protocol_map.get("finding_categories") or {})
        sanitized["templates"] = templates
        sanitized["message_families"] = message_families
        if "protocol_summary" in sanitized:
            sanitized["protocol_summary"] = dict(sanitized.get("protocol_summary") or {})
            sanitized["protocol_summary"]["field_profiles"] = field_profiles
        return sanitized

    @staticmethod
    def _sanitize_project_name(name: str) -> str:
        cleaned = "".join(ch if ch.isalnum() or ch in "-._" else "-" for ch in (name or "wshawk-project"))
        return cleaned.strip("-") or "wshawk-project"

    def _render_markdown(self, bundle: Dict[str, Any]) -> str:
        project = bundle.get("project") or {}
        timeline = bundle.get("timeline") or {}
        protocol_map = bundle.get("protocol_map") or {}
        attack_runs = timeline.get("attack_runs", [])
        notes = bundle.get("notes", [])
        replay_recipes = bundle.get("sanitized_preview", {}).get("replay_recipes", [])
        correlation_chains = bundle.get("sanitized_preview", {}).get("correlation_chains", [])
        integrity = bundle.get("integrity") or {}
        provenance = bundle.get("provenance") or {}
        lines = [
            f"# WSHawk Evidence Bundle: {project.get('name', 'Unnamed Project')}",
            "",
            f"- Generated: {bundle.get('generated_at', datetime.now().isoformat())}",
            f"- Target: {project.get('target_url', '')}",
            f"- Operator: {provenance.get('operator', '')}@{provenance.get('hostname', '')}",
            f"- Integrity: {integrity.get('scheme', 'unsigned')} ({integrity.get('key_id', 'n/a')})",
            f"- Identities: {len(bundle.get('identities', []))}",
            f"- HTTP flows: {len(timeline.get('http_flows', []))}",
            f"- WS connections: {len(timeline.get('ws_connections', []))}",
            f"- WS frames: {len(timeline.get('ws_frames', []))}",
            f"- Attack runs: {len(attack_runs)}",
            f"- Evidence items: {len(bundle.get('evidence', []))}",
            "",
            "## Correlation Groups",
        ]

        for group in timeline.get("correlation_groups", []):
            lines.append(
                f"- `{group['correlation_id']}`: {group['summary']['http_flow_count']} HTTP, "
                f"{group['summary']['ws_connection_count']} WS, "
                f"{group['summary']['browser_artifact_count']} browser artifacts"
            )

        lines.extend(["", "## Correlation Chains"])
        for chain in correlation_chains[:12]:
            lines.append(
                f"- `{chain['correlation_id']}` -> HTTP: {len(chain.get('http_urls', []))}, "
                f"WS: {len(chain.get('ws_urls', []))}, "
                f"Runs: {len(chain.get('attack_runs', []))}, Findings: {len(chain.get('findings', []))}"
            )

        lines.extend(["", "## Findings"])
        for finding in timeline.get("findings", []):
            lines.append(
                f"- **[{str(finding.get('severity', 'info')).upper()}]** {finding.get('title', 'Untitled')} - "
                f"{finding.get('description', '').strip()}"
            )

        lines.extend(["", "## Evidence"])
        for evidence in bundle.get("evidence", []):
            lines.append(
                f"- **{evidence.get('title', 'Untitled')}** ({evidence.get('category', 'note')}, "
                f"{evidence.get('severity', 'info')})"
            )

        lines.extend(["", "## Attack Runs"])
        for run in attack_runs:
            summary = run.get("summary", {})
            preview = ", ".join(
                str(item)
                for item in [
                    f"status={run.get('status', 'unknown')}",
                    f"completed={summary.get('completed')}" if summary.get("completed") is not None else "",
                    f"errors={summary.get('errors')}" if summary.get("errors") is not None else "",
                    f"suspicious={summary.get('suspicious_attempt_count')}" if summary.get("suspicious_attempt_count") is not None else "",
                ]
                if item
            ) or "no summary"
            lines.append(f"- `{run.get('attack_type', 'attack')}` at {run.get('created_at', '')}: {preview}")

        lines.extend(["", "## Replay Recipes"])
        for recipe in replay_recipes[:16]:
            if recipe.get("type") == "http":
                lines.append(f"- **HTTP** `{recipe.get('method', 'GET')} {recipe.get('url', '')}`")
                lines.append(f"  `flow_id={recipe.get('flow_id', '')}` `correlation={recipe.get('correlation_id', '')}`")
                lines.append(f"  `curl`: `{sanitize_text(recipe.get('curl', ''))}`")
            else:
                lines.append(f"- **WS** `{recipe.get('url', '')}`")
                lines.append(f"  `connection_id={recipe.get('connection_id', '')}` `correlation={recipe.get('correlation_id', '')}`")
                lines.append(f"  payloads: {len(recipe.get('payloads', []))} captured outbound frame(s)")

        lines.extend(["", "## Operator Notes"])
        for note in notes[:20]:
            lines.append(f"- **{note.get('title', 'Untitled')}**")
            lines.append(f"  {note.get('body', '').strip()[:240]}")

        if protocol_map:
            lines.extend(
                [
                    "",
                    "## Protocol Map",
                    f"- Message families: {protocol_map.get('summary', {}).get('family_count', 0)}",
                    f"- Transitions: {protocol_map.get('summary', {}).get('transition_count', 0)}",
                    "",
                    "### Top Message Families",
                ]
            )
            for family in protocol_map.get("message_families", [])[:12]:
                lines.append(
                    f"- `{family.get('name', 'unknown')}` x {family.get('count', 0)} "
                    f"(fields: {', '.join(family.get('fields', [])[:8]) or 'none'})"
                )
            lines.extend(["", "### Target Packs"])
            for pack in protocol_map.get("target_packs", [])[:8]:
                operation_preview = ", ".join(
                    str(item)
                    for item in [
                        op.get("operation_name")
                        or op.get("root_field")
                        or op.get("event")
                        or op.get("target")
                        or op.get("command")
                        or op.get("action")
                        or op.get("format")
                        for op in (pack.get("operations") or [])[:4]
                    ]
                    if item
                ) or "none"
                lines.append(
                    f"- `{pack.get('id', '')}` ({pack.get('confidence', 'medium')}) - "
                    f"ops: {operation_preview}"
                )
            lines.extend(["", "### Suggested Playbooks"])
            for playbook in protocol_map.get("playbook_candidates", [])[:8]:
                lines.append(f"- `{playbook.get('id', '')}` - {playbook.get('reason', '')}")

        return "\n".join(lines) + "\n"

    def _render_html(self, bundle: Dict[str, Any]) -> str:
        project = bundle.get("project") or {}
        timeline = bundle.get("timeline") or {}
        evidence = bundle.get("evidence", [])
        findings = timeline.get("findings", [])
        protocol_map = bundle.get("protocol_map") or {}
        attack_runs = timeline.get("attack_runs", [])
        notes = bundle.get("notes", [])
        replay_recipes = bundle.get("sanitized_preview", {}).get("replay_recipes", [])
        correlation_chains = bundle.get("sanitized_preview", {}).get("correlation_chains", [])
        integrity = bundle.get("integrity") or {}
        provenance = bundle.get("provenance") or {}

        finding_cards = "".join(
            f"""
            <div class="card finding">
                <h3>{escape(finding.get('title', 'Untitled'))}</h3>
                <p><strong>Severity:</strong> {escape(str(finding.get('severity', 'info')).upper())}</p>
                <p>{escape(finding.get('description', ''))}</p>
            </div>
            """
            for finding in findings
        ) or "<p>No findings recorded.</p>"

        evidence_rows = "".join(
            f"""
            <tr>
                <td>{escape(item.get('created_at', ''))}</td>
                <td>{escape(item.get('title', 'Untitled'))}</td>
                <td>{escape(item.get('category', ''))}</td>
                <td>{escape(item.get('severity', 'info'))}</td>
            </tr>
            """
            for item in evidence
        ) or '<tr><td colspan="4">No evidence recorded.</td></tr>'

        attack_rows = "".join(
            f"""
            <tr>
                <td>{escape(item.get('created_at', ''))}</td>
                <td>{escape(item.get('attack_type', 'attack'))}</td>
                <td>{escape(item.get('status', 'unknown'))}</td>
                <td>{escape(json.dumps(item.get('summary', {}))[:180])}</td>
            </tr>
            """
            for item in attack_runs[:30]
        ) or '<tr><td colspan="4">No attack runs recorded.</td></tr>'

        protocol_rows = "".join(
            f"""
            <tr>
                <td>{escape(family.get('name', 'unknown'))}</td>
                <td>{family.get('count', 0)}</td>
                <td>{escape(', '.join(family.get('fields', [])[:8]) or 'none')}</td>
            </tr>
            """
            for family in protocol_map.get("message_families", [])[:15]
        ) or '<tr><td colspan="3">No protocol families observed.</td></tr>'

        note_cards = "".join(
            f"""
            <div class="card">
                <h3>{escape(note.get('title', 'Untitled'))}</h3>
                <p style="white-space: pre-wrap;">{escape(str(note.get('body', ''))[:400])}</p>
            </div>
            """
            for note in notes[:12]
        ) or "<p>No notes recorded.</p>"

        replay_rows = "".join(
            f"""
            <tr>
                <td>{escape(item.get('type', 'unknown'))}</td>
                <td>{escape(item.get('url', ''))}</td>
                <td>{escape(item.get('correlation_id', ''))}</td>
                <td>{escape(str(item.get('method', item.get('subprotocol', ''))))}</td>
            </tr>
            """
            for item in replay_recipes[:18]
        ) or '<tr><td colspan="4">No replay recipes captured.</td></tr>'

        chain_rows = "".join(
            f"""
            <tr>
                <td>{escape(item.get('correlation_id', ''))}</td>
                <td>{len(item.get('http_urls', []))}</td>
                <td>{len(item.get('ws_urls', []))}</td>
                <td>{len(item.get('attack_runs', []))}</td>
            </tr>
            """
            for item in correlation_chains[:18]
        ) or '<tr><td colspan="4">No correlation chains available.</td></tr>'

        playbook_rows = "".join(
            f"""
            <tr>
                <td>{escape(item.get('id', ''))}</td>
                <td>{escape(item.get('title', ''))}</td>
                <td>{escape(item.get('reason', ''))}</td>
            </tr>
            """
            for item in protocol_map.get("playbook_candidates", [])[:12]
        ) or '<tr><td colspan="3">No playbook guidance available.</td></tr>'

        target_pack_rows = "".join(
            f"""
            <tr>
                <td>{escape(item.get('id', ''))}</td>
                <td>{escape(item.get('confidence', 'medium'))}</td>
                <td>{escape(', '.join(
                    str(op.get('operation_name')
                        or op.get('root_field')
                        or op.get('event')
                        or op.get('target')
                        or op.get('command')
                        or op.get('action')
                        or op.get('format'))
                    for op in (item.get('operations') or [])[:4]
                    if (
                        op.get('operation_name')
                        or op.get('root_field')
                        or op.get('event')
                        or op.get('target')
                        or op.get('command')
                        or op.get('action')
                        or op.get('format')
                    )
                ) or 'none')}</td>
            </tr>
            """
            for item in protocol_map.get("target_packs", [])[:12]
        ) or '<tr><td colspan="3">No target-pack guidance available.</td></tr>'

        return f"""<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="utf-8">
  <title>WSHawk Evidence Bundle</title>
  <style>
    body {{ font-family: Arial, sans-serif; background: #0f172a; color: #e5e7eb; margin: 0; padding: 32px; }}
    h1, h2, h3 {{ color: #f8fafc; }}
    .grid {{ display: grid; grid-template-columns: repeat(4, minmax(0, 1fr)); gap: 12px; margin-bottom: 24px; }}
    .card {{ background: #111827; border: 1px solid #334155; border-radius: 10px; padding: 16px; }}
    .finding {{ border-left: 4px solid #ef4444; }}
    table {{ width: 100%; border-collapse: collapse; }}
    th, td {{ border-bottom: 1px solid #334155; padding: 10px; text-align: left; }}
    th {{ color: #93c5fd; }}
    code {{ background: #1f2937; padding: 2px 6px; border-radius: 4px; }}
  </style>
</head>
<body>
  <h1>WSHawk Evidence Bundle</h1>
  <p><strong>Project:</strong> {escape(project.get('name', 'Unnamed Project'))}</p>
  <p><strong>Target:</strong> {escape(project.get('target_url', ''))}</p>
  <p><strong>Generated:</strong> {escape(bundle.get('generated_at', datetime.now().isoformat()))}</p>
  <p><strong>Operator:</strong> {escape(str(provenance.get('operator', '')))}@{escape(str(provenance.get('hostname', '')))}</p>
  <p><strong>Integrity:</strong> {escape(str(integrity.get('scheme', 'unsigned')))} / {escape(str(integrity.get('key_id', 'n/a')))}</p>

  <div class="grid">
    <div class="card"><h3>Identities</h3><div>{len(bundle.get('identities', []))}</div></div>
    <div class="card"><h3>HTTP Flows</h3><div>{len(timeline.get('http_flows', []))}</div></div>
    <div class="card"><h3>WS Connections</h3><div>{len(timeline.get('ws_connections', []))}</div></div>
    <div class="card"><h3>WS Frames</h3><div>{len(timeline.get('ws_frames', []))}</div></div>
    <div class="card"><h3>Correlation Groups</h3><div>{len(timeline.get('correlation_groups', []))}</div></div>
  </div>

  <h2>Findings</h2>
  {finding_cards}

  <h2>Evidence Timeline</h2>
  <table>
    <thead><tr><th>Time</th><th>Title</th><th>Category</th><th>Severity</th></tr></thead>
    <tbody>{evidence_rows}</tbody>
  </table>

  <h2>Attack Runs</h2>
  <table>
    <thead><tr><th>Time</th><th>Type</th><th>Status</th><th>Summary</th></tr></thead>
    <tbody>{attack_rows}</tbody>
  </table>

  <h2>Correlation Chains</h2>
  <table>
    <thead><tr><th>Correlation</th><th>HTTP</th><th>WS</th><th>Runs</th></tr></thead>
    <tbody>{chain_rows}</tbody>
  </table>

  <h2>Replay Recipes</h2>
  <table>
    <thead><tr><th>Type</th><th>Target</th><th>Correlation</th><th>Method/Subprotocol</th></tr></thead>
    <tbody>{replay_rows}</tbody>
  </table>

  <h2>Protocol Families</h2>
  <table>
    <thead><tr><th>Family</th><th>Count</th><th>Fields</th></tr></thead>
    <tbody>{protocol_rows}</tbody>
  </table>

  <h2>Target Packs</h2>
  <table>
    <thead><tr><th>ID</th><th>Confidence</th><th>Operations</th></tr></thead>
    <tbody>{target_pack_rows}</tbody>
  </table>

  <h2>Suggested Playbooks</h2>
  <table>
    <thead><tr><th>ID</th><th>Title</th><th>Reason</th></tr></thead>
    <tbody>{playbook_rows}</tbody>
  </table>

  <h2>Operator Notes</h2>
  {note_cards}
</body>
</html>
"""

    def export(self, project_id: str, fmt: str) -> Dict[str, Any]:
        fmt = str(fmt or "json").strip().lower()
        bundle = self.integrity.attach(
            self._sanitize_bundle(self._bundle_with_protocol(project_id)),
            export_format=fmt,
        )
        project = bundle.get("project") or {}
        stem = self._sanitize_project_name(project.get("name", "wshawk-project"))

        if fmt == "json":
            return {
                "content": json.dumps(bundle, indent=2),
                "media_type": "application/json",
                "filename": f"{stem}.json",
            }
        if fmt in {"md", "markdown"}:
            return {
                "content": self._render_markdown(bundle),
                "media_type": "text/markdown",
                "filename": f"{stem}.md",
            }
        if fmt == "html":
            return {
                "content": self._render_html(bundle),
                "media_type": "text/html",
                "filename": f"{stem}.html",
            }

        raise ValueError("Unsupported export format. Use json, markdown, or html.")

    def verify_bundle(self, bundle: Dict[str, Any]) -> Dict[str, Any]:
        return self.integrity.verify(bundle)
