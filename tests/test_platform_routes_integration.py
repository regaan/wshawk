import asyncio
import importlib
import json
import os
import sys
import tempfile
import unittest
from typing import Dict, Optional
from urllib.parse import urlencode, urlsplit


async def asgi_request(
    app,
    method: str,
    path: str,
    *,
    headers: Optional[Dict[str, str]] = None,
    json_body=None,
    client_host: str = "127.0.0.1",
):
    headers = headers or {}
    body = b""
    if json_body is not None:
        body = json.dumps(json_body).encode("utf-8")
        headers = {**headers, "content-type": "application/json"}

    split = urlsplit(path)
    scope = {
        "type": "http",
        "asgi": {"version": "3.0"},
        "http_version": "1.1",
        "method": method.upper(),
        "scheme": "http",
        "path": split.path,
        "raw_path": split.path.encode("utf-8"),
        "query_string": split.query.encode("utf-8"),
        "headers": [(key.lower().encode("utf-8"), value.encode("utf-8")) for key, value in headers.items()],
        "client": (client_host, 12345),
        "server": ("testserver", 80),
    }

    messages = []
    delivered = False

    async def receive():
        nonlocal delivered
        if delivered:
            await asyncio.sleep(0)
            return {"type": "http.disconnect"}
        delivered = True
        return {"type": "http.request", "body": body, "more_body": False}

    async def send(message):
        messages.append(message)

    await app(scope, receive, send)
    start = next(message for message in messages if message["type"] == "http.response.start")
    payload = b"".join(message.get("body", b"") for message in messages if message["type"] == "http.response.body")
    response_headers = {
        key.decode("utf-8"): value.decode("utf-8")
        for key, value in start.get("headers", [])
    }
    return start["status"], response_headers, payload.decode("utf-8", errors="replace")


class _FakeSubscriptionService:
    async def probe(self, **kwargs):
        return {
            "attack_run_id": None,
            "summary": {
                "identity_count": 1,
                "baseline_count": 1,
                "mutation_count": 2,
                "accepted_mutation_count": 1,
                "suspicious_attempt_count": 1,
                "behavior_change_count": 1,
                "field_summary": [{"field_name": "channel", "attempts": 2, "suspicious_attempts": 1, "accepted_attempts": 1, "values": ["admin"]}],
                "recommended_severity": "high",
            },
            "mutations": [{"field_path": "channel", "candidate_value": "admin"}],
            "suspicious_attempts": [{"field_path": "channel", "candidate_value": "admin", "status": "received"}],
        }


class _FakeRaceService:
    async def run(self, **kwargs):
        return {
            "attack_run_id": None,
            "results": [{"wave": 1, "attempt": 1, "status": "received", "response": '{"ok":true}'}],
            "summary": {
                "mode": "duplicate_action",
                "wave_count": 2,
                "concurrency": 3,
                "attempt_count": 6,
                "received_count": 6,
                "sent_count": 0,
                "timeout_count": 0,
                "error_count": 0,
                "behavior_group_count": 1,
                "wave_success": {"wave_1": 3, "wave_2": 3},
                "duplicate_success_observed": True,
                "later_wave_success_observed": True,
                "suspicious_race_window": True,
                "recommended_severity": "high",
            },
        }


class _FakeWorkflowService:
    def list_playbooks(self):
        return [{"id": "login_bootstrap", "title": "Login Bootstrap", "description": "Bootstraps a login flow."}]

    async def execute(self, **kwargs):
        return {
            "attack_run_id": None,
            "results": [
                {"step": 1, "name": "Fetch Token", "type": "http", "status": "success", "response_preview": '{"csrf":"token-1"}', "extracted": {"csrf": "token-1"}},
                {"step": 2, "name": "Replay WS", "type": "ws", "status": "success", "response_preview": '{"ok":true}', "extracted": {"accepted": True}},
            ],
            "variables": {"csrf": "token-1", "accepted": True},
            "summary": {"total_steps": 2, "completed": 2, "skipped": 0, "errors": 0, "variable_count": 2},
        }


class _FakeHTTPReplayService:
    def build_template_from_flow(self, **kwargs):
        return {
            "name": "GET https://route.test/api/admin",
            "source_flow_id": kwargs.get("flow_id"),
            "correlation_id": "corr-http-template",
            "method": "GET",
            "url": "https://route.test/api/admin",
            "headers": {"Accept": "application/json"},
            "body": "",
            "editable_fields": [{"location": "query", "name": "tenant", "current_value": "red", "suggested_variable": "tenant"}],
        }

    def build_template(self, **kwargs):
        return {
            "name": kwargs.get("name") or "inline-template",
            "source_flow_id": None,
            "correlation_id": "corr-http-inline",
            "method": kwargs.get("method", "GET"),
            "url": kwargs.get("url", "https://route.test/api/admin"),
            "headers": kwargs.get("headers") or {},
            "body": kwargs.get("body", ""),
            "editable_fields": [],
        }

    async def replay(self, **kwargs):
        template = kwargs.get("template") or {}
        return {
            "attack_run_id": None,
            "method": template.get("method", "GET"),
            "url": template.get("url", "https://route.test/api/admin"),
            "status": "received",
            "http_status": "200",
            "headers": {"content-type": "application/json"},
            "body": '{"ok":true}',
            "response": '{"ok":true}',
            "response_length": 11,
            "response_preview": '{"ok":true}',
            "flow_id": "flow-http-replay",
            "timing_ms": 4.2,
            "template": template,
        }


class _FakeHTTPAuthzDiffService:
    async def compare(self, **kwargs):
        template = kwargs.get("template") or {}
        return {
            "attack_run_id": None,
            "method": template.get("method", "GET"),
            "url": template.get("url", "https://route.test/api/admin"),
            "template": template,
            "results": [
                {
                    "identity_id": "id-user",
                    "identity_alias": "user",
                    "status": "received",
                    "http_status": "403",
                    "response": '{"ok":false}',
                    "response_length": 12,
                    "response_preview": '{"ok":false}',
                    "flow_id": "flow-http-user",
                },
                {
                    "identity_id": "id-admin",
                    "identity_alias": "admin",
                    "status": "received",
                    "http_status": "200",
                    "response": '{"ok":true}',
                    "response_length": 11,
                    "response_preview": '{"ok":true}',
                    "flow_id": "flow-http-admin",
                },
            ],
            "summary": {
                "identity_count": 2,
                "behavior_changed": True,
                "behavior_group_count": 2,
                "status_breakdown": {"received": 2},
                "http_status_breakdown": {"403": 1, "200": 1},
                "recommended_severity": "high",
                "behavior_groups": [],
                "interesting_identities": [{"identity_alias": "admin"}],
            },
        }


class _FakeHTTPRaceService:
    async def run(self, **kwargs):
        template = kwargs.get("template") or {}
        return {
            "attack_run_id": None,
            "method": template.get("method", "POST"),
            "url": template.get("url", "https://route.test/api/redeem"),
            "template": template,
            "results": [{"wave": 1, "attempt": 1, "status": "received", "http_status": "200", "response": '{"ok":true}'}],
            "summary": {
                "mode": "duplicate_action",
                "wave_count": 2,
                "concurrency": 3,
                "attempt_count": 6,
                "success_count": 6,
                "error_count": 0,
                "behavior_group_count": 1,
                "wave_success": {"wave_1": 3, "wave_2": 3},
                "duplicate_success_observed": True,
                "later_wave_success_observed": True,
                "suspicious_race_window": True,
                "recommended_severity": "high",
            },
        }


class _FakeWSReplayService:
    async def replay(self, **kwargs):
        payload = kwargs.get("payload") or {}
        action = payload.get("action")
        if action == "subscribe_invoice":
            response = {
                "type": "invoice_snapshot",
                "invoice": {
                    "id": payload.get("invoice_id", "inv-beta-9001"),
                    "tenant": "tenant-beta",
                    "customer": "Northwind Health",
                    "approval_token": "approve-beta-9001",
                },
            }
        elif action == "approve_refund":
            response = {
                "type": "refund_result",
                "ok": True,
                "invoice_id": payload.get("invoice_id", "inv-beta-9001"),
                "tenant": "tenant-beta",
                "approval_token_reused": True,
                "processed_by": "alice",
            }
        else:
            response = {"type": "ok"}
        return {
            "status": "received",
            "response": json.dumps(response),
            "response_length": len(json.dumps(response)),
            "response_preview": json.dumps(response)[:240],
            "timing_ms": 5.1,
            "attack_run_id": None,
            "connection_id": "conn-ws-replay",
        }


class PlatformRouteIntegrationTests(unittest.TestCase):
    def setUp(self):
        self.temp_dir = tempfile.TemporaryDirectory()
        self.addCleanup(self.temp_dir.cleanup)
        os.environ["WSHAWK_DATA_DIR"] = self.temp_dir.name

        for module_name in list(sys.modules):
            if module_name.startswith("wshawk.gui_bridge"):
                sys.modules.pop(module_name, None)
        sys.modules.pop("wshawk.db_manager", None)

        import wshawk.gui_bridge as gui_bridge  # pylint: disable=import-outside-toplevel

        self.gui_bridge = importlib.reload(gui_bridge)
        self.headers = {"X-WSHawk-Token": self.gui_bridge.BRIDGE_TOKEN}

    def request(self, method, path, *, json_body=None, headers=None, client_host="127.0.0.1"):
        merged_headers = dict(self.headers)
        if headers:
            merged_headers.update(headers)
        status, response_headers, payload = asyncio.run(
            asgi_request(self.gui_bridge.app, method, path, headers=merged_headers, json_body=json_body, client_host=client_host)
        )
        return status, response_headers, payload

    def test_protocol_map_and_export_routes_require_auth_and_return_project_data(self):
        status, _, payload = self.request(
            "POST",
            "/platform/projects",
            json_body={"name": "route-project", "target_url": "wss://route.test/ws"},
        )
        self.assertEqual(status, 200)
        project_id = json.loads(payload)["project"]["id"]

        connection = self.gui_bridge.platform_store.open_ws_connection(
            project_id=project_id,
            url="wss://route.test/ws",
            handshake_headers={"Origin": "https://route.test"},
            correlation_id="corr-route",
        )
        self.gui_bridge.platform_store.add_ws_frame(
            project_id=project_id,
            connection_id=connection["id"],
            direction="out",
            payload={"action": "subscribe", "channel": "alerts"},
        )
        self.gui_bridge.platform_store.add_finding(
            project_id=project_id,
            title="Route-level finding",
            category="integration",
            severity="medium",
            description="Integration route stored a finding.",
            related_connection_id=connection["id"],
        )

        status, _, payload = self.request("GET", f"/platform/projects/{project_id}/protocol-map")
        self.assertEqual(status, 200)
        protocol_map = json.loads(payload)["protocol_map"]
        self.assertGreaterEqual(protocol_map["summary"]["family_count"], 1)

        status, response_headers, payload = self.request("GET", f"/platform/projects/{project_id}/exports/json")
        self.assertEqual(status, 200)
        self.assertIn("application/json", response_headers.get("content-type", ""))
        self.assertIn("protocol_map", payload)
        self.assertIn("Route-level finding", payload)

    def test_offensive_attack_routes_persist_evidence_and_findings(self):
        status, _, payload = self.request(
            "POST",
            "/platform/projects",
            json_body={"name": "attack-route-project", "target_url": "wss://route.test/ws"},
        )
        self.assertEqual(status, 200)
        project_id = json.loads(payload)["project"]["id"]

        self.gui_bridge.ctx.ws_subscription_abuse_service = _FakeSubscriptionService()
        self.gui_bridge.ctx.ws_race_service = _FakeRaceService()
        self.gui_bridge.ctx.workflow_service = _FakeWorkflowService()

        status, _, payload = self.request(
            "POST",
            f"/platform/projects/{project_id}/attacks/subscription-abuse",
            json_body={"payload": {"action": "subscribe", "channel": "alerts"}},
        )
        self.assertEqual(status, 200)
        subscription_body = json.loads(payload)
        self.assertEqual(subscription_body["evidence"]["category"], "subscription_abuse")

        status, _, payload = self.request(
            "POST",
            f"/platform/projects/{project_id}/attacks/race",
            json_body={"payload": {"action": "redeem", "code": "RACE"}, "mode": "duplicate_action"},
        )
        self.assertEqual(status, 200)
        race_body = json.loads(payload)
        self.assertEqual(race_body["evidence"]["category"], "websocket_race")

        status, _, payload = self.request(
            "POST",
            f"/platform/projects/{project_id}/attacks/workflow",
            json_body={
                "steps": [
                    {"name": "Fetch Token", "type": "http", "url": "https://route.test/token"},
                    {"name": "Replay WS", "type": "ws", "payload": {"action": "ping"}},
                ]
            },
        )
        self.assertEqual(status, 200)
        workflow_body = json.loads(payload)
        self.assertEqual(workflow_body["evidence"]["category"], "workflow_execution")

        evidence = self.gui_bridge.db.list_evidence(project_id, limit=20)
        self.assertGreaterEqual(len(evidence), 3)
        findings = self.gui_bridge.platform_store.list_findings(project_id, limit=20)
        categories = {item["category"] for item in findings}
        self.assertIn("subscription_abuse", categories)
        self.assertIn("websocket_race", categories)

    def test_http_attack_routes_persist_templates_evidence_and_findings(self):
        status, _, payload = self.request(
            "POST",
            "/platform/projects",
            json_body={"name": "http-attack-route-project", "target_url": "https://route.test/api/admin"},
        )
        self.assertEqual(status, 200)
        project_id = json.loads(payload)["project"]["id"]

        self.gui_bridge.db.save_identity(
            project_id=project_id,
            alias="user",
            source="manual",
            headers={"X-Tenant": "red"},
            cookies=[],
            tokens={},
        )
        self.gui_bridge.db.save_identity(
            project_id=project_id,
            alias="admin",
            source="manual",
            headers={"X-Tenant": "red-admin"},
            cookies=[],
            tokens={},
        )

        self.gui_bridge.ctx.http_replay_service = _FakeHTTPReplayService()
        self.gui_bridge.ctx.http_authz_diff_service = _FakeHTTPAuthzDiffService()
        self.gui_bridge.ctx.http_race_service = _FakeHTTPRaceService()

        status, _, payload = self.request(
            "POST",
            f"/platform/projects/{project_id}/http-templates",
            json_body={"method": "GET", "url": "https://route.test/api/admin"},
        )
        self.assertEqual(status, 200)
        template_body = json.loads(payload)
        self.assertEqual(template_body["template"]["method"], "GET")

        status, _, payload = self.request(
            "POST",
            f"/platform/projects/{project_id}/replay/http",
            json_body={"template": template_body["template"], "identity_alias": "admin"},
        )
        self.assertEqual(status, 200)
        replay_body = json.loads(payload)
        self.assertEqual(replay_body["replay"]["http_status"], "200")

        status, _, payload = self.request(
            "POST",
            f"/platform/projects/{project_id}/attacks/http-authz-diff",
            json_body={"template": template_body["template"], "identity_aliases": ["user", "admin"]},
        )
        self.assertEqual(status, 200)
        diff_body = json.loads(payload)
        self.assertEqual(diff_body["evidence"]["category"], "http_authz_diff")

        status, _, payload = self.request(
            "POST",
            f"/platform/projects/{project_id}/attacks/http-race",
            json_body={"template": template_body["template"], "identity_alias": "admin", "mode": "duplicate_action"},
        )
        self.assertEqual(status, 200)
        race_body = json.loads(payload)
        self.assertEqual(race_body["evidence"]["category"], "http_race")

        findings = self.gui_bridge.platform_store.list_findings(project_id, limit=20)
        categories = {item["category"] for item in findings}
        self.assertIn("http_authz_diff", categories)
        self.assertIn("http_race", categories)

    def test_ws_replay_routes_promote_direct_findings_into_evidence(self):
        status, _, payload = self.request(
            "POST",
            "/platform/projects",
            json_body={"name": "ws-replay-evidence-project", "target_url": "ws://route.test/ws"},
        )
        self.assertEqual(status, 200)
        project_id = json.loads(payload)["project"]["id"]

        self.gui_bridge.db.save_identity(
            project_id=project_id,
            alias="alice-tenant-alpha-user",
            source="manual",
            headers={"Cookie": "session=alpha-cookie"},
            cookies=[],
            tokens={"tenant": "tenant-alpha"},
            storage={"tenant": "tenant-alpha"},
        )

        self.gui_bridge.ctx.ws_replay_service = _FakeWSReplayService()

        status, _, payload = self.request(
            "POST",
            f"/platform/projects/{project_id}/replay/ws",
            json_body={
                "payload": {"action": "subscribe_invoice", "invoice_id": "inv-beta-9001"},
                "identity_alias": "alice-tenant-alpha-user",
            },
        )
        self.assertEqual(status, 200)
        invoice_body = json.loads(payload)
        self.assertEqual(invoice_body["evidence"]["category"], "websocket_data_exposure")

        status, _, payload = self.request(
            "POST",
            f"/platform/projects/{project_id}/replay/ws",
            json_body={
                "payload": {
                    "action": "approve_refund",
                    "invoice_id": "inv-beta-9001",
                    "approval_token": "approve-beta-9001",
                },
                "identity_alias": "alice-tenant-alpha-user",
            },
        )
        self.assertEqual(status, 200)
        refund_body = json.loads(payload)
        self.assertEqual(refund_body["evidence"]["category"], "websocket_token_replay")

        evidence = self.gui_bridge.db.list_evidence(project_id, limit=20)
        self.assertGreaterEqual(len(evidence), 2)
        categories = {item["category"] for item in evidence}
        self.assertIn("websocket_data_exposure", categories)
        self.assertIn("websocket_token_replay", categories)

        findings = self.gui_bridge.platform_store.list_findings(project_id, limit=20)
        finding_categories = {item["category"] for item in findings}
        self.assertIn("websocket_data_exposure", finding_categories)
        self.assertIn("websocket_token_replay", finding_categories)

    def test_platform_routes_require_bridge_auth(self):
        status, _, payload = asyncio.run(
            asgi_request(self.gui_bridge.app, "GET", "/platform/projects", headers={})
        )
        self.assertEqual(status, 401)
        self.assertIn("Bridge authentication required", payload)

    def test_bridge_rejects_non_local_clients_and_exposes_playbook_catalog(self):
        status, _, payload = self.request("GET", "/platform/projects", client_host="203.0.113.9")
        self.assertEqual(status, 403)
        self.assertIn("local clients", payload)

        status, _, payload = self.request("GET", "/platform/workflow-playbooks")
        self.assertEqual(status, 200)
        body = json.loads(payload)
        self.assertIn("login_bootstrap", {item["id"] for item in body["playbooks"]})

    def test_extension_pairing_routes_are_origin_scoped_and_require_session_token(self):
        extension_headers = {
            "Origin": "chrome-extension://trusted-extension-id",
            "X-WSHawk-Extension-Id": "trusted-extension-id",
        }

        status, _, payload = asyncio.run(
            asgi_request(self.gui_bridge.app, "GET", "/api/extension/status", headers=extension_headers)
        )
        self.assertEqual(status, 200)
        body = json.loads(payload)
        self.assertEqual(body["status"], "online")
        self.assertTrue(body["project_id_supported"])
        self.assertTrue(body["capture_scope_required"])

        status, _, payload = asyncio.run(
            asgi_request(self.gui_bridge.app, "POST", "/api/extension/pair", headers=extension_headers, json_body={"extension_id": "trusted-extension-id"})
        )
        self.assertEqual(status, 200)
        pair_body = json.loads(payload)
        self.assertEqual(pair_body["status"], "success")
        extension_token = pair_body["pairing"]["token"]

        status, _, payload = asyncio.run(
            asgi_request(
                self.gui_bridge.app,
                "POST",
                "/api/extension/ingest/handshake",
                headers=extension_headers,
                json_body={"url": "wss://route.test/ws", "headers": {"Origin": "https://route.test"}},
            )
        )
        self.assertEqual(status, 401)
        self.assertIn("Extension pairing token required", payload)

        status, _, payload = asyncio.run(
            asgi_request(
                self.gui_bridge.app,
                "POST",
                "/api/extension/ingest/handshake",
                headers={**extension_headers, "X-WSHawk-Extension-Token": extension_token},
                json_body={"url": "wss://route.test/ws", "headers": {"Origin": "https://route.test"}},
            )
        )
        self.assertEqual(status, 200)
        ingest_body = json.loads(payload)
        self.assertEqual(ingest_body["status"], "success")

        status, _, payload = asyncio.run(
            asgi_request(
                self.gui_bridge.app,
                "POST",
                "/api/extension/pair",
                headers={
                    "Origin": "chrome-extension://unexpected-extension-id",
                    "X-WSHawk-Extension-Id": "unexpected-extension-id",
                },
                json_body={"extension_id": "unexpected-extension-id"},
            )
        )
        self.assertEqual(status, 403)
        self.assertIn("paired", payload)

        status, _, payload = asyncio.run(
            asgi_request(self.gui_bridge.app, "GET", "/api/extension/status", headers=extension_headers, client_host="203.0.113.19")
        )
        self.assertEqual(status, 403)
        self.assertIn("local clients", payload)


if __name__ == "__main__":
    unittest.main()
