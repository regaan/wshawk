import asyncio
import tempfile
import unittest
from pathlib import Path

from wshawk.attacks import HTTPAuthzDiffService, HTTPRaceService, HTTPReplayService
from wshawk.attacks.http_common import build_http_template, render_http_template
from wshawk.db_manager import WSHawkDatabase
from wshawk.store import ProjectStore
from wshawk.transport import WSHawkHTTPProxy


class FakeHTTPProxy(WSHawkHTTPProxy):
    async def send_request(self, **kwargs):
        headers = dict(kwargs.get("headers") or {})
        body = kwargs.get("body", "")
        project_id = kwargs.get("project_id")
        correlation_id = kwargs.get("correlation_id", "")
        attack_run_id = kwargs.get("attack_run_id")
        metadata = kwargs.get("metadata") or {}

        tenant = headers.get("X-Tenant", "guest")
        auth = headers.get("Authorization", "")
        if "admin" in tenant.lower() or "admin" in auth.lower():
            response_body = '{"scope":"admin","allowed":true}'
            status = "200"
        elif metadata.get("source") == "http_race":
            response_body = '{"ok":true,"race":"accepted"}'
            status = "200"
        else:
            response_body = '{"scope":"user","allowed":false}'
            status = "403" if metadata.get("source") == "http_authz_diff" else "200"

        flow_id = None
        if project_id and self.store:
            flow = self.store.add_http_flow(
                project_id=project_id,
                method=kwargs["method"],
                url=kwargs["url"],
                request_headers=headers,
                request_body=body,
                response_status=status,
                response_headers={"content-type": "application/json"},
                response_body=response_body,
                correlation_id=correlation_id,
                attack_run_id=attack_run_id,
                metadata=metadata,
            )
            flow_id = flow["id"]

        return {
            "status": status,
            "headers": "content-type: application/json",
            "headers_dict": {"content-type": "application/json"},
            "cookies": {},
            "body": response_body,
            "flow_id": flow_id,
        }


class HTTPAttackServiceTests(unittest.TestCase):
    def make_store(self):
        temp_dir = tempfile.TemporaryDirectory()
        db = WSHawkDatabase(str(Path(temp_dir.name) / "http_attacks.db"))
        store = ProjectStore(db)
        project = db.save_project(name=f"http-attack-project-{id(temp_dir)}", target_url="https://target.test/api")
        return temp_dir, db, store, project

    def test_http_replay_builds_template_and_records_attack_run(self):
        temp_dir, db, store, project = self.make_store()
        self.addCleanup(temp_dir.cleanup)
        proxy = FakeHTTPProxy(store=store)

        baseline = store.add_http_flow(
            project_id=project["id"],
            method="POST",
            url="https://target.test/api/orders?tenant=red",
            request_headers={"Content-Type": "application/json"},
            request_body='{"amount": 10, "tenant": "red"}',
            response_status="200",
            response_headers={"content-type": "application/json"},
            response_body='{"ok":true}',
            correlation_id="corr-http-base",
        )
        identity = db.save_identity(
            project_id=project["id"],
            alias="operator",
            source="manual",
            headers={"X-Tenant": "red-admin"},
            cookies=[],
            tokens={},
        )

        async def scenario():
            service = HTTPReplayService(store=store, http_proxy=proxy)
            template = service.build_template_from_flow(project_id=project["id"], flow_id=baseline["id"])
            self.assertEqual(template["source_flow_id"], baseline["id"])
            self.assertGreaterEqual(len(template["editable_fields"]), 2)
            return await service.replay(
                project_id=project["id"],
                flow_id=baseline["id"],
                identity=identity,
            )

        result = asyncio.run(scenario())
        self.assertEqual(result["http_status"], "200")
        self.assertEqual(result["status"], "received")
        self.assertIsNotNone(result["attack_run_id"])
        self.assertGreaterEqual(len(store.list_http_flows(project["id"])), 2)
        self.assertEqual(len(store.list_attack_runs(project["id"])), 1)

    def test_http_authz_diff_detects_role_drift(self):
        temp_dir, db, store, project = self.make_store()
        self.addCleanup(temp_dir.cleanup)
        proxy = FakeHTTPProxy(store=store)

        identities = [
            {"id": "identity-user", "alias": "user", "headers": {"X-Tenant": "red"}, "tokens": {}},
            {"id": "identity-admin", "alias": "admin", "headers": {"X-Tenant": "red-admin"}, "tokens": {}},
        ]

        async def scenario():
            service = HTTPAuthzDiffService(store=store, http_proxy=proxy)
            return await service.compare(
                project_id=project["id"],
                identities=identities,
                method="GET",
                url="https://target.test/api/admin/report",
                headers={"Accept": "application/json"},
            )

        result = asyncio.run(scenario())
        self.assertTrue(result["summary"]["behavior_changed"])
        self.assertEqual(result["summary"]["recommended_severity"], "high")
        self.assertEqual(len(result["results"]), 2)
        self.assertEqual(len(store.list_attack_runs(project["id"])), 1)
        self.assertEqual(len(store.list_http_flows(project["id"])), 2)

    def test_http_race_records_concurrent_replays(self):
        temp_dir, db, store, project = self.make_store()
        self.addCleanup(temp_dir.cleanup)
        proxy = FakeHTTPProxy(store=store)

        async def scenario():
            service = HTTPRaceService(store=store, http_proxy=proxy)
            return await service.run(
                project_id=project["id"],
                method="POST",
                url="https://target.test/api/redeem",
                body='{"code":"RACE"}',
                concurrency=3,
                waves=2,
                stagger_ms=5,
                mode="duplicate_action",
                identities=[{"id": "identity-1", "alias": "operator", "headers": {"X-Tenant": "red-admin"}, "tokens": {}}],
            )

        result = asyncio.run(scenario())
        self.assertEqual(result["summary"]["attempt_count"], 6)
        self.assertTrue(result["summary"]["duplicate_success_observed"])
        self.assertTrue(result["summary"]["suspicious_race_window"])
        self.assertEqual(result["summary"]["recommended_severity"], "high")
        self.assertEqual(len(store.list_attack_runs(project["id"])), 1)
        self.assertEqual(len(store.list_http_flows(project["id"])), 6)

    def test_http_templates_normalize_prefixed_urls(self):
        template = build_http_template(
            method="POST",
            url="POST http://127.0.0.1:8010/api/invoices/inv-beta-9001/refund",
            headers={"Content-Type": "application/json"},
            body={"reason": "http replay"},
        )
        self.assertEqual(template["url"], "http://127.0.0.1:8010/api/invoices/inv-beta-9001/refund")
        self.assertEqual(template["name"], "POST http://127.0.0.1:8010/api/invoices/inv-beta-9001/refund")

        rendered = render_http_template(template, url="POST http://127.0.0.1:8010/api/invoices/inv-beta-9001/refund")
        self.assertEqual(rendered["url"], "http://127.0.0.1:8010/api/invoices/inv-beta-9001/refund")


if __name__ == "__main__":
    unittest.main()
