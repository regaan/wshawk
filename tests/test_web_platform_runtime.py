import tempfile
import unittest
from pathlib import Path

from wshawk.db_manager import WSHawkDatabase
from wshawk.store import ProjectStore
from wshawk.transport import WSHawkHTTPProxy
from wshawk.web_pentest import WebPentestPlatformRuntime


class WebPentestPlatformRuntimeTests(unittest.TestCase):
    def make_runtime(self):
        temp_dir = tempfile.TemporaryDirectory()
        db = WSHawkDatabase(str(Path(temp_dir.name) / "web_runtime.db"))
        store = ProjectStore(db)
        http_proxy = WSHawkHTTPProxy(store=store)
        runtime = WebPentestPlatformRuntime(db, store, http_proxy)
        return temp_dir, db, store, runtime

    def test_resolve_request_context_merges_identity_tokens_headers_cookies_and_csrf(self):
        temp_dir, db, store, runtime = self.make_runtime()
        self.addCleanup(temp_dir.cleanup)

        project = db.save_project(name="web-runtime", target_url="https://target.test")
        identity = db.save_identity(
            project_id=project["id"],
            alias="operator",
            source="manual",
            cookies=[{"name": "sid", "value": "cookie-1"}, {"name": "XSRF-TOKEN", "value": "csrf-cookie"}],
            headers={"X-Tenant": "red"},
            tokens={"access_token": "token-1", "csrf_token": "csrf-token-1"},
            storage={"csrf_state": "csrf-storage"},
        )

        context = runtime.resolve_request_context(
            project_id=project["id"],
            identity_id=identity["id"],
            headers={"X-Trace": "trace-1"},
            cookies={"pref": "dark"},
        )

        self.assertEqual(context.identity["id"], identity["id"])
        self.assertEqual(context.headers["Authorization"], "Bearer token-1")
        self.assertEqual(context.headers["X-Tenant"], "red")
        self.assertEqual(context.headers["X-Trace"], "trace-1")
        self.assertEqual(context.cookies["sid"], "cookie-1")
        self.assertEqual(context.cookies["pref"], "dark")
        self.assertTrue(context.correlation_id)
        self.assertIn("csrf-cookie", context.csrf_tokens)
        self.assertIn("csrf-token-1", context.csrf_tokens)
        self.assertIn("csrf-storage", context.csrf_tokens)

        attack = runtime.start_attack(
            project_id=project["id"],
            attack_type="http_request",
            target_url="https://target.test/api",
            identity=context.identity,
            parameters={"method": "GET"},
        )
        self.assertEqual(attack["attack_type"], "http_request")

        stored_findings = runtime.add_findings(
            project_id=project["id"],
            attack_run_id=attack["id"],
            target_url="https://target.test/api",
            category="cors_misconfiguration",
            findings=[{"title": "Wildcard ACAO", "detail": "Reflected origin.", "severity": "high"}],
            default_severity="medium",
        )
        self.assertEqual(len(stored_findings), 1)
        self.assertEqual(store.list_findings(project["id"])[0]["category"], "cors_misconfiguration")

    def test_http_proxy_prepares_json_body_as_real_json_payload(self):
        kwargs = WSHawkHTTPProxy._prepare_request_kwargs(
            '{"reason":"http replay","approval_token":"approve-beta-9001"}',
            {"Content-Type": "application/json"},
        )
        self.assertEqual(
            kwargs,
            {
                "json": {
                    "reason": "http replay",
                    "approval_token": "approve-beta-9001",
                }
            },
        )

    def test_http_proxy_unwraps_double_encoded_json_body(self):
        kwargs = WSHawkHTTPProxy._prepare_request_kwargs(
            '"{\\"reason\\":\\"http replay\\",\\"approval_token\\":\\"approve-beta-9001\\"}"',
            {"Content-Type": "application/json"},
        )
        self.assertEqual(
            kwargs,
            {
                "json": {
                    "reason": "http replay",
                    "approval_token": "approve-beta-9001",
                }
            },
        )


if __name__ == "__main__":
    unittest.main()
