import asyncio
import tempfile
import unittest
from pathlib import Path

from wshawk.db_manager import WSHawkDatabase
from wshawk.session import BrowserCaptureService, BrowserReplayService, IdentityVaultService
from wshawk.store import ProjectStore


class _FakePool:
    def __init__(self):
        self.is_started = False


class _FakeReplayTokens:
    def __init__(self):
        self.valid = True
        self.cookies = [{"name": "sid", "value": "cookie-1"}]
        self.headers = {"Authorization": "Bearer replay-token"}
        self.session_token = "replay-token"


class _FakeDOMEngine:
    def __init__(self):
        self.is_available = True
        self.pool = _FakePool()
        self.started = 0
        self.saved_flow = {"login_url": "https://target.test/login"}

    async def start(self):
        self.pool.is_started = True
        self.started += 1

    def get_saved_flow(self):
        return self.saved_flow

    async def verify_response(self, payload: str, response: str, timeout_ms: int = 3000):
        raise AssertionError("verify_response should not be used in this test")

    async def batch_verify_responses(self, results, timeout_ms: int = 3000):
        raise AssertionError("batch_verify_responses should not be used in this test")

    async def record_auth_flow(self, login_url: str, target_ws_url: str = "", timeout_s: int = 120):
        return {
            "login_url": login_url,
            "target_ws_url": target_ws_url,
            "cookies": [{"name": "sid", "value": "cookie-1"}],
            "extracted_tokens": {"session_token": "capture-token"},
            "local_storage": {"tenant": "red"},
        }

    async def replay_auth_flow(self, flow_data=None):
        return _FakeReplayTokens()


class SessionServiceTests(unittest.TestCase):
    def make_services(self):
        temp_dir = tempfile.TemporaryDirectory()
        db = WSHawkDatabase(str(Path(temp_dir.name) / "session_services.db"))
        store = ProjectStore(db)
        vault = IdentityVaultService(db=db, store=store)
        return temp_dir, db, store, vault

    def test_browser_capture_replay_and_identity_vault_integration(self):
        temp_dir, db, store, vault = self.make_services()
        self.addCleanup(temp_dir.cleanup)
        project = db.save_project(name="auth-project", target_url="wss://target.test/ws")

        engine = _FakeDOMEngine()
        capture = BrowserCaptureService(engine=engine)
        replay = BrowserReplayService(engine=engine)

        async def scenario():
            flow = await capture.record_auth_flow(
                login_url="https://target.test/login",
                target_ws_url="wss://target.test/ws",
                timeout_s=15,
            )
            tokens = await replay.replay_auth_flow(flow)
            return flow, tokens

        flow, tokens = asyncio.run(scenario())

        identity = vault.save_auth_tokens(
            project_id=project["id"],
            alias="captured-admin",
            source="dom_replay",
            cookies=tokens.cookies,
            headers=tokens.headers,
            session_token=tokens.session_token,
            storage=flow.get("local_storage"),
            flow=flow,
            role="admin",
        )

        self.assertEqual(engine.started, 1)
        self.assertEqual(identity["alias"], "captured-admin")
        self.assertEqual(identity["tokens"]["session_token"], "replay-token")
        self.assertEqual(identity["tokens"]["role"], "admin")

        artifacts = store.list_browser_artifacts(project["id"])
        artifact_types = {artifact["artifact_type"] for artifact in artifacts}
        self.assertIn("identity_lineage", artifact_types)
        self.assertIn("auth_flow_replay", artifact_types)


if __name__ == "__main__":
    unittest.main()
