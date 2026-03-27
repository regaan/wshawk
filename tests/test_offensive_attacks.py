import asyncio
import tempfile
import unittest
from pathlib import Path

from wshawk.attacks import (
    WebSocketRaceService,
    WebSocketReplayService,
    WebSocketSubscriptionAbuseService,
    WorkflowExecutionService,
)
from wshawk.web_pentest.attack_chainer import WSHawkAttackChainer
import wshawk.attacks.race as race_module
import wshawk.attacks.replay as replay_module
import wshawk.attacks.subscription_abuse as subscription_module
import wshawk.attacks.workflows as workflow_module
from wshawk.db_manager import WSHawkDatabase
from wshawk.store import ProjectStore
from wshawk.transport import WSHawkHTTPProxy


class OffensiveAttackServiceTests(unittest.TestCase):
    def make_store(self):
        temp_dir = tempfile.TemporaryDirectory()
        db = WSHawkDatabase(str(Path(temp_dir.name) / "offensive_attacks.db"))
        store = ProjectStore(db)
        project = db.save_project(name=f"attack-project-{id(temp_dir)}", target_url="wss://target.test/ws")
        return temp_dir, db, store, project

    def test_subscription_abuse_detects_accepted_sensitive_mutations(self):
        temp_dir, db, store, project = self.make_store()
        self.addCleanup(temp_dir.cleanup)

        async def fake_replay(*, payload, **kwargs):
            channel = payload.get("channel")
            tenant_id = payload.get("tenant_id")
            if channel in {"admin", "private", "internal", "*"} or tenant_id != "red":
                response = '{"ok": true, "scope": "elevated"}'
            else:
                response = '{"ok": true, "scope": "standard"}'
            return {
                "status": "received",
                "response": response,
                "response_length": len(response),
                "response_preview": response[:240],
                "timing_ms": 1.5,
            }

        original_replay = subscription_module.replay_websocket_message
        subscription_module.replay_websocket_message = fake_replay
        self.addCleanup(setattr, subscription_module, "replay_websocket_message", original_replay)

        async def scenario():
            service = WebSocketSubscriptionAbuseService(store=store)
            return await service.probe(
                project_id=project["id"],
                url="ws://target.test/ws",
                payload={"action": "subscribe", "channel": "alerts", "tenant_id": "red"},
                identities=[None],
                max_mutations=12,
            )

        result = asyncio.run(scenario())
        self.assertGreater(result["summary"]["mutation_count"], 0)
        self.assertGreater(result["summary"]["suspicious_attempt_count"], 0)
        self.assertEqual(result["summary"]["recommended_severity"], "high")
        self.assertEqual(len(store.list_attack_runs(project["id"])), 1)
        self.assertGreaterEqual(len(store.list_ws_connections(project["id"])), 2)
        self.assertGreaterEqual(len(store.list_ws_frames(project["id"])), 2)

    def test_replay_skips_welcome_banner_and_captures_action_response(self):
        temp_dir, db, store, project = self.make_store()
        self.addCleanup(temp_dir.cleanup)

        class FakeWebSocket:
            def __init__(self):
                self.prelude_messages = [
                    '{"type":"welcome","client_id":"abc","username":"alice","tenant":"tenant-alpha","role":"user","token_replay_supported":true}',
                ]
                self.post_send_messages = [
                    '{"type":"invoice_snapshot","invoice":{"id":"inv-beta-9001","tenant":"tenant-beta"}}',
                ]
                self.sent_payload = None

            async def __aenter__(self):
                return self

            async def __aexit__(self, exc_type, exc, tb):
                return False

            async def send(self, payload):
                self.sent_payload = payload

            async def recv(self):
                queue = self.post_send_messages if self.sent_payload is not None else self.prelude_messages
                if not queue:
                    raise asyncio.TimeoutError
                return queue.pop(0)

        original_connect = replay_module.websockets.connect
        replay_module.websockets.connect = lambda *args, **kwargs: FakeWebSocket()
        self.addCleanup(setattr, replay_module.websockets, "connect", original_connect)

        async def scenario():
            service = WebSocketReplayService(store=store)
            return await service.replay(
                project_id=project["id"],
                url="ws://target.test/ws",
                payload={"action": "subscribe_invoice", "invoice_id": "inv-beta-9001"},
                identity=None,
            )

        result = asyncio.run(scenario())
        self.assertEqual(result["status"], "received")
        self.assertIn('"type":"invoice_snapshot"', result["response"].replace(" ", ""))
        self.assertNotIn('"type":"welcome"', result["response"].replace(" ", ""))
        self.assertEqual(result.get("prelude_frame_count"), 1)

    def test_race_attack_records_duplicate_success(self):
        temp_dir, db, store, project = self.make_store()
        self.addCleanup(temp_dir.cleanup)
        observed = {"count": 0}

        async def fake_attempt(**kwargs):
            observed["count"] += 1
            return {
                "wave": kwargs["wave"],
                "attempt": kwargs["attempt"],
                "status": "received",
                "response": f'{{"ok": true, "attempt": {observed["count"]}}}',
                "response_length": 26,
                "response_preview": '{"ok": true}',
                "timing_ms": 2.0,
                "identity_id": None,
                "identity_alias": None,
            }

        original_attempt = race_module._race_attempt
        race_module._race_attempt = fake_attempt
        self.addCleanup(setattr, race_module, "_race_attempt", original_attempt)

        async def scenario():
            service = WebSocketRaceService(store=store)
            return await service.run(
                project_id=project["id"],
                url="ws://target.test/ws",
                payload={"action": "redeem", "code": "RACE"},
                identities=[None],
                concurrency=3,
                waves=2,
                stagger_ms=5,
                mode="duplicate_action",
            )

        result = asyncio.run(scenario())
        self.assertEqual(result["summary"]["attempt_count"], 6)
        self.assertTrue(result["summary"]["duplicate_success_observed"])
        self.assertTrue(result["summary"]["suspicious_race_window"])
        self.assertEqual(result["summary"]["recommended_severity"], "high")
        self.assertEqual(len(store.list_attack_runs(project["id"])), 1)
        self.assertGreaterEqual(len(store.list_ws_connections(project["id"])), 6)

    def test_race_attack_does_not_treat_error_frames_as_success(self):
        temp_dir, db, store, project = self.make_store()
        self.addCleanup(temp_dir.cleanup)

        async def fake_attempt(**kwargs):
            return {
                "wave": kwargs["wave"],
                "attempt": kwargs["attempt"],
                "status": "received",
                "response": '{"type":"error","error":"permission_denied","status_code":403}',
                "response_length": 60,
                "response_preview": '{"type":"error","error":"permission_denied"}',
                "timing_ms": 2.0,
                "identity_id": None,
                "identity_alias": None,
            }

        original_attempt = race_module._race_attempt
        race_module._race_attempt = fake_attempt
        self.addCleanup(setattr, race_module, "_race_attempt", original_attempt)

        async def scenario():
            service = WebSocketRaceService(store=store)
            return await service.run(
                project_id=project["id"],
                url="ws://target.test/ws",
                payload={"action": "approve_refund", "invoice_id": "inv-beta-9001"},
                identities=[None],
                concurrency=3,
                waves=2,
                mode="duplicate_action",
            )

        result = asyncio.run(scenario())
        self.assertEqual(result["summary"]["accepted_count"], 0)
        self.assertFalse(result["summary"]["duplicate_success_observed"])
        self.assertFalse(result["summary"]["suspicious_race_window"])
        self.assertEqual(result["summary"]["recommended_severity"], "info")

    def test_subscription_abuse_does_not_mark_error_frames_as_accepted(self):
        temp_dir, db, store, project = self.make_store()
        self.addCleanup(temp_dir.cleanup)

        async def fake_replay(*, payload, **kwargs):
            channel = payload.get("channel")
            if channel == "alerts":
                response = '{"ok": true, "scope": "standard"}'
            else:
                response = '{"type":"error","error":"forbidden","status_code":403}'
            return {
                "status": "received",
                "response": response,
                "response_length": len(response),
                "response_preview": response[:240],
                "timing_ms": 1.5,
            }

        original_replay = subscription_module.replay_websocket_message
        subscription_module.replay_websocket_message = fake_replay
        self.addCleanup(setattr, subscription_module, "replay_websocket_message", original_replay)

        async def scenario():
            service = WebSocketSubscriptionAbuseService(store=store)
            return await service.probe(
                project_id=project["id"],
                url="ws://target.test/ws",
                payload={"action": "subscribe", "channel": "alerts"},
                identities=[None],
                max_mutations=6,
            )

        result = asyncio.run(scenario())
        self.assertEqual(result["summary"]["accepted_mutation_count"], 0)
        self.assertEqual(result["summary"]["suspicious_attempt_count"], 0)
        self.assertEqual(result["summary"]["recommended_severity"], "info")

    def test_workflow_execution_links_http_and_ws_steps(self):
        temp_dir, db, store, project = self.make_store()
        self.addCleanup(temp_dir.cleanup)

        class FakeHTTPProxy(WSHawkHTTPProxy):
            async def send_request(self, **kwargs):
                flow = self.store.add_http_flow(
                    project_id=kwargs["project_id"],
                    method=kwargs["method"],
                    url=kwargs["url"],
                    request_headers={},
                    request_body=kwargs.get("body", ""),
                    response_status="200",
                    response_headers={"content-type": "application/json"},
                    response_body='{"csrf": "csrf-123", "tenant": "red"}',
                    correlation_id=kwargs.get("correlation_id", ""),
                    attack_run_id=kwargs.get("attack_run_id"),
                    metadata=kwargs.get("metadata"),
                )
                return {
                    "status": "200",
                    "headers": "content-type: application/json",
                    "body": '{"csrf": "csrf-123", "tenant": "red"}',
                    "flow_id": flow["id"],
                }

        async def fake_replay(*, payload, **kwargs):
            accepted = payload.get("csrf") == "csrf-123"
            response = '{"accepted": true, "tenant": "red"}' if accepted else '{"accepted": false}'
            return {
                "status": "received",
                "response": response,
                "response_length": len(response),
                "response_preview": response[:240],
                "timing_ms": 1.0,
            }

        original_replay = workflow_module.replay_websocket_message
        workflow_module.replay_websocket_message = fake_replay
        self.addCleanup(setattr, workflow_module, "replay_websocket_message", original_replay)

        async def scenario():
            service = WorkflowExecutionService(
                db=db,
                store=store,
                http_proxy=FakeHTTPProxy(store=store),
            )
            return await service.execute(
                project_id=project["id"],
                default_url="ws://target.test/ws",
                steps=[
                    {
                        "name": "Fetch Token",
                        "type": "http",
                        "method": "GET",
                        "url": "https://target.test/token",
                        "extract": [{"var": "csrf", "from": "json", "path": "csrf"}],
                    },
                    {
                        "name": "Subscribe",
                        "type": "ws",
                        "payload": {"action": "subscribe", "tenant": "red", "csrf": "{{csrf}}"},
                        "extract": [{"var": "accepted", "from": "json", "path": "accepted"}],
                    },
                    {
                        "name": "Record Note",
                        "type": "note",
                        "title": "Workflow completed",
                        "body": "Captured CSRF and replayed subscription.",
                    },
                ],
            )

        result = asyncio.run(scenario())
        self.assertEqual(result["summary"]["completed"], 3)
        self.assertEqual(result["summary"]["errors"], 0)
        self.assertEqual(result["variables"]["csrf"], "csrf-123")
        self.assertTrue(result["variables"]["accepted"])
        self.assertEqual(len(store.list_http_flows(project["id"])), 1)
        self.assertEqual(len(store.list_ws_connections(project["id"])), 1)
        self.assertGreaterEqual(len(store.list_ws_frames(project["id"])), 2)
        self.assertEqual(len(store.list_notes(project["id"])), 1)

    def test_workflow_playbook_and_attack_chainer_support_cross_protocol_sequence(self):
        temp_dir, db, store, project = self.make_store()
        self.addCleanup(temp_dir.cleanup)

        class FakeHTTPProxy(WSHawkHTTPProxy):
            async def send_request(self, **kwargs):
                flow = self.store.add_http_flow(
                    project_id=kwargs["project_id"],
                    method=kwargs["method"],
                    url=kwargs["url"],
                    request_headers=kwargs.get("headers") or {},
                    request_body=kwargs.get("body", ""),
                    response_status="200",
                    response_headers={"content-type": "application/json"},
                    response_body='{"bootstrap": true, "token": "bootstrap-1"}',
                    correlation_id=kwargs.get("correlation_id", ""),
                    attack_run_id=kwargs.get("attack_run_id"),
                    metadata=kwargs.get("metadata"),
                )
                return {
                    "status": "200",
                    "headers": "content-type: application/json",
                    "headers_dict": {"content-type": "application/json"},
                    "body": '{"bootstrap": true, "token": "bootstrap-1"}',
                    "flow_id": flow["id"],
                }

        async def fake_replay(*, payload, **kwargs):
            accepted = payload.get("token") == "bootstrap-1"
            response = '{"accepted": true, "role": "admin"}' if accepted else '{"accepted": false}'
            return {
                "status": "received",
                "response": response,
                "response_length": len(response),
                "response_preview": response[:240],
                "timing_ms": 1.2,
            }

        original_replay = workflow_module.replay_websocket_message
        workflow_module.replay_websocket_message = fake_replay
        self.addCleanup(setattr, workflow_module, "replay_websocket_message", original_replay)

        async def scenario():
            workflow_service = WorkflowExecutionService(
                db=db,
                store=store,
                http_proxy=FakeHTTPProxy(store=store),
            )
            chainer = WSHawkAttackChainer(store=store)
            chainer.workflow_service = workflow_service
            return await chainer.execute_chain(
                steps=[],
                playbook="ws_privilege_escalation",
                project_id=project["id"],
                default_url="https://target.test/bootstrap",
                default_ws_url="ws://target.test/ws",
                initial_vars={
                    "http_method": "GET",
                    "http_body": "",
                    "ws_payload": {"action": "subscribe", "channel": "admin", "token": "bootstrap-1"},
                },
            )

        result = asyncio.run(scenario())
        self.assertEqual(result["playbook"], "ws_privilege_escalation")
        self.assertEqual(result["summary"]["completed"], 2)
        self.assertEqual(result["summary"]["errors"], 0)
        self.assertEqual(len(store.list_http_flows(project["id"])), 1)
        self.assertEqual(len(store.list_ws_connections(project["id"])), 1)
        self.assertGreaterEqual(len(store.list_ws_frames(project["id"])), 2)
        timeline = store.build_correlation_groups(project["id"])
        self.assertEqual(len(timeline), 1)
        self.assertEqual(timeline[0]["summary"]["http_flow_count"], 1)
        self.assertEqual(timeline[0]["summary"]["ws_connection_count"], 1)


if __name__ == "__main__":
    unittest.main()
