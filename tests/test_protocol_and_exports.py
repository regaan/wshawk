import json
import tempfile
import unittest
from pathlib import Path

from wshawk.db_manager import WSHawkDatabase
from wshawk.evidence import EvidenceBundleBuilder, EvidenceExportService
from wshawk.protocol import ProtocolGraphService
from wshawk.store import ProjectStore


class ProtocolAndExportTests(unittest.TestCase):
    def make_store(self):
        temp_dir = tempfile.TemporaryDirectory()
        db = WSHawkDatabase(str(Path(temp_dir.name) / "protocol_exports.db"))
        store = ProjectStore(db)
        return temp_dir, db, store

    def test_ws_connection_auto_correlates_recent_http_and_browser_artifacts(self):
        temp_dir, db, store = self.make_store()
        self.addCleanup(temp_dir.cleanup)

        project = db.save_project(name="corr-project", target_url="wss://example.test/ws")
        flow = store.add_http_flow(
            project_id=project["id"],
            method="GET",
            url="https://example.test/app/bootstrap",
            request_headers={"Origin": "https://example.test", "Referer": "https://example.test/app"},
            response_status="200",
            response_body='{"bootstrap":true}',
        )
        artifact = store.add_browser_artifact(
            project_id=project["id"],
            artifact_type="auth_flow_recorded",
            source="browser_capture",
            url="wss://example.test/ws",
            payload={
                "login_url": "https://example.test/login",
                "target_ws_url": "wss://example.test/ws",
            },
        )

        connection = store.open_ws_connection(
            project_id=project["id"],
            url="wss://example.test/ws",
            handshake_headers={
                "Origin": "https://example.test",
                "Referer": "https://example.test/app",
            },
        )

        self.assertTrue(connection["correlation_id"])

        linked_flow = store.list_http_flows(project["id"], limit=10)[0]
        self.assertEqual(linked_flow["id"], flow["id"])
        self.assertEqual(linked_flow["correlation_id"], connection["correlation_id"])

        linked_artifact = store.list_browser_artifacts(project["id"], limit=10)[0]
        self.assertEqual(linked_artifact["id"], artifact["id"])
        self.assertEqual(linked_artifact["payload"]["correlation_id"], connection["correlation_id"])
        self.assertEqual(linked_artifact["payload"]["linked_ws_url"], "wss://example.test/ws")

        groups = store.build_correlation_groups(project["id"])
        self.assertEqual(len(groups), 1)
        self.assertEqual(groups[0]["correlation_id"], connection["correlation_id"])
        self.assertEqual(groups[0]["summary"]["http_flow_count"], 1)
        self.assertEqual(groups[0]["summary"]["ws_connection_count"], 1)
        self.assertEqual(groups[0]["summary"]["browser_artifact_count"], 1)

    def test_protocol_graph_and_export_formats_include_live_map_data(self):
        temp_dir, db, store = self.make_store()
        self.addCleanup(temp_dir.cleanup)

        project = db.save_project(name="graph-project", target_url="wss://graph.test/ws")
        connection = store.open_ws_connection(
            project_id=project["id"],
            url="wss://graph.test/ws",
            handshake_headers={"Origin": "https://graph.test"},
            correlation_id="corr-graph",
        )
        store.add_ws_frame(
            project_id=project["id"],
            connection_id=connection["id"],
            direction="out",
            payload={"action": "login", "token": "abc"},
        )
        store.add_ws_frame(
            project_id=project["id"],
            connection_id=connection["id"],
            direction="in",
            payload={"event": "login_ok", "session_id": "sess-1"},
        )
        store.add_ws_frame(
            project_id=project["id"],
            connection_id=connection["id"],
            direction="out",
            payload={"action": "subscribe", "channel": "alerts", "tenant_id": "red"},
        )
        store.add_finding(
            project_id=project["id"],
            title="Unauthorized subscription accepted",
            category="subscription_abuse",
            severity="high",
            description="Server accepted a privileged subscription channel.",
            related_connection_id=connection["id"],
        )

        graph_service = ProtocolGraphService(store)
        protocol_map = graph_service.build_project_map(project["id"])

        family_names = [family["name"] for family in protocol_map["message_families"]]
        self.assertIn("login", family_names)
        self.assertIn("subscribe", family_names)
        self.assertGreaterEqual(protocol_map["summary"]["transition_count"], 1)
        self.assertTrue(any(edge["label"] == "transition" for edge in protocol_map["edges"]))

        bundle_builder = EvidenceBundleBuilder(db=db, store=store)
        exporter = EvidenceExportService(bundle_builder, protocol_graph=graph_service)

        json_export = exporter.export(project["id"], "json")
        markdown_export = exporter.export(project["id"], "markdown")
        html_export = exporter.export(project["id"], "html")

        json_payload = json.loads(json_export["content"])
        self.assertIn("protocol_map", json_payload)
        self.assertIn("integrity", json_payload)
        self.assertIn("provenance", json_payload)
        self.assertTrue(json_payload["sanitized_preview"]["replay_recipes"])
        self.assertTrue(json_payload["sanitized_preview"]["correlation_chains"])
        self.assertTrue(exporter.verify_bundle(json_payload)["ok"])
        self.assertEqual(json_export["media_type"], "application/json")
        self.assertIn("# WSHawk Evidence Bundle: graph-project", markdown_export["content"])
        self.assertIn("## Replay Recipes", markdown_export["content"])
        self.assertIn("## Correlation Chains", markdown_export["content"])
        self.assertIn("### Suggested Playbooks", markdown_export["content"])
        self.assertIn("Unauthorized subscription accepted", html_export["content"])
        self.assertIn("Replay Recipes", html_export["content"])
        self.assertIn("Suggested Playbooks", html_export["content"])
        self.assertIn("Integrity:", html_export["content"])

    def test_json_export_redacts_raw_session_material(self):
        temp_dir, db, store = self.make_store()
        self.addCleanup(temp_dir.cleanup)

        project = db.save_project(
            name="redaction-project",
            target_url="ws://example.test/ws?token=abcdefghijklmnopqrstuvwxyz123456",
        )
        db.save_identity(
            project_id=project["id"],
            alias="alice-tenant-alpha-user",
            source="manual",
            cookies=[{"name": "sessionid", "value": "super-secret-session-cookie"}],
            headers={
                "Cookie": "sessionid=super-secret-session-cookie; csrftoken=csrf-secret-value",
                "Authorization": "Bearer abcdefghijklmnopqrstuvwxyz123456",
            },
            tokens={
                "bearer": "abcdefghijklmnopqrstuvwxyz123456",
                "csrf": "csrf-secret-value",
            },
            storage={"localStorage": {"bearerToken": "abcdefghijklmnopqrstuvwxyz123456"}},
            notes="token=abcdefghijklmnopqrstuvwxyz123456",
        )
        connection = store.open_ws_connection(
            project_id=project["id"],
            url="ws://example.test/ws?token=abcdefghijklmnopqrstuvwxyz123456",
            handshake_headers={
                "Cookie": "sessionid=super-secret-session-cookie; csrftoken=csrf-secret-value",
                "Authorization": "Bearer abcdefghijklmnopqrstuvwxyz123456",
            },
            correlation_id="corr-redact",
        )
        store.add_ws_frame(
            project_id=project["id"],
            connection_id=connection["id"],
            direction="out",
            payload='{"approval_token":"approve-beta-9001","csrf":"csrf-secret-value"}',
        )
        db.add_event(
            project_id=project["id"],
            event_type="ws_platform_replay_sent",
            payload={
                "headers": {
                    "Cookie": "sessionid=super-secret-session-cookie",
                    "Authorization": "Bearer abcdefghijklmnopqrstuvwxyz123456",
                }
            },
            target="ws://example.test/ws?token=abcdefghijklmnopqrstuvwxyz123456",
        )
        db.add_evidence(
            project_id=project["id"],
            title="Token replay evidence",
            category="websocket_token_replay",
            severity="high",
            payload={
                "request_headers": {
                    "Cookie": "sessionid=super-secret-session-cookie",
                    "Authorization": "Bearer abcdefghijklmnopqrstuvwxyz123456",
                },
                "csrf": "csrf-secret-value",
                "approval_token": "approve-beta-9001",
            },
        )

        exporter = EvidenceExportService(EvidenceBundleBuilder(db=db, store=store))
        json_export = exporter.export(project["id"], "json")
        content = json_export["content"]

        self.assertNotIn("super-secret-session-cookie", content)
        self.assertNotIn("csrf-secret-value", content)
        self.assertNotIn("abcdefghijklmnopqrstuvwxyz123456", content)
        self.assertIn("abcd***3456", content)
        self.assertIn("appr***9001", content)
        self.assertIn("***", content)

    def test_bundle_verification_detects_tampering(self):
        temp_dir, db, store = self.make_store()
        self.addCleanup(temp_dir.cleanup)

        project = db.save_project(name="tamper-project", target_url="wss://tamper.test/ws")
        store.add_finding(
            project_id=project["id"],
            title="Replay accepted",
            category="subscription_abuse",
            severity="high",
            description="Server accepted an unauthorized channel replay.",
        )

        exporter = EvidenceExportService(EvidenceBundleBuilder(db=db, store=store))
        payload = json.loads(exporter.export(project["id"], "json")["content"])
        self.assertTrue(exporter.verify_bundle(payload)["ok"])

        payload["timeline"]["findings"][0]["description"] = "tampered"
        verification = exporter.verify_bundle(payload)
        self.assertFalse(verification["ok"])
        self.assertIn("mismatch", verification["reason"])

    def test_export_derives_replay_findings_from_stored_events(self):
        temp_dir, db, store = self.make_store()
        self.addCleanup(temp_dir.cleanup)

        project = db.save_project(name="derived-replay-project", target_url="ws://example.test/ws")
        identity = db.save_identity(
            project_id=project["id"],
            alias="alice-tenant-alpha-user",
            source="manual",
            cookies=[{"name": "session", "value": "cookie-value"}],
            headers={"Cookie": "session=cookie-value"},
        )
        connection = store.open_ws_connection(
            project_id=project["id"],
            url="ws://example.test/ws",
            handshake_headers={"Cookie": "session=cookie-value"},
            correlation_id="corr-derived",
        )
        db.add_event(
            project_id=project["id"],
            event_type="ws_platform_replay_response",
            direction="in",
            connection_id=connection["id"],
            target="ws://example.test/ws",
            payload={
                "identity_id": identity["id"],
                "identity_alias": identity["alias"],
                "result": {
                    "url": "ws://example.test/ws",
                    "status": "received",
                    "payload": '{"action":"subscribe_invoice","invoice_id":"inv-beta-9001"}',
                    "identity_id": identity["id"],
                    "identity_alias": identity["alias"],
                    "response": json.dumps(
                        {
                            "type": "invoice_snapshot",
                            "invoice": {
                                "id": "inv-beta-9001",
                                "tenant": "tenant-beta",
                                "customer": "Northwind Health",
                                "approval_token": "approve-beta-9001",
                            },
                        }
                    ),
                    "attack_run_id": "run-exposure",
                    "connection_id": connection["id"],
                },
            },
        )
        db.add_event(
            project_id=project["id"],
            event_type="ws_platform_replay_response",
            direction="in",
            connection_id=connection["id"],
            target="ws://example.test/ws",
            payload={
                "identity_id": identity["id"],
                "identity_alias": identity["alias"],
                "result": {
                    "url": "ws://example.test/ws",
                    "status": "received",
                    "payload": '{"action":"approve_refund","invoice_id":"inv-beta-9001","approval_token":"approve-beta-9001"}',
                    "identity_id": identity["id"],
                    "identity_alias": identity["alias"],
                    "response": json.dumps(
                        {
                            "type": "refund_result",
                            "ok": True,
                            "invoice_id": "inv-beta-9001",
                            "tenant": "tenant-beta",
                            "approval_token_reused": True,
                            "processed_by": "alice",
                        }
                    ),
                    "attack_run_id": "run-replay",
                    "connection_id": connection["id"],
                },
            },
        )

        graph_service = ProtocolGraphService(store)
        exporter = EvidenceExportService(EvidenceBundleBuilder(db=db, store=store), protocol_graph=graph_service)

        payload = json.loads(exporter.export(project["id"], "json")["content"])

        self.assertIn("websocket_data_exposure", {item.get("category") for item in payload["evidence"]})
        self.assertIn("websocket_token_replay", {item.get("category") for item in payload["evidence"]})
        self.assertIn("websocket_data_exposure", payload["protocol_map"]["finding_categories"])
        self.assertIn("websocket_token_replay", payload["protocol_map"]["finding_categories"])
        self.assertGreaterEqual(payload["statistics"]["evidence_count"], 2)
        self.assertGreaterEqual(payload["statistics"]["finding_count"], 2)

    def test_export_derives_http_replay_findings_from_stored_events(self):
        temp_dir, db, store = self.make_store()
        self.addCleanup(temp_dir.cleanup)

        project = db.save_project(name="derived-http-replay-project", target_url="http://example.test/api")
        identity = db.save_identity(
            project_id=project["id"],
            alias="alice-tenant-alpha-user",
            source="manual",
            cookies=[{"name": "session", "value": "cookie-value"}],
            headers={"Cookie": "session=cookie-value"},
        )

        db.add_event(
            project_id=project["id"],
            event_type="http_replay_completed",
            direction="in",
            target="http://example.test/api/invoices/inv-beta-9001/refund",
            payload={
                "identity_id": identity["id"],
                "identity_alias": identity["alias"],
                "result": {
                    "method": "GET",
                    "url": "http://example.test/api/invoices/inv-beta-9001?preview=true",
                    "status": "received",
                    "body": json.dumps(
                        {
                            "id": "inv-beta-9001",
                            "tenant": "tenant-beta",
                            "customer": "Northwind Health",
                            "approval_token": "approve-beta-9001",
                        }
                    ),
                    "attack_run_id": "http-run-exposure",
                },
            },
        )
        db.add_event(
            project_id=project["id"],
            event_type="http_replay_completed",
            direction="in",
            target="http://example.test/api/team/messages?tenant=tenant-beta",
            payload={
                "identity_id": identity["id"],
                "identity_alias": identity["alias"],
                "result": {
                    "method": "GET",
                    "url": "http://example.test/api/team/messages?tenant=tenant-beta",
                    "status": "received",
                    "body": json.dumps(
                        {
                            "tenant": "tenant-beta",
                            "messages": [{"id": "m1", "text": "sensitive"}],
                        }
                    ),
                    "attack_run_id": "http-run-messages",
                },
            },
        )
        db.add_event(
            project_id=project["id"],
            event_type="http_replay_completed",
            direction="in",
            target="http://example.test/api/invoices/inv-beta-9001/refund",
            payload={
                "identity_id": identity["id"],
                "identity_alias": identity["alias"],
                "result": {
                    "method": "POST",
                    "url": "http://example.test/api/invoices/inv-beta-9001/refund",
                    "status": "received",
                    "body": json.dumps(
                        {
                            "ok": True,
                            "invoice_id": "inv-beta-9001",
                            "tenant": "tenant-beta",
                            "approval_token_reused": True,
                        }
                    ),
                    "attack_run_id": "http-run-replay",
                },
            },
        )

        graph_service = ProtocolGraphService(store)
        exporter = EvidenceExportService(EvidenceBundleBuilder(db=db, store=store), protocol_graph=graph_service)

        payload = json.loads(exporter.export(project["id"], "json")["content"])
        evidence_categories = {item.get("category") for item in payload["evidence"]}

        self.assertIn("http_data_exposure", evidence_categories)
        self.assertIn("http_token_replay", evidence_categories)
        self.assertIn("http_data_exposure", payload["protocol_map"]["finding_categories"])
        self.assertIn("http_token_replay", payload["protocol_map"]["finding_categories"])
        self.assertGreaterEqual(payload["statistics"]["evidence_count"], 3)
        self.assertGreaterEqual(payload["statistics"]["finding_count"], 3)

    def test_protocol_map_redacts_sensitive_samples_but_preserves_category_counts(self):
        temp_dir, db, store = self.make_store()
        self.addCleanup(temp_dir.cleanup)

        project = db.save_project(name="protocol-redact-project", target_url="ws://example.test/ws")
        connection = store.open_ws_connection(
            project_id=project["id"],
            url="ws://example.test/ws?token=abcdefghijklmnopqrstuvwxyz123456",
            handshake_headers={"Cookie": "sessionid=super-secret-session-cookie"},
            correlation_id="corr-proto-redact",
        )
        store.add_ws_frame(
            project_id=project["id"],
            connection_id=connection["id"],
            direction="out",
            payload={
                "action": "approve_refund",
                "invoice_id": "inv-beta-9001",
                "approval_token": "approve-beta-9001",
                "api_key": "alpha-user-key",
                "approval_token_reused": True,
            },
        )
        store.add_finding(
            project_id=project["id"],
            title="Replay reused token",
            category="websocket_token_replay",
            severity="high",
            description="Approval token reused.",
            related_connection_id=connection["id"],
        )

        graph_service = ProtocolGraphService(store)
        exporter = EvidenceExportService(EvidenceBundleBuilder(db=db, store=store), protocol_graph=graph_service)
        payload = json.loads(exporter.export(project["id"], "json")["content"])

        protocol_map = payload["protocol_map"]
        self.assertEqual(protocol_map["finding_categories"]["websocket_token_replay"], 1)

        content = json.dumps(protocol_map)
        self.assertNotIn("approve-beta-9001", content)
        self.assertNotIn("alpha-user-key", content)
        self.assertIn("appr***9001", content)
        self.assertIn("alph***-key", content)
        approval_flag_profile = next(
            item for item in protocol_map["protocol_summary"]["field_profiles"] if item["path"] == "approval_token_reused"
        )
        self.assertIn("True", approval_flag_profile["samples"])

    def test_json_export_redacts_truncated_json_style_secret_previews(self):
        temp_dir, db, store = self.make_store()
        self.addCleanup(temp_dir.cleanup)

        project = db.save_project(name="preview-redact-project", target_url="ws://example.test/ws")
        db.add_event(
            project_id=project["id"],
            event_type="ws_platform_replay_response",
            payload={
                "result": {
                    "response_preview": '{"type":"whoami","bearer":"abcdefghijklmnopqrstuvwxyz123456","api_key":"alpha-user-key","csrf":"csrf-secret-value"',
                }
            },
        )

        exporter = EvidenceExportService(EvidenceBundleBuilder(db=db, store=store))
        content = exporter.export(project["id"], "json")["content"]

        self.assertNotIn("abcdefghijklmnopqrstuvwxyz123456", content)
        self.assertNotIn("alpha-user-key", content)
        self.assertNotIn("csrf-secret-value", content)
        self.assertIn('abcd***3456', content)
        self.assertIn('alph***-key', content)

    def test_protocol_graph_detects_target_packs(self):
        temp_dir, db, store = self.make_store()
        self.addCleanup(temp_dir.cleanup)

        project = db.save_project(name="pack-project", target_url="wss://graph.test/graphql")
        connection = store.open_ws_connection(
            project_id=project["id"],
            url="wss://graph.test/graphql",
            handshake_headers={"Origin": "https://graph.test"},
            correlation_id="corr-pack",
            subprotocol="graphql-transport-ws",
        )
        store.add_ws_frame(
            project_id=project["id"],
            connection_id=connection["id"],
            direction="out",
            payload={"type": "connection_init"},
        )
        store.add_ws_frame(
            project_id=project["id"],
            connection_id=connection["id"],
            direction="out",
            payload={"type": "subscribe", "id": "1", "payload": {"query": "subscription { alerts }"}},
        )

        graph_service = ProtocolGraphService(store)
        protocol_map = graph_service.build_project_map(project["id"])
        packs = {pack["id"]: pack for pack in protocol_map["target_packs"]}
        pack_ids = set(packs)

        self.assertIn("graphql_ws", pack_ids)
        self.assertGreaterEqual(len(protocol_map["recommended_attacks"]), 1)
        graphql_pack = packs["graphql_ws"]
        self.assertTrue(graphql_pack["operations"])
        self.assertEqual(graphql_pack["operations"][0]["operation_type"], "subscription")
        self.assertTrue(graphql_pack["attack_templates"])
        self.assertIn("alerts", json.dumps(graphql_pack["normalized_messages"]))
        self.assertTrue(protocol_map["playbook_candidates"])

    def test_protocol_graph_extracts_socketio_adapter_details(self):
        temp_dir, db, store = self.make_store()
        self.addCleanup(temp_dir.cleanup)

        project = db.save_project(name="socketio-pack", target_url="wss://graph.test/socket.io/?transport=websocket")
        connection = store.open_ws_connection(
            project_id=project["id"],
            url="wss://graph.test/socket.io/?transport=websocket",
            handshake_headers={"Origin": "https://graph.test"},
            correlation_id="corr-sio",
        )
        store.add_ws_frame(
            project_id=project["id"],
            connection_id=connection["id"],
            direction="out",
            payload='42["subscribe",{"room":"alerts","tenant_id":"red"}]',
        )

        protocol_map = ProtocolGraphService(store).build_project_map(project["id"])
        packs = {pack["id"]: pack for pack in protocol_map["target_packs"]}

        self.assertIn("socket_io", packs)
        socketio_pack = packs["socket_io"]
        self.assertIn("alerts", socketio_pack["channels"])
        self.assertTrue(socketio_pack["operations"])
        self.assertEqual(socketio_pack["operations"][0]["event"], "subscribe")
        self.assertTrue(socketio_pack["attack_templates"])

    def test_protocol_graph_detects_binary_adapter_details(self):
        temp_dir, db, store = self.make_store()
        self.addCleanup(temp_dir.cleanup)

        project = db.save_project(name="binary-pack", target_url="wss://graph.test/binary")
        connection = store.open_ws_connection(
            project_id=project["id"],
            url="wss://graph.test/binary",
            handshake_headers={"Origin": "https://graph.test"},
            correlation_id="corr-binary",
        )
        store.add_ws_frame(
            project_id=project["id"],
            connection_id=connection["id"],
            direction="out",
            payload=b"\x82\xa4type\xa9subscribe\xa6tenant\xa3red",
            opcode="binary",
            is_binary=True,
            metadata={
                "binary_analysis": {
                    "format": "msgpack",
                    "injectable_fields": ["tenant", "channel_id"],
                }
            },
        )

        protocol_map = ProtocolGraphService(store).build_project_map(project["id"])
        packs = {pack["id"]: pack for pack in protocol_map["target_packs"]}

        self.assertIn("binary_realtime", packs)
        binary_pack = packs["binary_realtime"]
        self.assertIn("msgpack", binary_pack["metadata"]["formats"])
        self.assertIn("tenant", binary_pack["identifiers"])
        self.assertTrue(binary_pack["attack_templates"])


if __name__ == "__main__":
    unittest.main()
