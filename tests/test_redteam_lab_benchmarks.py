import asyncio
import json
import tempfile
import unittest
from pathlib import Path

from wshawk.attacks.workflows import WorkflowExecutionService
from wshawk.db_manager import WSHawkDatabase
from wshawk.evidence import EvidenceBundleBuilder, EvidenceExportService, TimelineService
from wshawk.protocol import ProtocolGraphService
from wshawk.store import ProjectStore
from wshawk.transport import WSHawkHTTPProxy
import wshawk.attacks.workflows as workflow_module


class _LabHTTPProxy(WSHawkHTTPProxy):
    async def send_request(self, **kwargs):
        response_body = '{"csrf":"csrf-lab","tenant":"red","bootstrap":true}'
        flow = self.store.add_http_flow(
            project_id=kwargs["project_id"],
            method=kwargs["method"],
            url=kwargs["url"],
            request_headers=kwargs.get("headers") or {},
            request_body=kwargs.get("body", ""),
            response_status="200",
            response_headers={"content-type": "application/json"},
            response_body=response_body,
            correlation_id=kwargs.get("correlation_id", ""),
            attack_run_id=kwargs.get("attack_run_id"),
            metadata=kwargs.get("metadata"),
        )
        return {
            "status": "200",
            "headers": "content-type: application/json",
            "headers_dict": {"content-type": "application/json"},
            "body": response_body,
            "flow_id": flow["id"],
        }


class RedTeamLabBenchmarkTests(unittest.TestCase):
    def make_store(self, name: str, target_url: str):
        temp_dir = tempfile.TemporaryDirectory()
        db = WSHawkDatabase(str(Path(temp_dir.name) / "lab_benchmarks.db"))
        store = ProjectStore(db)
        project = db.save_project(name=name, target_url=target_url)
        return temp_dir, db, store, project

    def test_lab_graphql_subscription_protocol_guidance(self):
        temp_dir, db, store, project = self.make_store("graphql-lab", "wss://lab.test/graphql")
        self.addCleanup(temp_dir.cleanup)

        connection = store.open_ws_connection(
            project_id=project["id"],
            url="wss://lab.test/graphql",
            handshake_headers={"Origin": "https://lab.test"},
            correlation_id="corr-graphql-lab",
            subprotocol="graphql-transport-ws",
        )
        store.add_ws_frame(
            project_id=project["id"],
            connection_id=connection["id"],
            direction="out",
            payload={"type": "connection_init", "payload": {"Authorization": "Bearer red"}},
        )
        store.add_ws_frame(
            project_id=project["id"],
            connection_id=connection["id"],
            direction="out",
            payload={"type": "subscribe", "id": "1", "payload": {"query": "subscription { adminFeed }"}},
        )
        store.add_finding(
            project_id=project["id"],
            title="Privileged GraphQL subscription accepted",
            category="subscription_abuse",
            severity="high",
            description="GraphQL subscription returned privileged events.",
            related_connection_id=connection["id"],
        )

        protocol_map = ProtocolGraphService(store).build_project_map(project["id"])
        exporter = EvidenceExportService(EvidenceBundleBuilder(db=db, store=store), protocol_graph=ProtocolGraphService(store))
        markdown_export = exporter.export(project["id"], "markdown")

        pack_ids = {pack["id"] for pack in protocol_map["target_packs"]}
        playbook_ids = {item["id"] for item in protocol_map["playbook_candidates"]}

        self.assertIn("graphql_ws", pack_ids)
        self.assertIn("ws_privilege_escalation", playbook_ids)
        self.assertIn("Suggested Playbooks", markdown_export["content"])
        self.assertIn("graphql_ws", markdown_export["content"])

    def test_lab_http_bootstrap_to_ws_workflow_generates_replayable_bundle(self):
        temp_dir, db, store, project = self.make_store("cross-protocol-lab", "wss://lab.test/ws")
        self.addCleanup(temp_dir.cleanup)

        async def fake_replay(*, payload, **kwargs):
            response = '{"accepted": true, "tenant": "red"}' if payload.get("csrf") == "csrf-lab" else '{"accepted": false}'
            return {
                "status": "received",
                "response": response,
                "response_length": len(response),
                "response_preview": response[:240],
                "timing_ms": 1.1,
            }

        original_replay = workflow_module.replay_websocket_message
        workflow_module.replay_websocket_message = fake_replay
        self.addCleanup(setattr, workflow_module, "replay_websocket_message", original_replay)

        async def scenario():
            service = WorkflowExecutionService(
                db=db,
                store=store,
                http_proxy=_LabHTTPProxy(store=store),
            )
            return await service.execute(
                project_id=project["id"],
                playbook="ws_privilege_escalation",
                default_url="https://lab.test/bootstrap",
                default_ws_url="ws://lab.test/ws",
                initial_vars={
                    "http_method": "GET",
                    "http_body": "",
                    "ws_payload": {"action": "subscribe", "tenant": "red", "csrf": "csrf-lab"},
                },
            )

        result = asyncio.run(scenario())
        timeline = TimelineService(store).build_project_summary(project["id"])
        bundle = EvidenceBundleBuilder(db=db, store=store).build(project["id"])

        self.assertEqual(result["playbook"], "ws_privilege_escalation")
        self.assertEqual(result["summary"]["completed"], 2)
        self.assertEqual(len(timeline["http_flows"]), 1)
        self.assertEqual(len(timeline["ws_connections"]), 1)
        self.assertEqual(len(timeline["correlation_chains"]), 1)
        recipe_types = {item["type"] for item in bundle["sanitized_preview"]["replay_recipes"]}
        self.assertEqual(recipe_types, {"http", "websocket"})

    def test_lab_binary_protocol_adapter_surfaces_attack_templates(self):
        temp_dir, db, store, project = self.make_store("binary-lab", "wss://lab.test/binary")
        self.addCleanup(temp_dir.cleanup)

        connection = store.open_ws_connection(
            project_id=project["id"],
            url="wss://lab.test/binary",
            handshake_headers={"Origin": "https://lab.test"},
            correlation_id="corr-binary-lab",
        )
        store.add_ws_frame(
            project_id=project["id"],
            connection_id=connection["id"],
            direction="out",
            payload=b"\x82\xa4type\xa9mutate\xa6tenant\xa3red",
            opcode="binary",
            is_binary=True,
            metadata={
                "binary_analysis": {
                    "format": "protobuf",
                    "injectable_fields": ["tenant_id", "object_id"],
                }
            },
        )

        protocol_map = ProtocolGraphService(store).build_project_map(project["id"])
        binary_pack = next(pack for pack in protocol_map["target_packs"] if pack["id"] == "binary_realtime")

        self.assertIn("protobuf", binary_pack["metadata"]["formats"])
        self.assertIn("tenant_id", binary_pack["identifiers"])
        self.assertGreaterEqual(len(binary_pack["attack_templates"]), 1)
        self.assertIn("binary:protobuf", binary_pack["signals"])


if __name__ == "__main__":
    unittest.main()
