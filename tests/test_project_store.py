import tempfile
import unittest
import sqlite3
from pathlib import Path

from wshawk.db_manager import WSHawkDatabase
from wshawk.store import ProjectStore


class ProjectStoreTests(unittest.TestCase):
    def make_store(self):
        temp_dir = tempfile.TemporaryDirectory()
        db = WSHawkDatabase(str(Path(temp_dir.name) / "project_store.db"))
        store = ProjectStore(db)
        return temp_dir, db, store

    def test_normalized_transport_round_trip(self):
        temp_dir, db, store = self.make_store()
        self.addCleanup(temp_dir.cleanup)

        project = db.save_project(name="alpha", target_url="wss://example.test/ws")
        target = store.ensure_target(project["id"], "wss://example.test/ws", kind="websocket")
        self.assertEqual(target["kind"], "websocket")

        http_flow = store.add_http_flow(
            project_id=project["id"],
            method="GET",
            url="https://example.test/bootstrap",
            request_headers={"Accept": "application/json"},
            response_status="200",
            response_headers={"Content-Type": "application/json"},
            response_body='{"ok":true}',
            correlation_id="corr-1",
        )
        self.assertEqual(http_flow["correlation_id"], "corr-1")

        connection = store.open_ws_connection(
            project_id=project["id"],
            url="wss://example.test/ws",
            handshake_headers={"Origin": "https://example.test"},
            correlation_id="corr-1",
        )
        self.assertEqual(connection["correlation_id"], "corr-1")

        frame = store.add_ws_frame(
            project_id=project["id"],
            connection_id=connection["id"],
            direction="out",
            payload='{"action":"ping"}',
            metadata={"source": "test"},
        )
        self.assertEqual(frame["direction"], "out")

        closed = store.close_ws_connection(connection["id"], state="closed")
        self.assertEqual(closed["state"], "closed")

        self.assertEqual(len(store.list_http_flows(project["id"])), 1)
        self.assertEqual(len(store.list_ws_frames(project["id"])), 1)

        conn = sqlite3.connect(db.db_path)
        try:
            raw_flow = conn.execute(
                "SELECT request_headers_json, response_headers_json, response_body FROM http_flows WHERE id = ?",
                (http_flow["id"],),
            ).fetchone()
            raw_conn = conn.execute(
                "SELECT handshake_headers_json FROM ws_connections WHERE id = ?",
                (connection["id"],),
            ).fetchone()
            raw_frame = conn.execute(
                "SELECT payload_text FROM ws_frames WHERE id = ?",
                (frame["id"],),
            ).fetchone()
        finally:
            conn.close()

        combined = " ".join(str(value) for value in (*raw_flow, *raw_conn, *raw_frame))
        self.assertNotIn("application/json", combined)
        self.assertNotIn('{"ok":true}', combined)
        self.assertNotIn("https://example.test", combined)
        self.assertNotIn('{"action":"ping"}', combined)

    def test_browser_artifacts_attack_runs_findings_and_notes(self):
        temp_dir, db, store = self.make_store()
        self.addCleanup(temp_dir.cleanup)

        project = db.save_project(name="engagement", target_url="https://target.test")
        identity = db.save_identity(project_id=project["id"], alias="operator", source="manual")

        artifact = store.add_browser_artifact(
            project_id=project["id"],
            identity_id=identity["id"],
            artifact_type="auth_flow_replayed",
            source="browser_replay",
            url="https://target.test/login",
            payload={"token": "abc"},
        )
        self.assertEqual(artifact["artifact_type"], "auth_flow_replayed")

        target = store.ensure_target(project["id"], "wss://target.test/ws", kind="websocket")
        run = store.start_attack_run(
            project_id=project["id"],
            attack_type="ws_replay",
            target_id=target["id"],
            identity_id=identity["id"],
            parameters={"payload": '{"action":"ping"}'},
        )
        self.assertEqual(run["attack_type"], "ws_replay")

        updated = store.update_attack_run(run["id"], status="completed", summary={"ok": True}, completed=True)
        self.assertEqual(updated["status"], "completed")
        self.assertTrue(updated["completed_at"])

        finding = store.add_finding(
            project_id=project["id"],
            attack_run_id=run["id"],
            title="Unauthorized replay accepted",
            category="authz",
            severity="high",
            description="Replay succeeded with elevated role",
            payload={"role": "admin"},
            related_target_id=target["id"],
        )
        self.assertEqual(finding["severity"], "high")

        note = store.save_note(project["id"], "operator note", "Need to verify stale token window")
        self.assertEqual(note["title"], "operator note")

        self.assertEqual(len(store.list_browser_artifacts(project["id"])), 1)
        self.assertEqual(len(store.list_attack_runs(project["id"])), 1)
        self.assertEqual(len(store.list_findings(project["id"])), 1)
        self.assertEqual(len(store.list_notes(project["id"])), 1)

        conn = sqlite3.connect(db.db_path)
        try:
            raw_artifact = conn.execute(
                "SELECT payload_json FROM browser_artifacts WHERE id = ?",
                (artifact["id"],),
            ).fetchone()
            raw_run = conn.execute(
                "SELECT parameters_json, summary_json FROM attack_runs WHERE id = ?",
                (run["id"],),
            ).fetchone()
            raw_finding = conn.execute(
                "SELECT description, payload_json FROM findings WHERE id = ?",
                (finding["id"],),
            ).fetchone()
            raw_note = conn.execute(
                "SELECT body FROM notes WHERE id = ?",
                (note["id"],),
            ).fetchone()
        finally:
            conn.close()

        combined = " ".join(str(value) for value in (*raw_artifact, *raw_run, *raw_finding, raw_note[0]))
        self.assertNotIn('"token": "abc"', combined)
        self.assertNotIn('{"action":"ping"}', combined)
        self.assertNotIn("Replay succeeded with elevated role", combined)
        self.assertNotIn("Need to verify stale token window", combined)


if __name__ == "__main__":
    unittest.main()
