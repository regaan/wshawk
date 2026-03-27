import tempfile
import unittest
import sqlite3
from pathlib import Path

from wshawk.db_manager import WSHawkDatabase


def make_db(tmp_path: Path) -> WSHawkDatabase:
    return WSHawkDatabase(str(tmp_path / "platform.db"))


class DatabasePlatformTests(unittest.TestCase):
    def test_project_round_trip(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db = make_db(Path(temp_dir))

            project = db.save_project(
                name="alpha",
                target_url="wss://example.test/ws",
                metadata={"type": "session_snapshot", "data": {"target": "wss://example.test/ws"}},
            )

            self.assertEqual(project["name"], "alpha")
            self.assertEqual(project["target_url"], "wss://example.test/ws")
            self.assertEqual(project["metadata"]["data"]["target"], "wss://example.test/ws")

            updated = db.save_project(
                name="alpha",
                target_url="wss://example.test/v2",
                metadata={"type": "session_snapshot", "data": {"target": "wss://example.test/v2"}},
            )

            self.assertEqual(updated["id"], project["id"])
            self.assertEqual(updated["target_url"], "wss://example.test/v2")
            self.assertEqual(db.get_project_by_name("alpha")["id"], project["id"])
            self.assertEqual(len(db.list_projects()), 1)

    def test_identity_event_and_evidence_round_trip(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db = make_db(Path(temp_dir))
            project = db.save_project(name="engagement-1", target_url="https://target.test")

            identity = db.save_identity(
                project_id=project["id"],
                alias="admin-cookie",
                source="dom_replay",
                cookies=[{"name": "sid", "value": "abc"}],
                headers={"Authorization": "Bearer token"},
                tokens={"session_token": "token"},
                storage={"localStorage": {"tenant": "red"}},
            )

            self.assertEqual(identity["alias"], "admin-cookie")
            self.assertEqual(identity["cookies"][0]["name"], "sid")
            self.assertEqual(identity["tokens"]["session_token"], "token")
            self.assertEqual(db.get_identity_by_alias(project["id"], "admin-cookie")["id"], identity["id"])

            identities = db.list_identities(project["id"])
            self.assertEqual(len(identities), 1)

            event = db.add_event(
                project_id=project["id"],
                event_type="ws_proxy_frame",
                direction="out",
                connection_id="conn-1",
                target="wss://target.test/ws",
                payload={"message": '{"action":"subscribe"}'},
            )

            self.assertEqual(event["event_type"], "ws_proxy_frame")
            self.assertEqual(event["payload"]["message"], '{"action":"subscribe"}')

            evidence = db.add_evidence(
                project_id=project["id"],
                title="Unauthorized channel replay",
                category="authz",
                severity="high",
                payload={"channel": "admin"},
                related_event_id=event["id"],
            )

            self.assertEqual(evidence["title"], "Unauthorized channel replay")
            self.assertEqual(evidence["payload"]["channel"], "admin")
            self.assertEqual(db.list_events(project["id"])[0]["id"], event["id"])
            self.assertEqual(db.list_evidence(project["id"])[0]["id"], evidence["id"])

            conn = sqlite3.connect(db.db_path)
            try:
                raw_identity = conn.execute(
                    "SELECT cookies_json, headers_json, tokens_json, storage_json FROM identities WHERE id = ?",
                    (identity["id"],),
                ).fetchone()
                raw_event = conn.execute(
                    "SELECT payload_json FROM traffic_events WHERE id = ?",
                    (event["id"],),
                ).fetchone()
                raw_evidence = conn.execute(
                    "SELECT payload_json FROM evidence WHERE id = ?",
                    (evidence["id"],),
                ).fetchone()
            finally:
                conn.close()

            joined = " ".join(str(value) for value in (*raw_identity, raw_event[0], raw_evidence[0]))
            self.assertNotIn("Bearer token", joined)
            self.assertNotIn('"session_token": "token"', joined)
            self.assertNotIn('"channel": "admin"', joined)

    def test_scan_update_rejects_unknown_columns(self):
        with tempfile.TemporaryDirectory() as temp_dir:
            db = make_db(Path(temp_dir))
            scan_id = db.create("ws://localhost:8765")

            with self.assertRaises(ValueError):
                db.update(scan_id, totally_invalid_column="boom")


if __name__ == "__main__":
    unittest.main()
