import asyncio
import json
import unittest
from urllib.parse import urlsplit

from validation.full_stack_realtime_saas.app import app, INVOICES, _select_ws_subprotocol


async def asgi_request(
    app,
    method: str,
    path: str,
    *,
    headers=None,
    json_body=None,
    body: bytes = b"",
    client_host: str = "127.0.0.1",
):
    headers = headers or {}
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
        "client": (client_host, 12000),
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


class ValidationRealtimeSaaSTests(unittest.TestCase):
    def setUp(self):
        INVOICES["inv-alpha-1001"]["status"] = "open"
        INVOICES["inv-alpha-1001"]["refund_attempts"] = 0
        INVOICES["inv-alpha-1001"]["notes"] = ["Annual support renewal"]
        INVOICES["inv-beta-9001"]["status"] = "paid"
        INVOICES["inv-beta-9001"]["refund_attempts"] = 0
        INVOICES["inv-beta-9001"]["notes"] = ["Enterprise emergency retainer"]

    def test_api_login_sets_cookie_and_returns_tokens(self):
        status, headers, payload = asyncio.run(
            asgi_request(app, "POST", "/api/auth/login", json_body={"username": "alice", "password": "alice123"})
        )
        self.assertEqual(status, 200)
        self.assertIn("set-cookie", headers)
        data = json.loads(payload)
        self.assertEqual(data["tenant"], "tenant-alpha")
        self.assertTrue(data["bearer_token"])

    def test_browser_form_login_redirects_without_python_multipart(self):
        status, headers, _ = asyncio.run(
            asgi_request(
                app,
                "POST",
                "/login",
                headers={"content-type": "application/x-www-form-urlencoded"},
                body=b"username=alice&password=alice123",
            )
        )
        self.assertEqual(status, 302)
        self.assertEqual(headers["location"], "/dashboard")
        self.assertIn("set-cookie", headers)

    def test_preview_endpoint_leaks_foreign_invoice_token(self):
        _, _, login_payload = asyncio.run(
            asgi_request(app, "POST", "/api/auth/login", json_body={"username": "alice", "password": "alice123"})
        )
        bearer = json.loads(login_payload)["bearer_token"]
        status, _, payload = asyncio.run(
            asgi_request(
                app,
                "GET",
                "/api/invoices/inv-beta-9001?preview=true",
                headers={"Authorization": f"Bearer {bearer}"},
            )
        )
        self.assertEqual(status, 200)
        data = json.loads(payload)
        self.assertEqual(data["tenant"], "tenant-beta")
        self.assertEqual(data["approval_token"], "approve-beta-9001")

    def test_stale_bearer_token_survives_logout(self):
        _, headers, payload = asyncio.run(
            asgi_request(app, "POST", "/api/auth/login", json_body={"username": "alice", "password": "alice123"})
        )
        data = json.loads(payload)
        cookie = headers["set-cookie"].split(";", 1)[0]

        asyncio.run(
            asgi_request(
                app,
                "POST",
                "/api/auth/logout",
                headers={"Cookie": cookie, "Authorization": f"Bearer {data['bearer_token']}"},
                json_body={},
            )
        )

        status, _, profile_payload = asyncio.run(
            asgi_request(
                app,
                "GET",
                "/api/profile",
                headers={"Authorization": f"Bearer {data['bearer_token']}"},
            )
        )
        self.assertEqual(status, 200)
        profile = json.loads(profile_payload)
        self.assertEqual(profile["username"], "alice")
        self.assertEqual(profile["auth_type"], "bearer")

    def test_open_redirect_stays_enabled(self):
        status, headers, _ = asyncio.run(
            asgi_request(app, "GET", "/api/public/redirect?next=https://evil.example")
        )
        self.assertEqual(status, 302)
        self.assertEqual(headers["location"], "https://evil.example")

    def test_ws_subprotocol_selection_accepts_optional_clients(self):
        self.assertEqual(_select_ws_subprotocol(["wshawk-validation-v1"]), "wshawk-validation-v1")
        self.assertIsNone(_select_ws_subprotocol([]))
        self.assertIsNone(_select_ws_subprotocol(None))
