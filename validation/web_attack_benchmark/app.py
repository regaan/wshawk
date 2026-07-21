from __future__ import annotations

import asyncio
from typing import Any

from fastapi import FastAPI, HTTPException, Request
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import HTMLResponse, JSONResponse, PlainTextResponse, RedirectResponse


app = FastAPI(title="WSHawk Web Attack Benchmark")
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

RACE_STATE = {"attempts": 0}
TRANSFER_STATE = {"attempts": 0}


def reset_state() -> None:
    RACE_STATE["attempts"] = 0
    TRANSFER_STATE["attempts"] = 0


def _authorization(request: Request) -> str:
    return request.headers.get("Authorization", "").strip()


@app.get("/", response_class=HTMLResponse)
async def index():
    return HTMLResponse(
        """
        <!doctype html>
        <html>
          <head>
            <meta name="generator" content="WordPress 6.0">
            <script src="/static/jquery.min.js"></script>
          </head>
          <body>
            <a href="/admin">Admin</a>
            <a href="/api/search?q=hello">Search</a>
            <a href="/redirect?next=/">Continue</a>
            <form method="post" action="/transfer">
              <input name="amount" value="10">
            </form>
          </body>
        </html>
        """,
        headers={"X-Powered-By": "Express"},
    )


@app.get("/static/jquery.min.js")
async def jquery_asset():
    return PlainTextResponse("window.jQuery={version:'3.7.1'};", media_type="application/javascript")


@app.get("/robots.txt")
async def robots():
    return PlainTextResponse("User-agent: *\nDisallow: /admin\nDisallow: /.env\n")


@app.get("/sitemap.xml")
async def sitemap(request: Request):
    base = str(request.base_url).rstrip("/")
    return PlainTextResponse(
        f'<urlset><url><loc>{base}/admin</loc></url><url><loc>{base}/api/search?q=hello</loc></url></urlset>',
        media_type="application/xml",
    )


@app.get("/.env")
async def environment_file():
    return PlainTextResponse(
        "DATABASE_URL=postgres://benchmark:benchmark@10.20.30.40/wshawk\n"
        "CONTACT=security-benchmark@example.test\n"
    )


@app.get("/admin")
async def admin_page():
    return HTMLResponse("<h1>Benchmark administration</h1>")


@app.get("/api/search")
async def search(q: str = ""):
    return HTMLResponse(f"<p>Search result: {q}</p>")


@app.get("/api/private")
async def private_data(request: Request):
    if _authorization(request) != "Bearer benchmark-user":
        raise HTTPException(status_code=401, detail="Authentication required")
    return PlainTextResponse(
        "AWS_ACCESS_KEY=AKIAABCDEFGHIJKLMNOP\n"
        "internal_service=10.20.30.40\n"
        "owner=security-benchmark@example.test\n"
    )


@app.get("/api/identity")
async def identity(request: Request):
    authorization = _authorization(request)
    if authorization == "Bearer benchmark-admin":
        return {"ok": True, "role": "admin", "scope": "all"}
    if authorization == "Bearer benchmark-user":
        return JSONResponse({"ok": False, "error": "forbidden", "role": "user"}, status_code=403)
    raise HTTPException(status_code=401, detail="Authentication required")


@app.post("/api/race")
async def race_action():
    await asyncio.sleep(0.03)
    RACE_STATE["attempts"] += 1
    return {"ok": True, "attempt": RACE_STATE["attempts"], "duplicate": RACE_STATE["attempts"] > 1}


@app.get("/redirect")
async def redirect(next: str = "/"):
    return RedirectResponse(next, status_code=302)


@app.get("/fetch")
async def fetch(request: Request, url: str):
    if _authorization(request) != "Bearer benchmark-user":
        raise HTTPException(status_code=401, detail="Authentication required")
    if "169.254.169.254" in url:
        return PlainTextResponse(
            "ami-id\ninstance-id\niam/security-credentials/benchmark-role\nAccessKeyId\nSecretAccessKey"
        )
    return JSONResponse({"ok": True, "result": "external fetch completed"})


@app.get("/large-static")
async def large_static(url: str):
    return PlainTextResponse("A" * 800)


@app.api_route("/merge", methods=["GET", "POST"])
async def merge(request: Request):
    polluted_query = any(
        "__proto__" in key or "constructor" in key
        for key in request.query_params.keys()
    )
    polluted_json = False
    if request.method == "POST":
        try:
            payload: Any = await request.json()
            serialized = str(payload)
            polluted_json = "__proto__" in serialized or "constructor" in serialized
        except Exception:
            polluted_json = False
    if polluted_query or polluted_json:
        return {"polluted": "wshawk_pp_test", "isAdmin": True}
    return {"ok": True}


@app.post("/transfer")
async def transfer(request: Request):
    await request.body()
    TRANSFER_STATE["attempts"] += 1
    return {"ok": True, "transfer_attempt": TRANSFER_STATE["attempts"]}


@app.get("/waf")
async def waf(request: Request):
    if request.query_params:
        return PlainTextResponse(
            "ModSecurity: 406 Not Acceptable",
            status_code=406,
            headers={"Server": "mod_security"},
        )
    return PlainTextResponse("Normal benchmark response")
