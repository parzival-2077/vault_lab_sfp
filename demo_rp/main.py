import base64
import hashlib
import secrets
import os

import httpx
from jose import jwt, jwk
from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import HTMLResponse, RedirectResponse
from jinja2 import Template


VAULT = os.getenv("VAULT_ISSUER", "http://127.0.0.1:8000")
CLIENT_ID = os.getenv("VAULT_CLIENT_ID", "dab83dc7-e726-4a93-849e-e150746f4629")
REDIRECT = os.getenv("VAULT_REDIRECT", "http://127.0.0.1:8001/callback")
SCOPES = "openid profile email"

app = FastAPI()

_jwks_cache = None


def b64url(b: bytes) -> str:
    return base64.urlsafe_b64encode(b).rstrip(b"=").decode()


def get_jwks() -> dict:
    global _jwks_cache
    if _jwks_cache is None:
        r = httpx.get(f"{VAULT}/.well-known/jwks.json")
        r.raise_for_status()
        _jwks_cache = r.json()
    return _jwks_cache


def verify_id_token(id_token: str, nonce: str | None):
    header = jwt.get_unverified_header(id_token)
    jwks = get_jwks()
    key = next(
        (k for k in jwks["keys"] if k["kid"] == header["kid"]),
        None,
    )
    if key is None:
        raise HTTPException(400, "Unknown kid in id_token")

    public_key = jwk.construct(key, algorithm="RS256").to_pem()
    payload = jwt.decode(
        id_token,
        public_key,
        algorithms=["RS256"],
        audience=CLIENT_ID,
        issuer=VAULT,
        options={"verify_aud": True},
    )
    if nonce and payload.get("nonce") != nonce:
        raise HTTPException(400, "nonce mismatch")
    return payload


HOME = Template("""
<!doctype html>
<html><head><meta charset="utf-8"><title>Demo RP</title>
<style>
body{font-family:sans-serif;max-width:640px;margin:40px auto;padding:0 16px}
a.btn,button{display:inline-block;padding:10px 16px;background:#2563eb;color:#fff;border:none;border-radius:6px;text-decoration:none;cursor:pointer}
pre{background:#f3f4f6;padding:12px;border-radius:6px;overflow:auto}
.err{background:#fee2e2;border:1px solid #fca5a5;padding:12px;border-radius:6px}
</style></head>
<body>
<h1>Demo RP</h1>
{% if email %}
  <p>Привет, <b>{{ email }}</b></p>
  {% if sub %}<p>sub: <code>{{ sub }}</code></p>{% endif %}
  <form method="post" action="/logout"><button>Выйти</button></form>
{% else %}
  <p>Это демо-клиент OIDC. Нажмите кнопку — Vault выдаст access/id/refresh токены.</p>
  <a class="btn" href="/login">Войти через Vault</a>
{% endif %}
</body></html>
""")


ERROR_PAGE = Template("""
<!doctype html>
<html><head><meta charset="utf-8"><title>Demo RP — ошибка</title>
<style>
body{font-family:sans-serif;max-width:720px;margin:40px auto;padding:0 16px}
pre{background:#f3f4f6;padding:12px;border-radius:6px;overflow:auto;white-space:pre-wrap}
.err{background:#fee2e2;border:1px solid #fca5a5;padding:12px;border-radius:6px}
a{color:#2563eb}
</style></head>
<body>
<h1>Ошибка авторизации</h1>
<div class="err">
  <p><b>error:</b> {{ error }}</p>
  {% if description %}<p><b>error_description:</b> {{ description }}</p>{% endif %}
  {% if hint %}<p><b>Подсказка:</b> {{ hint }}</p>{% endif %}
</div>
{% if detail %}<h3>Детали</h3><pre>{{ detail }}</pre>{% endif %}
<p><a href="/">← На главную</a></p>
</body></html>
""")


def _error_page(error, description=None, hint=None, detail=None, status=400):
    return HTMLResponse(
        ERROR_PAGE.render(
            error=error, description=description,
            hint=hint, detail=detail,
        ),
        status_code=status,
    )


@app.get("/", response_class=HTMLResponse)
async def home(request: Request):
    return HOME.render(
        email=request.cookies.get("email"),
        sub=request.cookies.get("sub"),
    )


@app.get("/login")
async def login():
    if CLIENT_ID == "REPLACE_WITH_CLIENT_ID":
        return _error_page(
            "configuration_error",
            "CLIENT_ID не задан в demo_rp/main.py",
            hint=(
                "Создайте публичного клиента через GraphQL createClient "
                "с redirectUris=[\"http://127.0.0.1:8001/callback\"] и "
                "вставьте его clientId в CLIENT_ID."
            ),
            status=500,
        )

    state = secrets.token_urlsafe(24)
    verifier = secrets.token_urlsafe(64)[:64]
    challenge = b64url(hashlib.sha256(verifier.encode()).digest())
    nonce = secrets.token_urlsafe(24)

    url = (
        f"{VAULT}/oauth/authorize?response_type=code"
        f"&client_id={CLIENT_ID}"
        f"&redirect_uri={REDIRECT}"
        f"&scope={SCOPES.replace(' ', '%20')}"
        f"&state={state}"
        f"&nonce={nonce}"
        f"&code_challenge={challenge}"
        f"&code_challenge_method=S256"
    )
    resp = RedirectResponse(url)
    resp.set_cookie("state", state, httponly=True, max_age=300, samesite="lax")
    resp.set_cookie("verifier", verifier, httponly=True, max_age=300, samesite="lax")
    resp.set_cookie("nonce", nonce, httponly=True, max_age=300, samesite="lax")
    return resp


@app.get("/callback")
async def callback(
    request: Request,
    code: str | None = None,
    state: str | None = None,
    error: str | None = None,
    error_description: str | None = None,
):
    # 1) Vault вернул ошибку
    if error:
        hint_map = {
            "invalid_client": (
                "Vault не знает такого client_id. Проверьте CLIENT_ID в "
                "demo_rp/main.py — он должен совпадать с clientId из "
                "GraphQL createClient. Если клиент отключён — enableClient."
            ),
            "access_denied": (
                "В ЛБ3 /oauth/authorize требует Authorization: Bearer. "
                "Браузер его не шлёт — это ограничение задания. "
                "Для демо используйте Swagger-флоу или dev-режим в authorize.py."
            ),
            "invalid_request": (
                "Проверьте redirect_uri, PKCE (code_challenge_method=S256), scope. "
                "Точные значения см. в error_description."
            ),
            "invalid_scope": (
                "Запрошенный scope не входит в client.scopes. "
                "Проверьте scopes клиента в GraphQL."
            ),
            "unsupported_response_type": (
                "response_type должен быть code."
            ),
        }
        return _error_page(
            error, error_description,
            hint=hint_map.get(error),
            detail=f"state={state}",
        )

    # 2) Нет code/state
    if not code or not state:
        return _error_page(
            "missing_parameters",
            "Vault не передал code или state",
            detail=f"query={dict(request.query_params)}",
        )

    # 3) state mismatch
    if state != request.cookies.get("state"):
        return _error_page(
            "state_mismatch",
            "state в callback не совпадает с cookie",
            hint="Откройте demo-RP в одном браузере, без блокировщиков cookie. "
                 "Cookie живут 5 минут — не тяните с логином.",
        )

    verifier = request.cookies.get("verifier")
    nonce = request.cookies.get("nonce")

    # 4) Обмен code → tokens
    async with httpx.AsyncClient(timeout=10.0) as client:
        try:
            r = await client.post(f"{VAULT}/oauth/token", data={
                "grant_type": "authorization_code",
                "client_id": CLIENT_ID,
                "code": code,
                "redirect_uri": REDIRECT,
                "code_verifier": verifier,
            })
        except httpx.HTTPError as e:
            return _error_page(
                "token_endpoint_unreachable",
                f"Не удалось достучаться до {VAULT}/oauth/token",
                detail=str(e),
            )

        if r.status_code != 200:
            return _error_page(
                "token_exchange_failed",
                f"HTTP {r.status_code}",
                detail=r.text,
            )

        tokens = r.json()

        # 5) Проверка id_token по JWKS
        try:
            id_claims = verify_id_token(tokens["id_token"], nonce)
        except HTTPException as e:
            return _error_page(
                "id_token_invalid",
                e.detail,
                detail=tokens["id_token"][:80] + "...",
            )

        # 6) userinfo
        ui = await client.get(
            f"{VAULT}/oauth/userinfo",
            headers={"Authorization": f"Bearer {tokens['access_token']}"},
        )
        if ui.status_code != 200:
            return _error_page(
                "userinfo_failed",
                f"HTTP {ui.status_code}",
                detail=ui.text,
            )

    payload = ui.json()
    email = payload.get("email", id_claims.get("email", "unknown"))
    sub = payload.get("sub", id_claims.get("sub"))

    resp = RedirectResponse("/")
    resp.set_cookie("access", tokens["access_token"], httponly=True, samesite="lax")
    if "refresh_token" in tokens:
        resp.set_cookie("refresh", tokens["refresh_token"], httponly=True, samesite="lax")
    resp.set_cookie("email", email, httponly=True, samesite="lax")
    resp.set_cookie("sub", sub or "", httponly=True, samesite="lax")
    resp.delete_cookie("state")
    resp.delete_cookie("verifier")
    resp.delete_cookie("nonce")
    return resp


@app.post("/logout")
async def logout(request: Request):
    refresh = request.cookies.get("refresh")
    if refresh:
        async with httpx.AsyncClient(timeout=10.0) as client:
            try:
                await client.post(f"{VAULT}/oauth/revoke", data={
                    "token": refresh,
                    "token_type_hint": "refresh_token",
                })
            except httpx.HTTPError:
                pass

    resp = RedirectResponse("/")
    for c in ("access", "refresh", "email", "sub", "state", "verifier", "nonce"):
        resp.delete_cookie(c)
    return resp