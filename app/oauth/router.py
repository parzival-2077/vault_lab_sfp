from fastapi import APIRouter, Form, Request, Depends
from sqlalchemy.orm import Session

from app.db.session import get_db
from app.oauth.helpers import authenticate_client, oauth_error
from app.oauth.grants import (
    password as g_password,
    authorization_code as g_code,
    refresh_token as g_refresh,
    client_credentials as g_cc
)


router = APIRouter(tags=["OAuth2 / Token"])


@router.post("/oauth/token")
def token(
    request: Request,
    grant_type: str = Form(...),
    client_id: str = Form(...),
    client_secret: str | None = Form(None),
    # password
    username: str | None = Form(None),
    password: str | None = Form(None),
    # code
    code: str | None = Form(None),
    redirect_uri: str | None = Form(None),
    code_verifier: str | None = Form(None),
    # refresh
    refresh_token: str | None = Form(None),
    # common
    scope: str = Form(""),
    db: Session = Depends(get_db)
):
    client = authenticate_client(db, client_id, client_secret)

    if grant_type == "password":
        return g_password.handle(db, client, username, password, scope, request)
    if grant_type == "authorization_code":
        return g_code.handle(db, client, code, redirect_uri, code_verifier, request)
    if grant_type == "refresh_token":
        return g_refresh.handle(db, client, refresh_token, scope or None, request)
    if grant_type == "client_credentials":
        return g_cc.handle(db, client, scope, request)

    oauth_error("unsupported_grant_type")