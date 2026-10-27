from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.db.session import SessionLocal
from app.auth.router import router as auth_router
from app.graphql.schema import graphql_app

# OAuth2 / OIDC
from app.oauth.jwks import router as jwks_router
from app.oauth.discovery import router as discovery_router
from app.oauth.authorize import router as authorize_router
from app.oauth.userinfo import router as userinfo_router
from app.oauth.revoke import router as revoke_router
from app.oauth.introspect import router as introspect_router
from app.oauth.router import router as token_router


app = FastAPI(title=settings.app_name)


@app.middleware("http")
async def database_middleware(request: Request, call_next):
    db = SessionLocal()
    request.state.db = db
    try:
        response = await call_next(request)
        return response
    finally:
        db.close()


@app.get("/")
def home():
    return {"message": "Vault API is running"}


# REST auth
app.include_router(auth_router)

# OAuth2 / OIDC
app.include_router(jwks_router)
app.include_router(discovery_router)
app.include_router(authorize_router)
app.include_router(token_router)
app.include_router(userinfo_router)
app.include_router(revoke_router)
app.include_router(introspect_router)

# GraphQL
app.mount("/graphql", graphql_app)

# Admin SPA
app.mount(
    "/admin",
    StaticFiles(directory="app/static", html=True),
    name="admin"
)