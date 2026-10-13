from fastapi import FastAPI, Request
from fastapi.staticfiles import StaticFiles

from app.config import settings
from app.db.session import SessionLocal
from app.auth.router import router
from app.graphql.schema import graphql_app


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


app.include_router(router)

app.mount("/graphql", graphql_app)

app.mount(
    "/admin",
    StaticFiles(directory="app/static", html=True),
    name="admin"
)