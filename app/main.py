from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.database import init_db
from app.database import engine
from app.routers import api, sub, ui
from app.scheduler import start_scheduler
from app.bootstrap import seed_if_empty
from app.routers.sub import serve_sub
from app.settings import ROOT, session_signing_key, settings
from app.sub_link import init_sub_path
from sqlmodel import Session


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    with Session(engine) as session:
        seed_if_empty(session)
        path = init_sub_path(session)
    _app.add_api_route(
        f'/{path}/{{token}}',
        serve_sub,
        methods=['GET', 'HEAD'],
        name='secret_sub',
    )
    start_scheduler()
    yield


app = FastAPI(title='XUI Master', lifespan=lifespan)
app.add_middleware(
    SessionMiddleware,
    secret_key=session_signing_key(),
    session_cookie='master_session',
    max_age=60 * 60 * 24 * 14,
    same_site='lax',
    https_only=False,
    path='/',
)
app.mount('/static', StaticFiles(directory=str(ROOT / 'app' / 'static')), name='static')
app.include_router(api.router)
app.include_router(ui.router)
app.include_router(sub.router)


def run() -> None:
    import uvicorn

    uvicorn.run('app.main:app', host=settings.host, port=settings.port, reload=False)


if __name__ == '__main__':
    run()
