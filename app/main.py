from contextlib import asynccontextmanager

from fastapi import FastAPI
from fastapi.staticfiles import StaticFiles
from starlette.middleware.sessions import SessionMiddleware

from app.database import init_db
from app.database import engine
from app.routers import api, sub, ui, updates
from app.routers.pings import router as pings_router
from app.routers.pings import take_report
from app.scheduler import start_scheduler
from app.bootstrap import seed_if_empty
from app.routers.sub import serve_sub
from app.settings import ROOT, session_signing_key, settings
from app.sub_link import init_sub_path
from sqlmodel import Session


@asynccontextmanager
async def lifespan(_app: FastAPI):
    init_db()
    from app.ssh_access import ensure_fleet_key

    ensure_fleet_key()
    with Session(engine) as session:
        seed_if_empty(session)
        from app.provision import ensure_default_node_templates

        ensure_default_node_templates(session)
        path = init_sub_path(session)
    from app.routers.sub import serve_provider_yaml

    report_path = f'/{path}/{{token}}/report'
    mounted = {getattr(route, 'path', '') for route in _app.routes}
    if report_path not in mounted:
        _app.add_api_route(
            report_path,
            take_report,
            methods=['POST'],
            name=f'secret_report_{path}',
        )

    _app.add_api_route(
        f'/{path}/{{token}}/prov/{{key}}.yaml',
        serve_provider_yaml,
        methods=['GET', 'HEAD'],
        name='secret_provider',
    )
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
app.include_router(updates.router)
app.include_router(pings_router)


def run() -> None:
    import uvicorn

    uvicorn.run('app.main:app', host=settings.host, port=settings.port, reload=False)


if __name__ == '__main__':
    run()
