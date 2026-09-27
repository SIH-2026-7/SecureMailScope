from contextlib import asynccontextmanager
import os
import secrets
import base64
from fastapi import FastAPI
from fastapi.responses import Response
from fastapi.staticfiles import StaticFiles
from sqlalchemy import text
from .models.db_models import Base, engine, DB, Job
from .api import routes_upload, routes_analysis, routes_report, routes_auth


@asynccontextmanager
async def lifespan(app):
    if routes_auth.required():
        for key in ('SUPABASE_URL', 'SUPABASE_ANON_KEY', 'APP_URL'):
            if not os.environ.get(key):
                raise RuntimeError(f'{key} is required for Google sign-in.')
        if not os.environ['APP_URL'].startswith('https://'):
            raise RuntimeError('APP_URL must use HTTPS for secure sign-in cookies.')
    Base.metadata.create_all(engine)
    if engine.dialect.name == 'postgresql':
        with engine.begin() as connection:
            for table in Base.metadata.sorted_tables:
                connection.execute(text(f'ALTER TABLE "{table.name}" ENABLE ROW LEVEL SECURITY'))
    with DB.begin() as db:
        for job in db.query(Job).filter_by(status='processing'):
            job.status, job.error = 'error', 'Analysis interrupted by service restart; upload the capture again.'
    yield


app = FastAPI(title='SecureMailScope', version='2.0.0', lifespan=lifespan)


@app.middleware('http')
async def demo_access(request, call_next):
    password = os.environ.get('DEMO_PASSWORD')
    if password and not routes_auth.required() and request.url.path != '/api/health':
        expected = 'Basic ' + base64.b64encode(
            (os.environ.get('DEMO_USERNAME', 'demo') + ':' + password).encode()).decode()
        if not secrets.compare_digest(request.headers.get('authorization', '').encode(), expected.encode()):
            return Response(status_code=401, headers={'WWW-Authenticate': 'Basic realm="SecureMailScope"'})
    response = await call_next(request)
    if request.url.path.startswith('/api/'):
        response.headers['Cache-Control'] = 'no-store'
        response.headers['Referrer-Policy'] = 'no-referrer'
    return response
for router in (routes_auth.router, routes_upload.router, routes_analysis.router, routes_report.router):
    app.include_router(router, prefix='/api')


@app.get('/api/health')
def health():
    return {'status': 'ok', 'mode': 'offline', 'extractor': 'Scapy'}


if os.environ.get('STATIC_DIR'):
    app.mount('/', StaticFiles(directory=os.environ['STATIC_DIR'], html=True), name='frontend')
