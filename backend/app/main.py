from contextlib import asynccontextmanager
from fastapi import FastAPI
from .models.db_models import Base, engine, DB, Job
from .api import routes_upload, routes_analysis, routes_report


@asynccontextmanager
async def lifespan(app):
    Base.metadata.create_all(engine)
    with DB.begin() as db:
        for job in db.query(Job).filter_by(status='processing'):
            job.status, job.error = 'error', 'Analysis interrupted by service restart; upload the capture again.'
    yield


app = FastAPI(title='SecureMailScope', version='2.0.0', lifespan=lifespan)
for router in (routes_upload.router, routes_analysis.router, routes_report.router):
    app.include_router(router, prefix='/api')


@app.get('/api/health')
def health():
    return {'status': 'ok', 'mode': 'offline', 'extractor': 'Scapy'}
