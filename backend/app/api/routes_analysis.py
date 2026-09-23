from fastapi import APIRouter, HTTPException
from ..models.db_models import DB, Job

router = APIRouter()


def get_job(job_id):
    with DB() as db:
        job = db.get(Job, job_id)
        if job is None:
            raise HTTPException(404, 'Analysis job not found.')
        return job


@router.get('/analysis/{job_id}')
def analysis(job_id: str):
    job = get_job(job_id)
    return {'status': job.status, 'report': job.report, 'error': job.error}
