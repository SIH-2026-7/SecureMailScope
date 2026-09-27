from fastapi import APIRouter, HTTPException
from fastapi.responses import FileResponse
from datetime import timezone
from ..models.db_models import DB, DATA, Job

router = APIRouter()


def get_job(job_id):
    with DB() as db:
        job = db.get(Job, job_id)
        if job is None:
            raise HTTPException(404, 'Analysis job not found.')
        return job


@router.get('/analysis')
def history():
    with DB() as db:
        jobs = db.query(Job.id, Job.filename, Job.status, Job.created_at).order_by(Job.created_at.desc(), Job.id.desc()).all()
        return {'analyses': [
            {'job_id': job.id, 'filename': job.filename, 'status': job.status,
             'created_at': job.created_at.replace(tzinfo=timezone.utc).isoformat(),
             'capture_available': (DATA / (job.id + '.capture')).is_file()}
            for job in jobs
        ]}


@router.get('/analysis/{job_id}/capture')
def capture(job_id: str):
    job = get_job(job_id)
    path = DATA / (job.id + '.capture')
    if not path.is_file():
        raise HTTPException(404, 'Original capture is unavailable for this older analysis.')
    return FileResponse(path, filename=job.filename, media_type='application/octet-stream')


@router.get('/analysis/{job_id}')
def analysis(job_id: str):
    job = get_job(job_id)
    return {'status': job.status, 'report': job.report, 'error': job.error}
