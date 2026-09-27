from fastapi import APIRouter, HTTPException, Depends
from fastapi.responses import FileResponse, RedirectResponse
from datetime import timezone
from ..models.db_models import DB, DATA, Job, RemoteCapture, JobOwner
from .routes_auth import current_user
from ..core import capture_storage

router = APIRouter()


def get_job(job_id, user=None):
    with DB() as db:
        owner = db.get(JobOwner, job_id)
        if user and (owner is None or owner.user_id != user['id']):
            raise HTTPException(404, 'Analysis job not found.')
        job = db.get(Job, job_id)
        if job is None:
            raise HTTPException(404, 'Analysis job not found.')
        return job


@router.get('/analysis')
def history(user=Depends(current_user)):
    with DB() as db:
        remote_ids = {row.id for row in db.query(RemoteCapture.id).all()}
        query = db.query(Job.id, Job.filename, Job.status, Job.created_at)
        if user:
            query = query.join(JobOwner, JobOwner.id == Job.id).filter(JobOwner.user_id == user['id'])
        jobs = query.order_by(Job.created_at.desc(), Job.id.desc()).all()
        return {'analyses': [
            {'job_id': job.id, 'filename': job.filename, 'status': job.status,
             'created_at': job.created_at.replace(tzinfo=timezone.utc).isoformat(),
             'capture_available': (DATA / (job.id + '.capture')).is_file() or (capture_storage.enabled() and job.id in remote_ids)}
            for job in jobs
        ]}


@router.get('/analysis/{job_id}/capture')
def capture(job_id: str, user=Depends(current_user)):
    job = get_job(job_id, user)
    path = DATA / (job.id + '.capture')
    with DB() as db:
        remote = db.get(RemoteCapture, job.id) is not None
    if remote and capture_storage.enabled():
        try:
            return RedirectResponse(capture_storage.download_url(job.id, job.filename), status_code=307)
        except Exception:
            raise HTTPException(503, 'Capture storage unavailable. Please retry.') from None
    if not path.is_file():
        raise HTTPException(404, 'Original capture is unavailable for this older analysis.')
    return FileResponse(path, filename=job.filename, media_type='application/octet-stream')


@router.get('/analysis/{job_id}')
def analysis(job_id: str, user=Depends(current_user)):
    job = get_job(job_id, user)
    return {'status': job.status, 'report': job.report, 'error': job.error}
