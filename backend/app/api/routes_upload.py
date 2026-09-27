import os
import uuid
import asyncio
from pathlib import Path
from fastapi import APIRouter, BackgroundTasks, UploadFile, File, HTTPException, Depends
from ..models.db_models import DB, DATA, Job, RemoteCapture, JobOwner
from .routes_auth import current_user
from ..core import capture_storage
from ..core.integrity import MAX_BYTES, validate
from ..core.pipeline import run_analysis

router = APIRouter()


def analyze(job_id, path, filename):
    try:
        report = run_analysis(path, job_id, filename).model_dump(mode='json')
        with DB.begin() as db:
            job = db.get(Job, job_id)
            job.report, job.status = report, 'done'
    except Exception:
        # Never log packet data or parser exceptions that could contain credentials.
        with DB.begin() as db:
            job = db.get(Job, job_id)
            job.status, job.error = 'error', 'Analysis failed: malformed, unsupported, or incomplete capture.'
    finally:
        if capture_storage.enabled():
            path.unlink(missing_ok=True)


@router.post('/upload', status_code=202)
async def upload(background_tasks: BackgroundTasks, file: UploadFile = File(...), user=Depends(current_user)):
    filename = Path((file.filename or 'capture.pcap').replace('\\', '/')).name
    if Path(filename).suffix.lower() not in ('.pcap', '.pcapng'):
        raise HTTPException(400, 'Choose a .pcap or .pcapng file.')
    job_id = str(uuid.uuid4())
    path = DATA / (job_id + '.capture')
    total = 0
    try:
        with path.open('wb') as handle:
            while chunk := await file.read(1024 * 1024):
                total += len(chunk)
                if total > MAX_BYTES:
                    raise HTTPException(413, 'Capture exceeds the 50 MB limit.')
                handle.write(chunk)
        validate(path)
        if capture_storage.enabled():
            try:
                await asyncio.to_thread(capture_storage.upload, job_id, path)
            except Exception:
                raise HTTPException(503, 'Capture storage unavailable. Please retry.') from None
        with DB.begin() as db:
            db.add(Job(id=job_id, status='processing', filename=filename))
            if user:
                db.add(JobOwner(id=job_id, user_id=user['id']))
            if capture_storage.enabled():
                db.add(RemoteCapture(id=job_id))
    except ValueError as exc:
        path.unlink(missing_ok=True)
        raise HTTPException(400, str(exc)) from exc
    except Exception:
        path.unlink(missing_ok=True)
        raise
    finally:
        await file.close()
    background_tasks.add_task(analyze, job_id, path, filename)
    return {'job_id': job_id, 'status': 'processing'}
