import json
from typing import Literal
from fastapi import APIRouter, HTTPException, Response, Depends
from .routes_auth import current_user
from .routes_analysis import get_job
from ..core.report_builder import html_report, pdf_report

router = APIRouter()


@router.get('/report/{job_id}/export')
def export(job_id: str, format: Literal['json', 'html', 'pdf'] = 'json', user=Depends(current_user)):
    job = get_job(job_id, user)
    if job.status != 'done':
        raise HTTPException(409, 'Analysis has not completed.')
    builders = {'json': (lambda r: json.dumps(r, indent=2), 'application/json'),
                'html': (html_report, 'text/html'), 'pdf': (pdf_report, 'application/pdf')}
    build, mime = builders[format]
    return Response(build(job.report), media_type=mime, headers={'Content-Disposition': f'attachment; filename="securemailscope-{job.id}.{format}"'})
