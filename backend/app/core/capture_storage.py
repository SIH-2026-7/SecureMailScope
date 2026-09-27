"""Optional private Supabase capture storage; credentials stay on the server."""
import os
from urllib.parse import quote
import httpx


def enabled():
    return bool(os.environ.get('SUPABASE_URL'))


def request(method, endpoint, **kwargs):
    key = os.environ['SUPABASE_SERVICE_ROLE_KEY']
    headers = {'apikey': key, 'Authorization': f'Bearer {key}'}
    headers.update(kwargs.pop('headers', {}))
    response = httpx.request(
        method, os.environ['SUPABASE_URL'].rstrip('/') + '/storage/v1/' + endpoint,
        headers=headers, timeout=120, **kwargs)
    response.raise_for_status()
    return response


def object_path(job_id):
    bucket = quote(os.environ.get('SUPABASE_STORAGE_BUCKET', 'captures'), safe='')
    return f'{bucket}/{quote(job_id, safe="")}.capture'


def upload(job_id, path):
    with path.open('rb') as content:
        request('POST', 'object/' + object_path(job_id), content=content,
                headers={'Content-Type': 'application/octet-stream'})


def download_url(job_id, filename):
    response = request('POST', 'object/sign/' + object_path(job_id), json={'expiresIn': 60})
    signed = response.json()['signedURL']
    # The Storage API returns a path relative to /storage/v1.
    return (os.environ['SUPABASE_URL'].rstrip('/') + '/storage/v1' + signed
            + '&download=' + quote(filename, safe=''))
