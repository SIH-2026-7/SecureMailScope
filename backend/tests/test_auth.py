import time
import uuid
from urllib.parse import urlparse, parse_qs
import httpx
import pytest
from fastapi.testclient import TestClient
from scapy.all import wrpcap
from generate_traffic import generate
from app.main import app
from app.models.db_models import DB, Job, JobOwner, UserSession
from app.api import routes_auth
from app.core import capture_storage


@pytest.fixture
def hosted(monkeypatch):
    monkeypatch.setenv('AUTH_REQUIRED', 'true')
    monkeypatch.setenv('APP_URL', 'https://testserver')
    monkeypatch.setenv('SUPABASE_URL', 'https://example.supabase.co')
    monkeypatch.setenv('SUPABASE_ANON_KEY', 'test-anon')
    monkeypatch.setattr(capture_storage, 'enabled', lambda: False)
    with TestClient(app, base_url='https://testserver') as client:
        yield client


def sign_in(client, user, expires=None):
    token = str(uuid.uuid4())
    with DB.begin() as db:
        db.add(UserSession(id=routes_auth.fingerprint(token), user_id=user,
                           email=user + '@example.test', expires=expires or time.time() + 3600))
    client.cookies.set(routes_auth.SESSION, token)
    return token


def test_isolation_for_history_capture_and_every_export(hosted, tmp_path):
    client = hosted
    path = tmp_path / 'capture.pcap'
    wrpcap(str(path), generate('cleartext_auth'))
    sign_in(client, 'alice')
    result = client.post('/api/upload', files={'file': ('capture.pcap', path.read_bytes())},
                         headers={'Origin': 'https://testserver'})
    assert result.status_code == 202
    job = result.json()['job_id']
    with DB() as db:
        assert db.get(JobOwner, job).user_id == 'alice'
    urls = [f'/api/analysis/{job}', f'/api/analysis/{job}/capture'] + [
        f'/api/report/{job}/export?format={fmt}' for fmt in ('json', 'html', 'pdf')]
    assert all(client.get(url).status_code == 200 for url in urls)
    assert job in [x['job_id'] for x in client.get('/api/analysis').json()['analyses']]
    sign_in(client, 'bob')
    assert all(client.get(url).status_code == 404 for url in urls)
    assert job not in [x['job_id'] for x in client.get('/api/analysis').json()['analyses']]
    client.cookies.clear()
    assert all(client.get(url).status_code == 401 for url in urls)
    assert client.get('/api/analysis').status_code == 401
    assert client.post('/api/upload', files={'file': ('capture.pcap', path.read_bytes())},
                       headers={'Origin': 'https://testserver'}).status_code == 401


def test_legacy_data_hidden_and_expiry_logout_csrf(hosted):
    client = hosted
    legacy = str(uuid.uuid4())
    with DB.begin() as db:
        db.add(Job(id=legacy, filename='old.pcap', status='error'))
    token = sign_in(client, 'alice')
    assert client.get(f'/api/analysis/{legacy}').status_code == 404
    assert client.post('/api/auth/logout', headers={'Origin': 'https://evil.test'}).status_code == 403
    assert client.get('/api/auth/me').json()['user']['id'] == 'alice'
    assert client.post('/api/auth/logout', headers={'Origin': 'https://testserver'}).status_code == 200
    client.cookies.set(routes_auth.SESSION, token)
    assert client.get('/api/analysis').status_code == 401
    sign_in(client, 'alice', expires=time.time() - 1)
    assert client.get('/api/analysis').status_code == 401
    assert client.get('/api/health').status_code == 200


def test_pkce_browser_binding_and_callback(hosted, monkeypatch):
    client = hosted
    assert client.get('/api/auth/callback?code=unbound', follow_redirects=False).headers['location'] == '/?auth_error=1'
    login = client.get('/api/auth/login', follow_redirects=False)
    query = parse_qs(urlparse(login.headers['location']).query)
    assert query['provider'] == ['google']
    assert query['code_challenge_method'] == ['s256']
    assert query['redirect_to'] == ['https://testserver/api/auth/callback']
    assert 'HttpOnly' in login.headers['set-cookie'] and 'Secure' in login.headers['set-cookie']

    class AuthClient:
        async def __aenter__(self): return self
        async def __aexit__(self, *args): pass
        async def post(self, url, **kwargs):
            import base64
            import hashlib
            verifier = kwargs['json']['code_verifier']
            challenge = base64.urlsafe_b64encode(hashlib.sha256(verifier.encode()).digest()).decode().rstrip('=')
            assert query['code_challenge'] == [challenge]
            assert kwargs['json']['auth_code'] == 'valid-code'
            return httpx.Response(200, json={'access_token': 'verified-token'}, request=httpx.Request('POST', url))
        async def get(self, url, **kwargs):
            assert kwargs['headers']['Authorization'] == 'Bearer verified-token'
            return httpx.Response(200, json={'id': 'alice', 'email': 'alice@example.test',
                'email_confirmed_at': '2026-09-27', 'identities': [{'provider': 'google'}]}, request=httpx.Request('GET', url))
    monkeypatch.setattr(routes_auth.httpx, 'AsyncClient', lambda **kwargs: AuthClient())
    response = client.get('/api/auth/callback?code=valid-code', follow_redirects=False)
    assert response.headers['location'] == '/#workspace'
    assert response.headers['cache-control'] == 'no-store'
    assert client.get('/api/auth/me').json()['user']['id'] == 'alice'
    assert client.get('/api/auth/callback?code=valid-code', follow_redirects=False).headers['location'] == '/?auth_error=1'
