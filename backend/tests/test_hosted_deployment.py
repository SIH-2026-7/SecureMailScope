import httpx
from fastapi.testclient import TestClient
from scapy.all import wrpcap
from generate_traffic import generate
from app.main import app
from app.core import capture_storage
from app.models.db_models import DATA


def test_demo_password_protects_api_and_frontend(monkeypatch):
    monkeypatch.setenv('DEMO_PASSWORD', 'test-password')
    with TestClient(app) as client:
        assert client.get('/api/health').status_code == 200
        assert client.get('/').status_code == 401
        assert client.get('/api/analysis').status_code == 401
        assert client.get('/api/analysis', auth=('demo', 'wrong')).status_code == 401
        assert client.get('/api/analysis', auth=('demo', 'test-password')).status_code == 200


def test_remote_capture_survives_local_cleanup(monkeypatch, tmp_path):
    monkeypatch.setenv('SUPABASE_URL', 'https://example.supabase.co')
    monkeypatch.setenv('SUPABASE_SERVICE_ROLE_KEY', 'server-only-test-key')
    objects = {}

    def request(method, url, **kwargs):
        assert kwargs['headers']['Authorization'] == 'Bearer server-only-test-key'
        if '/object/sign/' in url:
            key = url.rsplit('/', 1)[1]
            assert key in objects
            return httpx.Response(200, json={'signedURL': '/object/sign/captures/' + key + '?token=test'},
                                  request=httpx.Request(method, url))
        objects[url.rsplit('/', 1)[1]] = b''.join(kwargs['content'])
        return httpx.Response(200, json={}, request=httpx.Request(method, url))

    monkeypatch.setattr(capture_storage.httpx, 'request', request)
    path = tmp_path / 'sample.pcap'
    wrpcap(str(path), generate('cleartext_auth'))
    with TestClient(app) as client:
        response = client.post('/api/upload', files={'file': ('sample.pcap', path.read_bytes())})
        assert response.status_code == 202
        job_id = response.json()['job_id']
        assert objects[job_id + '.capture'] == path.read_bytes()
        assert not (DATA / (job_id + '.capture')).exists()
    with TestClient(app) as client:
        assert client.get(f'/api/analysis/{job_id}').json()['status'] == 'done'
        entry = next(x for x in client.get('/api/analysis').json()['analyses'] if x['job_id'] == job_id)
        assert entry['capture_available']
        response = client.get(f'/api/analysis/{job_id}/capture', follow_redirects=False)
        assert response.status_code == 307
        assert response.headers['location'].endswith('?token=test&download=sample.pcap')


def test_storage_failure_is_safe(monkeypatch, tmp_path):
    monkeypatch.setenv('SUPABASE_URL', 'https://example.supabase.co')
    def fail(*args):
        raise RuntimeError('private credential must not reach user')
    monkeypatch.setattr(capture_storage, 'upload', fail)
    path = tmp_path / 'sample.pcap'
    wrpcap(str(path), generate('cleartext_auth'))
    with TestClient(app) as client:
        response = client.post('/api/upload', files={'file': ('sample.pcap', path.read_bytes())})
        assert response.status_code == 503
        assert 'private credential' not in response.text
