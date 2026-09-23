from fastapi.testclient import TestClient
from scapy.all import wrpcap
from generate_traffic import generate
from app.main import app


def test_upload_poll_and_all_exports(tmp_path):
    path = tmp_path / 'real.pcap'
    wrpcap(str(path), generate('cleartext_auth'))
    with TestClient(app) as client:
        response = client.post('/api/upload', files={'file': ('real.pcap', path.read_bytes(), 'application/octet-stream')})
        assert response.status_code == 202
        job = response.json()['job_id']
        result = client.get(f'/api/analysis/{job}').json()
        assert result['status'] == 'done'
        assert result['report']['summary']['critical_findings'] == 3
        for format in ('json', 'html', 'pdf'):
            exported = client.get(f'/api/report/{job}/export?format={format}')
            assert exported.status_code == 200
            assert 'demo-password' not in exported.text
            if format == 'pdf':
                assert exported.content.startswith(b'%PDF')
        assert client.get('/api/analysis/missing').status_code == 404
        assert client.get(f'/api/report/{job}/export?format=exe').status_code == 422


def test_invalid_upload():
    with TestClient(app) as client:
        assert client.post('/api/upload', files={'file': ('bad.pcap', b'not a capture')}).status_code == 400
        assert client.post('/api/upload', files={'file': ('bad.exe', b'not a capture')}).status_code == 400
