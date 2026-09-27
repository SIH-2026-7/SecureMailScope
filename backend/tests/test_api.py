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


def test_history_retains_pcapng_and_reports_across_restart(tmp_path):
    from scapy.utils import PcapNgWriter
    from app.models.db_models import DATA

    path = tmp_path / 'saved.pcapng'
    with PcapNgWriter(str(path)) as writer:
        writer.write(generate('cleartext_auth'))
    original = path.read_bytes()
    with TestClient(app) as client:
        ids = [client.post('/api/upload', files={'file': ('saved.pcapng', original)}).json()['job_id'] for _ in range(2)]
    with TestClient(app) as client:
        history = client.get('/api/analysis').json()['analyses']
        saved = [item for item in history if item['job_id'] in ids]
        assert [item['job_id'] for item in saved] == ids[::-1]
        assert all(item['filename'] == 'saved.pcapng' and item['status'] == 'done' and item['capture_available'] for item in saved)
        assert all(item['created_at'].endswith('+00:00') for item in saved)
        for job_id in ids:
            assert client.get(f'/api/analysis/{job_id}').json()['report']['capture_meta']['filename'] == 'saved.pcapng'
            response = client.get(f'/api/analysis/{job_id}/capture')
            assert response.content == original
            assert 'saved.pcapng' in response.headers['content-disposition']
        # Legacy reports must remain accessible without the original file.
        (DATA / (ids[0] + '.capture')).unlink()
        legacy = next(item for item in client.get('/api/analysis').json()['analyses'] if item['job_id'] == ids[0])
        assert not legacy['capture_available']
        assert client.get(f'/api/analysis/{ids[0]}/capture').status_code == 404
        assert client.get(f'/api/analysis/{ids[0]}').json()['status'] == 'done'
        assert client.get('/api/analysis/missing/capture').status_code == 404
