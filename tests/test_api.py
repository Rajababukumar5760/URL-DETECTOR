from fastapi.testclient import TestClient
from app.main import app

client=TestClient(app)

def test_health_endpoint():
    r=client.get('/health'); assert r.status_code==200; assert r.json()['status']=='ok'

def test_home_page_served():
    r=client.get('/'); assert r.status_code==200; assert 'PhishGuard' in r.text

def test_valid_analysis_schema():
    r=client.post('/api/analyze',json={'url':'https://example.com'}); assert r.status_code==200
    data=r.json(); assert data['valid'] is True; assert data['hostname']=='example.com'; assert 'findings' in data; assert 'ml' in data

def test_missing_url():
    r=client.post('/api/analyze',json={}); assert r.status_code==422

def test_empty_url():
    r=client.post('/api/analyze',json={'url':'   '}); assert r.status_code==422

def test_invalid_json():
    r=client.post('/api/analyze',content='{bad json',headers={'content-type':'application/json'}); assert r.status_code==422

def test_unsupported_scheme():
    r=client.post('/api/analyze',json={'url':'ftp://example.com'}); assert r.status_code==422

def test_long_input_rejected():
    r=client.post('/api/analyze',json={'url':'https://example.com/'+'a'*4100}); assert r.status_code==422

def test_missing_model_does_not_crash():
    r=client.post('/api/analyze',json={'url':'https://example.com'}); assert r.status_code==200; assert 'available' in r.json()['ml']

def test_threat_intelligence_not_falsely_claimed():
    data=client.post('/api/analyze',json={'url':'https://example.com'}).json(); assert data['threat_intelligence']['checked'] is False

def test_submitted_url_is_not_fetched(monkeypatch):
    import socket
    def forbidden(*args,**kwargs): raise AssertionError('network call attempted')
    monkeypatch.setattr(socket,'create_connection',forbidden)
    r=client.post('/api/analyze',json={'url':'https://example.com'}); assert r.status_code==200

def test_static_javascript_served(): assert client.get('/static/app.js').status_code==200