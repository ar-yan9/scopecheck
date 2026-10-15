import json
import socket
import ssl
import threading
from http.server import HTTPServer,BaseHTTPRequestHandler
import pytest
import scanner
from advisories import version_hints
from fastapi.testclient import TestClient
import app

@pytest.mark.parametrize('bad',['0','65536','1-0','1;2','22,','-1'])
def test_ports_reject(bad):
    with pytest.raises(ValueError):scanner.ports(bad)
def test_ports():
    assert scanner.ports('80,22,80,8000-8002')==[22,80,8000,8001,8002]
@pytest.mark.parametrize('bad',['http://example.com','x\r\nHost:evil','a@b','a/b','-host','a..b','192.0.2.1:80'])
def test_target_reject(bad):
    with pytest.raises(ValueError):scanner.target_name(bad)
def answers(*ips):
    return [(socket.AF_INET,socket.SOCK_STREAM,6,'',(ip,0)) for ip in ips]
def test_scope_and_dns_pinning(monkeypatch):
    monkeypatch.setattr(scanner.socket,'getaddrinfo',lambda *a,**k:answers('192.0.2.1','192.0.2.2'))
    with pytest.raises(ValueError):scanner.resolve_plan('example.test')
    with pytest.raises(ValueError):scanner.resolve_plan('example.test',True,['192.0.2.1'])
    plan=scanner.resolve_plan('example.test',True,['192.0.2.0/24'])
    assert plan['selected_address']=='192.0.2.1'
    assert plan['resolved_addresses']==['192.0.2.1','192.0.2.2']
@pytest.mark.parametrize('target',['0.0.0.0','169.254.169.254','224.0.0.1','::','fe80::1'])
def test_disallowed_addresses(monkeypatch,target):
    monkeypatch.setattr(scanner.socket,'getaddrinfo',lambda *a,**k:answers(target))
    with pytest.raises(ValueError):scanner.resolve_plan(target,True,['0.0.0.0/0','::/0'])
def test_loopback_allowed():
    assert scanner.resolve_plan('127.0.0.1')['loopback_only']
def test_advisory_exact_not_prefix():
    assert version_hints('Apache/2.4.49')[0]['advisories']==['CVE-2021-41773','CVE-2021-42013']
    assert version_hints('Apache/2.4.50')[0]['advisories']==['CVE-2021-42013']
    for version in ['Apache/2.4.490','Apache/2.4.51','nginx/1.0','Apache/2.4.49.1']:
        assert version_hints(version)==[]
class Demo(BaseHTTPRequestHandler):
    server_version='Apache/2.4.49'
    sys_version='TEST-FIXTURE'
    def do_HEAD(self):
        self.send_response(302)
        self.send_header('Location','http://never-follow.invalid/')
        self.send_header('X-Content-Type-Options','nosniff')
        self.end_headers()
    def log_message(self,*a):pass
@pytest.fixture
def lab():
    server=HTTPServer(('127.0.0.1',0),Demo)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    yield server.server_port
    server.shutdown();thread.join();server.server_close()
def test_real_local_scan_and_header_observation(lab):
    plan=scanner.resolve_plan('127.0.0.1')
    result=scanner.scan(plan,[lab],timeout=.5,rate=10,http_ports=[lab])
    row=result['results'][0]
    assert row['state']=='open'
    assert row['http']['response_status'].startswith('HTTP/1.0 302')
    assert 'x-content-type-options' not in row['http']['missing_headers']
    assert 'content-security-policy' in row['http']['missing_headers']
    assert row['http']['version_hints'][0]['kind']=='possible_version_match'
    assert result['summary']['open']==1

def test_bound_nonlistening_port_never_reported_open():
    sock=socket.socket();sock.bind(('127.0.0.1',0));port=sock.getsockname()[1]
    # Windows may silently drop this connection; Linux usually refuses it.
    # Preserve the observed distinction, never manufacture a closed verdict.
    try:assert scanner.tcp_probe('127.0.0.1',port,.3,scanner.RateGate(10))['state'] in {'closed','timeout'}
    finally:sock.close()

def test_no_insecure_tls_fallback(monkeypatch):
    class Raw:
        def __enter__(self):return self
        def __exit__(self,*a):pass
    class Context:
        def wrap_socket(self,*a,**k):raise ssl.SSLCertVerificationError(1,'untrusted fixture')
    monkeypatch.setattr(scanner.socket,'create_connection',lambda *a,**k:Raw())
    monkeypatch.setattr(scanner.ssl,'create_default_context',lambda:Context())
    assert scanner.tls_observation('127.0.0.1','localhost',443,.2,scanner.RateGate(10))['status']=='certificate_not_verified'

def test_export_exclusive(tmp_path):
    path=tmp_path/'report.json';scanner.write_report({'text':'<script>not markup</script>'},path)
    assert json.loads(path.read_text())['text'].startswith('<script>')
    with pytest.raises(FileExistsError):scanner.write_report({},path)

def test_http_api_gates_and_local_run(lab):
    with TestClient(app.app) as client:
        assert client.post('/api/scan',json={'authorized':False}).status_code==400
        assert client.post('/api/scan',json={'authorized':True,'target':'127.0.0.1','ports':str(lab)},headers={'Origin':'https://evil.invalid'}).status_code==403
        assert client.get('/api/health',headers={'Host':'evil.invalid'}).status_code==400
        assert client.post('/api/scan',content='text',headers={'Content-Type':'text/plain'}).status_code==415
        app.lock.acquire()
        try:assert client.post('/api/scan',json={'authorized':True}).status_code==409
        finally:app.lock.release()
        response=client.post('/api/scan',json={'authorized':True,'target':'127.0.0.1','ports':str(lab),'http_ports':str(lab)})
        assert response.status_code==200
        assert response.json()['results'][0]['state']=='open'
        assert response.headers['X-Frame-Options']=='DENY'
        assert response.headers['Cache-Control']=='no-store'
@pytest.mark.parametrize('kwargs',[{'rate':201},{'workers':129},{'timeout':0}])
def test_bounds_before_connections(monkeypatch,kwargs):
    monkeypatch.setattr(scanner.socket,'create_connection',lambda *a,**k:pytest.fail('must not connect'))
    with pytest.raises(ValueError):scanner.scan({'selected_address':'127.0.0.1'},[80],**kwargs)

def test_rate_gate_staggers_connections(monkeypatch):
    clock=[1.0];sleeps=[]
    monkeypatch.setattr(scanner.time,'monotonic',lambda:clock[0])
    def sleep(n):sleeps.append(n);clock[0]+=n
    monkeypatch.setattr(scanner.time,'sleep',sleep)
    gate=scanner.RateGate(5)
    gate.wait();gate.wait();gate.wait()
    assert len(sleeps)==2
    assert all(abs(x-.2)<.0001 for x in sleeps)

def test_passive_banner_strips_control_codes(monkeypatch):
    class Conn:
        def __enter__(self):return self
        def __exit__(self,*a):pass
        def recv(self,n):return b'\x1b[31mSSH-test\r\n'
    monkeypatch.setattr(scanner.socket,'create_connection',lambda *a,**k:Conn())
    result=scanner.passive_banner('127.0.0.1',22,.1,scanner.RateGate(10))
    assert '\x1b' not in result['text']
    assert result['text'].startswith('.[31m')

def test_real_tls_certificate_and_https_on_owned_local_fixture(tmp_path,monkeypatch):
    import shutil,subprocess
    if not shutil.which('openssl'):
        pytest.skip('OpenSSL CLI needed to generate an ephemeral local test certificate')
    key=tmp_path/'key.pem';cert=tmp_path/'cert.pem'
    subprocess.run(['openssl','req','-x509','-newkey','rsa:2048','-nodes','-keyout',str(key),'-out',str(cert),'-days','1','-subj','/CN=localhost','-addext','subjectAltName=DNS:localhost'],check=True,capture_output=True)
    server=HTTPServer(('127.0.0.1',0),Demo)
    context=ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER);context.load_cert_chain(cert,key)
    server.socket=context.wrap_socket(server.socket,server_side=True)
    thread=threading.Thread(target=server.serve_forever,daemon=True);thread.start()
    trusted=ssl.create_default_context(cafile=str(cert))
    monkeypatch.setattr(scanner.ssl,'create_default_context',lambda:trusted)
    try:
        gate=scanner.RateGate(10)
        result=scanner.tls_observation('127.0.0.1','localhost',server.server_port,1,gate)
        assert result['status']=='verified'
        assert result['protocol'].startswith('TLS')
        assert result['days_remaining'] is not None
        response=scanner.http_observation('127.0.0.1','localhost',server.server_port,1,gate,tls=True)
        assert response['status']=='observed'
        assert response['transport']=='HTTPS'
        assert 'strict-transport-security' in response['missing_headers']
    finally:
        server.shutdown();thread.join();server.server_close()


@pytest.mark.parametrize('error,expected',[(ConnectionRefusedError(), 'closed'), (TimeoutError(), 'timeout')])
def test_refused_and_timeout_keep_distinct_states(monkeypatch,error,expected):
    def fail(*args,**kwargs):
        raise error
    monkeypatch.setattr(scanner.socket,'create_connection',fail)
    assert scanner.tcp_probe('127.0.0.1',22,.3,scanner.RateGate(10))['state']==expected
