"""Owned localhost fixture. Fake Apache banner demonstrates hints, NOT a real vulnerable server."""
from http.server import BaseHTTPRequestHandler, HTTPServer
class Demo(BaseHTTPRequestHandler):
    server_version = 'Apache/2.4.49'
    sys_version = 'ScopeCheck-LAB-FIXTURE'
    def do_HEAD(self):
        self.send_response(200)
        self.send_header('X-ScopeCheck-Lab','synthetic server banner, not actual Apache')
        self.end_headers()
    def log_message(self,*args):
        pass
if __name__ == '__main__':
    print('Local demo on 127.0.0.1:8899. Simulated version header, not a vulnerable Apache instance.')
    HTTPServer(('127.0.0.1',8899),Demo).serve_forever()
