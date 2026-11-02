"""Small, explicit offline hint set, not a vulnerability database or live CVE feed."""
import re

APACHE_SOURCE='https://httpd.apache.org/security/vulnerabilities_24.html'
NGINX_SOURCE='http://nginx.org/en/security_advisories.html'
REVIEWED='2026-11-02'

_NOTE=('Unverified Server header only. This may be a spoofed banner or a patched build. '
      'Configuration and vendor patch status must be verified by the owner. No exploit request was sent.')

def _apache(server):
    match=re.search(r'\bApache/(2\.4\.(?:49|50))(?![\d.])',server or '',re.I)
    if not match:return None
    version=match.group(1)
    ids=['CVE-2021-42013']
    if version=='2.4.49':ids.insert(0,'CVE-2021-41773')
    return {'kind':'possible_version_match','product':'Apache HTTP Server','reported_version':version,
            'advisories':ids,'source':APACHE_SOURCE,'reviewed':REVIEWED,'note':_NOTE}

def _nginx(server):
    match=re.search(r'\bnginx/(\d+)\.(\d+)\.(\d+)(?![\d.])',server or '',re.I)
    if not match:return None
    version=tuple(int(g) for g in match.groups())
    if not (0,6,18)<=version<=(1,20,0):return None
    return {'kind':'possible_version_match','product':'nginx','reported_version':'.'.join(match.groups()),
            'advisories':['CVE-2021-23017'],'source':NGINX_SOURCE,'reviewed':REVIEWED,'note':_NOTE}

def version_hints(server):
    hints=[]
    for rule in (_apache,_nginx):
        hint=rule(server)
        if hint:hints.append(hint)
    return hints
