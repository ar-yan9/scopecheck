"""Small, explicit offline hint set, not a vulnerability database or live CVE feed."""
import re

APACHE_SOURCE='https://httpd.apache.org/security/vulnerabilities_24.html'
NGINX_SOURCE='http://nginx.org/en/security_advisories.html'
REVIEWED='2026-11-17'

_NOTE=('Unverified Server header only. This may be a spoofed banner or a patched build. '
      'Configuration and vendor patch status must be verified by the owner. No exploit request was sent.')

_APACHE_RULES={'2.4.49':['CVE-2021-41773','CVE-2021-42013'],
               '2.4.50':['CVE-2021-42013'],
               '2.4.51':['CVE-2021-44790'],
               '2.4.52':['CVE-2022-22720'],
               '2.4.53':['CVE-2022-26377','CVE-2022-28330','CVE-2022-28614','CVE-2022-28615',
                         'CVE-2022-29404','CVE-2022-30522','CVE-2022-30556','CVE-2022-31813'],
               '2.4.54':['CVE-2006-20001','CVE-2022-36760','CVE-2022-37436']}

def _apache(server):
    match=re.search(r'\bApache/(2\.4\.(?:49|50|51|52|53|54))(?![\d.])',server or '',re.I)
    if not match:return None
    version=match.group(1)
    return {'kind':'possible_version_match','product':'Apache HTTP Server','reported_version':version,
            'advisories':list(_APACHE_RULES[version]),'source':APACHE_SOURCE,'reviewed':REVIEWED,'note':_NOTE}

def _nginx(server):
    match=re.search(r'\bnginx/(\d+)\.(\d+)\.(\d+)(?![\d.])',server or '',re.I)
    if not match:return None
    version=tuple(int(g) for g in match.groups())
    advisories=[]
    if (0,6,18)<=version<=(1,20,0):advisories.append('CVE-2021-23017')
    if (1,0,7)<=version<=(1,0,15) or (1,1,3)<=version<=(1,23,1):
        advisories.extend(['CVE-2022-41741','CVE-2022-41742'])
    if not advisories:return None
    return {'kind':'possible_version_match','product':'nginx','reported_version':'.'.join(match.groups()),
            'advisories':advisories,'source':NGINX_SOURCE,'reviewed':REVIEWED,'note':_NOTE}

def version_hints(server):
    hints=[]
    for rule in (_apache,_nginx):
        hint=rule(server)
        if hint:hints.append(hint)
    return hints
