"""Small, explicit offline hint set, not a vulnerability database or live CVE feed."""
import re

SOURCE = 'https://httpd.apache.org/security/vulnerabilities_24.html'

def version_hints(server):
    match = re.search(r'\bApache/(2\.4\.(?:49|50))(?![\d.])', server or '', re.I)
    if not match:
        return []
    version = match.group(1)
    ids = ['CVE-2021-42013']
    if version == '2.4.49':
        ids.insert(0, 'CVE-2021-41773')
    return [{'kind': 'possible_version_match', 'product': 'Apache HTTP Server', 'reported_version': version,
             'advisories': ids, 'source': SOURCE, 'reviewed': '2026-10-16',
             'note': 'Unverified Server header only. This may be a spoofed banner or a patched build. Configuration and vendor patch status must be verified by the owner. No exploit request was sent.'}]
