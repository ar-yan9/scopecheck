"""Loopback binding is deliberate; no command line host override."""
import uvicorn
if __name__ == '__main__':
    print('ScopeCheck local draft: http://127.0.0.1:8765 - do not expose through a tunnel')
    uvicorn.run('app:app', host='127.0.0.1', port=8765, access_log=False)
