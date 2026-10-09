import json
from http.server import BaseHTTPRequestHandler, HTTPServer
from handler import handle

invoices = {
    'inv_a': {'tenant_id': 'a', 'amount_minor': 1299, 'currency': 'usd'},
    'inv_b': {'tenant_id': 'b', 'amount_minor': 4200, 'currency': 'usd'},
}
class server(BaseHTTPRequestHandler):
    def do_GET(self):
        try:
            status, body = handle(self.headers.get('X-Tenant-Id'), self.path.rsplit('/', 1)[-1], invoices)
        except Exception:
            status, body = 500, {'error': 'schema or runtime fault'}
        data = json.dumps(body).encode()
        self.send_response(status)
        self.send_header('Content-Type', 'application/json')
        self.send_header('Content-Length', str(len(data)))
        self.end_headers()
        self.wfile.write(data)
    def log_message(self, *args):
        pass
HTTPServer(('0.0.0.0', 8080), server).serve_forever()
