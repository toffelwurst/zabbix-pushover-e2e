# Minimal fake Pushover API for local tests: logs each POST body (one JSON per line) and answers like Pushover.
import http.server, json, sys
LOG = sys.argv[1] if len(sys.argv) > 1 else '/data/requests.jsonl'
class H(http.server.BaseHTTPRequestHandler):
    def do_POST(self):
        body = self.rfile.read(int(self.headers.get('Content-Length', 0)))
        with open(LOG, 'ab') as f:
            f.write(body.replace(b'\n', b' ') + b'\n')
        resp = json.dumps({"status": 1, "request": "local-echo"}).encode()
        self.send_response(200); self.send_header('Content-Type', 'application/json'); self.end_headers(); self.wfile.write(resp)
    def log_message(self, *a): pass
http.server.HTTPServer(('0.0.0.0', 8000), H).serve_forever()
