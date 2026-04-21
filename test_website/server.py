import os
import datetime
from http.server import SimpleHTTPRequestHandler, HTTPServer
import urllib.parse


class StaticAndLoggingHandler(SimpleHTTPRequestHandler):
    def log_message(self, format, *args):
        try:
            ip = self.client_address[0]
            timestamp = datetime.datetime.now().strftime("%d/%b/%Y:%H:%M:%S +0000")
            msg = f'{ip} - - [{timestamp}] "{self.requestline}" {self.status} {getattr(self, "bytes_sent", 2490)}'
            log_path = os.path.join(os.path.dirname(__file__), "access.log")
            with open(log_path, "a", buffering=1) as f:
                f.write(msg + "\n")
            print(f"Logged request: {msg.strip()}")
        except Exception:
            pass

    def do_GET(self):
        # We parse the path so if the user adds ?q=attack doing custom routes it doesn't 404 immediately
        parsed = urllib.parse.urlparse(self.path)
        if parsed.path in ["/", "/index.html", "/style.css"]:
            super().do_GET()
            self.bytes_sent = 1200
        else:
            # Fallback to serving index.html for forms
            self.status = 200
            self.bytes_sent = 500
            self.send_response(self.status)
            self.send_header("Content-type", "text/html")
            self.end_headers()
            self.wfile.write(
                b"<html><head><title>Success</title></head><body><h1>Action acknowledged</h1><a href='/'>Go back</a></body></html>"
            )
            self.log_message(None)

    def do_POST(self):
        self.status = 200
        self.bytes_sent = 550
        self.send_response(self.status)
        self.send_header("Content-type", "text/html")
        self.end_headers()
        self.wfile.write(
            b"<html><head><title>Success</title></head><body><h1>Authentication captured</h1><a href='/'>Go back</a></body></html>"
        )
        # Ensure log happens for POSTs too!
        self.log_message(None)


if __name__ == "__main__":
    SERVER_PORT = int(os.environ.get("AUTOSHIELD_TEST_SITE_PORT", "9090"))
    print(f"[*] Starting Nexus Solutions Test Site on http://localhost:{SERVER_PORT}")
    print(f"[*] Traffic will be written to access.log")

    # Reset log
    with open("access.log", "w") as f:
        pass

    server = HTTPServer(("0.0.0.0", SERVER_PORT), StaticAndLoggingHandler)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nExiting server")
