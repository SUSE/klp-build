from http.server import HTTPServer, SimpleHTTPRequestHandler
from pathlib import Path
import ssl

httpd = HTTPServer(("localhost", 443), SimpleHTTPRequestHandler)
ssl_context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
ssl_context.load_cert_chain(Path("/usr/share/pki/trust/anchors/server.crt"))
httpd.socket = ssl_context.wrap_socket(
        httpd.socket,
        server_side=True,
)

httpd.serve_forever()
