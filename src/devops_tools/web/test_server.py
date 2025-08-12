import logging
import time
from http.server import BaseHTTPRequestHandler, HTTPServer

# Server configuration
HOST_NAME = "localhost"
SERVER_PORT = 8080

# Setup Logging (Standard Library)
logging.basicConfig(level=logging.INFO, format="%(asctime)s - %(levelname)s - %(message)s")


class SimpleHTTPRequestHandler(BaseHTTPRequestHandler):
    def do_GET(self):
        """Handle GET requests and serve a simple HTML response."""
        self.send_response(200)
        self.send_header("Content-type", "text/html")
        self.end_headers()

        response_content = f"""
        <html>
        <head><title>Simple Web Server</title></head>
        <body>
            <h2>Welcome to the Python Testing Server</h2>
            <p>Request Path: {self.path}</p>
            <p>Server Time: {time.strftime('%Y-%m-%d %H: %M: %S')}</p>
        </body>
        </html>
        """
        self.wfile.write(response_content.encode("utf-8"))
        logging.info(f"Handled GET request: {self.path}")

    def do_POST(self):
        """Handle POST requests and echo back the received data."""
        content_length = int(self.headers.get("Content-Length", 0))  # Get POST data length
        post_data = self.rfile.read(content_length).decode("utf-8")

        self.send_response(200)
        self.send_header("Content-type", "text/plain")
        self.end_headers()

        response = f"Received POST data: {post_data}"
        self.wfile.write(response.encode("utf-8"))
        logging.info(f"Handled POST request: {self.path} | Data: {post_data}")

    def log_message(self, format, *args):
        """Suppress default server logs and integrate with Python logging."""
        logging.info("%s - %s" % (self.client_address[0], format % args))


if __name__ == "__main__":
    try:
        server = HTTPServer((HOST_NAME, SERVER_PORT), SimpleHTTPRequestHandler)
        logging.info(f"Server started at http: //{HOST_NAME}: {SERVER_PORT}")

        server.serve_forever()
    except KeyboardInterrupt:
        logging.info("Received shutdown signal. Stopping server...")
    except Exception as e:
        logging.error(f"Unexpected server error: {e}")
    finally:
        server.server_close()
        logging.info("Server has stopped.")
