import json
import threading
import logging
import os
from waitress import serve
from .cloudflare_client import get_consolidated_cache, CloudflareJSONEncoder

# Determine the absolute path to the templates directory
_current_dir = os.path.dirname(os.path.abspath(__file__))
_template_path = os.path.join(_current_dir, 'templates', 'index.html')


def wsgi_app(environ, start_response):
    """A simple WSGI application to serve the cache and UI."""
    path = environ.get('PATH_INFO', '/')

    if path == "/api/cache":
        status = '200 OK'
        headers = [('Content-type', 'application/json')]
        start_response(status, headers)
        cache_data = get_consolidated_cache()
        json_data = json.dumps(cache_data, cls=CloudflareJSONEncoder, indent=2)
        return [json_data.encode("utf-8")]
    
    elif path == "/":
        try:
            with open(_template_path, "rb") as f:
                content = f.read()
            status = '200 OK'
            headers = [('Content-type', 'text/html')]
            start_response(status, headers)
            return [content]
        except FileNotFoundError:
            status = '44 Not Found'
            headers = [('Content-type', 'text/plain')]
            start_response(status, headers)
            return [f"File not found: {_template_path}".encode('utf-8')]
    
    else:
        status = '404 Not Found'
        headers = [('Content-type', 'text/plain')]
        start_response(status, headers)
        return [b"Not Found"]

def start_server(port: int):
    """
    Starts the HTTP server in a separate thread.
    """
    def run_server():
        try:
            logging.info(f"Web server starting on http://localhost:{port}.")
            serve(wsgi_app, host='0.0.0.0', port=port, _quiet=True)
        except OSError as e:
            logging.error(f"Could not start web server on port {port}: {e}")

    # Run the server in a daemon thread so it doesn't block shutdown
    server_thread = threading.Thread(target=run_server)
    server_thread.daemon = True
    server_thread.start()
