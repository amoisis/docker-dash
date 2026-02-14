import json
import threading
import logging
import os
from waitress import serve
from cloudflare_client import get_consolidated_cache, CloudflareJSONEncoder

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
            status = '404 Not Found'
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
    Logs critical error if server fails to start.
    """
    server_started = threading.Event()
    server_error = [None]  # Use list to store exception from thread
    
    def run_server():
        try:
            logging.info(f"Web server starting on http://0.0.0.0:{port}.")
            server_started.set()  # Signal that we're attempting to start
            serve(wsgi_app, host='0.0.0.0', port=port, _quiet=True)
        except OSError as e:
            logging.critical(f"FATAL: Failed to start web server on port {port}: {e}")
            logging.critical("Common causes:")
            logging.critical("  - Port already in use (another process is using port {})".format(port))
            logging.critical("  - Insufficient permissions to bind to port")
            logging.critical("  - Invalid network configuration")
            logging.critical("The application will continue but the web UI will NOT be available.")
            logging.critical("Container events will still be processed normally.")
            server_error[0] = e
            server_started.set()
        except Exception as e:
            logging.critical(f"FATAL: Unexpected error starting web server: {e}")
            logging.critical("The web UI will NOT be available. Container events will still be processed.")
            server_error[0] = e
            server_started.set()

    # Run the server in a daemon thread so it doesn't block shutdown
    server_thread = threading.Thread(target=run_server, name="WebServerThread")
    server_thread.daemon = True
    server_thread.start()
    
    # Wait briefly for server to start or fail
    server_started.wait(timeout=3)
    
    # Provide clear feedback about server status
    if server_error[0]:
        logging.warning("=" * 60)
        logging.warning("WEB SERVER DID NOT START - APPLICATION RUNNING IN HEADLESS MODE")
        logging.warning("=" * 60)
    elif server_thread.is_alive():
        logging.info(f"✓ Web server successfully started and listening on http://0.0.0.0:{port}")
        logging.info(f"  Access the UI at: http://localhost:{port}/")
    else:
        logging.warning("Web server thread status unclear - may not be running properly")
