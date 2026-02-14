import logging
import os
import signal
import sys
from cloudflare_client import initialize_and_log_tunnels, stop_cache_refresh_thread
from docker_client import start_event_listener, stop_event_listener
from web_server import start_server

# Configure logging
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))

# Graceful shutdown flag
shutdown_requested = False

def signal_handler(signum, frame):
    """Handle shutdown signals gracefully."""
    global shutdown_requested
    logging.info(f"Received signal {signum}. Initiating graceful shutdown...")
    shutdown_requested = True
    stop_cache_refresh_thread()
    stop_event_listener()
    sys.exit(0)

def main():
    # Register signal handlers for graceful shutdown
    signal.signal(signal.SIGTERM, signal_handler)
    signal.signal(signal.SIGINT, signal_handler)
    
    logging.info("Starting docker.dash service...")
    
    # Perform startup tasks
    initialize_and_log_tunnels()

    # Web port is configurable via environment variable
    web_port = int(os.environ.get("WEB_PORT", "3445"))
    start_server(web_port)
    
    # Start the main, long-running process
    start_event_listener()

if __name__ == "__main__":
    main()