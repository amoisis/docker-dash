import logging
import os
from .cloudflare_client import initialize_and_log_tunnels
from .docker_client import start_event_listener
from .web_server import start_server

# Configure logging
logging.basicConfig(level=os.environ.get("LOG_LEVEL", "INFO"))

def main():
    logging.info("Starting docker.dash service...")
    
    # Perform startup tasks
    initialize_and_log_tunnels()

    web_port  = 3445
    start_server(web_port)
    
    # Start the main, long-running process
    start_event_listener()

if __name__ == "__main__":
    main()