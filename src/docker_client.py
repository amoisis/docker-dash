import docker
import logging
import os
import threading
import time
from cloudflare_client import (
    add_or_update_ingress_rule, 
    add_or_update_access_application, 
    remove_ingress_rule, 
    remove_access_application
)

# Debounce settings
_last_processed_time = {}
_container_ingress_state = {}
_debounce_delay_seconds = 10

# Container status tracking for diagnostics
_container_status = {}

# Event listener control
_event_stream = None
_docker_client = None
_listener_stop_event = threading.Event()
_reconcile_thread = None
_reconcile_interval_seconds = int(os.environ.get("RECONCILE_INTERVAL", "60"))
_event_listener_running = False

# Thread safety for shared state
_state_lock = threading.Lock()

def get_docker_client():
    """
    Initializes and returns a Docker client.
    It will connect using environment variables (like DOCKER_HOST) or the
    default socket path.
    """
    try:
        client = docker.from_env()
        client.ping()
        logging.info("Successfully connected to Docker daemon.")
        return client
    except Exception as e:
        logging.error(f"Failed to connect to Docker daemon: {e}")
        return None

def get_container_statuses():
    """
    Returns a copy of the container status dictionary for diagnostics.
    """
    with _state_lock:
        return dict(_container_status)


def get_event_listener_status():
    """
    Returns the current event listener health status.
    """
    return {
        "status": "ok" if _event_listener_running else "unknown",
        "connected": _event_listener_running
    }

def process_container(container):
    """
    Inspects a container for docker.dash labels and triggers Cloudflare updates.
    Includes a debounce mechanism and stateful cleanup of old rules.
    """
    container_id = container.id
    current_time = time.time()

    with _state_lock:
        # Debounce check
        last_time = _last_processed_time.get(container_id)
        if last_time and (current_time - last_time) < _debounce_delay_seconds:
            logging.info(f"Debouncing event for container {container.name} ({container_id[:12]}). Skipping.")
            return

    label_prefix = "docker.dash."
    try:
        container_labels = container.labels or {}
        dash_labels = {
            k: v for k, v in container_labels.items() if k.startswith(label_prefix)
        }

        with _state_lock:
            # Get the last known state for this container
            old_state = _container_ingress_state.get(container_id)

            # Determine the new desired state from labels
            enable_label = dash_labels.get(f"{label_prefix}enable", "false")
            new_tunnel_name = dash_labels.get(f"{label_prefix}tunnel")
            new_hostname = dash_labels.get(f"{label_prefix}hostname")
            new_service = dash_labels.get(f"{label_prefix}service")

            is_enabled = enable_label == "true" and all([new_tunnel_name, new_hostname, new_service])
            new_state = (new_tunnel_name, new_hostname) if is_enabled else None

            # If state has changed, and there was an old rule, remove it
            if old_state and old_state != new_state:
                old_tunnel, old_hostname = old_state
                logging.info(f"State changed for {container.name}. Removing old ingress rule: {old_hostname} from {old_tunnel}")
                remove_ingress_rule(old_tunnel, old_hostname)
                # Also try to remove the associated Access Application
                remove_access_application(old_hostname)

            # If the container is not enabled or is missing labels, we are done.
            if not is_enabled:
                # Determine if disabled or misconfigured
                if enable_label != "true":
                    logging.debug(f"Container '{container.name}' is disabled (docker.dash.enable != true). Skipping.")
                    _container_status[container_id] = {
                        "name": container.name,
                        "status": "disabled",
                        "reason": "docker.dash.enable is not set to 'true'",
                        "labels": dash_labels
                    }
                else:
                    # Enabled but missing required labels
                    missing = []
                    if not new_tunnel_name:
                        missing.append("docker.dash.tunnel")
                    if not new_hostname:
                        missing.append("docker.dash.hostname")
                    if not new_service:
                        missing.append("docker.dash.service")
                    logging.warning(f"Container '{container.name}' is misconfigured. Missing required labels: {', '.join(missing)}")
                    _container_status[container_id] = {
                        "name": container.name,
                        "status": "misconfigured",
                        "reason": f"Missing required labels: {', '.join(missing)}",
                        "labels": dash_labels
                    }
                _container_ingress_state.pop(container_id, None) # Clean up state
                _last_processed_time[container_id] = current_time
                return

        # Sanitize the service URL
        if new_service.endswith('/'):
            new_service = new_service.rstrip('/')
            logging.debug(f"Sanitized service URL for '{new_hostname}' to '{new_service}'")

        # Add/Update the new ingress rule
        new_rule = {"hostname": new_hostname, "service": new_service}
        ingress_updated = add_or_update_ingress_rule(new_tunnel_name, new_rule)
        if not ingress_updated:
            with _state_lock:
                _container_status[container_id] = {
                    "name": container.name,
                    "status": "error",
                    "reason": f"Failed to update ingress rule for tunnel '{new_tunnel_name}'",
                    "labels": dash_labels
                }
                _last_processed_time[container_id] = current_time
            return

        with _state_lock:
            _container_ingress_state[container_id] = new_state # Update state

            # Handle Access Application
            access_policy = dash_labels.get(f"{label_prefix}application.access.policy")
            if access_policy:
                logging.info(f"Found Access Policy configuration for '{new_hostname}'.")
                access_config = {
                    "policy": access_policy,
                    "loginmethods": dash_labels.get(f"{label_prefix}application.access.loginmethods", ""),
                    "instantauth": dash_labels.get(f"{label_prefix}application.access.instantauth", "false"),
                    "icon": dash_labels.get(f"{label_prefix}application.access.icon"),
                }
                access_config = {k: v for k, v in access_config.items() if v is not None}
                add_or_update_access_application(new_hostname, access_config)

            # Update container status to active
            _container_status[container_id] = {
                "name": container.name,
                "status": "active",
                "tunnel": new_tunnel_name,
                "hostname": new_hostname,
                "service": new_service,
                "has_access_policy": bool(access_policy),
                "labels": dash_labels
            }
            _last_processed_time[container_id] = current_time

    except Exception as e:
        logging.error(f"Error processing container {container_id[:12]}: {e}")

def stop_event_listener():
    """
    Stops the event listener and reconciliation threads gracefully.
    """
    global _event_stream, _docker_client, _reconcile_thread
    _listener_stop_event.set()
    if _event_stream:
        try:
            _event_stream.close()
            logging.info("Docker event stream closed.")
        except Exception as e:
            logging.error(f"Error closing event stream: {e}")
    if _docker_client:
        try:
            _docker_client.close()
            logging.info("Docker client connection closed.")
        except Exception as e:
            logging.error(f"Error closing Docker client: {e}")
    if _reconcile_thread and _reconcile_thread.is_alive():
        _reconcile_thread.join(timeout=5)
        logging.info("Reconciliation thread stopped.")

def _handle_container_event(docker_client, event):
    """
    Process a single Docker container event.
    """
    action = event.get("Action")
    container_id = event.get("Actor", {}).get("ID") or event.get("id")

    if action == "start":
        if not container_id:
            logging.warning(f"Received start event with no container ID. Event: {event}")
            return
        try:
            logging.info(f"Received start event for container {container_id[:12]}")
            container = docker_client.containers.get(container_id)
            process_container(container)
        except docker.errors.NotFound:
            logging.warning(
                f"Container {container_id[:12]} not found after start event. It may have been short-lived."
            )
    elif action == "stop":
        if not container_id:
            logging.warning(f"Received stop event with no container ID. Event: {event}")
            return
        with _state_lock:
            # Clean up state on stop
            if container_id in _container_ingress_state:
                old_tunnel, old_hostname = _container_ingress_state.pop(container_id)
                logging.info(f"Container {container_id[:12]} stopped. Removing ingress rule: {old_hostname} from {old_tunnel}")
                remove_ingress_rule(old_tunnel, old_hostname)
                remove_access_application(old_hostname)
            else:
                # Fallback for containers that were not in the state
                attributes = event.get("Actor", {}).get("Attributes", {})
                label_prefix = "docker.dash."
                dash_labels = {
                    k: v for k, v in attributes.items() if k.startswith(label_prefix)
                }
                if dash_labels.get(f"{label_prefix}enable") == "true":
                    logging.info(f"Received stop event for enabled container {container_id[:12]}. Removing resources based on labels.")
                    hostname = dash_labels.get(f"{label_prefix}hostname")
                    tunnel_name = dash_labels.get(f"{label_prefix}tunnel")

                    if hostname:
                        remove_access_application(hostname)
                    if tunnel_name and hostname:
                        remove_ingress_rule(tunnel_name, hostname)
            # Clean up status tracking
            _container_status.pop(container_id, None)


def _reconcile_loop(docker_client):
    """
    Periodically reconcile local state with actually running containers.
    Catches containers missed while the event stream was disconnected.
    """
    if _reconcile_interval_seconds <= 0:
        logging.info("Container reconciliation disabled (RECONCILE_INTERVAL <= 0).")
        return

    logging.info(f"Starting periodic container reconciliation (interval: {_reconcile_interval_seconds}s)...")
    while not _listener_stop_event.is_set():
        _listener_stop_event.wait(_reconcile_interval_seconds)
        if _listener_stop_event.is_set():
            break
        try:
            running_containers = docker_client.containers.list()
            running_ids = {c.id for c in running_containers}
            with _state_lock:
                tracked_ids = set(_container_ingress_state.keys())

            # Process any running containers we may have missed
            for container in running_containers:
                if container.id not in tracked_ids:
                    logging.info(f"Reconciliation: found un-tracked running container {container.name} ({container.id[:12]}).")
                    process_container(container)

            # Remove ingress rules for tracked containers that are no longer running
            for missing_id in tracked_ids - running_ids:
                with _state_lock:
                    old_tunnel, old_hostname = _container_ingress_state.pop(missing_id)
                    _container_status.pop(missing_id, None)
                logging.info(f"Reconciliation: container {missing_id[:12]} is no longer running. Removing ingress rule: {old_hostname} from {old_tunnel}")
                remove_ingress_rule(old_tunnel, old_hostname)
                remove_access_application(old_hostname)
        except docker.errors.APIError as e:
            logging.error(f"Docker API error during reconciliation: {e}")
        except Exception as e:
            logging.error(f"Unexpected error during reconciliation: {e}", exc_info=True)


def _listen_for_events(docker_client):
    """
    Listen for Docker events with automatic reconnect on stream failure.
    """
    global _event_stream, _event_listener_running
    reconnect_delay = 1
    max_reconnect_delay = 30
    _event_listener_running = True

    try:
        while not _listener_stop_event.is_set():
            try:
                logging.info("Listening for Docker container events...")
                _event_stream = docker_client.events(decode=True)
                for event in _event_stream:
                    if _listener_stop_event.is_set():
                        break
                    try:
                        if event.get("Type") == "container":
                            _handle_container_event(docker_client, event)
                    except docker.errors.APIError as e:
                        logging.error(f"Docker API error during event processing: {e}")
                    except Exception as e:
                        logging.error(f"An unexpected error occurred while processing an event: {e}", exc_info=True)
                # Stream ended normally or was closed
                if _listener_stop_event.is_set():
                    break
                logging.warning("Docker event stream ended. Reconnecting...")
            except Exception as e:
                logging.error(f"Docker event stream error: {e}. Reconnecting in {reconnect_delay}s...")
            if _listener_stop_event.wait(reconnect_delay):
                break
            reconnect_delay = min(reconnect_delay * 2, max_reconnect_delay)
    finally:
        _event_listener_running = False


def start_event_listener():
    """
    Initializes docker client, scans existing containers, and listens for new
    container events indefinitely.
    """
    global _event_stream, _docker_client, _reconcile_thread
    docker_client = get_docker_client()
    if not docker_client:
        logging.critical("Could not connect to Docker. Exiting.")
        return
    
    _docker_client = docker_client
    _listener_stop_event.clear()

    # 1. Process already running containers
    logging.info("Scanning for existing containers...")
    for container in docker_client.containers.list():
        process_container(container)

    # 2. Start reconciliation thread
    _reconcile_thread = threading.Thread(target=_reconcile_loop, args=(docker_client,), name="ReconcileThread", daemon=True)
    _reconcile_thread.start()

    # 3. Listen for new events (blocking)
    try:
        _listen_for_events(docker_client)
    finally:
        _listener_stop_event.set()
        if _reconcile_thread and _reconcile_thread.is_alive():
            _reconcile_thread.join(timeout=5)