import docker
import logging
import os
import re
import threading
import time
from cloudflare_client import (
    add_or_update_ingress_rule, 
    add_or_update_access_application, 
    get_container_state_db,
    get_warp_state_db,
    reconcile_warp_profiles,
    remove_ingress_rule, 
    remove_access_application,
    resolve_device_policy_ids,
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

_TRAEFIK_HOST_CALL_RE = re.compile(r"Host\((.*?)\)", re.IGNORECASE)
_TRAEFIK_BACKTICK_HOST_RE = re.compile(r"`([^`]+)`")


def parse_warp_labels(dash_labels):
    """Parse Warp labels from docker.dash labels."""
    return {
        "enabled": dash_labels.get("docker.dash.warp", "false") == "true",
        "profiles": dash_labels.get("docker.dash.warp.profiles", ""),
    }


def extract_traefik_hostnames(container_labels):
    """Extract unique hostnames from traefik.http.routers.*.rule Host(...) expressions."""
    hostnames = set()
    for key, value in (container_labels or {}).items():
        if not (key.startswith("traefik.http.routers.") and key.endswith(".rule")):
            continue
        if not isinstance(value, str) or not value:
            continue

        for host_call in _TRAEFIK_HOST_CALL_RE.findall(value):
            for token in _TRAEFIK_BACKTICK_HOST_RE.findall(host_call):
                host = token.strip()
                if host:
                    hostnames.add(host)

    return sorted(hostnames)


def _cleanup_warp_for_container(container_id):
    """Remove all managed Warp routes for a container and reconcile affected profiles."""
    warp_db = get_warp_state_db()
    removed_routes = warp_db.delete_routes_for_container(container_id)
    affected_profiles = sorted({profile_id for profile_id, _hostname in removed_routes})
    if affected_profiles:
        reconcile_warp_profiles(affected_profiles)


def _cleanup_container_resources(container_id, fallback_state=None, fallback_labels=None):
    """Remove managed tunnel and Access resources for a container using persisted state when available."""
    container_db = get_container_state_db()
    managed_state = container_db.get_container_route(container_id)

    if managed_state:
        tunnel_name = managed_state["tunnel_name"]
        hostname = managed_state["hostname"]
        logging.info(
            f"Cleaning up managed tunnel/access state for container {container_id[:12]}: {hostname} from {tunnel_name}."
        )
        remove_ingress_rule(tunnel_name, hostname)
        remove_access_application(hostname)
        container_db.delete_container_route(container_id)
        return True

    if fallback_state:
        tunnel_name, hostname = fallback_state
        logging.info(
            f"Cleaning up in-memory tunnel/access state for container {container_id[:12]}: {hostname} from {tunnel_name}."
        )
        remove_ingress_rule(tunnel_name, hostname)
        remove_access_application(hostname)
        return True

    if fallback_labels:
        label_prefix = "docker.dash."
        if fallback_labels.get(f"{label_prefix}enable") == "true":
            hostname = fallback_labels.get(f"{label_prefix}hostname")
            tunnel_name = fallback_labels.get(f"{label_prefix}tunnel")
            if hostname:
                logging.info(
                    f"Cleaning up label-derived Access Application for container {container_id[:12]}: {hostname}."
                )
                remove_access_application(hostname)
            if tunnel_name and hostname:
                logging.info(
                    f"Cleaning up label-derived ingress rule for container {container_id[:12]}: {hostname} from {tunnel_name}."
                )
                remove_ingress_rule(tunnel_name, hostname)
            return bool(hostname and tunnel_name)

    return False


def _reconcile_container_warp_state(container_id, container_name, container_labels, dash_labels):
    """Reconcile desired Warp routes for this container against persistent state and Cloudflare."""
    warp_cfg = parse_warp_labels(dash_labels)
    warp_db = get_warp_state_db()
    current_routes = set(warp_db.get_routes_for_container(container_id))

    if not warp_cfg["enabled"]:
        if current_routes:
            logging.info(f"Warp disabled for '{container_name}'. Cleaning up {len(current_routes)} managed route(s).")
            _cleanup_warp_for_container(container_id)
        return {"enabled": False, "misconfigured": False, "active": False}

    desired_hostnames = extract_traefik_hostnames(container_labels)
    profile_ids = resolve_device_policy_ids(warp_cfg["profiles"])

    if not desired_hostnames or not profile_ids:
        if current_routes:
            logging.warning(
                f"Warp enabled for '{container_name}' but configuration is incomplete. Removing existing managed routes."
            )
            _cleanup_warp_for_container(container_id)
        return {
            "enabled": True,
            "misconfigured": True,
            "active": False,
            "reason": "Missing Traefik Host(...) rules or unresolved warp profiles",
        }

    desired_routes = {(profile_id, hostname) for profile_id in profile_ids for hostname in desired_hostnames}

    removed = current_routes - desired_routes
    added = desired_routes - current_routes

    for profile_id, hostname in removed:
        warp_db.remove_route(container_id, profile_id, hostname)
    for profile_id, hostname in added:
        warp_db.upsert_route(container_id, profile_id, hostname)

    affected_profiles = sorted({profile_id for profile_id, _hostname in removed | added})
    if affected_profiles:
        reconcile_warp_profiles(affected_profiles)
        logging.info(
            f"Reconciled Warp state for '{container_name}' ({len(added)} added, {len(removed)} removed, {len(affected_profiles)} profile(s) touched)."
        )

    return {
        "enabled": True,
        "misconfigured": False,
        "active": True,
        "hostnames": desired_hostnames,
        "profile_count": len(profile_ids),
    }


def _reconcile_warp_tunnel_routes(container_name, dash_labels, warp_state):
    """Ensure Traefik-derived Warp hostnames have tunnel ingress routes when tunnel/service are provided."""
    if not warp_state.get("enabled"):
        return

    hostnames = warp_state.get("hostnames", [])
    if not hostnames:
        return

    tunnel_name = dash_labels.get("docker.dash.tunnel")
    service = dash_labels.get("docker.dash.service")
    if not tunnel_name or not service:
        logging.debug(
            f"Warp is enabled for '{container_name}' but docker.dash.tunnel/service is missing; skipping private hostname tunnel route reconciliation."
        )
        return

    if service.endswith('/'):
        service = service.rstrip('/')

    for hostname in hostnames:
        add_or_update_ingress_rule(tunnel_name, {"hostname": hostname, "service": service})

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

        warp_state = _reconcile_container_warp_state(container_id, container.name, container_labels, dash_labels)

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
                _cleanup_container_resources(container_id, fallback_state=old_state, fallback_labels=dash_labels)

            # If the container is not enabled or is missing labels, we are done.
            if not is_enabled:
                # Determine if disabled or misconfigured
                if enable_label != "true":
                    logging.debug(f"Container '{container.name}' is disabled (docker.dash.enable != true). Skipping.")
                    _container_status[container_id] = {
                        "name": container.name,
                        "status": "disabled",
                        "reason": "docker.dash.enable is not set to 'true'",
                        "labels": dash_labels,
                        "warp_enabled": warp_state.get("enabled", False),
                        "warp_active": warp_state.get("active", False),
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
                        "labels": dash_labels,
                        "warp_enabled": warp_state.get("enabled", False),
                        "warp_active": warp_state.get("active", False),
                    }
                _cleanup_container_resources(container_id, fallback_state=old_state, fallback_labels=dash_labels)
                _container_ingress_state.pop(container_id, None) # Clean up state
                _last_processed_time[container_id] = current_time
                return

            _reconcile_warp_tunnel_routes(container.name, dash_labels, warp_state)

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

        container_db = get_container_state_db()

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

            try:
                container_db.upsert_container_route(container_id, new_tunnel_name, new_hostname, new_service)
            except Exception as db_error:
                logging.error(f"Failed to persist managed tunnel/access state for '{container.name}': {db_error}")

            # Update container status to active
            _container_status[container_id] = {
                "name": container.name,
                "status": "active",
                "tunnel": new_tunnel_name,
                "hostname": new_hostname,
                "service": new_service,
                "has_access_policy": bool(access_policy),
                "labels": dash_labels,
                "warp_enabled": warp_state.get("enabled", False),
                "warp_active": warp_state.get("active", False),
                "warp_hostnames": warp_state.get("hostnames", []),
                "warp_profile_count": warp_state.get("profile_count", 0),
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

    def _cleanup_container_tracking(container_id, *, labels=None, fallback_state=None):
        _cleanup_warp_for_container(container_id)
        with _state_lock:
            if container_id in _container_ingress_state:
                old_tunnel, old_hostname = _container_ingress_state.pop(container_id)
                logging.info(
                    f"Container {container_id[:12]} stopped. Removing ingress rule: {old_hostname} from {old_tunnel}"
                )
                _cleanup_container_resources(container_id, fallback_state=(old_tunnel, old_hostname))
            else:
                _cleanup_container_resources(
                    container_id,
                    fallback_state=fallback_state,
                    fallback_labels=labels,
                )
            _container_status.pop(container_id, None)
            _last_processed_time.pop(container_id, None)

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
    elif action in {"stop", "die", "destroy", "kill"}:
        if not container_id:
            logging.warning(f"Received {action} event with no container ID. Event: {event}")
            return
        attributes = event.get("Actor", {}).get("Attributes", {})
        label_prefix = "docker.dash."
        dash_labels = {
            k: v for k, v in attributes.items() if k.startswith(label_prefix)
        }
        _cleanup_container_tracking(container_id, labels=dash_labels)


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
            container_db = get_container_state_db()
            db_tracked_ids = {row["container_id"] for row in container_db.list_container_routes()}
            for missing_id in (tracked_ids | db_tracked_ids) - running_ids:
                _cleanup_warp_for_container(missing_id)
                with _state_lock:
                    old_state = _container_ingress_state.pop(missing_id, None)
                    _container_status.pop(missing_id, None)
                _cleanup_container_resources(missing_id, fallback_state=old_state)
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

    # Clean up any managed tunnel/access resources whose containers are no longer running.
    try:
        running_container_ids = {container.id for container in docker_client.containers.list()}
        container_db = get_container_state_db()
        for record in container_db.list_container_routes():
            if record["container_id"] not in running_container_ids:
                _cleanup_warp_for_container(record["container_id"])
                _cleanup_container_resources(record["container_id"])
    except Exception as e:
        logging.warning(f"Initial managed resource reconciliation skipped due to error: {e}")

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