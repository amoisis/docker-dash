import docker
import logging
import os
import re
import threading
import time
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from cloudflare_client import (
    add_or_update_ingress_rule, 
    add_or_update_access_application, 
    ensure_private_hostname_route,
    get_container_state_db,
    get_warp_state_db,
    reconcile_warp_profiles,
    remove_cname_record,
    remove_ingress_rule, 
    remove_access_application,
    remove_private_hostname_route,
)

# Debounce settings
_last_processed_time = {}
_container_ingress_state = {}
_debounce_delay_seconds = 10

# Container status tracking for diagnostics
_container_status = {}
_deferred_cleanup_ids = set()

# Event listener control
_event_stream = None
_docker_client = None
_listener_stop_event = threading.Event()
_reconcile_thread = None
_reconcile_interval_seconds = int(os.environ.get("RECONCILE_INTERVAL", "60"))
_event_listener_running = False

# Thread safety for shared state
_state_lock = threading.Lock()
_cleanup_lock = threading.Lock()

_TRAEFIK_HOST_CALL_RE = re.compile(r"Host\((.*?)\)", re.IGNORECASE)
_TRAEFIK_BACKTICK_HOST_RE = re.compile(r"`([^`]+)`")


def _is_swarm_manager(docker_client):
    """Return True only when this daemon exposes the Swarm manager API."""
    try:
        swarm = (docker_client.info() or {}).get("Swarm") or {}
        return (
            swarm.get("LocalNodeState") == "active"
            and bool(swarm.get("ControlAvailable"))
        )
    except (docker.errors.APIError, docker.errors.DockerException):
        return False


def _get_swarm_discovery_mode(docker_client):
    configured = os.environ.get("SWARM_DISCOVERY_MODE", "containers").lower()
    if configured not in {"containers", "manager", "auto"}:
        raise ValueError(
            "SWARM_DISCOVERY_MODE must be containers, manager, or auto"
        )
    manager = _is_swarm_manager(docker_client)
    if configured == "manager" and not manager:
        raise RuntimeError(
            "SWARM_DISCOVERY_MODE=manager requires Docker Dash to run on a Swarm manager"
        )
    return "manager" if configured == "manager" or (configured == "auto" and manager) else "containers"


def _effective_service_labels(service):
    """Merge deploy labels with task labels; top-level task labels win."""
    spec = (service.attrs or {}).get("Spec") or {}
    deploy_labels = spec.get("Labels") or {}
    container_spec = ((spec.get("TaskTemplate") or {}).get("ContainerSpec") or {})
    task_labels = container_spec.get("Labels") or {}
    for key in set(deploy_labels) & set(task_labels):
        if (
            key.startswith("docker.dash.")
            and deploy_labels[key] != task_labels[key]
        ):
            logging.warning(
                "Swarm service %s defines conflicting %s values; task label takes precedence.",
                getattr(service, "name", service.id),
                key,
            )
    return {**deploy_labels, **task_labels}


def _service_owner(service):
    """Adapt a Swarm service to the existing desired-owner processor."""
    owner_id = f"swarm-service:{service.id}"
    spec = (service.attrs or {}).get("Spec") or {}
    replicas = ((spec.get("Mode") or {}).get("Replicated") or {}).get("Replicas")
    return SimpleNamespace(
        id=owner_id,
        name=getattr(service, "name", None) or spec.get("Name") or service.id,
        labels=_effective_service_labels(service),
        owner_kind="swarm_service",
        replicas_desired=replicas,
    )


def _is_local_swarm_task(container):
    labels = container.labels or {}
    return bool(
        labels.get("com.docker.swarm.service.id")
        or labels.get("com.docker.swarm.service.name")
    )


def _resource_key(resource_type, hostname, tunnel_name=None):
    if resource_type in {"ingress", "hostname_route"}:
        return f"{resource_type}:{tunnel_name}:{hostname}"
    return f"{resource_type}:{hostname}"


def _record_managed_resource(
    container_db, resource_type, hostname, *, tunnel_name=None, operation_result=None
):
    """Record ownership without downgrading a resource previously known as created."""
    key = _resource_key(resource_type, hostname, tunnel_name)
    existing = container_db.get_resource(key)
    ownership = getattr(operation_result, "ownership", None)
    if ownership not in {"created", "adopted", "legacy_unknown"}:
        ownership = "legacy_unknown"
    result_remote_id = getattr(operation_result, "remote_id", None)
    result_outcome = getattr(operation_result, "outcome", None)
    result_original_state = getattr(operation_result, "original_state", None)
    if result_original_state is not None and not isinstance(
        result_original_state,
        (dict, list, tuple, str, int, float, bool, datetime),
    ):
        result_original_state = None
    if existing and existing["ownership"] == "created" and ownership != "created":
        same_remote = bool(
            result_remote_id
            and existing["remote_id"]
            and str(result_remote_id) == str(existing["remote_id"])
        )
        if resource_type == "access" and same_remote:
            ownership = "created"
        elif resource_type == "dns" and same_remote and result_outcome == "unchanged":
            ownership = "created"
        elif resource_type == "hostname_route" and same_remote:
            ownership = "created"
        elif resource_type == "ingress":
            previous = result_original_state or {}
            previous_fingerprint = None
            if previous:
                tunnel_id = str(result_remote_id or "").split("|", 1)[0]
                previous_fingerprint = (
                    f"{tunnel_id}|{hostname}|{previous.get('service')}"
                )
            if (
                (result_outcome == "unchanged" and same_remote)
                or previous_fingerprint == existing["remote_id"]
            ):
                ownership = "created"
    container_db.upsert_resource(
        key,
        resource_type,
        hostname,
        tunnel_name=tunnel_name,
        remote_id=result_remote_id
        or (existing and existing["remote_id"]),
        ownership=ownership,
        original_state_json=result_original_state
        or (existing and existing["original_state_json"]),
    )
    if hasattr(container_db, "cancel_cleanup"):
        container_db.cancel_cleanup(key)


def _enqueue_last_owner_cleanup(container_db, managed_state):
    """Retire a claim and enqueue cleanup only for last-owner resources we created."""
    container_id = managed_state["container_id"]
    tunnel_name = managed_state["tunnel_name"]
    hostname = managed_state["hostname"]
    container_db.retire_container_route(container_id)

    candidates = []
    if container_db.count_active_route_claims(tunnel_name, hostname) == 0:
        candidates.append(("ingress", tunnel_name))
    if container_db.count_active_hostname_claims(hostname) == 0:
        candidates.append(("dns", None))
    if (
        managed_state.get("access_desired")
        and container_db.count_active_access_claims(hostname) == 0
    ):
        candidates.append(("access", None))

    for resource_type, resource_tunnel in candidates:
        key = _resource_key(resource_type, hostname, resource_tunnel)
        resource = container_db.get_resource(key)
        if resource and resource["ownership"] == "created":
            container_db.mark_resource_cleanup_pending(key, f"remove_{resource_type}")


def _cleanup_retry_time(attempts):
    delay = min(3600, 5 * (2 ** min(attempts, 10)))
    return datetime.now(timezone.utc) + timedelta(seconds=delay)


def _run_due_cleanup_jobs():
    """Execute persisted cleanup jobs serially, with claim rechecks and retries."""
    if not _cleanup_lock.acquire(blocking=False):
        return
    try:
        container_db = get_container_state_db()
        for job in container_db.list_due_cleanup_jobs():
            key = job["resource_key"]
            resource_type = job["resource_type"]
            hostname = job["hostname"]
            tunnel_name = job["tunnel_name"]
            expected_action = f"remove_{resource_type}"
            if job["action"] != expected_action:
                container_db.record_cleanup_failure(
                    key,
                    f"Invalid cleanup action {job['action']} for {resource_type}",
                    _cleanup_retry_time(job["attempts"]),
                )
                continue

            # A desired-state pass may have changed the resource after the due
            # list was read. Re-fetch before making any remote mutation.
            current_resource = container_db.get_resource(key)
            if (
                not current_resource
                or current_resource["state"] not in {"cleanup_pending", "cleanup_failed"}
            ):
                continue

            has_owner = (
                container_db.count_active_route_claims(tunnel_name, hostname) > 0
                if resource_type == "ingress"
                else get_warp_state_db().count_private_hostname_claims(
                    tunnel_name, hostname
                ) > 0
                if resource_type == "hostname_route"
                else container_db.count_active_hostname_claims(hostname) > 0
                if resource_type == "dns"
                else container_db.count_active_access_claims(hostname) > 0
            )
            if has_owner:
                if hasattr(container_db, "cancel_cleanup"):
                    container_db.cancel_cleanup(key)
                continue
            if job["ownership"] != "created":
                if hasattr(container_db, "cancel_cleanup"):
                    container_db.cancel_cleanup(key)
                continue

            try:
                if resource_type == "ingress":
                    result = remove_ingress_rule(tunnel_name, hostname)
                elif resource_type == "dns":
                    result = remove_cname_record(
                        hostname, remote_id=current_resource["remote_id"]
                    )
                elif resource_type == "access":
                    result = remove_access_application(
                        hostname, remote_id=current_resource["remote_id"]
                    )
                elif resource_type == "hostname_route":
                    result = remove_private_hostname_route(
                        hostname,
                        tunnel_name,
                        remote_id=current_resource["remote_id"],
                    )
                else:
                    raise ValueError(f"Unsupported cleanup resource type: {resource_type}")

                if result and (result.success or result.confirmed_absent):
                    container_db.complete_cleanup(key)
                else:
                    error = getattr(result, "error", None) or getattr(
                        result, "outcome", "unknown cleanup failure"
                    )
                    container_db.record_cleanup_failure(
                        key, error, _cleanup_retry_time(job["attempts"])
                    )
            except Exception as error:
                container_db.record_cleanup_failure(
                    key, error, _cleanup_retry_time(job["attempts"])
                )
        container_db.delete_retired_claims_without_jobs()
    finally:
        _cleanup_lock.release()


def parse_warp_labels(dash_labels):
    """Parse private hostname routing labels."""
    return {
        "enabled": dash_labels.get("docker.dash.warp", "false") == "true",
        "tunnel": dash_labels.get("docker.dash.tunnel"),
        # Retained only to migrate entries created by releases <= v0.4.1.
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
    """Retire private hostname claims and migrate legacy Split Tunnel entries."""
    warp_db = get_warp_state_db()
    container_db = get_container_state_db()
    for tunnel_name, hostname in warp_db.get_private_hostname_claims(container_id):
        warp_db.remove_private_hostname_claim(container_id, tunnel_name, hostname)
        if warp_db.count_private_hostname_claims(tunnel_name, hostname) == 0:
            key = _resource_key("hostname_route", hostname, tunnel_name)
            resource = container_db.get_resource(key)
            if resource and resource["ownership"] == "created":
                container_db.mark_resource_cleanup_pending(
                    key, "remove_hostname_route"
                )
    _cleanup_legacy_warp_profile_claims(container_id)


def _cleanup_legacy_warp_profile_claims(owner_id):
    """Remove legacy per-host Split Tunnel entries and roll back on API failure."""
    warp_db = get_warp_state_db()
    legacy_routes = warp_db.get_routes_for_owner(owner_id)
    if not legacy_routes:
        return True
    for profile_id, hostname in legacy_routes:
        warp_db.remove_route(owner_id, profile_id, hostname)
    profiles = sorted({profile_id for profile_id, _hostname in legacy_routes})
    if reconcile_warp_profiles(profiles):
        logging.info(
            "Removed %d legacy per-host Warp Split Tunnel entries for '%s'.",
            len(legacy_routes),
            owner_id,
        )
        return True
    for profile_id, hostname in legacy_routes:
        warp_db.upsert_owner_route(owner_id, profile_id, hostname)
    logging.warning(
        "Could not remove legacy Warp Split Tunnel entries for '%s'; "
        "local claims were restored for a later retry.",
        owner_id,
    )
    return False


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
        _enqueue_last_owner_cleanup(container_db, managed_state)
        return True

    if fallback_state:
        tunnel_name, hostname = fallback_state
        logging.info(
            f"Cleaning up in-memory tunnel/access state for container {container_id[:12]}: {hostname} from {tunnel_name}."
        )
        logging.warning(
            "No persisted ownership exists for %s on %s; preserving remote resources.",
            hostname,
            tunnel_name,
        )
        return False

    if fallback_labels:
        label_prefix = "docker.dash."
        if fallback_labels.get(f"{label_prefix}enable") == "true":
            hostname = fallback_labels.get(f"{label_prefix}hostname")
            tunnel_name = fallback_labels.get(f"{label_prefix}tunnel")
            if hostname and tunnel_name:
                logging.warning(
                    "No persisted ownership exists for label-derived route %s on %s; "
                    "preserving remote resources.",
                    hostname,
                    tunnel_name,
                )
            return False

    return False


def _container_desires_route(container, tunnel_name, hostname):
    """Return whether a running container declares the same managed ingress route."""
    labels = container.labels or {}
    return (
        labels.get("docker.dash.enable") == "true"
        and labels.get("docker.dash.tunnel") == tunnel_name
        and labels.get("docker.dash.hostname") == hostname
        and bool(labels.get("docker.dash.service"))
    )


def _route_has_running_owner(docker_client, container_id, tunnel_name, hostname, running_containers=None):
    """
    Check whether another running container still owns a route.

    Swarm replaces task containers during rolling updates. The old task's terminal
    event must not remove a route already adopted by the replacement task.
    """
    try:
        containers = running_containers
        if containers is None:
            containers = docker_client.containers.list()
        return any(
            container.id != container_id
            and _container_desires_route(container, tunnel_name, hostname)
            for container in containers
        )
    except (docker.errors.APIError, docker.errors.DockerException) as error:
        logging.warning(
            "Could not verify whether route %s on tunnel %s has another running owner: %s. "
            "Preserving the route to avoid disrupting a Swarm replacement.",
            hostname,
            tunnel_name,
            error,
        )
        return True


def _cleanup_stopped_container_resources(
    docker_client,
    container_id,
    *,
    labels=None,
    fallback_state=None,
    running_containers=None,
):
    """Clean local state for a stopped container and remote state only when unowned."""
    container_db = get_container_state_db()
    managed_state = container_db.get_container_route(container_id)
    is_swarm_task = bool(
        labels
        and (
            labels.get("com.docker.swarm.service.id")
            or labels.get("com.docker.swarm.service.name")
        )
    )

    # Swarm's default update order is stop-first, so a replacement task may not
    # be running yet when the old task emits its terminal event. Leave the
    # persisted route for the periodic reconciler, which can make the decision
    # after the update has had time to advance.
    if is_swarm_task and managed_state and running_containers is None:
        logging.info(
            "Container %s is a stopped Swarm task; deferring remote route cleanup "
            "to reconciliation.",
            container_id[:12],
        )
        return False

    route_state = fallback_state
    if managed_state:
        route_state = (managed_state["tunnel_name"], managed_state["hostname"])
    elif not route_state and labels:
        if labels.get("docker.dash.enable") == "true":
            tunnel_name = labels.get("docker.dash.tunnel")
            hostname = labels.get("docker.dash.hostname")
            if tunnel_name and hostname:
                route_state = (tunnel_name, hostname)

    if route_state:
        tunnel_name, hostname = route_state
        if _route_has_running_owner(
            docker_client,
            container_id,
            tunnel_name,
            hostname,
            running_containers=running_containers,
        ):
            logging.info(
                "Container %s stopped, but route %s on tunnel %s is still owned by another "
                "running container; preserving Cloudflare resources.",
                container_id[:12],
                hostname,
                tunnel_name,
            )
            if managed_state:
                container_db.retire_container_route(container_id)
            return False

    return _cleanup_container_resources(
        container_id,
        fallback_state=fallback_state,
        fallback_labels=labels,
    )


def _reconcile_container_warp_state(container_id, container_name, container_labels, dash_labels):
    """Reconcile Traefik hostnames as Zero Trust private hostname routes."""
    warp_cfg = parse_warp_labels(dash_labels)
    warp_db = get_warp_state_db()
    current_routes = set(warp_db.get_private_hostname_claims(container_id))

    if not warp_cfg["enabled"]:
        if current_routes or warp_db.get_routes_for_owner(container_id):
            logging.info(
                "Private hostname routing disabled for '%s'. Cleaning up managed claims.",
                container_name,
            )
            _cleanup_warp_for_container(container_id)
        return {"enabled": False, "misconfigured": False, "active": False}

    desired_hostnames = extract_traefik_hostnames(container_labels)
    tunnel_name = warp_cfg["tunnel"]
    if warp_cfg["profiles"]:
        logging.warning(
            "docker.dash.warp.profiles on '%s' is deprecated and no longer "
            "mutates device profiles; configure WARP synthetic routes once "
            "at the account/profile level.",
            container_name,
        )

    if not desired_hostnames or not tunnel_name:
        if current_routes:
            logging.warning(
                "Private hostname routing for '%s' is incomplete. Removing stale claims.",
                container_name,
            )
            _cleanup_warp_for_container(container_id)
        return {
            "enabled": True,
            "misconfigured": True,
            "active": False,
            "reason": "Missing Traefik Host(...) rules or docker.dash.tunnel",
        }

    _cleanup_legacy_warp_profile_claims(container_id)
    desired_routes = {(tunnel_name, hostname) for hostname in desired_hostnames}
    failures = []
    applied = 0
    container_db = get_container_state_db()
    for desired_tunnel, hostname in sorted(desired_routes):
        result = ensure_private_hostname_route(hostname, desired_tunnel)
        if not result or not getattr(result, "success", False):
            failures.append(
                getattr(result, "error", None)
                or f"Failed to reconcile private hostname route for {hostname}"
            )
            continue
        _record_managed_resource(
            container_db,
            "hostname_route",
            hostname,
            tunnel_name=desired_tunnel,
            operation_result=result,
        )
        warp_db.upsert_private_hostname_claim(
            container_id, desired_tunnel, hostname
        )
        applied += 1

    removed = current_routes - desired_routes
    for old_tunnel, old_hostname in removed:
        warp_db.remove_private_hostname_claim(
            container_id, old_tunnel, old_hostname
        )
        if warp_db.count_private_hostname_claims(old_tunnel, old_hostname) == 0:
            key = _resource_key("hostname_route", old_hostname, old_tunnel)
            resource = container_db.get_resource(key)
            if resource and resource["ownership"] == "created":
                container_db.mark_resource_cleanup_pending(
                    key, "remove_hostname_route"
                )

    logging.info(
        "Reconciled private hostname routing for '%s' "
        "(%d applied, %d removed, %d failed).",
        container_name,
        applied,
        len(removed),
        len(failures),
    )

    return {
        "enabled": True,
        "misconfigured": False,
        "active": not failures and applied == len(desired_routes),
        "hostnames": desired_hostnames,
        "route_count": applied,
        "profile_count": 0,
        **({"reason": "; ".join(failures)} if failures else {}),
    }


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

def _process_container_locked(container, *, force=False):
    """
    Inspects a container for docker.dash labels and triggers Cloudflare updates.
    Includes a debounce mechanism and stateful cleanup of old rules.
    """
    container_id = container.id
    owner_kind = getattr(container, "owner_kind", "container")
    if owner_kind not in {"container", "swarm_service"}:
        # Mock-like objects and third-party Docker wrappers may synthesize an
        # attribute instead of raising AttributeError. Treat them as ordinary
        # containers unless they provide a supported explicit owner kind.
        owner_kind = "container"
    current_time = time.time()

    with _state_lock:
        # Debounce check
        last_time = _last_processed_time.get(container_id)
        if not force and last_time and (current_time - last_time) < _debounce_delay_seconds:
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
                    if warp_state.get("active"):
                        status = "active"
                        reason = "Private hostname routing is active; published routing is disabled"
                    elif warp_state.get("enabled") and warp_state.get("misconfigured"):
                        status = "misconfigured"
                        reason = warp_state.get(
                            "reason", "Private hostname routing is misconfigured"
                        )
                    elif warp_state.get("enabled"):
                        status = "error"
                        reason = warp_state.get(
                            "reason", "Private hostname routing failed"
                        )
                    else:
                        status = "disabled"
                        reason = "docker.dash.enable is not set to 'true'"
                    logging.debug(
                        "Container '%s' published routing is disabled; status=%s.",
                        container.name,
                        status,
                    )
                    _container_status[container_id] = {
                        "name": container.name,
                        "owner_id": container_id,
                        "owner_kind": owner_kind,
                        "status": status,
                        "reason": reason,
                        "labels": dash_labels,
                        "warp_enabled": warp_state.get("enabled", False),
                        "warp_active": warp_state.get("active", False),
                        "warp_hostnames": warp_state.get("hostnames", []),
                        "warp_route_count": warp_state.get("route_count", 0),
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
                        "owner_id": container_id,
                        "owner_kind": owner_kind,
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

            # Persist desired ownership before any ingress/DNS mutation. The
            # cleanup worker shares _cleanup_lock, so it cannot delete a route
            # between this claim and the Cloudflare apply.
            container_db = get_container_state_db()
            access_policy = dash_labels.get(
                f"{label_prefix}application.access.policy"
            )
            prior_managed_state = container_db.get_container_route(container_id)
            container_db.upsert_route_claim(
                container_id,
                owner_kind,
                new_tunnel_name,
                new_hostname,
                new_service,
                access_desired=bool(access_policy),
            )
        # Sanitize the service URL
        if new_service.endswith('/'):
            new_service = new_service.rstrip('/')
            logging.debug(f"Sanitized service URL for '{new_hostname}' to '{new_service}'")

        # Add/Update the new ingress rule
        new_rule = {"hostname": new_hostname, "service": new_service}
        ingress_result = add_or_update_ingress_rule(new_tunnel_name, new_rule)
        ingress_succeeded = bool(ingress_result) and getattr(
            ingress_result, "success", True
        )
        if not ingress_succeeded:
            with _state_lock:
                _container_status[container_id] = {
                    "name": container.name,
                    "owner_id": container_id,
                    "owner_kind": owner_kind,
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
                access_result = add_or_update_access_application(new_hostname, access_config)
                if access_result and getattr(access_result, "success", False) is True:
                    _record_managed_resource(
                        container_db,
                        "access",
                        new_hostname,
                        operation_result=access_result,
                    )

            try:
                container_db.upsert_route_claim(
                    container_id,
                    owner_kind,
                    new_tunnel_name,
                    new_hostname,
                    new_service,
                    access_desired=bool(access_policy),
                )
                if (
                    prior_managed_state
                    and prior_managed_state.get("access_desired")
                    and not access_policy
                    and container_db.count_active_access_claims(new_hostname) == 0
                ):
                    access_key = _resource_key("access", new_hostname)
                    access_resource = container_db.get_resource(access_key)
                    if access_resource and access_resource["ownership"] == "created":
                        container_db.mark_resource_cleanup_pending(
                            access_key, "remove_access"
                        )
                # Ingress/DNS creation APIs predate structured ownership
                # outcomes. Track them conservatively until those operations
                # can prove whether Docker Dash created or adopted them.
                _record_managed_resource(
                    container_db,
                    "ingress",
                    new_hostname,
                    tunnel_name=new_tunnel_name,
                    operation_result=ingress_result,
                )
                dns_result = getattr(ingress_result, "results", {}).get("dns")
                if dns_result and getattr(dns_result, "success", False):
                    _record_managed_resource(
                        container_db,
                        "dns",
                        new_hostname,
                        operation_result=dns_result,
                    )
            except Exception as db_error:
                logging.error(f"Failed to persist managed tunnel/access state for '{container.name}': {db_error}")

            # Update container status to active
            _container_status[container_id] = {
                "name": container.name,
                "owner_id": container_id,
                "owner_kind": owner_kind,
                "status": "active",
                "tunnel": new_tunnel_name,
                "hostname": new_hostname,
                "service": new_service,
                "has_access_policy": bool(access_policy),
                "labels": dash_labels,
                "warp_enabled": warp_state.get("enabled", False),
                "warp_active": warp_state.get("active", False),
                "warp_hostnames": warp_state.get("hostnames", []),
                "warp_route_count": warp_state.get("route_count", 0),
                "warp_profile_count": warp_state.get("profile_count", 0),
            }
            if owner_kind == "swarm_service":
                _container_status[container_id]["replicas_desired"] = getattr(
                    container, "replicas_desired", None
                )
            _last_processed_time[container_id] = current_time

    except Exception as e:
        logging.error(f"Error processing container {container_id[:12]}: {e}")


def process_container(container, *, force=False):
    """Serialize desired claims and Cloudflare apply against cleanup jobs."""
    with _cleanup_lock:
        return _process_container_locked(container, force=force)

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
        is_swarm_task = bool(
            labels
            and (
                labels.get("com.docker.swarm.service.id")
                or labels.get("com.docker.swarm.service.name")
            )
        )
        if is_swarm_task:
            # Swarm's default update order is stop-first. Keep the old task's
            # Warp ownership until reconciliation has processed its replacement,
            # otherwise the desired hostname can briefly disappear.
            with _state_lock:
                _deferred_cleanup_ids.add(container_id)
        else:
            _cleanup_warp_for_container(container_id)
        with _state_lock:
            if container_id in _container_ingress_state:
                old_tunnel, old_hostname = _container_ingress_state.pop(container_id)
                logging.info(
                    f"Container {container_id[:12]} stopped. Reconciling ingress rule: {old_hostname} from {old_tunnel}"
                )
                cleanup_state = (old_tunnel, old_hostname)
            else:
                cleanup_state = fallback_state
            _container_status.pop(container_id, None)
            _last_processed_time.pop(container_id, None)
        _cleanup_stopped_container_resources(
            docker_client,
            container_id,
            labels=labels,
            fallback_state=cleanup_state,
        )

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
        _cleanup_container_tracking(container_id, labels=attributes)


def _retire_absent_owner(owner_id):
    _cleanup_warp_for_container(owner_id)
    with _state_lock:
        old_state = _container_ingress_state.pop(owner_id, None)
        _container_status.pop(owner_id, None)
        _last_processed_time.pop(owner_id, None)
        _deferred_cleanup_ids.discard(owner_id)
    _cleanup_container_resources(owner_id, fallback_state=old_state)


def _reconcile_manager_desired_state(docker_client):
    """Reconcile stable service owners first, then retire absent owners."""
    services = docker_client.services.list()
    service_owners = [_service_owner(service) for service in services]
    local_containers = [
        container for container in docker_client.containers.list()
        if not _is_local_swarm_task(container)
    ]
    desired_ids = {owner.id for owner in service_owners}
    desired_ids.update(container.id for container in local_containers)

    # Desired-first ordering lets replacement/recreated owners cancel pending
    # outbox jobs before absent claims are retired.
    for owner in service_owners:
        process_container(owner, force=True)
    for container in local_containers:
        process_container(container)

    container_db = get_container_state_db()
    persisted_ids = {
        claim["owner_id"] for claim in container_db.list_route_claims()
    }
    warp_ids = set(get_warp_state_db().list_owner_ids())
    with _state_lock:
        tracked_ids = set(_container_status) | set(_container_ingress_state)
    for owner_id in (persisted_ids | warp_ids | tracked_ids) - desired_ids:
        _retire_absent_owner(owner_id)
    _run_due_cleanup_jobs()
    return desired_ids


def _handle_service_event(docker_client, event):
    action = event.get("Action")
    service_id = event.get("Actor", {}).get("ID") or event.get("id")
    if not service_id:
        logging.warning("Received service event with no service ID: %s", event)
        return
    owner_id = f"swarm-service:{service_id}"
    if action in {"remove", "destroy"}:
        # Retire immediately so it no longer counts as an active owner, but
        # defer Warp removal and cleanup enqueue to the next full desired-state
        # pass. This absorbs remove/recreate event races.
        get_container_state_db().retire_route_claim(owner_id)
        with _state_lock:
            _container_ingress_state.pop(owner_id, None)
            _last_processed_time.pop(owner_id, None)
            _container_status[owner_id] = {
                "owner_id": owner_id,
                "owner_kind": "swarm_service",
                "status": "cleanup_pending",
            }
        # Events remain useful when periodic reconciliation is intentionally
        # disabled. A desired-first manager scan also absorbs remove/recreate
        # races before it evaluates the retired claim.
        try:
            _reconcile_manager_desired_state(docker_client)
        except (docker.errors.APIError, docker.errors.DockerException) as error:
            logging.warning(
                "Immediate Swarm service removal reconciliation failed; "
                "the retired claim will be retried periodically: %s",
                error,
            )
        return
    if action in {"create", "update"}:
        try:
            process_container(_service_owner(docker_client.services.get(service_id)), force=True)
        except docker.errors.NotFound:
            _retire_absent_owner(owner_id)
        _run_due_cleanup_jobs()


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
            if _get_swarm_discovery_mode(docker_client) == "manager":
                _reconcile_manager_desired_state(docker_client)
                continue
            running_containers = docker_client.containers.list()
            running_ids = {c.id for c in running_containers}
            with _state_lock:
                # Status includes active, disabled, and misconfigured containers. Using
                # only ingress state made every unlabeled Swarm task look untracked on
                # every reconciliation pass.
                tracked_ids = set(_container_status.keys()) | set(_container_ingress_state.keys())

            # Process any running containers we may have missed
            for container in running_containers:
                if container.id not in tracked_ids:
                    logging.info(f"Reconciliation: found un-tracked running container {container.name} ({container.id[:12]}).")
                    process_container(container)

            # Remove ingress rules for tracked containers that are no longer running
            container_db = get_container_state_db()
            db_tracked_ids = {row["container_id"] for row in container_db.list_container_routes()}
            with _state_lock:
                deferred_cleanup_ids = set(_deferred_cleanup_ids)
            for missing_id in (tracked_ids | db_tracked_ids | deferred_cleanup_ids) - running_ids:
                _cleanup_warp_for_container(missing_id)
                with _state_lock:
                    old_state = _container_ingress_state.pop(missing_id, None)
                    _container_status.pop(missing_id, None)
                    _last_processed_time.pop(missing_id, None)
                    _deferred_cleanup_ids.discard(missing_id)
                _cleanup_stopped_container_resources(
                    docker_client,
                    missing_id,
                    fallback_state=old_state,
                    running_containers=running_containers,
                )
            # Desired owners and stale claims are reconciled before destructive
            # work so replacements can cancel jobs in the same pass.
            _run_due_cleanup_jobs()
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
                        event_type = event.get("Type")
                        mode = _get_swarm_discovery_mode(docker_client)
                        if event_type == "service" and mode == "manager":
                            _handle_service_event(docker_client, event)
                        elif event_type == "container":
                            attributes = event.get("Actor", {}).get("Attributes", {})
                            is_swarm_task = bool(
                                attributes.get("com.docker.swarm.service.id")
                                or attributes.get("com.docker.swarm.service.name")
                            )
                            if mode != "manager" or not is_swarm_task:
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
    try:
        discovery_mode = _get_swarm_discovery_mode(docker_client)
    except (RuntimeError, ValueError) as error:
        logging.critical("Docker discovery configuration is invalid: %s", error)
        return

    # Process running containers before stale ownership. During a Swarm rolling
    # update the persisted rows may reference old task IDs, while replacement
    # tasks already own the same desired routes under new IDs.
    try:
        if discovery_mode == "manager":
            _reconcile_manager_desired_state(docker_client)
            running_containers = None
        else:
            running_containers = docker_client.containers.list()
        if running_containers is None:
            pass
        else:
            running_container_ids = {container.id for container in running_containers}
            logging.info("Scanning for existing containers...")
            for container in running_containers:
                process_container(container)

            container_db = get_container_state_db()
            for record in container_db.list_container_routes():
                if record["container_id"] not in running_container_ids:
                    _cleanup_warp_for_container(record["container_id"])
                    _cleanup_stopped_container_resources(
                        docker_client,
                        record["container_id"],
                        running_containers=running_containers,
                    )
            _run_due_cleanup_jobs()
    except Exception as e:
        logging.warning(f"Initial managed resource reconciliation skipped due to error: {e}")

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
