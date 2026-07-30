from unittest.mock import MagicMock, Mock, patch

import pytest

import docker_client


def make_service(service_id="svc-id", task_labels=None, deploy_labels=None, replicas=1):
    service = Mock()
    service.id = service_id
    service.name = "stack_app"
    service.attrs = {
        "Spec": {
            "Name": "stack_app",
            "Labels": deploy_labels or {},
            "TaskTemplate": {
                "ContainerSpec": {"Labels": task_labels or {}}
            },
            "Mode": {"Replicated": {"Replicas": replicas}},
        }
    }
    return service


def test_discovery_mode_defaults_to_containers(monkeypatch):
    monkeypatch.delenv("SWARM_DISCOVERY_MODE", raising=False)
    client = MagicMock()
    client.info.return_value = {
        "Swarm": {"LocalNodeState": "active", "ControlAvailable": True}
    }
    assert docker_client._get_swarm_discovery_mode(client) == "containers"


def test_auto_uses_manager_only_when_control_available(monkeypatch):
    monkeypatch.setenv("SWARM_DISCOVERY_MODE", "auto")
    client = MagicMock()
    client.info.return_value = {
        "Swarm": {"LocalNodeState": "active", "ControlAvailable": True}
    }
    assert docker_client._get_swarm_discovery_mode(client) == "manager"
    client.info.return_value["Swarm"]["ControlAvailable"] = False
    assert docker_client._get_swarm_discovery_mode(client) == "containers"


def test_manager_mode_requires_manager(monkeypatch):
    monkeypatch.setenv("SWARM_DISCOVERY_MODE", "manager")
    client = MagicMock()
    client.info.return_value = {
        "Swarm": {"LocalNodeState": "active", "ControlAvailable": False}
    }
    with pytest.raises(RuntimeError):
        docker_client._get_swarm_discovery_mode(client)


def test_task_labels_override_deploy_labels():
    service = make_service(
        task_labels={
            "docker.dash.hostname": "task.example.com",
            "docker.dash.enable": "true",
        },
        deploy_labels={
            "docker.dash.hostname": "deploy.example.com",
            "docker.dash.tunnel": "tunnel",
        },
    )
    labels = docker_client._effective_service_labels(service)
    assert labels["docker.dash.hostname"] == "task.example.com"
    assert labels["docker.dash.tunnel"] == "tunnel"


def test_service_owner_is_stable_and_scale_zero_is_desired():
    owner = docker_client._service_owner(make_service(replicas=0))
    assert owner.id == "swarm-service:svc-id"
    assert owner.owner_kind == "swarm_service"
    assert owner.replicas_desired == 0


def test_manager_reconcile_ignores_local_tasks_and_is_desired_first(monkeypatch):
    monkeypatch.setattr(docker_client, "_container_status", {})
    monkeypatch.setattr(docker_client, "_container_ingress_state", {})
    monkeypatch.setattr(docker_client, "_last_processed_time", {})
    service = make_service()
    swarm_task = Mock()
    swarm_task.id = "task-id"
    swarm_task.labels = {"com.docker.swarm.service.id": service.id}
    standalone = Mock()
    standalone.id = "standalone-id"
    standalone.labels = {}
    client = MagicMock()
    client.services.list.return_value = [service]
    client.containers.list.return_value = [swarm_task, standalone]

    db = docker_client.get_container_state_db()
    db.upsert_route_claim(
        "swarm-service:old", "swarm_service", "tunnel", "old.example.com"
    )
    calls = []

    def process(owner, **kwargs):
        calls.append(("process", owner.id))

    monkeypatch.setattr(docker_client, "process_container", process)
    monkeypatch.setattr(
        docker_client, "_retire_absent_owner",
        lambda owner_id: calls.append(("retire", owner_id)),
    )
    monkeypatch.setattr(docker_client, "_run_due_cleanup_jobs", lambda: None)

    desired = docker_client._reconcile_manager_desired_state(client)

    assert desired == {"swarm-service:svc-id", "standalone-id"}
    assert calls == [
        ("process", "swarm-service:svc-id"),
        ("process", "standalone-id"),
        ("retire", "swarm-service:old"),
    ]


def test_service_remove_retires_but_does_not_enqueue(monkeypatch):
    owner_id = "swarm-service:svc-id"
    db = docker_client.get_container_state_db()
    db.upsert_route_claim(
        owner_id, "swarm_service", "tunnel", "app.example.com"
    )
    monkeypatch.setattr(docker_client, "_container_status", {})
    reconcile = Mock()
    monkeypatch.setattr(
        docker_client, "_reconcile_manager_desired_state", reconcile
    )
    client = MagicMock()

    with patch.object(db, "mark_resource_cleanup_pending") as enqueue:
        docker_client._handle_service_event(
            client,
            {"Type": "service", "Action": "remove", "Actor": {"ID": "svc-id"}},
        )

    assert db.get_route_claim(owner_id)["lifecycle_state"] == "retired"
    assert docker_client._container_status[owner_id]["status"] == "cleanup_pending"
    enqueue.assert_not_called()
    reconcile.assert_called_once_with(client)


def test_service_remove_reconciles_when_periodic_interval_is_disabled(monkeypatch):
    monkeypatch.setattr(docker_client, "_reconcile_interval_seconds", 0)
    reconcile = Mock()
    monkeypatch.setattr(
        docker_client, "_reconcile_manager_desired_state", reconcile
    )
    client = MagicMock()

    docker_client._handle_service_event(
        client,
        {"Type": "service", "Action": "remove", "Actor": {"ID": "svc-id"}},
    )

    reconcile.assert_called_once_with(client)
