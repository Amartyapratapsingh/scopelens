"""Unavailable worker daemons settle through the coordinator failure path."""

from unittest.mock import patch

import docker
import pytest

from scopelens.config import Settings
from scopelens.execution.supervisor import DockerWorkerSupervisor, SupervisorError, WorkerSpec


def test_docker_initialization_failure_uses_supervisor_error_without_exception_details():
    supervisor = DockerWorkerSupervisor(Settings(_env_file=None))
    with (
        patch(
            "docker.from_env", side_effect=docker.errors.DockerException("private daemon detail")
        ),
        pytest.raises(
            SupervisorError, match="configured worker Docker daemon unavailable"
        ) as error,
    ):
        _ = supervisor.client
    assert "private daemon detail" not in str(error.value)


def test_followup_and_browser_request_limits_are_admitted_worker_environment():
    supervisor = DockerWorkerSupervisor(Settings(_env_file=None))
    spec = WorkerSpec(
        image="image",
        command=["python", "-m", "scopelens.orchestration.expansion"],
        environment={"SCOPELENS_FOLLOWUP_INPUT": "{}", "SCOPELENS_BROWSER_MAX_REQUESTS": "6"},
        network="isolated",
    )
    kwargs = supervisor._container_kwargs(spec)
    assert kwargs["environment"] == spec.environment
    assert not kwargs["privileged"]
