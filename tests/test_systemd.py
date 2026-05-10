from __future__ import annotations

from hbse.core.systemd import install_broker_service, render_broker_service, render_broker_socket


def test_render_user_broker_service_starts_broker_with_selected_paths() -> None:
    service = render_broker_service(
        scope="user",
        broker_executable="/opt/hbse/bin/hbse-broker",
        vault_path="/home/alice/.local/share/hbse/vault.db",
        socket_path="%t/hbse/broker.sock",
        idle_timeout_seconds=900,
    )

    assert "ExecStart=/opt/hbse/bin/hbse-broker --vault /home/alice/.local/share/hbse/vault.db --socket %t/hbse/broker.sock --idle-timeout-seconds 900" in service
    assert "WantedBy=default.target" in service
    assert "NoNewPrivileges=true" in service
    assert "ReadWritePaths=/home/alice/.local/share/hbse %t/hbse" in service


def test_render_system_broker_service_can_run_at_boot_as_service_user() -> None:
    service = render_broker_service(
        scope="system",
        broker_executable="/opt/hbse/bin/hbse-broker",
        vault_path="/var/lib/hbse/vault.db",
        socket_path="/run/hbse/broker.sock",
        idle_timeout_seconds=900,
        service_user="hbse",
    )
    socket = render_broker_socket(scope="system", socket_path="/run/hbse/broker.sock")

    assert "User=hbse" in service
    assert "WantedBy=multi-user.target" in service
    assert "StateDirectory=hbse" in service
    assert "RuntimeDirectory=hbse" in service
    assert "ListenStream=/run/hbse/broker.sock" in socket
    assert "WantedBy=sockets.target" in socket


def test_install_broker_service_dry_run_reports_paths_without_writing(tmp_path) -> None:
    result = install_broker_service(
        scope="user",
        unit_dir=tmp_path / "systemd/user",
        broker_executable="/opt/hbse/bin/hbse-broker",
        vault_path=str(tmp_path / "vault.db"),
        socket_path=str(tmp_path / "broker.sock"),
        idle_timeout_seconds=30,
        enable=True,
        start=True,
        dry_run=True,
    )

    assert result.enabled is False
    assert result.started is False
    assert result.commands == []
    assert result.service_path.endswith("hbse-broker.service")
    assert result.socket_path.endswith("hbse-broker.socket")
    assert not (tmp_path / "systemd/user/hbse-broker.service").exists()
