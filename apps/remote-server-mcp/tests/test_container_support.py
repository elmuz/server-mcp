"""Container-oriented configuration and token-file tests."""

import asyncio
from pathlib import Path
from unittest.mock import AsyncMock

import pytest

from remote_server_mcp import server


def _config(tmp_path: Path, text: str) -> Path:
    path = tmp_path / "config.yaml"
    path.write_text(text)
    return path


def _token(tmp_path: Path, content: str = "secret\n") -> Path:
    path = tmp_path / "token"
    path.write_text(content)
    path.chmod(0o600)
    return path


def test_check_config_accepts_a_local_stdio_config(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("SERVER_MCP_CONTAINER", raising=False)
    path = _config(
        tmp_path,
        "executor: local\nsecurity:\n  services_path: /srv\n"
        "transport:\n  type: stdio\n",
    )

    assert server.check_config(path) == 0
    assert "Configuration OK" in capsys.readouterr().out


def test_check_config_rejects_local_executor_in_a_container(
    tmp_path, monkeypatch, capsys
):
    monkeypatch.setenv("SERVER_MCP_CONTAINER", "1")
    path = _config(
        tmp_path,
        "executor: local\nsecurity:\n  services_path: /srv\n"
        "transport:\n  type: stdio\n",
    )

    assert server.check_config(path) == 2
    assert "executor: local" in capsys.readouterr().err


def test_check_config_accepts_a_token_file(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("SERVER_MCP_CONTAINER", raising=False)
    token = _token(tmp_path)
    path = _config(
        tmp_path,
        "executor: local\nsecurity:\n  services_path: /srv\n"
        "transport:\n  type: streamable-http\n  host: 0.0.0.0\n"
        f"  token_file: {token}\n",
    )

    assert server.check_config(path) == 0
    assert "token: file" in capsys.readouterr().out


def test_check_config_rejects_a_missing_token_file(tmp_path, monkeypatch, capsys):
    monkeypatch.delenv("SERVER_MCP_CONTAINER", raising=False)
    path = _config(
        tmp_path,
        "executor: local\nsecurity:\n  services_path: /srv\n"
        "transport:\n  type: streamable-http\n  host: 0.0.0.0\n"
        f"  token_file: {tmp_path / 'missing'}\n",
    )

    assert server.check_config(path) == 2
    assert "Cannot read HTTP token file" in capsys.readouterr().err


def _patch_main(monkeypatch, config: dict) -> None:
    monkeypatch.setattr(server, "apply_config", lambda path: Path("/tmp/c.yaml"))
    monkeypatch.setattr(server, "open_metric_tunnels", AsyncMock(return_value=[]))
    monkeypatch.setattr(server, "close_metric_clients", AsyncMock())
    monkeypatch.setattr(server, "close_metric_tunnels", AsyncMock())
    stub_executor = AsyncMock()
    stub_executor.execute_safe_command.return_value = "ok"
    monkeypatch.setattr(server, "executor", stub_executor)
    monkeypatch.setattr(server, "config", config)


def test_main_resolves_the_token_file(tmp_path, monkeypatch):
    monkeypatch.delenv("SERVER_MCP_CONTAINER", raising=False)
    token = _token(tmp_path)
    captured = {}

    async def fake_http(*args, **kwargs):
        captured.update(kwargs)

    monkeypatch.setattr(server, "run_streamable_http", fake_http)
    _patch_main(
        monkeypatch,
        {
            "transport": {
                "type": "streamable-http",
                "host": "127.0.0.1",
                "port": 8000,
                "path": "/mcp",
                "token_file": str(token),
            }
        },
    )

    asyncio.run(server.main(transport="streamable-http"))

    assert captured["token"] == "secret"


def test_main_rejects_an_unreadable_token_file(tmp_path, monkeypatch):
    monkeypatch.delenv("SERVER_MCP_CONTAINER", raising=False)
    missing = tmp_path / "missing"
    _patch_main(
        monkeypatch,
        {
            "transport": {
                "type": "streamable-http",
                "host": "127.0.0.1",
                "token_file": str(missing),
            }
        },
    )

    with pytest.raises(SystemExit) as excinfo:
        asyncio.run(server.main(transport="streamable-http"))

    assert excinfo.value.code == 2
