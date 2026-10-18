"""
Tests for server_management_lib.config module.

Covers:
- Default configuration structure
- YAML config loading
- Edge cases (non-existent files, invalid YAML, valid overrides)
"""

from pathlib import Path

import pytest

from server_management_lib.config import DEFAULT_CONFIG, load_config


class TestDefaultConfiguration:
    """Test default configuration structure."""

    def test_has_all_sections(self):
        """Default config must have all expected sections."""
        assert "ssh" in DEFAULT_CONFIG
        assert "security" in DEFAULT_CONFIG
        assert "host" in DEFAULT_CONFIG
        assert "influxdb" in DEFAULT_CONFIG
        assert "prometheus" in DEFAULT_CONFIG
        assert "health" in DEFAULT_CONFIG

    def test_health_disk_paths_default_to_root(self):
        """get_server_health must have a disk path even without configuration."""
        assert DEFAULT_CONFIG["health"]["disk_paths"] == ["/"]

    def test_security_settings(self):
        """Generic command execution must be disabled by default."""
        assert DEFAULT_CONFIG["security"]["allow_generic_commands"] is False
        assert DEFAULT_CONFIG["security"]["host_units"] == [
            "telegraf",
            "smartd",
            "docker",
            "snapraid",
            "mergerfs",
            "smbd",
        ]

    def test_load_example_config(self):
        """Example config file should load without error."""
        example_path = Path(__file__).parent.parent / "config.example.yaml"
        if example_path.exists():
            config = load_config(example_path)
            assert "ssh" in config
            assert "security" in config


class TestConfigLoading:
    """Test config loading edge cases."""

    def test_load_nonexistent_config(self):
        """Loading non-existent config should return defaults."""
        result = load_config(Path("/nonexistent/path/config.yaml"))
        assert result == DEFAULT_CONFIG.copy()

    def test_load_invalid_yaml(self, tmp_path):
        """Loading invalid YAML should return defaults."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("invalid: yaml: content: [")

        result = load_config(config_file)
        assert result == DEFAULT_CONFIG.copy()

    def test_load_valid_config(self, tmp_path):
        """Loading valid config should override defaults."""
        config_file = tmp_path / "config.yaml"
        config_content = """
ssh:
  host: example.com
  port: 2222
security:
  services_path: /custom/srv
"""
        config_file.write_text(config_content)

        result = load_config(config_file)
        assert result["ssh"]["host"] == "example.com"
        assert result["ssh"]["port"] == 2222
        assert result["security"]["services_path"] == "/custom/srv"


class TestConfigResolution:
    """Test config path resolution (explicit, env var, XDG, cwd)."""

    def test_required_raises_when_missing(self, tmp_path, monkeypatch):
        """required=True must fail fast instead of using root@localhost defaults."""
        from server_management_lib.config import ConfigNotFoundError

        monkeypatch.chdir(tmp_path)
        monkeypatch.delenv("TEST_MCP_CONFIG", raising=False)
        with pytest.raises(ConfigNotFoundError, match="No configuration file found"):
            load_config(
                tmp_path / "missing.yaml",
                env_var="TEST_MCP_CONFIG",
                app_name="test-mcp",
                required=True,
            )

    def test_env_var_selects_config(self, tmp_path, monkeypatch):
        """The env var path must be used when no explicit path is given."""
        config_file = tmp_path / "config.yaml"
        config_file.write_text("ssh:\n  host: envvar.example.com\n")
        monkeypatch.chdir(
            tmp_path / "elsewhere" if (tmp_path / "elsewhere").mkdir() else tmp_path
        )
        monkeypatch.setenv("TEST_MCP_CONFIG", str(config_file))

        result = load_config(
            env_var="TEST_MCP_CONFIG", app_name="test-mcp", use_dotenv=False
        )
        assert result["ssh"]["host"] == "envvar.example.com"

    def test_xdg_config_is_used(self, tmp_path, monkeypatch):
        """$XDG_CONFIG_HOME/<app>/config.yaml must be discovered."""
        xdg = tmp_path / "xdg"
        config_dir = xdg / "test-mcp"
        config_dir.mkdir(parents=True)
        (config_dir / "config.yaml").write_text("ssh:\n  host: xdg.example.com\n")

        workdir = tmp_path / "work"
        workdir.mkdir()
        monkeypatch.chdir(workdir)
        monkeypatch.setenv("XDG_CONFIG_HOME", str(xdg))
        monkeypatch.delenv("TEST_MCP_CONFIG", raising=False)

        result = load_config(
            env_var="TEST_MCP_CONFIG", app_name="test-mcp", use_dotenv=False
        )
        assert result["ssh"]["host"] == "xdg.example.com"

    def test_explicit_path_wins(self, tmp_path, monkeypatch):
        """An explicit path must win over the env var."""
        explicit = tmp_path / "explicit.yaml"
        explicit.write_text("ssh:\n  host: explicit.example.com\n")
        other = tmp_path / "other.yaml"
        other.write_text("ssh:\n  host: env.example.com\n")
        monkeypatch.setenv("TEST_MCP_CONFIG", str(other))

        result = load_config(
            explicit, env_var="TEST_MCP_CONFIG", app_name="test-mcp", use_dotenv=False
        )
        assert result["ssh"]["host"] == "explicit.example.com"


class TestConfigMerging:
    """Test defaults merging, env overrides and edge cases."""

    def test_missing_keys_fall_back_to_defaults(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("ssh:\n  host: example.com\n")

        result = load_config(config_file, use_dotenv=False)
        assert result["ssh"]["host"] == "example.com"
        assert result["ssh"]["port"] == 22
        assert result["security"]["services_path"] == "/srv"
        assert result["influxdb"]["enabled"] is False

    def test_empty_section_keeps_defaults(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("influxdb:\nssh:\n  host: example.com\n")

        result = load_config(config_file, use_dotenv=False)
        assert isinstance(result["influxdb"], dict)
        assert result["influxdb"]["port"] == 8181

    def test_explicit_null_is_preserved(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("ssh:\n  known_hosts: null\n")

        result = load_config(config_file, use_dotenv=False)
        assert result["ssh"]["known_hosts"] is None

    def test_env_overrides_yaml(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("ssh:\n  host: from-yaml.example.com\n")

        result = load_config(
            config_file,
            use_dotenv=False,
            env={
                "SSH_HOST": "from-env.example.com",
                "SSH_PORT": "2222",
                "INFLUXDB_USE_HTTPS": "true",
                "PROMETHEUS_TOKEN": "secret",
            },
        )
        assert result["ssh"]["host"] == "from-env.example.com"
        assert result["ssh"]["port"] == 2222
        assert result["influxdb"]["use_https"] is True
        assert result["prometheus"]["token"] == "secret"

    def test_invalid_env_value_is_ignored(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("ssh:\n  port: 22\n")

        result = load_config(
            config_file, use_dotenv=False, env={"SSH_PORT": "not-a-port"}
        )
        assert result["ssh"]["port"] == 22

    def test_defaults_are_not_mutated(self, tmp_path):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("ssh:\n  host: example.com\n")

        result = load_config(config_file, use_dotenv=False)
        result["ssh"]["host"] = "mutated.example.com"
        assert DEFAULT_CONFIG["ssh"]["host"] == "localhost"

    def test_dotenv_next_to_config_is_loaded(self, tmp_path, monkeypatch):
        config_file = tmp_path / "config.yaml"
        config_file.write_text("ssh:\n  host: yaml.example.com\n")
        (tmp_path / ".env").write_text("SSH_HOST=dotenv.example.com\n")
        monkeypatch.delenv("SSH_HOST", raising=False)
        monkeypatch.setenv("XDG_CONFIG_HOME", str(tmp_path / "xdg-empty"))

        result = load_config(config_file, use_dotenv=True)
        assert result["ssh"]["host"] == "dotenv.example.com"

    def test_required_invalid_yaml_raises(self, tmp_path):
        from server_management_lib.config import ConfigError

        config_file = tmp_path / "config.yaml"
        config_file.write_text("invalid: yaml: content: [")

        with pytest.raises(ConfigError, match="Error loading config"):
            load_config(config_file, required=True, use_dotenv=False)

    def test_required_non_mapping_raises(self, tmp_path):
        from server_management_lib.config import ConfigError

        config_file = tmp_path / "config.yaml"
        config_file.write_text("- just\n- a\n- list\n")

        with pytest.raises(ConfigError, match="must be a YAML mapping"):
            load_config(config_file, required=True, use_dotenv=False)
