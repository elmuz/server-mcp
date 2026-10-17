# Getting Started

## Installation

### Production

```bash
uv pip install -e . --python .venv
```

### Development

```bash
uv pip install -e ".[dev]" --python .venv
pre-commit install
```

Dev dependencies include **pytest**, **ruff** (linter/formatter), **ty** (type checker), and **pre-commit** (git hooks).

## Configuration

1. Copy the example config:

   ```bash
   cp config.example.yaml config.yaml
   ```

2. Edit `config.yaml` with your server details:

   ```yaml
   ssh:
     host: "your-server.example.com"
     port: 22
     username: "your-username"

     # Option 1: SSH key (recommended)
     key_path: "~/.ssh/id_rsa"

     # Option 2: Password (less secure)
     # password: "your-password"

   security:
     services_path: "/srv"  # All operations restricted to this path
     allow_generic_commands: false  # NEVER enable
   ```

## Running

### With Qwen Code

Add to `.qwen/settings.json`:

```json
{
  "mcpServers": {
    "remote-server": {
      "command": "uv",
      "args": ["run", "python", "-m", "remote_server_mcp.server"],
      "cwd": "/path/to/remote-server-mcp"
    }
  }
}
```

Then restart Qwen Code.

### Standalone (testing)

```bash
uv run python -m remote_server_mcp.server
```

## Verifying

```bash
# Run all tests
uv run pytest tests/ -v
```

## Troubleshooting

| Symptom | Fix |
|---------|-----|
| Tests failing | Run `uv run pytest tests/test_security.py -v` |
| Connection errors | Test SSH manually: `ssh -i ~/.ssh/id_rsa user@host` |
| Tools not appearing | Restart Qwen Code; verify `config.yaml` exists |
| "p must be exactly 1024, 2048, 3072, or 4096 bits" | Known asyncssh + ML-KEM issue; server handles this automatically by disabling known_hosts checking (TOFU trade-off) |
