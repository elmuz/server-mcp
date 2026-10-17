# Getting Started

## Production vs Development Installation

### Development (Recommended for Building)

```bash
cd disk-health-mcp
uv pip install -e ".[dev]" --python .venv
```

Editable install with all dev dependencies (tests, linting, type checking).

### Production (Running as MCP Server)

```bash
uv pip install -e . --python .venv
```

Minimal dependencies without dev tools.

## Configuration

Copy and edit the configuration:

```bash
cp config.example.yaml config.yaml
nano config.yaml
```

### SSH Configuration

```yaml
ssh:
  host: "your-server.example.com"
  port: 22
  username: "your-user"
  key_path: "~/.ssh/id_ed25519"
```

### Data Sources

Enable at least one data source:

```yaml
# Host-based (via SSH)
host:
  enabled: true

# Prometheus (optional)
prometheus:
  enabled: false
  host: "prometheus.example.com"
  port: 443
  use_https: true
  token: "your-token"

# InfluxDB (optional)
influxdb:
  enabled: false
  host: "influxdb.example.com"
  port: 443
  use_https: true
  database: "telegraf"
  token: "your-token"
  query_limit: 1000
```

## Qwen Code Integration

The MCP server is configured in `.qwen/settings.json`:

```json
{
  "mcpServers": {
    "disk-health": {
      "command": "uv",
      "args": ["run", "python", "-m", "disk_health_mcp.server"],
      "cwd": "/path/to/disk-health-mcp"
    }
  }
}
```

Just restart Qwen Code after setup.

## Standalone Running

For debugging:

```bash
uv run python -m disk_health_mcp.server
```

This starts the MCP server using stdio transport.

## Verification

```bash
# Run all tests
uv run pytest tests/ -v

# List registered tools
uv run python test_tools.py

# Test SSH connection
uv run python -c "
import asyncio
from disk_health_mcp.config import load_config
from pathlib import Path

config = load_config(Path('config.yaml'))
from disk_health_mcp.security import SecurityValidator
from disk_health_mcp.ssh_manager import SSHManager

security = SecurityValidator(config)
manager = SSHManager(config, security)

async def test():
    await manager.connect()
    result = await manager.execute_safe_command('lsblk -d --json')
    print(result[:500])
    await manager.disconnect()

asyncio.run(test())
"
```

## Troubleshooting

| Problem | Solution |
|---------|----------|
| Qwen doesn't see tools | Restart Qwen Code, check `.qwen/settings.json` |
| SSH connection fails | Test manually: `ssh -i ~/.ssh/id_ed25519 user@host` |
| SMART data returns empty | Drive may not support SMART: `smartctl -i /dev/sdX` |
| smartctl/nvme-cli permission errors | These tools require root. Either: configure InfluxDB/Telegraf (no sudo needed), or grant passwordless sudo for smartctl |
| nvme commands fail | `nvme-cli` not installed: `apt install nvme-cli` |
| ZFS commands fail | ZFS not installed on target host |
| Tests failing | `uv run pytest tests/ -v --tb=short` for details |
