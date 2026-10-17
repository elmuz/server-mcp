# Quick Start Guide

## Your Disk Health MCP is Ready! 🎉

You now have a **security-first** MCP server for diagnosing disk health.

## What You Got

An MCP server that provides AI assistants with **safe, controlled diagnostics**:

### ✅ Available Operations

**Host-based** (SSH to target server):

- List all storage devices
- Analyze SMART data with manufacturer-aware normalization
- Get NVMe health logs
- Run SMART self-tests (short, long, conveyance)
- Check ZFS pool status
- Check mdadm RAID status
- Monitor I/O statistics

**Prometheus** (HTTP API):

- Query node_exporter smartmon metrics
- Query disk I/O metrics
- Query RAID metrics

**InfluxDB** (HTTP API):

- Query historical SMART trends
- Query disk I/O trends over time

### ❌ Blocked Operations

- Generic command execution (removed entirely)
- Access to system files (`/etc/shadow`, etc.)
- Privilege escalation (`sudo`, `su`)
- Shell execution (`bash`, `python`, etc.)
- Disk modification (`dd`, `mkfs`, `mount`)

## Security Model

**Design Principle: Whitelist operations, don't blacklist commands.**

Instead of trying to filter dangerous commands (impossible to do perfectly), we only expose **specific, safe operations** that the AI actually needs.

**Example:**
- ❌ Old approach: `exec_command("smartctl -a /dev/sda")` with filtering
- ✅ New approach: `get_disk_health("sda")` — specific, validated, normalized

## Next Steps

### 1. Configure Your Server (5 minutes)

```bash
# Copy the example config
cp config.example.yaml config.yaml

# Edit with your server details
nano config.yaml
```

Update these fields:

```yaml
ssh:
  host: "your-server.example.com"
  username: "your-username"
  key_path: "~/.ssh/id_rsa"  # or use password

host:
  enabled: true

prometheus:
  enabled: false  # set true if you have Prometheus

influxdb:
  enabled: false  # set true if you have InfluxDB
```

### 2. Test It Works

```bash
# Run security tests
uv run pytest tests/test_security.py -v

# Run SMART parser tests
uv run pytest tests/test_smart_parser.py -v

# Verify tools
uv run python test_tools.py
```

### 3. Use with Qwen Code

The MCP server is **already configured** in `.qwen/settings.json`. Just restart Qwen Code!

**Example conversation:**

```text
You: "Can you check the health of all my disks?"

Qwen: [Uses get_full_disk_report tool]
      "I found 4 disks. Here's the overview..."

Qwen: [Uses get_disk_health for each disk]
      "sda (Seagate IronWolf): Health 65/100 🔴
       Reallocated_Sector_Ct: 20 sectors (critical)
       This drive is degrading — back up data soon."
```

## Security Features

### Device Name Validation

Only safe device name patterns:
- ✅ `sda`, `nvme0n1`, `vda`, `mmcblk0`, `dm-0`
- ❌ `sda;rm -rf /` → **Blocked**
- ❌ `/dev/sda` → **Blocked** (absolute paths)

### Command Whitelist

Only specific diagnostic commands:
- ✅ `smartctl -j -a /dev/sda`
- ✅ `nvme smart-log /dev/nvme0n1`
- ✅ `zpool status -x`
- ❌ `dd if=/dev/zero of=/dev/sda` → **Blocked**
- ❌ `mkfs.ext4 /dev/sda` → **Blocked**

### SMART Test Safety

Self-tests are **safe** — they don't modify data on the drive:
- ✅ `smartctl -t short /dev/sda` — Quick diagnostic scan
- ✅ `smartctl -t long /dev/sda` — Full media scan
- ✅ `smartctl -t conveyance /dev/sda` — Transport damage check

## Files Created

```text
src/disk_health_mcp/
├── server.py                # MCP server with 11 diagnostic tools
└── smart_parser.py          # SMART parser with manufacturer normalization

server-management-lib (dependency):
├── security.py              # Command whitelist + device validation
├── config.py                # Config loader
├── ssh_manager.py           # SSH connection manager
└── http_clients.py          # InfluxDB/Prometheus clients

tests/
├── test_security.py         # Security validation tests
└── test_smart_parser.py     # SMART parser + severity tests
```

## Common Commands

```bash
# Run all tests
uv run pytest tests/ -v

# Verify tools
uv run python test_tools.py

# Run MCP server standalone (for debugging)
uv run python -m disk_health_mcp.server

# View configuration
cat config.yaml
```

## SMART Severity Quick Reference

| Severity | Meaning | Action |
|----------|---------|--------|
| ✅ OK | Normal operation | No action needed |
| 🟡 WARNING | Approaching threshold | Monitor closely, plan replacement |
| 🔴 CRITICAL | Active degradation | Back up immediately, replace drive |

### Common Confusions

- **"Pre-fail"** doesn't mean "about to fail" — it means the attribute is tracked since manufacturing
- **Seagate raw values** look huge (billions) — that's normal 48-bit encoding
- **Temperature** flagged as Pre-fail is normal — it's always been tracked
- **Reallocated_Sector_Ct > 0** is always concerning, regardless of normalized value

## What's MCP?

**MCP (Model Context Protocol)** is like USB-C for AI assistants. Build once, works everywhere:
- Qwen Code ✅
- Claude Desktop ✅
- Any MCP client ✅

Learn more: [modelcontextprotocol.io](https://modelcontextprotocol.io)

## Need Help?

See the full documentation in:
- `README.md` - Complete guide with security details
- `AGENTS.md` - Project overview
- `config.example.yaml` - Configuration reference

---

**Ready to go!** 🚀

Configure your server in `config.yaml` and start asking Qwen Code to help diagnose disk health!
