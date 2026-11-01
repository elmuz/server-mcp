# Deployment Assets

Quadlet units and example configuration for the containerized MCP services.

- `quadlet/` — `server-mcp.target`, the two `.container` units and the
  `pi-control`/`mcp-egress` networks.
- `examples/catafalco/` — example configs, `.env`, `known_hosts` and SSH-key placeholder.
- `install.sh` — creates the user config/state directories, token and units.

See [docs/container.md](../docs/container.md) for the full deployment, token, network and
verification instructions.
