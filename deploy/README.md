# Deployment Assets

Quadlet units and example configuration for the containerized MCP services.

- `quadlet/` — `server-mcp.target`, the two MCP `.container` units, the
  `mcp-egress-proxy` unit and the `pi-control`/`mcp-egress`/`mcp-egress-uplink` networks.
  `install.sh` copies the container and network units to
  `~/.config/containers/systemd/` and the target to `~/.config/systemd/user/`.
- `examples/catafalco/` — example configs, `.env`, `known_hosts`, SSH-key placeholder and
  the default-deny `egress-policy.conf`.
- `render-egress-policy.py` — derives the proxy allow rules from the installed configs.
- `install.sh` — creates the user config/state directories, token, policy and units.
  `--force` refreshes units only; `--replace-config` replaces configuration with a
  timestamped backup.

See [docs/container.md](../docs/container.md) for the full deployment, token, network and
verification instructions.
