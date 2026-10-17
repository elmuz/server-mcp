# server-management-lib

Shared core for the Server MCP suite: security validation, SSH and local executors,
configuration resolution, output limits, audit logging, and read-only InfluxDB/Prometheus
clients.

Part of the [Server MCP suite](../../README.md).

- [Architecture](../../docs/architecture.md)
- [Security model](../../docs/security-model.md)
- [Configuration](../../docs/configuration.md)

The two MCP servers depend on this package through the uv workspace. It has no MCP
dependency and can be used by other server-management tools.
