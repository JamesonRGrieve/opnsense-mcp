# opnsense-mcp

OPNsense-native MCP server plugin — read-only firewall inspection tools that run
**on the firewall itself**, integrated with OPNsense's auth system and managed
through the standard plugin UI.

No Node.js, no external runtime, no API-key-to-yourself round-trip. Python (already
on every OPNsense box) + the `mcp` SDK, packaged as a standard `os-*` plugin.

## What it does

Exposes read-only MCP tools so an AI assistant (Claude Code, etc.) can inspect
firewall state through typed tool calls instead of screen-scraping the web UI or
hand-writing curl scripts:

| Tool | Reads |
|---|---|
| `get_system_info` | hostname, version, uptime, architecture |
| `get_interfaces` | all interfaces + addresses + status + MAC |
| `get_firewall_rules` | active pf rules + config.xml filter rules |
| `get_nat_rules` | outbound and inbound NAT from config.xml |
| `get_vlans` | VLAN assignments |
| `get_arp_table` | ARP cache |
| `get_routes` | routing table (IPv4/IPv6) |
| `get_dhcp_leases` | active DHCP leases |
| `get_services` | OPNsense service status |
| `get_wireguard_status` | WireGuard tunnel status (if installed) |
| `get_haproxy_status` | HAProxy backends/frontends (if os-haproxy installed) |
| `get_unbound_status` | Unbound DNS resolver stats (if running) |

**Read-only by design** — no write tools exist. Not "write tools that are disabled"
but "write tools were never written." The server reads local state directly
(`config.xml`, `ifconfig`, `pfctl -sr`, `arp`, `netstat`, lease files) and never
calls its own REST API.

## Install

```sh
# From the OPNsense shell (or SSH):
pkg install os-mcpserver
# The plugin appears under Services > MCP Server in the web UI.
```

Until the plugin is accepted into the OPNsense community repo, install from source:

```sh
# On the OPNsense box:
cd /tmp
fetch https://github.com/JamesonRGrieve/opnsense-mcp/archive/refs/heads/main.tar.gz
tar xf main.tar.gz
cd opnsense-mcp-main

# Copy plugin files into place
cp -R src/etc/inc/plugins.inc.d/* /usr/local/etc/inc/plugins.inc.d/
cp -R src/opnsense/* /usr/local/opnsense/

# Install Python dependencies
chmod +x /usr/local/opnsense/scripts/OPNsense/McpServer/setup.sh
/usr/local/opnsense/scripts/OPNsense/McpServer/setup.sh

# Make the server executable
chmod +x /usr/local/opnsense/scripts/OPNsense/McpServer/server.py

# Reload configd to pick up the new actions
service configd restart
```

Then configure via the web UI: **Services > MCP Server**.

## Configuration

In the OPNsense web UI under **Services > MCP Server**:

- **Enable** — start/stop the MCP server daemon
- **Listen Address** — IP to bind to (default `127.0.0.1`; set to a management
  interface IP for remote access)
- **Listen Port** — TCP port (default `8500`)
- **Transport** — `http` (network clients) or `stdio` (local pipe)
- **Auth Token** — bearer token clients must present; auto-generated on first
  enable if blank

Access to this settings page is controlled by OPNsense's user/group ACL system —
only users with the "Services: MCP Server" privilege can view or change the config.

## Connect Claude Code

```sh
claude mcp add opnsense \
  --transport http \
  http://<firewall-mgmt-ip>:8500/mcp \
  --header "Authorization: Bearer <auth-token>"
```

Or in `settings.json`:

```json
{
  "mcpServers": {
    "opnsense": {
      "command": "npx",
      "args": [
        "-y", "mcp-remote",
        "http://<firewall-mgmt-ip>:8500/mcp",
        "--header", "Authorization: Bearer <auth-token>"
      ]
    }
  }
}
```

## Architecture

```
┌─────────────────────────────────────────────────┐
│ OPNsense (FreeBSD)                              │
│                                                 │
│  ┌──────────────┐    ┌───────────────────────┐  │
│  │ Web UI (PHP) │    │ Python MCP Server     │  │
│  │              │    │ (venv, port 8500)     │  │
│  │ Services >   │    │                       │  │
│  │ MCP Server   │    │ Reads:                │  │
│  │              │    │  • config.xml         │  │
│  │ config.xml ◄─┼────┤  • ifconfig / arp    │  │
│  │ enable/port/ │    │  • pfctl / netstat   │  │
│  │ auth_token   │    │  • lease files       │  │
│  └──────────────┘    │  • pluginctl         │  │
│         │            │  • wg show           │  │
│    ┌────▼────┐       │  • haproxy socket    │  │
│    │ configd │───────┤  • unbound-control   │  │
│    │ actions │ start/ │                      │  │
│    └─────────┘ stop   └──────────┬───────────┘  │
│                                  │ :8500/mcp    │
└──────────────────────────────────┼──────────────┘
                                   │
                          ┌────────▼────────┐
                          │ Claude Code     │
                          │ (MCP client)    │
                          └─────────────────┘
```

## License

AGPL-3.0-or-later. PHP/XML structural glue follows OPNsense's BSD-2-Clause
convention; the Python MCP server (the novel code) is AGPL.
