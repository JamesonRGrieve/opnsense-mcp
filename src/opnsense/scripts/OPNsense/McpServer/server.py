#!/usr/local/opnsense/scripts/OPNsense/McpServer/venv/bin/python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
OPNsense-native MCP server — read-only firewall inspection tools.

Runs on the firewall itself as a configd-managed daemon, reading local state
directly (config.xml, ifconfig, pfctl, arp, netstat, lease files) instead of
calling its own REST API. Read-only by design: no write tools exist.

All tools return TOON (Token-Optimized Object Notation) for compact,
token-efficient LLM consumption.

Daemon lifecycle (start/stop/restart/status) is driven by configd actions and
the OPNsense ServiceController; this script handles the PID file and
daemonization when called with those verbs.
"""
import json
import os
import signal
import subprocess
import sys
import xml.etree.ElementTree as ET
from typing import Any

from mcp.server.fastmcp import FastMCP

PID_FILE = "/var/run/mcpserver.pid"
CONFIG_FILE = "/conf/config.xml"
CONFIG_XPATH = ".//OPNsense/mcpserver/general"
DHCP_LEASE_FILE = "/var/dhcpd/var/db/dhcpd.leases"


def read_config() -> dict[str, str]:
    """Read MCP server config from OPNsense config.xml."""
    try:
        tree = ET.parse(CONFIG_FILE)
        node = tree.find(CONFIG_XPATH)
        if node is None:
            return {}
        return {child.tag: (child.text or "") for child in node}
    except (ET.ParseError, FileNotFoundError):
        return {}


def run_cmd(cmd: list[str], timeout: int = 10) -> str:
    """Run a command and return its stdout. Never raises — returns error text."""
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return r.stdout
    except (subprocess.TimeoutExpired, FileNotFoundError, OSError) as e:
        return f"error: {e}"


def toon_table(name: str, rows: list[dict[str, str]], cols: list[str]) -> str:
    """Render a list of dicts as a TOON tabular array."""
    if not rows:
        return f"{name}: []"
    hdr = f"{name}[{len(rows)}]{{{','.join(cols)}}}:"
    body = "\n".join("  " + ",".join(_toon_val(r.get(c, "")) for c in cols) for r in rows)
    return f"{hdr}\n{body}"


def _toon_val(v: str) -> str:
    """Quote a TOON value if it contains commas or is ambiguous."""
    if not v:
        return '""'
    if "," in v or ":" in v or '"' in v or v in ("true", "false", "null") or v.startswith("-") or v.startswith("#"):
        return '"' + v.replace("\\", "\\\\").replace('"', '\\"').replace("\n", "\\n") + '"'
    return v


def toon_kv(pairs: list[tuple[str, str]]) -> str:
    """Render key-value pairs as TOON object fields."""
    return "\n".join(f"{k}: {_toon_val(v)}" for k, v in pairs)


def parse_ifconfig(raw: str) -> list[dict[str, Any]]:
    """Parse ifconfig -a output into structured interface records."""
    interfaces = []
    current: dict[str, Any] | None = None
    for line in raw.splitlines():
        if line and not line[0].isspace():
            if current:
                interfaces.append(current)
            name = line.split(":")[0]
            flags_part = line.split("<")[1].split(">")[0] if "<" in line else ""
            current = {"name": name, "flags": flags_part, "addresses": [], "status": "", "mac": "", "media": ""}
        elif current and line.strip():
            parts = line.strip()
            if parts.startswith("inet "):
                tokens = parts.split()
                addr = tokens[1]
                if "netmask" in tokens:
                    addr += "/" + tokens[tokens.index("netmask") + 1]
                current["addresses"].append(addr)
            elif parts.startswith("inet6 "):
                current["addresses"].append(parts.split()[1])
            elif parts.startswith("ether "):
                current["mac"] = parts.split()[1]
            elif parts.startswith("status:"):
                current["status"] = parts.split(":", 1)[1].strip()
            elif parts.startswith("media:"):
                current["media"] = parts.split(":", 1)[1].strip()
    if current:
        interfaces.append(current)
    return interfaces


def parse_arp(raw: str) -> list[dict[str, str]]:
    """Parse arp -an output."""
    entries = []
    for line in raw.splitlines():
        if "(" not in line:
            continue
        parts = line.split()
        ip = parts[1].strip("()")
        mac = parts[3] if len(parts) > 3 else "incomplete"
        iface = parts[-1] if len(parts) > 5 else ""
        entries.append({"ip": ip, "mac": mac, "interface": iface})
    return entries


def parse_routes(raw: str) -> list[dict[str, str]]:
    """Parse netstat -rn output into route records."""
    routes = []
    header_seen = False
    for line in raw.splitlines():
        if "Destination" in line and "Gateway" in line:
            header_seen = True
            continue
        if not header_seen or not line.strip():
            continue
        parts = line.split()
        if len(parts) >= 4:
            routes.append({
                "destination": parts[0],
                "gateway": parts[1],
                "flags": parts[2],
                "interface": parts[3] if len(parts) > 3 else "",
            })
    return routes


def parse_pfctl_rules(raw: str) -> list[dict[str, str]]:
    """Parse pfctl -sr output into rule records."""
    rules = []
    for i, line in enumerate(raw.splitlines()):
        line = line.strip()
        if line and not line.startswith("#"):
            rules.append({"index": str(i), "rule": line})
    return rules


def parse_dhcp_leases(path: str) -> list[dict[str, str]]:
    """Parse ISC dhcpd.leases file."""
    leases = []
    current: dict[str, str] = {}
    try:
        with open(path) as f:
            for line in f:
                line = line.strip()
                if line.startswith("lease "):
                    current = {"ip": line.split()[1]}
                elif line.startswith("hardware ethernet") and current:
                    current["mac"] = line.split()[-1].rstrip(";")
                elif line.startswith("client-hostname") and current:
                    current["hostname"] = line.split('"')[1] if '"' in line else ""
                elif line.startswith("starts") and current:
                    current["starts"] = " ".join(line.split()[2:]).rstrip(";")
                elif line.startswith("ends") and current:
                    current["ends"] = " ".join(line.split()[2:]).rstrip(";")
                elif line.startswith("binding state") and current:
                    current["state"] = line.split()[-1].rstrip(";")
                elif line == "}" and current:
                    leases.append(current)
                    current = {}
    except FileNotFoundError:
        pass
    return leases


def create_server(cfg: dict[str, str]) -> FastMCP:
    """Create and configure the MCP server with read-only tools."""
    host = cfg.get("listen_address", "127.0.0.1")
    port = int(cfg.get("listen_port", "8500"))
    mcp = FastMCP("opnsense", host=host, port=port)

    @mcp.tool()
    async def get_system_info() -> str:
        """System information: hostname, version, uptime, architecture. TOON format."""
        uname = run_cmd(["uname", "-srm"])
        hostname = run_cmd(["hostname"]).strip()
        uptime = run_cmd(["uptime"]).strip()
        version = ""
        try:
            with open("/usr/local/opnsense/version/opnsense", "r") as f:
                version = f.read().strip()
        except FileNotFoundError:
            version = "unknown"
        return toon_kv([
            ("hostname", hostname),
            ("version", version),
            ("uname", uname.strip()),
            ("uptime", uptime),
        ])

    @mcp.tool()
    async def get_interfaces() -> str:
        """Network interfaces with addresses, status, MAC, and media. TOON format."""
        ifaces = parse_ifconfig(run_cmd(["ifconfig", "-a"]))
        lines = []
        for iface in ifaces:
            addrs = " ".join(iface.get("addresses", []))
            lines.append({
                "name": iface.get("name", ""),
                "status": iface.get("status", ""),
                "mac": iface.get("mac", ""),
                "addresses": addrs,
                "flags": iface.get("flags", ""),
            })
        return toon_table("interfaces", lines, ["name", "status", "mac", "addresses", "flags"])

    @mcp.tool()
    async def get_firewall_rules() -> str:
        """Active pf firewall rules (pfctl -sr). TOON format."""
        rules = parse_pfctl_rules(run_cmd(["pfctl", "-sr"]))
        return toon_table("rules", rules, ["index", "rule"])

    @mcp.tool()
    async def get_arp_table() -> str:
        """ARP table: IP-to-MAC mappings and their interfaces. TOON format."""
        entries = parse_arp(run_cmd(["arp", "-an"]))
        return toon_table("arp", entries, ["ip", "mac", "interface"])

    @mcp.tool()
    async def get_routes() -> str:
        """Routing table (IPv4 and IPv6). TOON format."""
        routes = parse_routes(run_cmd(["netstat", "-rn"]))
        return toon_table("routes", routes, ["destination", "gateway", "flags", "interface"])

    @mcp.tool()
    async def get_services() -> str:
        """OPNsense service status list via pluginctl. TOON format."""
        raw = run_cmd(["/usr/local/sbin/pluginctl", "-s"])
        services = []
        for line in raw.strip().splitlines():
            parts = line.split()
            if len(parts) >= 2:
                services.append({"name": parts[0], "status": parts[1]})
        return toon_table("services", services, ["name", "status"])

    @mcp.tool()
    async def get_nat_rules() -> str:
        """NAT rules from config.xml (outbound and inbound). TOON format."""
        parts = []
        try:
            tree = ET.parse(CONFIG_FILE)
            outbound = []
            for rule in tree.findall(".//nat/outbound/rule"):
                entry = {child.tag: (child.text or "") for child in rule}
                outbound.append(entry)
            if outbound:
                out_cols = sorted({k for e in outbound for k in e})
                parts.append(toon_table("outbound", outbound, out_cols))
            else:
                parts.append("outbound: []")
            inbound = []
            for rule in tree.findall(".//nat/rule"):
                entry = {child.tag: (child.text or "") for child in rule}
                inbound.append(entry)
            if inbound:
                in_cols = sorted({k for e in inbound for k in e})
                parts.append(toon_table("inbound", inbound, in_cols))
            else:
                parts.append("inbound: []")
        except (ET.ParseError, FileNotFoundError):
            parts.append("error: could not parse config.xml")
        return "\n".join(parts)

    @mcp.tool()
    async def get_vlans() -> str:
        """VLAN assignments from config.xml. TOON format."""
        vlans = []
        try:
            tree = ET.parse(CONFIG_FILE)
            for vlan in tree.findall(".//vlans/vlan"):
                entry = {child.tag: (child.text or "") for child in vlan}
                vlans.append(entry)
        except (ET.ParseError, FileNotFoundError):
            pass
        if not vlans:
            return "vlans: []"
        cols = sorted({k for e in vlans for k in e})
        return toon_table("vlans", vlans, cols)

    @mcp.tool()
    async def get_dhcp_leases() -> str:
        """Active DHCP leases from the ISC dhcpd lease file. TOON format."""
        leases = parse_dhcp_leases(DHCP_LEASE_FILE)
        return toon_table("leases", leases, ["ip", "mac", "hostname", "state", "starts", "ends"])

    @mcp.tool()
    async def get_wireguard_status() -> str:
        """WireGuard tunnel status. TOON format."""
        raw = run_cmd(["wg", "show", "all"])
        if raw.startswith("error:"):
            return "installed: false\nnote: WireGuard not available"
        tunnels: list[dict[str, str]] = []
        current: dict[str, str] = {}
        for line in raw.splitlines():
            if line.startswith("interface:"):
                if current:
                    tunnels.append(current)
                current = {"interface": line.split(":", 1)[1].strip()}
            elif ":" in line and current:
                k, v = line.split(":", 1)
                current[k.strip().replace(" ", "_")] = v.strip()
        if current:
            tunnels.append(current)
        if not tunnels:
            return "installed: true\ntunnels: []"
        cols = []
        for t in tunnels:
            for k in t:
                if k not in cols:
                    cols.append(k)
        return "installed: true\n" + toon_table("tunnels", tunnels, cols)

    def _parse_haproxy_xml(section: str) -> list[dict[str, str]]:
        """Parse HAProxy config.xml elements, filtering empty/default fields."""
        items = []
        try:
            tree = ET.parse(CONFIG_FILE)
            for el in tree.findall(f".//OPNsense/HAProxy/{section}/*"):
                entry = {}
                for child in el:
                    val = (child.text or "").strip()
                    if val and val != "0" and val != "unspecified":
                        entry[child.tag] = val
                if entry:
                    items.append(entry)
        except (ET.ParseError, FileNotFoundError):
            pass
        return items

    @mcp.tool()
    async def get_haproxy_config(section: str = "all") -> str:
        """HAProxy configuration from config.xml (pending/declared state). TOON format.

        Shows the declared config — frontends, backends, servers, ACLs, actions.
        This is what WILL be applied on next HAProxy reload. Compare with
        get_haproxy_status to see what is CURRENTLY running.

        Args:
            section: Which config section to return. One of: "all", "frontends",
                     "backends", "servers", "acls", "actions", "healthchecks"
        """
        sections = {
            "frontends": ["name", "enabled", "bind", "mode", "defaultBackend", "ssl_enabled", "ssl_certificates", "http2Enabled", "linkedActions", "description"],
            "backends": ["name", "enabled", "mode", "algorithm", "linkedServers", "healthCheckEnabled", "healthCheck", "http2Enabled", "persistence", "description"],
            "servers": ["name", "enabled", "address", "port", "checkport", "mode", "ssl", "weight", "description"],
            "acls": ["name", "expression", "negate", "hdr_beg", "hdr_end", "hdr", "hdr_reg", "path_beg", "path_end", "path", "path_reg", "ssl_fc_sni", "ssl_sni", "custom_acl", "value", "description"],
            "actions": ["name", "enabled", "testType", "linkedAcls", "operator", "type", "use_backend", "http_request_action", "http_request_option", "http_response_action", "http_response_option", "description"],
            "healthchecks": ["name", "type", "interval", "checkport", "description"],
        }
        if section != "all" and section not in sections:
            return f"error: unknown section '{section}'. Valid: all, {', '.join(sections)}"
        parts = []
        targets = sections if section == "all" else {section: sections[section]}
        for sec_name, cols in targets.items():
            items = _parse_haproxy_xml(sec_name)
            if not items:
                parts.append(f"{sec_name}: []")
                continue
            present_cols = [c for c in cols if any(c in item for item in items)]
            if not present_cols:
                present_cols = sorted({k for item in items for k in item})[:10]
            parts.append(toon_table(sec_name, items, present_cols))
        return "\n".join(parts)

    @mcp.tool()
    async def get_haproxy_status(source: str = "applied") -> str:
        """HAProxy runtime status from the stats socket. TOON format.

        Shows what is CURRENTLY running — live session counts, server health,
        bytes transferred. Compare with get_haproxy_config to see pending changes.

        Args:
            source: "applied" (default) for live stats from the running HAProxy,
                    "pending" for declared config from config.xml (alias for
                    get_haproxy_config), "both" for side-by-side.
        """
        if source == "pending":
            return await get_haproxy_config()
        stats_socket = "/var/run/haproxy.socket"
        if not os.path.exists(stats_socket):
            return "installed: false\nnote: HAProxy not available"
        raw = run_cmd(
            ["sh", "-c", f"echo 'show stat' | socat - UNIX-CONNECT:{stats_socket}"],
            timeout=5,
        )
        if raw.startswith("error:") or not raw.strip():
            return f"installed: true\nerror: {raw.strip() or 'empty response'}"
        all_lines = raw.strip().splitlines()
        header_line = all_lines[0]
        if header_line.startswith("# "):
            header_line = header_line[2:]
        fields = [f.strip() for f in header_line.split(",")]
        data_lines = [l for l in all_lines[1:] if l.strip()]
        proxies: list[dict[str, str]] = []
        for line in data_lines:
            vals = line.split(",")
            entry = {}
            for i, f in enumerate(fields):
                if i < len(vals) and f:
                    entry[f] = vals[i]
            proxies.append(entry)
        frontends = [p for p in proxies if p.get("svname") == "FRONTEND"]
        backends = [p for p in proxies if p.get("svname") == "BACKEND"]
        servers = [p for p in proxies if p.get("svname") not in ("FRONTEND", "BACKEND", "")]
        fe_cols = ["pxname", "status", "scur", "smax", "stot", "bin", "bout", "rate", "slim"]
        be_cols = ["pxname", "status", "scur", "smax", "stot", "bin", "bout", "act", "bck", "lastchg"]
        sv_cols = ["pxname", "svname", "status", "scur", "smax", "stot", "bin", "bout", "check_status", "lastchg"]
        parts = [
            "installed: true",
            toon_table("frontends", frontends, fe_cols),
            toon_table("backends", backends, be_cols),
            toon_table("servers", servers, sv_cols),
        ]
        applied = "\n".join(parts)
        if source == "both":
            pending = await get_haproxy_config()
            return f"# === APPLIED (running) ===\n{applied}\n\n# === PENDING (config.xml) ===\n{pending}"
        return applied

    @mcp.tool()
    async def get_unbound_status() -> str:
        """Unbound DNS resolver statistics. TOON format."""
        raw = run_cmd(["unbound-control", "stats_noreset"])
        if raw.startswith("error:"):
            return "running: false"
        pairs = [("running", "true")]
        for line in raw.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                pairs.append((k.strip(), v.strip()))
        return toon_kv(pairs)

    return mcp


def daemonize():
    """Double-fork daemonize (Unix)."""
    if os.fork() > 0:
        sys.exit(0)
    os.setsid()
    if os.fork() > 0:
        sys.exit(0)
    sys.stdin = open(os.devnull, "r")
    sys.stdout = open(os.devnull, "w")
    sys.stderr = open(os.devnull, "w")
    with open(PID_FILE, "w") as f:
        f.write(str(os.getpid()))


def read_pid() -> int | None:
    """Read PID from pidfile, return None if stale or missing."""
    try:
        with open(PID_FILE) as f:
            pid = int(f.read().strip())
        os.kill(pid, 0)
        return pid
    except (FileNotFoundError, ValueError, ProcessLookupError, PermissionError):
        return None


def cmd_start():
    if read_pid():
        print("already running")
        return
    cfg = read_config()
    if cfg.get("enabled") != "1":
        print("not enabled")
        return
    daemonize()
    server = create_server(cfg)
    transport = cfg.get("transport", "http")
    if transport == "http":
        transport = "streamable-http"
    server.run(transport=transport)


def cmd_stop():
    pid = read_pid()
    if pid:
        os.kill(pid, signal.SIGTERM)
        try:
            os.remove(PID_FILE)
        except FileNotFoundError:
            pass
        print("stopped")
    else:
        print("not running")


def cmd_status():
    pid = read_pid()
    if pid:
        print(json.dumps({"status": "running", "pid": pid}))
    else:
        print(json.dumps({"status": "stopped"}))


def main():
    if len(sys.argv) < 2:
        print(f"usage: {sys.argv[0]} start|stop|restart|status")
        sys.exit(1)
    action = sys.argv[1]
    if action == "start":
        cmd_start()
    elif action == "stop":
        cmd_stop()
    elif action == "restart":
        cmd_stop()
        cmd_start()
    elif action == "status":
        cmd_status()
    else:
        print(f"unknown action: {action}")
        sys.exit(1)


if __name__ == "__main__":
    main()
