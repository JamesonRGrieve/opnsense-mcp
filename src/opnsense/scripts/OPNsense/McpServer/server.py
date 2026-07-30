#!/usr/local/opnsense/scripts/OPNsense/McpServer/venv/bin/python3
# SPDX-License-Identifier: AGPL-3.0-or-later
"""
OPNsense-native MCP server — read-only firewall inspection tools.

Runs on the firewall itself as a configd-managed daemon, reading local state
directly (config.xml, ifconfig, pfctl, arp, netstat, lease files) instead of
calling its own REST API. Read-only by design: no write tools exist.

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
            current = {"name": name, "flags": flags_part, "addresses": [], "status": ""}
        elif current and line.strip():
            parts = line.strip()
            if parts.startswith("inet "):
                tokens = parts.split()
                addr = {"family": "inet", "address": tokens[1]}
                if "netmask" in tokens:
                    addr["netmask"] = tokens[tokens.index("netmask") + 1]
                current["addresses"].append(addr)
            elif parts.startswith("inet6 "):
                tokens = parts.split()
                current["addresses"].append({"family": "inet6", "address": tokens[1]})
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
            rules.append({"index": i, "rule": line})
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


def parse_fw_rules_xml(config_path: str) -> list[dict[str, str]]:
    """Parse firewall filter rules from config.xml for structured output."""
    rules = []
    try:
        tree = ET.parse(config_path)
        for rule in tree.findall(".//filter/rule"):
            entry: dict[str, str] = {}
            for child in rule:
                if child.tag in ("source", "destination"):
                    sub = {f"{child.tag}_{sc.tag}": (sc.text or "") for sc in child}
                    entry.update(sub)
                else:
                    entry[child.tag] = child.text or ""
            rules.append(entry)
    except (ET.ParseError, FileNotFoundError):
        pass
    return rules


def create_server(cfg: dict[str, str]) -> FastMCP:
    """Create and configure the MCP server with read-only tools."""
    host = cfg.get("listen_address", "127.0.0.1")
    port = int(cfg.get("listen_port", "8500"))
    mcp = FastMCP("opnsense", host=host, port=port)

    @mcp.tool()
    async def get_system_info() -> dict[str, Any]:
        """System information: hostname, version, uptime, architecture."""
        uname = run_cmd(["uname", "-srm"])
        hostname = run_cmd(["hostname"]).strip()
        uptime = run_cmd(["uptime"]).strip()
        version = ""
        try:
            with open("/usr/local/opnsense/version/opnsense", "r") as f:
                version = f.read().strip()
        except FileNotFoundError:
            version = "unknown"
        return {
            "hostname": hostname,
            "version": version,
            "uname": uname.strip(),
            "uptime": uptime,
        }

    @mcp.tool()
    async def get_interfaces() -> list[dict[str, Any]]:
        """All network interfaces with addresses, status, MAC, and media."""
        return parse_ifconfig(run_cmd(["ifconfig", "-a"]))

    @mcp.tool()
    async def get_firewall_rules() -> dict[str, Any]:
        """Active pf firewall rules (pfctl -sr) and config.xml filter rules."""
        return {
            "active_rules": parse_pfctl_rules(run_cmd(["pfctl", "-sr"])),
            "configured_rules": parse_fw_rules_xml(CONFIG_FILE),
        }

    @mcp.tool()
    async def get_arp_table() -> list[dict[str, str]]:
        """ARP table: IP-to-MAC mappings and their interfaces."""
        return parse_arp(run_cmd(["arp", "-an"]))

    @mcp.tool()
    async def get_routes() -> list[dict[str, str]]:
        """Routing table (IPv4 and IPv6)."""
        return parse_routes(run_cmd(["netstat", "-rn"]))

    @mcp.tool()
    async def get_services() -> dict[str, Any]:
        """OPNsense service status list via pluginctl."""
        raw = run_cmd(["/usr/local/sbin/pluginctl", "-s"])
        services = []
        for line in raw.strip().splitlines():
            parts = line.split()
            if len(parts) >= 2:
                services.append({"name": parts[0], "status": parts[1]})
        return {"services": services}

    @mcp.tool()
    async def get_nat_rules() -> dict[str, str]:
        """NAT rules from config.xml (outbound and inbound)."""
        rules: dict[str, Any] = {"outbound": [], "inbound": []}
        try:
            tree = ET.parse(CONFIG_FILE)
            for rule in tree.findall(".//nat/outbound/rule"):
                entry = {child.tag: (child.text or "") for child in rule}
                rules["outbound"].append(entry)
            for rule in tree.findall(".//nat/rule"):
                entry = {child.tag: (child.text or "") for child in rule}
                rules["inbound"].append(entry)
        except (ET.ParseError, FileNotFoundError):
            pass
        return rules

    @mcp.tool()
    async def get_vlans() -> dict[str, Any]:
        """VLAN assignments from config.xml."""
        vlans = []
        try:
            tree = ET.parse(CONFIG_FILE)
            for vlan in tree.findall(".//vlans/vlan"):
                entry = {child.tag: (child.text or "") for child in vlan}
                vlans.append(entry)
        except (ET.ParseError, FileNotFoundError):
            pass
        return {"vlans": vlans}

    @mcp.tool()
    async def get_dhcp_leases() -> list[dict[str, str]]:
        """Active DHCP leases from the ISC dhcpd lease file."""
        return parse_dhcp_leases(DHCP_LEASE_FILE)

    @mcp.tool()
    async def get_wireguard_status() -> dict[str, Any]:
        """WireGuard tunnel status. Returns empty if WireGuard is not installed."""
        raw = run_cmd(["wg", "show", "all"])
        if raw.startswith("error:"):
            return {"installed": False, "note": "WireGuard not available"}
        tunnels: list[dict[str, str]] = []
        current: dict[str, str] = {}
        for line in raw.splitlines():
            if line.startswith("interface:"):
                if current:
                    tunnels.append(current)
                current = {"interface": line.split(":", 1)[1].strip()}
            elif ":" in line and current:
                k, v = line.split(":", 1)
                current[k.strip()] = v.strip()
        if current:
            tunnels.append(current)
        return {"installed": True, "tunnels": tunnels}

    @mcp.tool()
    async def get_haproxy_status() -> dict[str, Any]:
        """HAProxy backend/frontend status. Returns empty if os-haproxy is not installed."""
        stats_socket = "/var/run/haproxy.socket"
        if not os.path.exists(stats_socket):
            return {"installed": False, "note": "HAProxy not available"}
        raw = run_cmd(["socat", f"UNIX-CONNECT:{stats_socket}", "STDIN"],
                      timeout=5)
        return {"installed": True, "raw_stats": raw[:4096]}

    @mcp.tool()
    async def get_unbound_status() -> dict[str, Any]:
        """Unbound DNS resolver statistics. Returns empty if not running."""
        raw = run_cmd(["unbound-control", "stats_noreset"])
        if raw.startswith("error:"):
            return {"running": False}
        stats: dict[str, str] = {}
        for line in raw.splitlines():
            if "=" in line:
                k, v = line.split("=", 1)
                stats[k.strip()] = v.strip()
        return {"running": True, "stats": stats}

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
