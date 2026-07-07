import ipaddress
import json
import logging
import os
import re
import socket
import subprocess
import threading
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path

import sys
sys.path.insert(0, os.path.abspath(os.path.join(os.path.dirname(__file__), "..", "..", "vipsy_core")))

try:
    from vipsy_core.config import (
        VPN_DATA_DIR, VPN_PEERS_FILE, VPN_SERVER_KEY, VPN_AUDIT_LOG,
        VPN_INTERFACE, VPN_DEFAULT_SUBNET, VPN_DEFAULT_PORT,
        VPN_MAX_PEERS, VPN_RATE_LIMIT, VPN_RATE_WINDOW, VPN_TTL_CHECK_INTERVAL,
    )
except ImportError:
    VPN_DATA_DIR = "/data/wireguard"
    VPN_PEERS_FILE = "/data/wireguard/peers.json"
    VPN_SERVER_KEY = "/data/wireguard/server.key"
    VPN_AUDIT_LOG = "/data/wireguard/audit.json"
    VPN_INTERFACE = "wg0"
    VPN_DEFAULT_SUBNET = "10.8.0.0/24"
    VPN_DEFAULT_PORT = 51820
    VPN_MAX_PEERS = 250
    VPN_RATE_LIMIT = 10
    VPN_RATE_WINDOW = 60
    VPN_TTL_CHECK_INTERVAL = 30

_lock = threading.Lock()
_rate_lock = threading.Lock()
_rate_buckets: list = []
_ttl_thread: threading.Thread | None = None
_ttl_stop = threading.Event()
_relay_process: subprocess.Popen | None = None
WG_RELAY_PORT = 51821
_RELAY_START_TIMEOUT = 3
_RELAY_RETRY_DELAY = 30
_relay_last_error: str | None = None
_relay_retry_after = 0.0
_VPN_PORTMAP_COMMENT = "vipsy-vpn-portmap"


def _subnet():
    return os.environ.get("VPN_SUBNET", VPN_DEFAULT_SUBNET)


def _port():
    return int(os.environ.get("VPN_PORT", VPN_DEFAULT_PORT))


def _data_dir():
    d = Path(VPN_DATA_DIR)
    d.mkdir(parents=True, exist_ok=True)
    return d


def _enabled_path():
    return _data_dir() / "enabled"


def _remember_enabled(enabled):
    path = _enabled_path()
    if enabled:
        path.write_text("1")
        path.chmod(0o600)
    else:
        path.unlink(missing_ok=True)


def is_enabled():
    return _enabled_path().exists()


def _server_key_path():
    return Path(VPN_SERVER_KEY)


def _peers_path():
    return Path(VPN_PEERS_FILE)


def _audit_path():
    return Path(VPN_AUDIT_LOG)


def _extra_subnets_path():
    return _data_dir() / "extra_subnets.json"


def _port_maps_path():
    return _data_dir() / "port_maps.json"


def _load_json_list(path):
    try:
        if path.exists():
            data = json.loads(path.read_text())
            if isinstance(data, list):
                return data
    except (json.JSONDecodeError, OSError):
        pass
    return []


def _save_json_list(path, items):
    _data_dir()
    tmp = path.with_suffix(".tmp")
    tmp.write_text(json.dumps(items, indent=2))
    tmp.chmod(0o600)
    tmp.replace(path)
    try:
        path.chmod(0o600)
    except OSError:
        pass


def _run(cmd, check=True, capture=True):
    try:
        r = subprocess.run(
            cmd, capture_output=capture, text=True,
            timeout=15, check=check,
        )
        return r.stdout.strip() if capture else ""
    except subprocess.CalledProcessError as e:
        raise RuntimeError(f"Command failed: {' '.join(cmd)}: {e.stderr or e}")
    except subprocess.TimeoutExpired:
        raise RuntimeError(f"Command timed out: {' '.join(cmd)}")


def _wg_genkey():
    return _run(["wg", "genkey"])


def _wg_pubkey(privkey):
    r = subprocess.run(
        ["wg", "pubkey"], input=privkey, capture_output=True, text=True, timeout=5,
    )
    if r.returncode != 0:
        raise RuntimeError("wg pubkey failed")
    return r.stdout.strip()


def _wg_preshared_key():
    return _run(["wg", "genpsk"])


def _get_or_create_server_keys():
    _data_dir()
    kp = _server_key_path()
    if kp.exists():
        privkey = kp.read_text().strip()
    else:
        privkey = _wg_genkey()
        kp.write_text(privkey + "\n")
        kp.chmod(0o600)
    pubkey = _wg_pubkey(privkey)
    return privkey, pubkey


def _load_peers():
    pp = _peers_path()
    if pp.exists():
        try:
            data = json.loads(pp.read_text())
            if isinstance(data, list):
                return data
        except (json.JSONDecodeError, OSError):
            pass
    return []


def _save_peers(peers):
    pp = _peers_path()
    _data_dir()
    tmp = pp.with_suffix(".tmp")
    tmp.write_text(json.dumps(peers, indent=2))
    tmp.chmod(0o600)
    tmp.replace(pp)
    try:
        pp.chmod(0o600)
    except OSError:
        pass


def _audit(action, peer_id=None, name=None, extra=None):
    ap = _audit_path()
    _data_dir()
    entries = []
    if ap.exists():
        try:
            entries = json.loads(ap.read_text())
        except (json.JSONDecodeError, OSError):
            entries = []
    entry = {
        "ts": datetime.now(timezone.utc).isoformat(),
        "action": action,
    }
    if peer_id:
        entry["peer_id"] = peer_id
    if name:
        entry["name"] = name
    if extra:
        entry.update(extra)
    entries.append(entry)
    if len(entries) > 1000:
        entries = entries[-500:]
    try:
        ap.write_text(json.dumps(entries, indent=2))
    except OSError:
        pass


def _check_rate_limit():
    now = time.monotonic()
    with _rate_lock:
        cutoff = now - VPN_RATE_WINDOW
        _rate_buckets[:] = [t for t in _rate_buckets if t > cutoff]
        if len(_rate_buckets) >= VPN_RATE_LIMIT:
            return False
        _rate_buckets.append(now)
        return True


def _network(subnet=None):
    return ipaddress.IPv4Network(subnet or _subnet(), strict=False)


def _server_ip(subnet=None):
    net = _network(subnet)
    return str(list(net.hosts())[0])


def _allocate_ip(peers, subnet=None):
    net = _network(subnet)
    used = {p["vpn_ip"] for p in peers}
    used.add(_server_ip(subnet))
    for host in list(net.hosts())[1:]:
        if str(host) not in used:
            return str(host)
    return None


def _detect_lan_subnet():
    host_cidr = os.environ.get("HOST_CIDR", "")
    if host_cidr and "/" in host_cidr:
        try:
            return str(ipaddress.IPv4Network(host_cidr, strict=False))
        except ValueError:
            pass
    host_ip = os.environ.get("HOST_IP", "")
    if host_ip:
        try:
            return str(ipaddress.IPv4Network(f"{host_ip}/24", strict=False))
        except ValueError:
            pass
    try:
        out = _run(["ip", "-4", "route", "show", "default"])
        parts = out.split()
        if "dev" in parts:
            dev = parts[parts.index("dev") + 1]
            addr_out = _run(["ip", "-4", "addr", "show", dev])
            for line in addr_out.splitlines():
                line = line.strip()
                if line.startswith("inet "):
                    cidr = line.split()[1]
                    net = ipaddress.IPv4Network(cidr, strict=False)
                    if not net.is_private or str(net).startswith("172."):
                        continue
                    return str(net)
    except Exception:
        pass
    return "192.168.1.0/24"


def _check_subnet_overlap():
    vpn_net = _network()
    for lan_str in _routed_subnets(include_vpn=False):
        try:
            lan_net = ipaddress.IPv4Network(lan_str, strict=False)
            if vpn_net.overlaps(lan_net):
                return f"VPN subnet {vpn_net} overlaps with routed subnet {lan_net}"
        except ValueError:
            pass
    return None


_log = logging.getLogger("vipsy.vpn")

_VPN_NFT_COMMENT = "vipsy-vpn"
_NFT_FAMILY = "ip"


def _clean_name(value, default="Route"):
    name = re.sub(r"\s+", " ", (value or "").strip())
    name = re.sub(r"[^A-Za-z0-9 _.\-]", "", name).strip()
    return (name or default)[:64]


def _private_subnet(value):
    try:
        net = ipaddress.IPv4Network((value or "").strip(), strict=False)
    except ValueError:
        return None
    if net.prefixlen < 8 or net.prefixlen > 32:
        return None
    if net.is_loopback or net.is_multicast or net.is_link_local or net.is_unspecified:
        return None
    if not net.is_private:
        return None
    return net


def _private_ip(value):
    try:
        ip = ipaddress.IPv4Address((value or "").strip())
    except ValueError:
        return None
    if ip.is_loopback or ip.is_multicast or ip.is_link_local or ip.is_unspecified:
        return None
    if not ip.is_private:
        return None
    return ip


def _valid_port(value):
    try:
        port = int(value)
    except (TypeError, ValueError):
        return None
    return port if 1 <= port <= 65535 else None


def _reserved_listen_ports():
    return {_port(), WG_RELAY_PORT, 443, 3478, 18099}


def list_extra_subnets():
    subnets = []
    seen = set()
    changed = False
    for item in _load_json_list(_extra_subnets_path()):
        net = _private_subnet(item.get("subnet") if isinstance(item, dict) else None)
        if not net:
            changed = True
            continue
        subnet = str(net)
        if subnet in seen:
            changed = True
            continue
        seen.add(subnet)
        subnets.append({
            "id": (item.get("id") or uuid.uuid4().hex[:8])[:16],
            "name": _clean_name(item.get("name"), subnet),
            "subnet": subnet,
            "created_at": item.get("created_at") or datetime.now(timezone.utc).isoformat(),
        })
    if changed:
        _save_json_list(_extra_subnets_path(), subnets)
    return subnets


def _routed_subnets(include_vpn=True):
    routes = [_detect_lan_subnet()]
    routes.extend(item["subnet"] for item in list_extra_subnets())
    if include_vpn:
        routes.append(_subnet())
    out = []
    seen = set()
    for route in routes:
        net = _private_subnet(route)
        if not net:
            continue
        value = str(net)
        if value not in seen:
            seen.add(value)
            out.append(value)
    return out


def add_extra_subnet(subnet, name=""):
    net = _private_subnet(subnet)
    if not net:
        return {"ok": False, "error": "Enter a private IPv4 subnet like 192.168.20.0/24"}
    if net.overlaps(_network()):
        return {"ok": False, "error": "Extra subnet cannot overlap the WireGuard VPN subnet"}
    routes = list_extra_subnets()
    if str(net) == str(_private_subnet(_detect_lan_subnet())) or any(item["subnet"] == str(net) for item in routes):
        return {"ok": False, "error": "Subnet is already routed"}
    item = {
        "id": uuid.uuid4().hex[:8],
        "name": _clean_name(name, str(net)),
        "subnet": str(net),
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    routes.append(item)
    _save_json_list(_extra_subnets_path(), routes)
    if _interface_exists():
        _apply_nat_rules()
    _audit("add_route", extra={"subnet": item["subnet"], "name": item["name"]})
    return {"ok": True, "route": item, "routes": routes}


def remove_extra_subnet(route_id):
    routes = list_extra_subnets()
    kept = [item for item in routes if item["id"] != route_id]
    if len(kept) == len(routes):
        return {"ok": False, "error": "Route not found"}
    _save_json_list(_extra_subnets_path(), kept)
    if _interface_exists():
        _apply_nat_rules()
    _audit("remove_route", extra={"route_id": route_id})
    return {"ok": True, "routes": kept}


def list_port_maps():
    maps = []
    used = set()
    changed = False
    for item in _load_json_list(_port_maps_path()):
        if not isinstance(item, dict):
            changed = True
            continue
        protocol = str(item.get("protocol") or "tcp").lower()
        if protocol not in {"tcp", "udp", "both"}:
            changed = True
            continue
        listen_port = _valid_port(item.get("listen_port"))
        target_port = _valid_port(item.get("target_port"))
        target_ip = _private_ip(item.get("target_ip"))
        if not listen_port or not target_port or not target_ip:
            changed = True
            continue
        key = (protocol, listen_port)
        if key in used:
            changed = True
            continue
        used.add(key)
        maps.append({
            "id": (item.get("id") or uuid.uuid4().hex[:8])[:16],
            "name": _clean_name(item.get("name"), f"{listen_port} to {target_ip}:{target_port}"),
            "protocol": protocol,
            "listen_port": listen_port,
            "target_ip": str(target_ip),
            "target_port": target_port,
            "created_at": item.get("created_at") or datetime.now(timezone.utc).isoformat(),
        })
    if changed:
        _save_json_list(_port_maps_path(), maps)
    return maps


def add_port_map(name, protocol, listen_port, target_ip, target_port):
    proto = str(protocol or "tcp").lower()
    if proto not in {"tcp", "udp", "both"}:
        return {"ok": False, "error": "Protocol must be tcp, udp, or both"}
    listen = _valid_port(listen_port)
    target = _valid_port(target_port)
    ip = _private_ip(target_ip)
    if not listen or not target or not ip:
        return {"ok": False, "error": "Enter a private target IP and valid ports"}
    if listen in _reserved_listen_ports() or listen < 1024:
        return {"ok": False, "error": "Listen port must be an unused high port"}
    maps = list_port_maps()
    if any(m["listen_port"] == listen and (m["protocol"] == proto or "both" in {m["protocol"], proto}) for m in maps):
        return {"ok": False, "error": "That listen port/protocol is already mapped"}
    item = {
        "id": uuid.uuid4().hex[:8],
        "name": _clean_name(name, f"{listen} to {ip}:{target}"),
        "protocol": proto,
        "listen_port": listen,
        "target_ip": str(ip),
        "target_port": target,
        "created_at": datetime.now(timezone.utc).isoformat(),
    }
    maps.append(item)
    _save_json_list(_port_maps_path(), maps)
    if _interface_exists():
        _apply_port_map_rules()
    _audit("add_port_map", extra=item)
    return {"ok": True, "map": item, "maps": maps}


def remove_port_map(map_id):
    maps = list_port_maps()
    kept = [item for item in maps if item["id"] != map_id]
    if len(kept) == len(maps):
        return {"ok": False, "error": "Port map not found"}
    _save_json_list(_port_maps_path(), kept)
    if _interface_exists():
        _apply_port_map_rules()
    _audit("remove_port_map", extra={"map_id": map_id})
    return {"ok": True, "maps": kept}


def _nft_cmd(*args):
    cmd = ["nft"] + list(args)
    try:
        r = subprocess.run(cmd, capture_output=True, text=True, timeout=15)
        if r.returncode == 0:
            return True
        print(f"[vipsy.vpn] nft FAIL: {' '.join(args)[:120]} -> {r.stderr.strip()[:200]}", flush=True)
    except Exception as e:
        print(f"[vipsy.vpn] nft ERROR: {e}", flush=True)
    return False


def _remove_nft_rules_by_comment(comment):
    for tbl, chains in [("filter", ["DOCKER-USER", "FORWARD"]), ("nat", ["PREROUTING", "OUTPUT", "POSTROUTING"])]:
        for chain_name in chains:
            try:
                r = subprocess.run(
                    ["nft", "-a", "list", "chain", _NFT_FAMILY, tbl, chain_name],
                    capture_output=True, text=True, timeout=10,
                )
                if r.returncode != 0:
                    continue
                for line in r.stdout.splitlines():
                    if f'comment "{comment}"' in line:
                        m = re.search(r'# handle (\d+)', line)
                        if m:
                            _nft_cmd("delete", "rule", _NFT_FAMILY, tbl, chain_name, "handle", m.group(1))
            except Exception:
                pass


def _inject_docker_rules(iface, comment, vpn_subnet):
    _remove_nft_rules_by_comment(comment)
    print(f"[vipsy.vpn] injecting rules into {_NFT_FAMILY} filter + nat for {iface}", flush=True)
    results = []
    for chain in ("DOCKER-USER", "FORWARD"):
        ok1 = _nft_cmd("insert", "rule", _NFT_FAMILY, "filter", chain,
                       "iifname", iface, "counter", "accept", "comment", f'"{comment}"')
        ok2 = _nft_cmd("insert", "rule", _NFT_FAMILY, "filter", chain,
                       "oifname", iface, "ct", "state", "established,related",
                       "counter", "accept", "comment", f'"{comment}"')
        results.extend([ok1, ok2])
        print(f"[vipsy.vpn] {chain}: iif_accept={ok1} oif_related={ok2}", flush=True)
    ok_nat = _nft_cmd("add", "rule", _NFT_FAMILY, "nat", "POSTROUTING",
                      "ip", "saddr", vpn_subnet, "oifname", "!=", iface,
                      "masquerade", "comment", f'"{comment}"')
    results.append(ok_nat)
    print(f"[vipsy.vpn] POSTROUTING masquerade: {ok_nat}", flush=True)
    return any(results)


def _protocols_for_map(item):
    return ("tcp", "udp") if item["protocol"] == "both" else (item["protocol"],)


def _apply_port_map_rules():
    _remove_nft_rules_by_comment(_VPN_PORTMAP_COMMENT)
    maps = list_port_maps()
    if not maps:
        return True
    ok = True
    for item in maps:
        for proto in _protocols_for_map(item):
            listen = str(item["listen_port"])
            target = f"{item['target_ip']}:{item['target_port']}"
            ok = _nft_cmd("add", "rule", _NFT_FAMILY, "nat", "PREROUTING",
                          proto, "dport", listen, "dnat", "to", target,
                          "comment", f'"{_VPN_PORTMAP_COMMENT}"') and ok
            ok = _nft_cmd("add", "rule", _NFT_FAMILY, "nat", "OUTPUT",
                          proto, "dport", listen, "dnat", "to", target,
                          "comment", f'"{_VPN_PORTMAP_COMMENT}"') and ok
            ok = _nft_cmd("insert", "rule", _NFT_FAMILY, "filter", "FORWARD",
                          "ip", "daddr", item["target_ip"], proto, "dport", str(item["target_port"]),
                          "counter", "accept", "comment", f'"{_VPN_PORTMAP_COMMENT}"') and ok
            ok = _nft_cmd("add", "rule", _NFT_FAMILY, "nat", "POSTROUTING",
                          "ip", "daddr", item["target_ip"], proto, "dport", str(item["target_port"]),
                          "masquerade", "comment", f'"{_VPN_PORTMAP_COMMENT}"') and ok
    return ok


def _interface_exists():
    try:
        _run(["ip", "link", "show", VPN_INTERFACE])
        return True
    except RuntimeError:
        return False


def _interface_ready(server_ip=None, subnet=None, port=None):
    if not _interface_exists():
        return False
    subnet = subnet or _subnet()
    server_ip = server_ip or _server_ip(subnet)
    port = port or _port()
    prefix = _network(subnet).prefixlen
    try:
        link = _run(["ip", "-o", "link", "show", "dev", VPN_INTERFACE])
        addrs = _run(["ip", "-o", "-4", "addr", "show", "dev", VPN_INTERFACE])
        listen_port = _run(["wg", "show", VPN_INTERFACE, "listen-port"])
    except RuntimeError:
        return False
    flags = link.split(":", 2)[1] if ":" in link else link
    return (
        "UP" in flags
        and f"{server_ip}/{prefix}" in addrs
        and listen_port.strip() == str(port)
    )


def _ensure_forwarding(iface=None):
    for cmd in [["sysctl", "-w", "net.ipv4.ip_forward=1"]]:
        try:
            subprocess.run(cmd, capture_output=True, text=True, timeout=10)
        except Exception:
            pass
    for path in ["/proc/sys/net/ipv4/ip_forward",
                 "/proc/sys/net/ipv4/conf/all/forwarding"]:
        try:
            with open(path, "w") as f:
                f.write("1\n")
        except Exception:
            pass
    for rp in ["/proc/sys/net/ipv4/conf/all/rp_filter",
               "/proc/sys/net/ipv4/conf/default/rp_filter"]:
        try:
            with open(rp, "w") as f:
                f.write("0\n")
        except Exception:
            pass
    if iface:
        for key, val in [("rp_filter", "0"), ("forwarding", "1")]:
            try:
                with open(f"/proc/sys/net/ipv4/conf/{iface}/{key}", "w") as f:
                    f.write(val + "\n")
            except Exception:
                pass
    enabled = False
    try:
        with open("/proc/sys/net/ipv4/ip_forward") as f:
            enabled = f.read().strip() == "1"
    except Exception:
        pass
    _log.info("ip_forward=%s iface=%s", enabled, iface)
    return enabled


def _apply_nat_rules():
    _ensure_forwarding(VPN_INTERFACE)
    lan = _detect_lan_subnet()
    subnet = _subnet()
    _log.info("apply VPN NAT: subnet=%s lan=%s iface=%s", subnet, lan, VPN_INTERFACE)

    ok = _inject_docker_rules(VPN_INTERFACE, _VPN_NFT_COMMENT, subnet)
    portmap_ok = _apply_port_map_rules()
    _log.info("rules injected: %s", ok)
    _log.info("port maps injected: %s", portmap_ok)

    for lbl, cmd in [
        ("DOCKER-USER", ["nft", "list", "chain", _NFT_FAMILY, "filter", "DOCKER-USER"]),
        ("FORWARD", ["nft", "list", "chain", _NFT_FAMILY, "filter", "FORWARD"]),
        ("NAT", ["nft", "list", "chain", _NFT_FAMILY, "nat", "POSTROUTING"]),
    ]:
        try:
            vfy = subprocess.run(cmd, capture_output=True, text=True, timeout=10)
            if vfy.returncode == 0:
                _log.info("%s:\n%s", lbl, vfy.stdout.strip())
            else:
                _log.info("%s: %s", lbl, vfy.stderr.strip()[:100])
        except Exception as e:
            _log.info("%s: %s", lbl, e)


def _flush_nat_rules():
    _log.info("flushing VPN NAT")
    _remove_nft_rules_by_comment(_VPN_NFT_COMMENT)
    _remove_nft_rules_by_comment(_VPN_PORTMAP_COMMENT)


def _create_interface(privkey, port, server_ip, subnet):
    prefix = str(_network(subnet).prefixlen)
    created = False
    try:
        _run(["ip", "link", "add", "dev", VPN_INTERFACE, "type", "wireguard"])
        created = True
        _run(["ip", "address", "add", "dev", VPN_INTERFACE, f"{server_ip}/{prefix}"])
        proc = subprocess.run(
            ["wg", "set", VPN_INTERFACE,
             "listen-port", str(port),
             "private-key", "/dev/stdin"],
            input=privkey, capture_output=True, text=True, timeout=10,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"wg set failed: {proc.stderr}")
        _run(["ip", "link", "set", "up", "dev", VPN_INTERFACE])
    except Exception:
        if created:
            _destroy_interface()
        raise


def _destroy_interface():
    try:
        _run(["ip", "link", "del", "dev", VPN_INTERFACE], check=False)
    except RuntimeError:
        pass


def _add_peer_to_wg(pubkey, preshared_key, vpn_ip):
    cmd = [
        "wg", "set", VPN_INTERFACE, "peer", pubkey,
        "allowed-ips", f"{vpn_ip}/32",
    ]
    if preshared_key:
        proc = subprocess.run(
            cmd + ["preshared-key", "/dev/stdin"],
            input=preshared_key, capture_output=True, text=True, timeout=10,
        )
        if proc.returncode != 0:
            raise RuntimeError(f"wg set peer failed: {proc.stderr}")
    else:
        _run(cmd)


def _remove_peer_from_wg(pubkey):
    try:
        _run(["wg", "set", VPN_INTERFACE, "peer", pubkey, "remove"])
    except RuntimeError:
        pass


def _restore_peers():
    peers = _load_peers()
    for p in peers:
        if not p.get("pubkey"):
            continue
        try:
            _add_peer_to_wg(p["pubkey"], p.get("preshared_key"), p["vpn_ip"])
        except RuntimeError:
            pass


def _generate_client_config(peer, server_pubkey, endpoint, dns=None):
    subnet = _subnet()
    allowed_ips = ", ".join(_routed_subnets(include_vpn=True))
    lines = [
        "[Interface]",
        f"PrivateKey = {peer['privkey']}",
        f"Address = {peer['vpn_ip']}/{_network(subnet).prefixlen}",
    ]
    if dns:
        lines.append(f"DNS = {dns}")
    lines += ["", "[Peer]", f"PublicKey = {server_pubkey}"]
    if peer.get("preshared_key"):
        lines.append(f"PresharedKey = {peer['preshared_key']}")
    lines += [
        f"AllowedIPs = {allowed_ips}",
        f"Endpoint = {endpoint}:{_port()}",
        "PersistentKeepalive = 25",
    ]
    return "\n".join(lines) + "\n"


def _generate_qr(config_text):
    try:
        proc = subprocess.run(
            ["qrencode", "-t", "PNG", "-o", "-"],
            input=config_text.encode(), capture_output=True, timeout=10,
        )
        if proc.returncode == 0 and proc.stdout:
            return proc.stdout
    except (FileNotFoundError, subprocess.TimeoutExpired):
        pass
    try:
        import qrcode
        import io
        qr = qrcode.QRCode(box_size=8, border=2)
        qr.add_data(config_text)
        qr.make(fit=True)
        img = qr.make_image(fill_color="black", back_color="white")
        buf = io.BytesIO()
        img.save(buf, format="PNG")
        return buf.getvalue()
    except ImportError:
        pass
    return None


def _get_endpoint(network="lan"):
    public_ip = os.environ.get("PUBLIC_IP", "")
    host_ip = os.environ.get("HOST_IP", "")
    if network == "tunnel":
        return "127.0.0.1"
    if network == "remote":
        return public_ip or host_ip or "YOUR_SERVER_IP"
    return host_ip or public_ip or "YOUR_SERVER_IP"


def _endpoint_info():
    host_ip = os.environ.get("HOST_IP", "")
    public_ip = os.environ.get("PUBLIC_IP", "")
    lan_ep = host_ip or public_ip or None
    remote_ep = public_ip or host_ip or None
    same = (lan_ep == remote_ep) if lan_ep and remote_ep else True
    return {
        "lan": lan_ep,
        "remote": remote_ep,
        "port": _port(),
        "same_endpoint": same,
        "port_forward_needed": bool(public_ip and host_ip and public_ip != host_ip),
        "relay_active": _is_relay_running(),
    }


def _relay_ready():
    try:
        with socket.create_connection(("127.0.0.1", WG_RELAY_PORT), timeout=0.25):
            return True
    except OSError:
        return False


def _relay_log_tail():
    try:
        log_path = Path(VPN_DATA_DIR) / "relay.log"
        lines = log_path.read_text(errors="replace").splitlines()
        return " | ".join(lines[-3:])[-400:]
    except Exception:
        return ""


def _start_relay():
    global _relay_process, _relay_last_error, _relay_retry_after
    if _relay_process and _relay_process.poll() is None and _relay_ready():
        return True
    if _relay_ready():
        _relay_last_error = None
        _relay_retry_after = 0.0
        return True
    if time.monotonic() < _relay_retry_after:
        return False
    _stop_relay()
    relay_script = os.path.join(os.path.dirname(__file__), "wg_tunnel_relay.py")
    if not os.path.exists(relay_script):
        _relay_last_error = "Relay server script is missing"
        _relay_retry_after = time.monotonic() + _RELAY_RETRY_DELAY
        return False
    env = dict(os.environ)
    env["VPN_PORT"] = str(_port())
    env["WG_RELAY_PORT"] = str(WG_RELAY_PORT)
    log_path = os.path.join(VPN_DATA_DIR, "relay.log")
    try:
        _data_dir()
        log_file = open(log_path, "a")
        try:
            _relay_process = subprocess.Popen(
                [sys.executable, relay_script],
                env=env,
                stdout=log_file,
                stderr=log_file,
            )
        finally:
            log_file.close()
    except Exception as exc:
        _relay_process = None
        _relay_last_error = f"Relay server failed to start: {exc}"
        _relay_retry_after = time.monotonic() + _RELAY_RETRY_DELAY
        return False

    deadline = time.monotonic() + _RELAY_START_TIMEOUT
    while time.monotonic() < deadline:
        if _relay_ready():
            _relay_last_error = None
            _relay_retry_after = 0.0
            return True
        if _relay_process.poll() is not None:
            break
        time.sleep(0.1)

    detail = _relay_log_tail()
    _relay_last_error = detail or "Relay server did not open its WebSocket listener"
    _relay_retry_after = time.monotonic() + _RELAY_RETRY_DELAY
    _stop_relay()
    return False


def _stop_relay():
    global _relay_process
    if _relay_process:
        try:
            _relay_process.terminate()
            _relay_process.wait(timeout=5)
        except Exception:
            try:
                _relay_process.kill()
            except Exception:
                pass
        _relay_process = None


def _is_relay_running():
    return (_relay_process is not None and _relay_process.poll() is None) or _relay_ready()


def relay_status():
    global _relay_last_error
    running = _is_relay_running()
    ready = _relay_ready()
    if ready:
        _relay_last_error = None
    return {
        "running": running,
        "ready": ready,
        "port": WG_RELAY_PORT,
        "error": _relay_last_error,
    }


def _tunnel_url():
    try:
        url_file = Path("/data/tunnel/tunnel_url")
        if url_file.exists():
            return url_file.read_text().strip()
    except Exception:
        pass
    try:
        url_file = Path("/data/tunnel/tunnel_fallback_url")
        if url_file.exists():
            return url_file.read_text().strip()
    except Exception:
        pass
    return None


def get_relay_client_script(tunnel_ws_url, local_udp_port=None):
    local_udp_port = int(local_udp_port or _port())
    return r'''#!/usr/bin/env python3
import base64, hashlib, os, select, socket, ssl, struct, sys, threading, time
from urllib.parse import urlparse

WS_URL = "''' + tunnel_ws_url + r'''"
LOCAL_UDP_PORT = ''' + str(local_udp_port) + r'''
_WS_GUID = "258EAFA5-E914-47DA-95CA-C5AB0DC85B11"
_stop = threading.Event()
_ws_lock = threading.Lock()


def _ws_connect(url):
    p = urlparse(url)
    host = p.hostname
    port = p.port or (443 if p.scheme == "wss" else 80)
    path = (p.path or "/") + ("?" + p.query if p.query else "")
    sock = socket.create_connection((host, port), timeout=20)
    if p.scheme == "wss":
        ctx = ssl.create_default_context()
        sock = ctx.wrap_socket(sock, server_hostname=host)
    key = base64.b64encode(os.urandom(16)).decode()
    expected = base64.b64encode(hashlib.sha1((key + _WS_GUID).encode()).digest()).decode()
    sock.sendall((
        f"GET {path} HTTP/1.1\r\n"
        f"Host: {host}\r\n"
        "Upgrade: websocket\r\nConnection: Upgrade\r\n"
        f"Sec-WebSocket-Key: {key}\r\nSec-WebSocket-Version: 13\r\n\r\n"
    ).encode())
    buf = b""
    while b"\r\n\r\n" not in buf:
        chunk = sock.recv(4096)
        if not chunk:
            raise ConnectionError("Server closed during handshake")
        buf += chunk
    status = buf.split(b"\r\n", 1)[0]
    if b"101" not in status:
        raise ConnectionError("Upgrade failed: " + status.decode(errors="replace"))
    if expected.encode() not in buf:
        raise ConnectionError("Sec-WebSocket-Accept mismatch")
    sock.settimeout(None)
    return sock


def _ws_send_frame(sock, opcode, data):
    with _ws_lock:
        mask = os.urandom(4)
        payload = bytes(b ^ mask[i % 4] for i, b in enumerate(data))
        n = len(data)
        if n < 126:
            hdr = struct.pack("BB", 0x80 | opcode, 0x80 | n)
        elif n < 65536:
            hdr = struct.pack("!BBH", 0x80 | opcode, 0x80 | 126, n)
        else:
            hdr = struct.pack("!BBQ", 0x80 | opcode, 0x80 | 127, n)
        sock.sendall(hdr + mask + payload)


def _ws_recv(sock, buf):
    def read(n):
        nonlocal buf
        while len(buf) < n:
            c = sock.recv(65536)
            if not c:
                raise ConnectionError("connection lost")
            buf += c
        data, buf = buf[:n], buf[n:]
        return data
    h = read(2)
    opcode = h[0] & 0x0F
    masked = bool(h[1] & 0x80)
    n = h[1] & 0x7F
    if n == 126:
        n = struct.unpack("!H", read(2))[0]
    elif n == 127:
        n = struct.unpack("!Q", read(8))[0]
    mk = read(4) if masked else b""
    raw = bytearray(read(n))
    if masked:
        for i in range(len(raw)):
            raw[i] ^= mk[i % 4]
    return opcode, bytes(raw), buf


def _ping_loop(sock, local_stop):
    while not _stop.is_set() and not local_stop.is_set():
        try:
            time.sleep(20)
            if not _stop.is_set() and not local_stop.is_set():
                _ws_send_frame(sock, 0x09, b"ping")
        except Exception:
            local_stop.set()
            break


def _run_once(udp):
    print("[vipsy-relay] Connecting to", WS_URL)
    try:
        sock = _ws_connect(WS_URL)
    except Exception as e:
        print("[vipsy-relay] Connection failed:", e)
        return False
    print("[vipsy-relay] Connected — relay active")
    wg_addr = [None]
    local_stop = threading.Event()

    def udp_to_ws():
        while not _stop.is_set() and not local_stop.is_set():
            try:
                r, _, _ = select.select([udp], [], [], 1.0)
                if r:
                    data, addr = udp.recvfrom(65535)
                    wg_addr[0] = addr
                    _ws_send_frame(sock, 0x02, data)
            except Exception as e:
                if not _stop.is_set():
                    print("[vipsy-relay] send error:", e)
                local_stop.set()
                return

    def ws_to_udp():
        buf = b""
        while not _stop.is_set() and not local_stop.is_set():
            try:
                op, payload, buf = _ws_recv(sock, buf)
                if op in (0x01, 0x02):
                    if wg_addr[0]:
                        udp.sendto(payload, wg_addr[0])
                elif op == 0x08:
                    local_stop.set()
                    return
                elif op == 0x09:
                    _ws_send_frame(sock, 0x0a, payload)
                elif op == 0x0a:
                    pass
            except Exception as e:
                if not _stop.is_set():
                    print("[vipsy-relay] recv error:", e)
                local_stop.set()
                return

    for fn in (udp_to_ws, ws_to_udp, lambda: _ping_loop(sock, local_stop)):
        threading.Thread(target=fn, daemon=True).start()
    try:
        while not _stop.is_set() and not local_stop.is_set():
            time.sleep(0.5)
    except KeyboardInterrupt:
        _stop.set()
    finally:
        local_stop.set()
        try:
            sock.close()
        except Exception:
            pass
    return not _stop.is_set()


def run():
    try:
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        udp.bind(("127.0.0.1", LOCAL_UDP_PORT))
    except OSError as e:
        print(f"[vipsy-relay] Cannot bind UDP port {LOCAL_UDP_PORT}: {e}")
        sys.exit(1)
    print(f"[vipsy-relay] Listening on 127.0.0.1:{LOCAL_UDP_PORT}")
    delay = 3
    try:
        while not _stop.is_set():
            ok = _run_once(udp)
            if _stop.is_set():
                break
            if ok:
                delay = 3
                print("[vipsy-relay] Disconnected — reconnecting in 3s...")
            else:
                delay = min(delay * 2, 30)
                print(f"[vipsy-relay] Retrying in {delay}s...")
            time.sleep(delay)
    except KeyboardInterrupt:
        pass
    finally:
        _stop.set()
        udp.close()
    print("[vipsy-relay] Stopped")


if __name__ == "__main__":
    run()
'''


def get_tunnel_bundle(peer_id, peer, server_pubkey, dns=None):
    import io
    import zipfile
    turl = _tunnel_url()
    if not turl:
        return None
    ws_url = turl.rstrip("/").replace("https://", "wss://").replace("http://", "ws://") + "/wg-tunnel"
    port = _port()
    relay_script = get_relay_client_script(ws_url, port)
    subnet = _subnet()
    allowed_ips = ", ".join(_routed_subnets(include_vpn=True))
    prefix = _network(subnet).prefixlen
    conf_lines = [
        "[Interface]",
        f"PrivateKey = {peer['privkey']}",
        f"Address = {peer['vpn_ip']}/{prefix}",
    ]
    if dns:
        conf_lines.append(f"DNS = {dns}")
    conf_lines += ["", "[Peer]", f"PublicKey = {server_pubkey}"]
    if peer.get("preshared_key"):
        conf_lines.append(f"PresharedKey = {peer['preshared_key']}")
    conf_lines += [
        f"AllowedIPs = {allowed_ips}",
        f"Endpoint = 127.0.0.1:{port}",
        "PersistentKeepalive = 25",
    ]
    conf_text = "\n".join(conf_lines) + "\n"
    conf_linux_lines = [
        "[Interface]",
        f"PrivateKey = {peer['privkey']}",
        f"Address = {peer['vpn_ip']}/{prefix}",
    ]
    if dns:
        conf_linux_lines.append(f"DNS = {dns}")
    conf_linux_lines += [
        "PreUp = nohup python3 %i/vipsy-relay.py >/dev/null 2>&1 &",
        "PreUp = sleep 2",
        "PostDown = pkill -f vipsy-relay.py || true",
        "",
        "[Peer]",
        f"PublicKey = {server_pubkey}",
    ]
    if peer.get("preshared_key"):
        conf_linux_lines.append(f"PresharedKey = {peer['preshared_key']}")
    conf_linux_lines += [
        f"AllowedIPs = {allowed_ips}",
        f"Endpoint = 127.0.0.1:{port}",
        "PersistentKeepalive = 25",
    ]
    conf_linux_text = "\n".join(conf_linux_lines) + "\n"
    setup_cmd = (
        '@echo off\r\n'
        'echo === Vipsy VPN Relay Setup ===\r\n'
        'set "DEST=%LOCALAPPDATA%\\Vipsy"\r\n'
        'mkdir "%DEST%" 2>nul\r\n'
        'copy /y "%~dp0vipsy-relay.pyw" "%DEST%\\vipsy-relay.pyw" >nul\r\n'
        'schtasks /create /tn "Vipsy VPN Relay" /tr "pythonw \\"%DEST%\\vipsy-relay.pyw\\"" '
        '/sc onlogon /rl limited /f >nul 2>&1\r\n'
        'echo.\r\n'
        'echo Relay installed to %DEST%\r\n'
        'echo It will auto-start at login.\r\n'
        'echo.\r\n'
        'echo Starting relay now...\r\n'
        'start "" pythonw "%DEST%\\vipsy-relay.pyw"\r\n'
        'timeout /t 2 /nobreak >nul\r\n'
        'echo.\r\n'
        'echo Done! Now import vipsy-tunnel.conf into WireGuard and Activate.\r\n'
        'pause\r\n'
    )
    uninstall_cmd = (
        '@echo off\r\n'
        'echo Stopping relay...\r\n'
        'taskkill /f /im pythonw.exe /fi "MODULES eq vipsy-relay*" >nul 2>&1\r\n'
        'taskkill /f /im python.exe /fi "MODULES eq vipsy-relay*" >nul 2>&1\r\n'
        'schtasks /delete /tn "Vipsy VPN Relay" /f >nul 2>&1\r\n'
        'set "DEST=%LOCALAPPDATA%\\Vipsy"\r\n'
        'del /q "%DEST%\\vipsy-relay.pyw" 2>nul\r\n'
        'rmdir "%DEST%" 2>nul\r\n'
        'echo Uninstalled.\r\n'
        'pause\r\n'
    )
    readme = (
        "Vipsy WireGuard Tunnel Bundle\r\n"
        "=============================\r\n\r\n"
        "This lets you connect to your home LAN remotely\r\n"
        "through a Cloudflare Tunnel (no port forwarding needed).\r\n\r\n"
        "WINDOWS (one-time setup):\r\n"
        "  1. Extract this zip\r\n"
        '  2. Double-click "setup.cmd"\r\n'
        "  3. Open WireGuard > Import tunnel > select vipsy-tunnel.conf\r\n"
        "  4. Click Activate — you're connected!\r\n\r\n"
        "The relay auto-starts at login. Just toggle WireGuard on/off.\r\n"
        "To remove: run uninstall.cmd\r\n\r\n"
        "LINUX / macOS:\r\n"
        "  1. Copy vipsy-relay.py + vipsy-tunnel-linux.conf to /etc/wireguard/\r\n"
        "  2. Rename vipsy-tunnel-linux.conf to wg-vipsy.conf\r\n"
        '  3. chmod +x /etc/wireguard/vipsy-relay.py\r\n'
        "  4. sudo wg-quick up wg-vipsy\r\n\r\n"
        "MOBILE (Android/iOS):\r\n"
        "  Tunnel mode is not supported on mobile.\r\n"
        "  Use the LAN config when on the same Wi-Fi.\r\n"
    )
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:
        zf.writestr("vipsy-tunnel/vipsy-tunnel.conf", conf_text)
        zf.writestr("vipsy-tunnel/vipsy-tunnel-linux.conf", conf_linux_text)
        zf.writestr("vipsy-tunnel/vipsy-relay.pyw", relay_script)
        zf.writestr("vipsy-tunnel/vipsy-relay.py", relay_script)
        zf.writestr("vipsy-tunnel/setup.cmd", setup_cmd)
        zf.writestr("vipsy-tunnel/uninstall.cmd", uninstall_cmd)
        zf.writestr("vipsy-tunnel/README.txt", readme)
    return buf.getvalue()


def get_peer_tunnel_bundle(peer_id, dns=None):
    peers = _load_peers()
    for p in peers:
        if p["peer_id"] == peer_id:
            _, server_pubkey = _get_or_create_server_keys()
            return get_tunnel_bundle(peer_id, p, server_pubkey, dns)
    return None


def _ttl_watcher():
    while not _ttl_stop.is_set():
        try:
            _expire_peers()
        except Exception:
            pass
        _ttl_stop.wait(VPN_TTL_CHECK_INTERVAL)


def _expire_peers():
    now = datetime.now(timezone.utc)
    with _lock:
        peers = _load_peers()
        expired = []
        remaining = []
        for p in peers:
            exp = p.get("expires_at")
            if exp and datetime.fromisoformat(exp) <= now:
                expired.append(p)
            else:
                remaining.append(p)
        if expired:
            for p in expired:
                if _interface_exists():
                    _remove_peer_from_wg(p["pubkey"])
                _audit("expire", p["peer_id"], p.get("name"))
            _save_peers(remaining)


def _start_ttl_watcher():
    global _ttl_thread
    if _ttl_thread and _ttl_thread.is_alive():
        return
    _ttl_stop.clear()
    _ttl_thread = threading.Thread(target=_ttl_watcher, daemon=True)
    _ttl_thread.start()


def _stop_ttl_watcher():
    _ttl_stop.set()
    global _ttl_thread
    if _ttl_thread:
        _ttl_thread.join(timeout=5)
        _ttl_thread = None


def enable():
    with _lock:
        overlap = _check_subnet_overlap()
        privkey, pubkey = _get_or_create_server_keys()
        subnet = _subnet()
        port = _port()
        server_ip = _server_ip(subnet)

        if _interface_exists():
            if _interface_ready(server_ip, subnet, port):
                _apply_nat_rules()
                _restore_peers()
                _remember_enabled(True)
                _start_ttl_watcher()
                relay_ready = _start_relay()
                result = {"ok": True, "message": "VPN already enabled"}
                if not relay_ready:
                    result["warning"] = _relay_last_error or "Cloudflare relay is not ready yet"
                return result
            _log.warning("local VPN interface exists but is not usable; recreating %s", VPN_INTERFACE)
            _destroy_interface()
            _flush_nat_rules()

        try:
            try:
                _create_interface(privkey, port, server_ip, subnet)
            except RuntimeError as first_error:
                if "Address in use" not in str(first_error) and "File exists" not in str(first_error):
                    raise
                _log.warning("local VPN interface create failed once, retrying after cleanup: %s", first_error)
                _destroy_interface()
                time.sleep(0.2)
                _create_interface(privkey, port, server_ip, subnet)
            _apply_nat_rules()
            _restore_peers()
        except Exception as exc:
            _stop_relay()
            _destroy_interface()
            _flush_nat_rules()
            _remember_enabled(False)
            message = str(exc)
            if "Address in use" in message:
                message = f"WireGuard port {port}/udp is already in use. Disable the old local VPN instance or choose another VPN port."
            _audit("enable_failed", extra={"error": message, "port": port, "subnet": subnet})
            return {"ok": False, "error": message}

        _remember_enabled(True)
        _start_ttl_watcher()
        relay_ready = _start_relay()
        _audit("enable", extra={"subnet": subnet, "port": port})

        result = {"ok": True, "message": "VPN enabled"}
        if overlap:
            result["warning"] = overlap
        if not relay_ready:
            relay_warning = _relay_last_error or "Cloudflare relay is not ready yet"
            result["warning"] = f"{result['warning']}; {relay_warning}" if result.get("warning") else relay_warning
        return result


def disable():
    with _lock:
        _remember_enabled(False)
        _stop_ttl_watcher()
        _stop_relay()
        if _interface_exists():
            _destroy_interface()
        _flush_nat_rules()
        _audit("disable")
        return {"ok": True, "message": "VPN disabled"}


def kill():
    with _lock:
        _remember_enabled(False)
        _stop_ttl_watcher()
        _stop_relay()
        peers = _load_peers()
        for p in peers:
            _audit("kill_remove", p["peer_id"], p.get("name"))
        _save_peers([])
        if _interface_exists():
            _destroy_interface()
        _flush_nat_rules()
        _audit("kill")
        return {"ok": True, "message": "VPN killed — all peers removed"}


_MAX_TTL = 365 * 24 * 3600  # 1 year cap
_PEER_NAME_RE = re.compile(r'^[\w\s\-\.]{1,64}$')


def add_peer(name, ttl=None, persistent=False, dns=None):
    if not _check_rate_limit():
        return {"ok": False, "error": "Rate limit exceeded — max 10 peers per minute"}

    if not name or not _PEER_NAME_RE.match(name):
        return {"ok": False, "error": "Peer name required (max 64 chars, alphanumeric/spaces/dashes/dots)"}

    if ttl is not None and (not isinstance(ttl, int) or ttl < 0 or ttl > _MAX_TTL):
        return {"ok": False, "error": f"TTL must be 0–{_MAX_TTL} seconds (max 1 year)"}

    with _lock:
        if not _interface_exists():
            return {"ok": False, "error": "VPN is not enabled"}

        peers = _load_peers()
        if len(peers) >= VPN_MAX_PEERS:
            return {"ok": False, "error": f"Maximum peers ({VPN_MAX_PEERS}) reached"}

        vpn_ip = _allocate_ip(peers)
        if not vpn_ip:
            return {"ok": False, "error": "No available IP addresses in subnet"}

        privkey = _wg_genkey()
        pubkey = _wg_pubkey(privkey)
        preshared_key = _wg_preshared_key()
        peer_id = uuid.uuid4().hex[:8]

        now = datetime.now(timezone.utc)
        expires_at = None
        if ttl and ttl > 0:
            from datetime import timedelta
            expires_at = (now + timedelta(seconds=ttl)).isoformat()

        peer = {
            "peer_id": peer_id,
            "name": name,
            "pubkey": pubkey,
            "privkey": privkey,
            "preshared_key": preshared_key,
            "vpn_ip": vpn_ip,
            "created_at": now.isoformat(),
            "expires_at": expires_at,
            "persistent": persistent,
        }

        _add_peer_to_wg(pubkey, preshared_key, vpn_ip)
        peers.append(peer)
        _save_peers(peers)
        _audit("add_peer", peer_id, name, {"vpn_ip": vpn_ip, "ttl": ttl})

        _, server_pubkey = _get_or_create_server_keys()
        lan_ep = _get_endpoint("lan")
        remote_ep = _get_endpoint("remote")
        tunnel_ep = _get_endpoint("tunnel")
        dns_str = dns or None
        lan_config = _generate_client_config(peer, server_pubkey, lan_ep, dns_str)
        remote_config = _generate_client_config(peer, server_pubkey, remote_ep, dns_str) if remote_ep != lan_ep else None
        tunnel_config = _generate_client_config(peer, server_pubkey, tunnel_ep, dns_str)
        qr_png = _generate_qr(lan_config)
        turl = _tunnel_url()

        return {
            "ok": True,
            "peer": _sanitize_peer(peer),
            "config": lan_config,
            "remote_config": remote_config,
            "tunnel_config": tunnel_config if turl else None,
            "tunnel_url": turl,
            "tunnel_bundle_available": bool(turl),
            "qr_available": qr_png is not None,
            "endpoints": _endpoint_info(),
        }


def remove_peer(peer_id):
    with _lock:
        peers = _load_peers()
        target = None
        remaining = []
        for p in peers:
            if p["peer_id"] == peer_id:
                target = p
            else:
                remaining.append(p)

        if not target:
            return {"ok": False, "error": "Peer not found"}

        if _interface_exists():
            _remove_peer_from_wg(target["pubkey"])
        _save_peers(remaining)
        _audit("remove_peer", peer_id, target.get("name"))
        return {"ok": True, "message": f"Peer {target.get('name', peer_id)} removed"}


def list_peers():
    peers = _load_peers()
    wg_data = _get_wg_show()
    result = []
    for p in peers:
        info = _sanitize_peer(p)
        wg_peer = wg_data.get(p["pubkey"], {})
        info["latest_handshake"] = wg_peer.get("latest_handshake")
        info["transfer_rx"] = wg_peer.get("transfer_rx")
        info["transfer_tx"] = wg_peer.get("transfer_tx")
        info["connected"] = bool(wg_peer.get("latest_handshake"))
        result.append(info)
    return result


def get_peer(peer_id):
    peers = _load_peers()
    for p in peers:
        if p["peer_id"] == peer_id:
            return _sanitize_peer(p)
    return None


def get_peer_config(peer_id, network="lan"):
    peers = _load_peers()
    for p in peers:
        if p["peer_id"] == peer_id:
            _, server_pubkey = _get_or_create_server_keys()
            endpoint = _get_endpoint(network)
            return _generate_client_config(p, server_pubkey, endpoint)
    return None


def get_peer_qr(peer_id, network="lan"):
    config = get_peer_config(peer_id, network)
    if not config:
        return None
    return _generate_qr(config)


def _sanitize_peer(peer):
    return {
        "peer_id": peer["peer_id"],
        "name": peer.get("name", ""),
        "vpn_ip": peer["vpn_ip"],
        "pubkey": peer["pubkey"],
        "created_at": peer.get("created_at"),
        "expires_at": peer.get("expires_at"),
        "persistent": peer.get("persistent", False),
    }


def _get_wg_show():
    if not _interface_exists():
        return {}
    try:
        out = _run(["wg", "show", VPN_INTERFACE, "dump"])
    except RuntimeError:
        return {}
    result = {}
    for line in out.splitlines()[1:]:
        parts = line.split("\t")
        if len(parts) >= 8:
            pubkey = parts[0]
            result[pubkey] = {
                "latest_handshake": int(parts[4]) if parts[4] != "0" else None,
                "transfer_rx": int(parts[5]) if parts[5] != "0" else 0,
                "transfer_tx": int(parts[6]) if parts[6] != "0" else 0,
            }
    return result


def status():
    up = _interface_exists()
    if up and not _is_relay_running():
        _start_relay()
    relay = relay_status()
    peers = _load_peers()
    connected = 0
    if up:
        wg_data = _get_wg_show()
        connected = sum(1 for d in wg_data.values() if d.get("latest_handshake"))
    overlap = _check_subnet_overlap() if up else None
    return {
        "enabled": up,
        "interface": VPN_INTERFACE if up else None,
        "subnet": _subnet(),
        "port": _port(),
        "server_ip": _server_ip() if up else None,
        "peer_count": len(peers),
        "connected_count": connected,
        "nat_active": up,
        "relay_running": relay["running"],
        "relay_ready": relay["ready"],
        "relay_error": relay["error"],
        "lan_subnet": _detect_lan_subnet(),
        "routed_subnets": _routed_subnets(include_vpn=False),
        "extra_subnets": list_extra_subnets(),
        "port_maps": list_port_maps(),
        "overlap_warning": overlap,
    }


def startup_cleanup():
    _stop_relay()
    _flush_nat_rules()
    if _interface_exists():
        # Preserve user intent before replacing stale host-network state.
        _remember_enabled(True)
        _destroy_interface()
    now = datetime.now(timezone.utc)
    peers = _load_peers()
    remaining = []
    for p in peers:
        exp = p.get("expires_at")
        if exp and datetime.fromisoformat(exp) <= now and not p.get("persistent"):
            _audit("startup_expire", p["peer_id"], p.get("name"))
        else:
            remaining.append(p)
    if len(remaining) != len(peers):
        _save_peers(remaining)


def startup_reconnect():
    if not is_enabled():
        print("[vipsy.vpn] startup_reconnect: no local VPN enabled flag, skipping", flush=True)
        return {"ok": True, "message": "Local VPN disabled"}
    print("[vipsy.vpn] startup_reconnect: restoring local VPN and Cloudflare relay...", flush=True)
    result = enable()
    if result.get("ok"):
        print(f"[vipsy.vpn] startup_reconnect OK: {result.get('message')}", flush=True)
    else:
        print(f"[vipsy.vpn] startup_reconnect FAILED: {result.get('error')}", flush=True)
    return result
