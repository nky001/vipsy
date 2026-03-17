import logging
import threading
from dataclasses import dataclass

try:
    from dnslib import A, QTYPE, RCODE, RR, DNSRecord
    from dnslib.server import BaseResolver, DNSServer
    _DNSLIB_OK = True
except Exception:
    A = QTYPE = RCODE = RR = DNSRecord = None
    BaseResolver = object
    DNSServer = None
    _DNSLIB_OK = False

_log = logging.getLogger("vipsy.dns")


@dataclass
class _DnsConfig:
    enabled: bool = False
    hostname: str = ""
    local_ip: str = ""
    upstream: str = "1.1.1.1"
    ttl: int = 30
    port: int = 53


_lock = threading.Lock()
_config = _DnsConfig()
_server: object | None = None
_stats = {
    "queries": 0,
    "local_answers": 0,
    "upstream_answers": 0,
    "upstream_failures": 0,
}


class _Resolver(BaseResolver):
    def resolve(self, request, handler):
        with _lock:
            cfg = _DnsConfig(**_config.__dict__)
        _stats["queries"] += 1

        qname = str(request.q.qname).rstrip(".").lower()
        qtype = QTYPE.get(request.q.qtype, "")
        reply = request.reply()

        target = cfg.hostname.strip().lower()
        if qtype == "A" and target and qname == target and cfg.local_ip:
            try:
                pkt = request.send(cfg.upstream, 53, timeout=2)
                upstream_reply = DNSRecord.parse(pkt)
                if upstream_reply.rr:
                    _stats["upstream_answers"] += 1
                    return upstream_reply
            except Exception:
                _stats["upstream_failures"] += 1

            reply.add_answer(
                RR(
                    rname=request.q.qname,
                    rtype=QTYPE.A,
                    rclass=1,
                    ttl=cfg.ttl,
                    rdata=A(cfg.local_ip),
                )
            )
            _stats["local_answers"] += 1
            return reply

        try:
            pkt = request.send(cfg.upstream, 53, timeout=2)
            upstream_reply = DNSRecord.parse(pkt)
            _stats["upstream_answers"] += 1
            return upstream_reply
        except Exception:
            _stats["upstream_failures"] += 1
            reply.header.rcode = RCODE.SERVFAIL
            return reply


def _build_status(running: bool):
    with _lock:
        cfg = _DnsConfig(**_config.__dict__)
    return {
        "enabled": cfg.enabled,
        "running": running,
        "available": _DNSLIB_OK,
        "hostname": cfg.hostname or None,
        "local_ip": cfg.local_ip or None,
        "upstream": cfg.upstream,
        "ttl": cfg.ttl,
        "port": cfg.port,
        "queries": _stats["queries"],
        "local_answers": _stats["local_answers"],
        "upstream_answers": _stats["upstream_answers"],
        "upstream_failures": _stats["upstream_failures"],
    }


def apply_config(enabled: bool, hostname: str, local_ip: str, upstream: str, ttl: int = 30, port: int = 53):
    global _server
    with _lock:
        _config.enabled = bool(enabled)
        _config.hostname = (hostname or "").strip().lower().rstrip(".")
        _config.local_ip = (local_ip or "").strip()
        _config.upstream = (upstream or "1.1.1.1").strip()
        _config.ttl = int(ttl) if int(ttl) > 0 else 30
        _config.port = int(port) if int(port) > 0 else 53

    stop()

    with _lock:
        cfg = _DnsConfig(**_config.__dict__)

    if not cfg.enabled or not cfg.hostname or not cfg.local_ip:
        return _build_status(False)

    if not _DNSLIB_OK:
        _log.warning("smart dns unavailable: dnslib is not installed")
        return _build_status(False)

    try:
        _server = DNSServer(_Resolver(), port=cfg.port, address="0.0.0.0", tcp=False, logger=None)
        _server.start_thread()
        _log.info("smart dns enabled on :%d for %s -> %s", cfg.port, cfg.hostname, cfg.local_ip)
        return _build_status(True)
    except Exception as e:
        _log.warning("smart dns failed to start: %s", e)
        _server = None
        return _build_status(False)


def stop():
    global _server
    if _server:
        try:
            _server.stop()
        except Exception:
            pass
        _server = None


def status():
    running = _server is not None
    return _build_status(running)
