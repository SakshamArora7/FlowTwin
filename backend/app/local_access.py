"""Capture controls and streams are available only to the local workspace."""
from ipaddress import ip_address
from urllib.parse import urlsplit

from fastapi import HTTPException

ORIGINS = {f"http://{host}:{port}" for host in ("localhost", "127.0.0.1", "[::1]") for port in (5174, 8000)}


def require_local(request):
    peer = request.client.host if request.client else ""
    try:
        local = ip_address(peer).is_loopback
    except ValueError:
        local = peer == "testclient"  # Starlette's in-process test transport.
    try:
        host = urlsplit(f"http://{request.headers.get('host', '')}").hostname
    except ValueError:
        host = None
    origin = request.headers.get("origin")
    if not local or host not in {"localhost", "127.0.0.1", "::1", "testserver"} or (origin is not None and origin not in ORIGINS):
        raise HTTPException(403, "Live monitoring is restricted to the local FlowTwin workspace")
