"""Network target policy used before verification or scanning.

The policy rejects destinations that could expose the server's own network.
Private targets are allowed only in an explicitly isolated laboratory.
"""

import ipaddress
import socket
from urllib.parse import urlsplit, urlunsplit

from vulnhunter.config import get_settings


class TargetPolicyError(ValueError):
    pass


def normalize_origin(raw_url: str) -> str:
    parsed = urlsplit(raw_url)
    if parsed.scheme not in {"http", "https"} or not parsed.hostname:
        raise TargetPolicyError("El sitio debe usar http:// o https://")
    if parsed.username or parsed.password:
        raise TargetPolicyError("La URL no puede contener credenciales")
    host = parsed.hostname.lower().rstrip(".")
    try:
        host_text = f"[{ipaddress.ip_address(host)}]" if ":" in host else host
    except ValueError:
        host_text = host.encode("idna").decode("ascii")
    default_port = 443 if parsed.scheme == "https" else 80
    netloc = host_text if parsed.port in {None, default_port} else f"{host_text}:{parsed.port}"
    return urlunsplit((parsed.scheme, netloc, "", "", ""))


def _is_forbidden(address: str) -> bool:
    ip = ipaddress.ip_address(address)
    return not ip.is_global


def validate_target(raw_url: str) -> str:
    """Normalize a URL and ensure every resolved address is public by default."""
    origin = normalize_origin(raw_url)
    if get_settings().allow_private_targets:
        return origin

    hostname = urlsplit(origin).hostname
    assert hostname is not None
    try:
        addresses = {
            item[4][0]
            for item in socket.getaddrinfo(hostname, None, type=socket.SOCK_STREAM)
        }
    except socket.gaierror as exc:
        raise TargetPolicyError("El dominio no pudo resolverse") from exc
    if not addresses or any(_is_forbidden(address) for address in addresses):
        raise TargetPolicyError(
            "El objetivo resuelve a una dirección privada, local o reservada"
        )
    return origin

