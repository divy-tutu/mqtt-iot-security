"""Optional real phone camera source for the 'camera' device and its preview.

A phone running an IP-webcam app serves MJPEG/JPEG over plain HTTP on the home
LAN. The hardened dashboard is HTTPS, so the gateway proxies that feed (see
gateway.py) and the camera device pulls snapshots from it to derive real
status/motion telemetry (device.py). Nothing here weakens the MQTT security
comparison: the camera still signs the same telemetry schema, and the broker
ACLs/TLS are unchanged.

The URL is operator-supplied, so set_source() and resolve_endpoint() enforce an
SSRF guard: only private/LAN addresses are accepted, and loopback, link-local
(including the 169.254.169.254 cloud-metadata address), multicast and other
reserved ranges are rejected. Validation happens both when the URL is saved and
again immediately before each fetch, because DNS can change between the two (a
small residual TOCTOU window remains; acceptable for a local lab).
"""
import ipaddress
import json
import socket
import time
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit

CONFIG_PATH = Path("/config/camera-source.json")
# Defaults match Android "IP Webcam"; other apps can override via set_source().
DEFAULT_VIDEO_PATH = "/video"
DEFAULT_SNAPSHOT_PATH = "/shot.jpg"
FETCH_TIMEOUT = 2.0


class SourceError(ValueError):
    """Raised when a supplied camera URL is missing, malformed or disallowed."""


def _check_ip(host):
    """Resolve host and require every address to be a private LAN address."""
    try:
        infos = socket.getaddrinfo(host, None)
    except socket.gaierror:
        raise SourceError("The camera address could not be resolved on the network.") from None
    addresses = {info[4][0] for info in infos}
    if not addresses:
        raise SourceError("The camera address could not be resolved on the network.")
    for address in addresses:
        ip = ipaddress.ip_address(address.split("%")[0])  # strip IPv6 zone id
        # Allow only ordinary home-LAN ranges; block loopback, link-local
        # (cloud metadata lives at 169.254.169.254), multicast and reserved.
        if not ip.is_private or ip.is_loopback or ip.is_link_local or ip.is_multicast or ip.is_reserved or ip.is_unspecified:
            raise SourceError("Only a private LAN camera address is allowed (not loopback, link-local or public).")
    return addresses


def _normalize(base_url):
    if not isinstance(base_url, str) or not base_url.strip():
        raise SourceError("Enter the camera address, for example http://192.168.1.42:8080")
    parts = urlsplit(base_url.strip())
    if parts.scheme not in ("http", "https") or not parts.hostname:
        raise SourceError("The camera address must start with http:// or https:// and include a host.")
    if parts.port is not None and not (0 < parts.port < 65536):
        raise SourceError("The camera address has an invalid port.")
    _check_ip(parts.hostname)
    # Keep scheme/host[:port] only; discard any path/query/fragment the user pasted.
    return urlunsplit((parts.scheme, parts.netloc, "", "", "")), parts.hostname, parts.port


def set_source(base_url, video_path=DEFAULT_VIDEO_PATH, snapshot_path=DEFAULT_SNAPSHOT_PATH):
    """Validate and persist a phone camera base URL. Returns the stored record."""
    normalized, _host, _port = _normalize(base_url)
    for name, value in (("video", video_path), ("snapshot", snapshot_path)):
        if not isinstance(value, str) or not value.startswith("/"):
            raise SourceError(f"The {name} path must start with '/'.")
    record = {"base_url": normalized, "video_path": video_path,
              "snapshot_path": snapshot_path, "updated": time.time()}
    CONFIG_PATH.parent.mkdir(parents=True, exist_ok=True)
    tmp = CONFIG_PATH.with_suffix(".tmp")
    tmp.write_text(json.dumps(record))
    tmp.replace(CONFIG_PATH)
    return record


def clear_source():
    CONFIG_PATH.unlink(missing_ok=True)


def get_source():
    """Return the stored record, or None if no phone camera is configured."""
    try:
        record = json.loads(CONFIG_PATH.read_text())
    except (FileNotFoundError, ValueError):
        return None
    if not isinstance(record, dict) or not isinstance(record.get("base_url"), str):
        return None
    record.setdefault("video_path", DEFAULT_VIDEO_PATH)
    record.setdefault("snapshot_path", DEFAULT_SNAPSHOT_PATH)
    return record


def resolve_endpoint(kind):
    """Return a fully validated URL for 'video' or 'snapshot', or None if unset.

    Re-validates the stored address against the SSRF guard right before use.
    """
    record = get_source()
    if not record:
        return None
    base_url, _host, _port = _normalize(record["base_url"])  # re-checks the LAN rule
    path = record["video_path"] if kind == "video" else record["snapshot_path"]
    return base_url + path
