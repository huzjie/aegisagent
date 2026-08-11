"""Shared indicator-of-compromise tables.

Kept in one place so the exfiltration, egress and supply-chain detectors agree
on what "a data-collection endpoint" or "a cloud metadata service" means, and
so an operator only has to extend one list.

Every entry is a lowercase host suffix, literal token or package name; matching
helpers below apply the correct comparison semantics for each table.
"""

from __future__ import annotations

import ipaddress
import re
from typing import Dict, Iterable, List, Optional, Set, Tuple
from urllib.parse import urlsplit

__all__ = [
    "EXFIL_SINK_DOMAINS",
    "PASTE_DOMAINS",
    "TUNNEL_DOMAINS",
    "SHORTENER_DOMAINS",
    "METADATA_ENDPOINTS",
    "CLOUD_METADATA_HOSTS",
    "SENSITIVE_PATHS",
    "PRODUCTION_MARKERS",
    "UNOFFICIAL_REGISTRIES",
    "POPULAR_PACKAGES",
    "MALICIOUS_PACKAGE_NAMES",
    "DANGEROUS_PORTS",
    "COMMON_WEB_PORTS",
    "is_exfil_sink",
    "is_private_host",
    "is_metadata_host",
    "classify_host",
    "split_url",
    "registrable_domain",
]


# --------------------------------------------------------------------------- #
# Data-collection / drop sites
# --------------------------------------------------------------------------- #
#: Request-capture services routinely used as prompt-injection exfil sinks.
EXFIL_SINK_DOMAINS: Set[str] = {
    "webhook.site", "requestbin.com", "requestbin.net", "pipedream.net",
    "requestcatcher.com", "hookb.in", "beeceptor.com", "mockbin.org",
    "postb.in", "typedwebhook.tools", "webhookinbox.com", "smee.io",
    "interact.sh", "oast.fun", "oast.pro", "oast.live", "oast.site",
    "burpcollaborator.net", "canarytokens.com", "dnslog.cn", "ceye.io",
    "pipedream.com", "webhookrelay.com", "hookdeck.com", "requestlogger.com",
}

#: Anonymous paste / file-drop services.
PASTE_DOMAINS: Set[str] = {
    "pastebin.com", "paste.ee", "hastebin.com", "ghostbin.com", "dpaste.com",
    "0bin.net", "privatebin.net", "termbin.com", "ix.io", "sprunge.us",
    "transfer.sh", "file.io", "anonfiles.com", "gofile.io", "catbox.moe",
    "0x0.st", "bashupload.com", "temp.sh", "litterbox.catbox.moe",
}

#: Reverse tunnels - a private service suddenly reachable from the internet.
TUNNEL_DOMAINS: Set[str] = {
    "ngrok.io", "ngrok-free.app", "ngrok.app", "loca.lt", "localtunnel.me",
    "serveo.net", "trycloudflare.com", "localhost.run", "telebit.io",
    "pagekite.me", "bore.pub", "tunnelto.dev", "expose.sh",
}

#: URL shorteners hide the true destination from both human and allowlist.
SHORTENER_DOMAINS: Set[str] = {
    "bit.ly", "tinyurl.com", "t.co", "goo.gl", "ow.ly", "is.gd", "buff.ly",
    "rebrand.ly", "cutt.ly", "shorturl.at", "rb.gy", "s.id", "t.ly", "lnk.to",
}


# --------------------------------------------------------------------------- #
# SSRF / metadata
# --------------------------------------------------------------------------- #
#: Instance metadata services - reading these yields cloud role credentials.
CLOUD_METADATA_HOSTS: Set[str] = {
    "169.254.169.254",          # AWS / Azure / OpenStack IMDS
    "metadata.google.internal",  # GCP
    "metadata.goog",
    "100.100.100.200",          # Alibaba Cloud
    "169.254.169.253",
    "169.254.170.2",            # AWS ECS task metadata
    "fd00:ec2::254",            # AWS IMDSv6
    "metadata",
    "instance-data",
    "metadata.platformequinix.com",
}

#: Full URLs seen in SSRF payloads (host plus the credential-bearing path).
METADATA_ENDPOINTS: Tuple[str, ...] = (
    "169.254.169.254/latest/meta-data",
    "169.254.169.254/metadata/identity/oauth2/token",
    "metadata.google.internal/computemetadata/v1",
    "169.254.170.2/v2/credentials",
    "100.100.100.200/latest/meta-data/ram/security-credentials",
)

#: Host-filesystem locations that should never appear in an agent tool call.
SENSITIVE_PATHS: Tuple[str, ...] = (
    "/etc/passwd", "/etc/shadow", "/etc/sudoers", "/root/.ssh", "/home/*/.ssh",
    "/proc/self/environ", "/var/run/secrets", "/run/secrets",
    "~/.aws/credentials", "~/.config/gcloud", "~/.kube/config", "~/.ssh/id_rsa",
    "~/.docker/config.json", "~/.npmrc", "~/.pypirc", "~/.netrc", "~/.git-credentials",
    "c:\\windows\\system32\\config\\sam", "c:\\users\\*\\.aws",
)

#: Tokens indicating an argument targets production rather than a sandbox.
PRODUCTION_MARKERS: Tuple[str, ...] = (
    "prod", "production", "prd", "live", "master", "main-db", "primary",
    "customer", "billing", "payment", "payroll", "生产", "正式", "线上",
)


# --------------------------------------------------------------------------- #
# Supply chain
# --------------------------------------------------------------------------- #
#: Package indexes other than the canonical ones for each ecosystem.
UNOFFICIAL_REGISTRIES: Set[str] = {
    "npm.pkg.evil.com", "registry.npmmirror.cf", "pypi.tuna.evil.org",
    "packages.internal.attacker.net", "registry.yarnpkg.cf",
}

#: Canonical registries - anything else in an install command is worth a look.
OFFICIAL_REGISTRIES: Set[str] = {
    "registry.npmjs.org", "pypi.org", "files.pythonhosted.org",
    "registry.yarnpkg.com", "crates.io", "static.crates.io", "proxy.golang.org",
    "repo.maven.apache.org", "rubygems.org", "nuget.org", "api.nuget.org",
    "ghcr.io", "docker.io", "registry-1.docker.io", "quay.io", "mcr.microsoft.com",
    "registry.npmmirror.com", "pypi.tuna.tsinghua.edu.cn", "mirrors.aliyun.com",
}

#: High-value packages that attackers typosquat.  Used with Levenshtein
#: distance: a *near miss* on one of these is the signal, not an exact match.
POPULAR_PACKAGES: Dict[str, Tuple[str, ...]] = {
    "pypi": (
        "requests", "urllib3", "numpy", "pandas", "boto3", "cryptography",
        "django", "flask", "fastapi", "pydantic", "setuptools", "pytest",
        "pillow", "sqlalchemy", "jinja2", "pyyaml", "certifi", "colorama",
        "openai", "anthropic", "langchain", "tensorflow", "torch", "scipy",
    ),
    "npm": (
        "express", "react", "lodash", "axios", "chalk", "commander", "debug",
        "webpack", "typescript", "eslint", "moment", "uuid", "dotenv", "next",
        "vue", "jest", "babel-core", "cross-env", "node-fetch", "socket.io",
    ),
    "crates": ("serde", "tokio", "clap", "rand", "regex", "reqwest", "syn"),
    "gem": ("rails", "rake", "nokogiri", "puma", "devise", "rspec"),
}

#: Package names publicly documented as malicious typosquats.
MALICIOUS_PACKAGE_NAMES: Set[str] = {
    "reqeusts", "requsts", "request3", "urllib", "urlib3", "python-sqlite",
    "colourama", "crossenv", "jeIlyfish", "python3-dateutil", "pytorch",
    "torchtriton", "distutil", "loadash", "lodahs", "expres", "axioss",
    "electron-native-notify", "eslint-scope-fix", "event-stream-fix",
    "discord.dll", "fallguys", "noblox.js-proxy", "ua-parser-js-v2",
    "openai-python-sdk", "anthropic-sdk-python", "langchain-community-extra",
}

#: Ports that should not be reached by an agent's HTTP tool.
DANGEROUS_PORTS: Dict[int, str] = {
    22: "ssh", 23: "telnet", 25: "smtp", 445: "smb", 1433: "mssql",
    1521: "oracle", 2049: "nfs", 2375: "docker-api-plain", 2376: "docker-api-tls",
    3306: "mysql", 3389: "rdp", 5432: "postgres", 5900: "vnc", 6379: "redis",
    9200: "elasticsearch", 11211: "memcached", 27017: "mongodb",
    10250: "kubelet", 2379: "etcd", 8500: "consul", 4444: "metasploit",
}

#: Ports normally expected for outbound web traffic.
COMMON_WEB_PORTS: Set[int] = {80, 443, 8080, 8443, 3000, 8000}


_IPV4_RE = re.compile(r"^\d{1,3}(?:\.\d{1,3}){3}$")


def split_url(url: str) -> Tuple[str, str, Optional[int], str]:
    """Return ``(scheme, host, port, path)`` for a URL or bare host string.

    Tolerates schemeless input (``example.com/path``) which is how URLs usually
    appear inside natural-language tool arguments.
    """
    raw = (url or "").strip()
    if not raw:
        return "", "", None, ""
    if "://" not in raw:
        raw = "//" + raw
    try:
        parts = urlsplit(raw)
    except ValueError:
        return "", "", None, ""
    host = (parts.hostname or "").lower()
    port: Optional[int]
    try:
        port = parts.port
    except ValueError:
        port = None
    return (parts.scheme or "").lower(), host, port, parts.path or ""


def registrable_domain(host: str) -> str:
    """Best-effort eTLD+1 without a public-suffix list dependency.

    Two-label suffixes common in practice (``co.uk``, ``com.cn`` ...) are
    handled explicitly; everything else falls back to the last two labels.
    """
    host = (host or "").strip().lower().rstrip(".")
    if not host or _IPV4_RE.match(host) or ":" in host:
        return host
    labels = host.split(".")
    if len(labels) <= 2:
        return host
    two_level = {"co", "com", "net", "org", "gov", "edu", "ac", "or", "ne"}
    if labels[-2] in two_level and len(labels[-1]) <= 3:
        return ".".join(labels[-3:])
    return ".".join(labels[-2:])


def _suffix_match(host: str, table: Iterable[str]) -> Optional[str]:
    host = (host or "").lower().rstrip(".")
    if not host:
        return None
    for entry in table:
        if host == entry or host.endswith("." + entry):
            return entry
    return None


def is_exfil_sink(host_or_url: str) -> Optional[Tuple[str, str]]:
    """Match a host against every drop-site table.

    Returns:
        ``(category, matched_domain)`` or ``None``.  Category is one of
        ``webhook_sink`` / ``paste_site`` / ``tunnel`` / ``shortener``.
    """
    _, host, _, _ = split_url(host_or_url) if ("/" in host_or_url or "://" in host_or_url) else ("", host_or_url.lower(), None, "")
    for category, table in (
        ("webhook_sink", EXFIL_SINK_DOMAINS),
        ("paste_site", PASTE_DOMAINS),
        ("tunnel", TUNNEL_DOMAINS),
        ("shortener", SHORTENER_DOMAINS),
    ):
        hit = _suffix_match(host, table)
        if hit:
            return category, hit
    return None


def is_metadata_host(host: str) -> bool:
    """True for cloud instance-metadata endpoints (credential theft via SSRF)."""
    host = (host or "").strip().lower().rstrip(".")
    return host in CLOUD_METADATA_HOSTS or _suffix_match(host, {"metadata.google.internal"}) is not None


def is_private_host(host: str) -> Optional[str]:
    """Classify a host as a non-routable / internal target.

    Returns a short reason (``loopback``, ``private``, ``link_local``,
    ``internal_tld``) or ``None`` when the host looks like a public name.
    """
    host = (host or "").strip().lower().rstrip(".")
    if not host:
        return None
    if host in ("localhost", "localhost.localdomain", "ip6-localhost"):
        return "loopback"
    try:
        address = ipaddress.ip_address(host)
    except ValueError:
        if host.endswith((".local", ".internal", ".intranet", ".corp", ".lan", ".home.arpa")):
            return "internal_tld"
        if "." not in host:
            return "bare_hostname"
        return None
    if address.is_loopback:
        return "loopback"
    if address.is_link_local:
        return "link_local"
    if address.is_private:
        return "private"
    if address.is_reserved or address.is_multicast:
        return "reserved"
    return None


def classify_host(host_or_url: str) -> Dict[str, object]:
    """One-shot triage used by the egress and exfiltration detectors.

    Returns a dict with ``host``, ``port``, ``scheme``, ``path`` plus the
    boolean/notable findings: ``sink``, ``private``, ``metadata``,
    ``is_ip_literal`` and ``dangerous_port``.
    """
    scheme, host, port, path = split_url(host_or_url)
    is_ip = bool(_IPV4_RE.match(host)) or (":" in host and host.count(":") > 1)
    return {
        "scheme": scheme,
        "host": host,
        "port": port,
        "path": path,
        "sink": is_exfil_sink(host),
        "private": is_private_host(host),
        "metadata": is_metadata_host(host),
        "is_ip_literal": is_ip,
        "dangerous_port": DANGEROUS_PORTS.get(port) if port else None,
        "registrable": registrable_domain(host),
    }


def all_sink_domains() -> List[str]:
    """Flat, sorted view of every drop-site domain (for reporting / config)."""
    return sorted(EXFIL_SINK_DOMAINS | PASTE_DOMAINS | TUNNEL_DOMAINS | SHORTENER_DOMAINS)
