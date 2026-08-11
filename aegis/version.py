"""Single source of truth for the AegisAgent version."""

from __future__ import annotations

__version__ = "1.0.0"
__release__ = "2026-08-11"
__codename__ = "CoreBreak Response"

VERSION_INFO = tuple(int(part) for part in __version__.split("."))

# Security content pack versions - bumped independently of the platform.
POLICY_PACK_VERSION = "2026.08.11"
SIGNATURE_PACK_VERSION = "2026.08.11"
SCENARIO_PACK_VERSION = "2026.08.11"

# Wire-protocol version for attestation tokens; bump on breaking changes.
ATTESTATION_VERSION = 1


def user_agent() -> str:
    return f"AegisAgent/{__version__} (+https://github.com/huzjie/aegisagent)"


def version_banner() -> str:
    return (
        f"AegisAgent {__version__} \"{__codename__}\" "
        f"(released {__release__}, policy pack {POLICY_PACK_VERSION})"
    )
