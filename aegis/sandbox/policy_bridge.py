"""Translate policy obligations into a concrete :class:`SandboxSpec`.

When the policy engine returns ``Effect.SANDBOX`` it attaches obligations such
as::

    {"sandbox": {"image": "python:3.12-slim", "network": "deny",
                 "timeout_s": 15, "memory_mb": 256, "profile": "strict"}}

This module turns that loose dictionary into a validated spec.  The important
property is **monotonic hardening**: merging a policy obligation may only make
the sandbox stricter than the baseline, never looser.  Otherwise a single
over-permissive rule - or an injected obligation - could quietly re-enable the
network for every subsequent call.
"""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any, Dict, List, Mapping, Optional, Sequence

from ..core.errors import ValidationError
from ..core.logging import get_logger
from ..core.types import Decision, RiskLevel, SandboxKind, SandboxSpec
from ..core.utils import coerce_bool

__all__ = ["PolicyBridge", "SandboxObligation", "spec_from_obligations", "merge_specs"]

log = get_logger("sandbox.policy_bridge")

#: Network modes ordered from most to least restrictive.
_NETWORK_RANK: Dict[str, int] = {"deny": 0, "allowlist": 1, "allow": 2}

#: Seccomp profiles ordered from most to least restrictive.
_PROFILE_RANK: Dict[str, int] = {"strict": 0, "default": 1, "network": 2}

#: Isolation kinds ordered from strongest to weakest.
_KIND_RANK: Dict[SandboxKind, int] = {
    SandboxKind.GVISOR: 0,
    SandboxKind.DOCKER: 1,
    SandboxKind.REMOTE: 2,
    SandboxKind.FIREJAIL: 3,
    SandboxKind.SUBPROCESS: 4,
    SandboxKind.NONE: 5,
}


@dataclass
class SandboxObligation:
    """Normalised view of the ``sandbox`` obligation block."""

    kind: Optional[SandboxKind] = None
    image: str = ""
    network: str = ""
    egress_allowlist: List[str] = None  # type: ignore[assignment]
    timeout_s: Optional[float] = None
    memory_mb: Optional[int] = None
    cpu_quota: Optional[float] = None
    pids_limit: Optional[int] = None
    seccomp_profile: str = ""
    read_only_root: Optional[bool] = None
    writable_paths: List[str] = None  # type: ignore[assignment]
    env: Dict[str, str] = None  # type: ignore[assignment]
    user: str = ""

    def __post_init__(self) -> None:
        if self.egress_allowlist is None:
            self.egress_allowlist = []
        if self.writable_paths is None:
            self.writable_paths = []
        if self.env is None:
            self.env = {}

    @classmethod
    def parse(cls, raw: Mapping[str, Any]) -> "SandboxObligation":
        """Build from an untyped obligation mapping, tolerating aliases."""
        data = {str(k).lower(): v for k, v in (raw or {}).items()}

        kind_text = str(data.get("kind") or data.get("driver") or "").strip().lower()
        kind: Optional[SandboxKind] = None
        if kind_text:
            try:
                kind = SandboxKind(kind_text)
            except ValueError:
                raise ValidationError(
                    f"unknown sandbox kind in policy obligation: '{kind_text}'",
                    details={"valid": [k.value for k in SandboxKind]},
                )

        network = str(data.get("network") or data.get("net") or "").strip().lower()
        if network and network not in _NETWORK_RANK:
            raise ValidationError(
                f"unknown network mode '{network}' in sandbox obligation",
                details={"valid": sorted(_NETWORK_RANK)},
            )

        profile = str(data.get("seccomp_profile") or data.get("profile") or "").strip().lower()
        if profile and profile not in _PROFILE_RANK:
            raise ValidationError(
                f"unknown seccomp profile '{profile}' in sandbox obligation",
                details={"valid": sorted(_PROFILE_RANK)},
            )

        return cls(
            kind=kind,
            image=str(data.get("image") or ""),
            network=network,
            egress_allowlist=[str(x) for x in (data.get("egress_allowlist") or data.get("allowlist") or [])],
            timeout_s=_as_float(data.get("timeout_s", data.get("timeout"))),
            memory_mb=_as_int(data.get("memory_mb", data.get("memory"))),
            cpu_quota=_as_float(data.get("cpu_quota", data.get("cpus"))),
            pids_limit=_as_int(data.get("pids_limit", data.get("pids"))),
            seccomp_profile=profile,
            read_only_root=(
                coerce_bool(data["read_only_root"]) if "read_only_root" in data else None
            ),
            writable_paths=[str(x) for x in (data.get("writable_paths") or [])],
            env={str(k): str(v) for k, v in (data.get("env") or {}).items()},
            user=str(data.get("user") or ""),
        )


def _as_float(value: Any) -> Optional[float]:
    """Coerce to float, returning None for missing/invalid input."""
    if value is None or value == "":
        return None
    try:
        return float(value)
    except (TypeError, ValueError):
        return None


def _as_int(value: Any) -> Optional[int]:
    """Coerce to int, returning None for missing/invalid input."""
    parsed = _as_float(value)
    return int(parsed) if parsed is not None else None


class PolicyBridge:
    """Merge policy obligations onto a baseline spec, hardening only.

    Args:
        baseline: Organisation default spec.
        allow_relaxation: When True the bridge honours obligations that loosen
            the baseline (useful for a trusted internal build pipeline).  The
            default False is what production should use.
        risk_overrides: Extra hardening applied per risk level, e.g. forcing a
            10 second timeout and 128MB for ``CRITICAL``.
    """

    def __init__(
        self,
        baseline: Optional[SandboxSpec] = None,
        *,
        allow_relaxation: bool = False,
        risk_overrides: Optional[Mapping[RiskLevel, Mapping[str, Any]]] = None,
    ) -> None:
        self.baseline = baseline or SandboxSpec()
        self.allow_relaxation = allow_relaxation
        self.risk_overrides: Dict[RiskLevel, Dict[str, Any]] = {
            RiskLevel.HIGH: {"network": "deny", "seccomp_profile": "strict", "timeout_s": 20.0},
            RiskLevel.CRITICAL: {
                "network": "deny",
                "seccomp_profile": "strict",
                "timeout_s": 10.0,
                "memory_mb": 128,
                "pids_limit": 16,
                "read_only_root": True,
            },
        }
        for level, override in (risk_overrides or {}).items():
            self.risk_overrides[level] = {**self.risk_overrides.get(level, {}), **dict(override)}

    # ------------------------------------------------------------------ #
    def _pick_network(self, current: str, proposed: str) -> str:
        """Keep the stricter of two network modes."""
        if not proposed:
            return current
        if self.allow_relaxation:
            return proposed
        return proposed if _NETWORK_RANK[proposed] < _NETWORK_RANK.get(current, 2) else current

    def _pick_profile(self, current: str, proposed: str) -> str:
        """Keep the stricter of two seccomp profiles."""
        if not proposed:
            return current
        if self.allow_relaxation:
            return proposed
        return proposed if _PROFILE_RANK[proposed] < _PROFILE_RANK.get(current, 2) else current

    def _pick_kind(self, current: SandboxKind, proposed: Optional[SandboxKind]) -> SandboxKind:
        """Keep the stronger of two isolation kinds."""
        if proposed is None:
            return current
        if self.allow_relaxation:
            return proposed
        return proposed if _KIND_RANK[proposed] < _KIND_RANK.get(current, 5) else current

    @staticmethod
    def _pick_min(current: Any, proposed: Any, allow_relaxation: bool) -> Any:
        """Keep the smaller (stricter) numeric budget."""
        if proposed is None:
            return current
        if allow_relaxation:
            return proposed
        return min(current, proposed)

    # ------------------------------------------------------------------ #
    def apply(
        self,
        obligation: Mapping[str, Any],
        *,
        base: Optional[SandboxSpec] = None,
        risk: RiskLevel = RiskLevel.MEDIUM,
    ) -> SandboxSpec:
        """Produce the effective spec for one obligation block."""
        parsed = SandboxObligation.parse(obligation)
        spec = base or self.baseline
        fields = dict(vars(spec))

        fields["kind"] = self._pick_kind(spec.kind, parsed.kind)
        fields["network"] = self._pick_network(spec.network or "deny", parsed.network)
        fields["seccomp_profile"] = self._pick_profile(
            spec.seccomp_profile or "default", parsed.seccomp_profile
        )
        fields["timeout_s"] = self._pick_min(spec.timeout_s, parsed.timeout_s, self.allow_relaxation)
        fields["memory_mb"] = int(
            self._pick_min(spec.memory_mb, parsed.memory_mb, self.allow_relaxation)
        )
        fields["cpu_quota"] = self._pick_min(spec.cpu_quota, parsed.cpu_quota, self.allow_relaxation)
        fields["pids_limit"] = int(
            self._pick_min(spec.pids_limit, parsed.pids_limit, self.allow_relaxation)
        )
        if parsed.image:
            fields["image"] = parsed.image
        if parsed.user:
            fields["user"] = parsed.user
        if parsed.read_only_root is not None:
            fields["read_only_root"] = (
                parsed.read_only_root if self.allow_relaxation
                else bool(spec.read_only_root or parsed.read_only_root)
            )

        # Allowlists intersect rather than union unless relaxation is enabled:
        # an obligation may narrow the permitted destinations, never widen them.
        if parsed.egress_allowlist:
            if self.allow_relaxation or not spec.egress_allowlist:
                fields["egress_allowlist"] = list(parsed.egress_allowlist)
            else:
                fields["egress_allowlist"] = [
                    host for host in parsed.egress_allowlist if host in spec.egress_allowlist
                ]
        if parsed.writable_paths:
            fields["writable_paths"] = list(
                dict.fromkeys([*(spec.writable_paths or []), *parsed.writable_paths])
            ) if self.allow_relaxation else list(parsed.writable_paths)
        if parsed.env:
            fields["env"] = {**dict(spec.env or {}), **parsed.env}

        merged = SandboxSpec(**fields)
        merged = self._apply_risk(merged, risk)
        self._validate(merged)
        log.debug(
            "sandbox spec derived from policy obligation",
            fields={
                "kind": merged.kind.value,
                "network": merged.network,
                "timeout_s": merged.timeout_s,
                "memory_mb": merged.memory_mb,
                "profile": merged.seccomp_profile,
                "risk": risk.value,
            },
        )
        return merged

    def _apply_risk(self, spec: SandboxSpec, risk: RiskLevel) -> SandboxSpec:
        """Force additional hardening for high-risk calls."""
        override = self.risk_overrides.get(risk)
        if not override:
            return spec
        fields = dict(vars(spec))
        if "network" in override:
            fields["network"] = self._pick_network(spec.network, str(override["network"]))
        if "seccomp_profile" in override:
            fields["seccomp_profile"] = self._pick_profile(
                spec.seccomp_profile, str(override["seccomp_profile"])
            )
        for key in ("timeout_s", "memory_mb", "cpu_quota", "pids_limit"):
            if key in override:
                fields[key] = min(getattr(spec, key), override[key])
        if override.get("read_only_root"):
            fields["read_only_root"] = True
        return SandboxSpec(**fields)

    @staticmethod
    def _validate(spec: SandboxSpec) -> None:
        """Reject nonsensical or unsafe specs before they reach a driver."""
        problems: List[str] = []
        if spec.timeout_s <= 0:
            problems.append("timeout_s must be positive")
        if spec.memory_mb < 16:
            problems.append("memory_mb below 16 will not start an interpreter")
        if spec.pids_limit < 1:
            problems.append("pids_limit must be at least 1")
        if spec.network == "allowlist" and not spec.egress_allowlist:
            problems.append("network='allowlist' requires a non-empty egress_allowlist")
        if spec.user.startswith("0:") or spec.user == "root":
            problems.append("sandbox must not run as uid 0")
        if problems:
            raise ValidationError(
                "invalid sandbox specification: " + "; ".join(problems),
                details={"problems": problems},
            )

    # ------------------------------------------------------------------ #
    def from_decision(self, decision: Decision, *, base: Optional[SandboxSpec] = None) -> SandboxSpec:
        """Derive the spec directly from a policy :class:`Decision`."""
        obligation = dict(decision.obligations or {}).get("sandbox", {})
        if not isinstance(obligation, Mapping):
            obligation = {}
        return self.apply(obligation, base=base, risk=decision.risk)

    def describe(self, spec: SandboxSpec) -> Dict[str, Any]:
        """Explain the effective isolation posture in review-friendly terms."""
        return {
            "kind": spec.kind.value,
            "isolation_rank": _KIND_RANK.get(spec.kind, 5),
            "image": spec.image,
            "network": spec.network,
            "egress_allowlist": list(spec.egress_allowlist),
            "seccomp_profile": spec.seccomp_profile,
            "read_only_root": spec.read_only_root,
            "user": spec.user,
            "limits": {
                "timeout_s": spec.timeout_s,
                "memory_mb": spec.memory_mb,
                "cpu_quota": spec.cpu_quota,
                "pids_limit": spec.pids_limit,
            },
            "relaxation_allowed": self.allow_relaxation,
        }


def spec_from_obligations(
    obligations: Mapping[str, Any],
    *,
    baseline: Optional[SandboxSpec] = None,
    risk: RiskLevel = RiskLevel.MEDIUM,
) -> SandboxSpec:
    """Convenience wrapper around :meth:`PolicyBridge.apply`."""
    block = obligations.get("sandbox", obligations) if obligations else {}
    if not isinstance(block, Mapping):
        block = {}
    return PolicyBridge(baseline).apply(block, risk=risk)


def merge_specs(specs: Sequence[SandboxSpec]) -> SandboxSpec:
    """Combine several specs by taking the strictest value of each field."""
    if not specs:
        return SandboxSpec()
    merged = dict(vars(specs[0]))
    for spec in specs[1:]:
        merged["kind"] = min(merged["kind"], spec.kind, key=lambda k: _KIND_RANK.get(k, 5))
        merged["network"] = min(
            merged["network"], spec.network, key=lambda n: _NETWORK_RANK.get(n, 2)
        )
        merged["seccomp_profile"] = min(
            merged["seccomp_profile"], spec.seccomp_profile, key=lambda p: _PROFILE_RANK.get(p, 2)
        )
        merged["timeout_s"] = min(merged["timeout_s"], spec.timeout_s)
        merged["memory_mb"] = min(merged["memory_mb"], spec.memory_mb)
        merged["cpu_quota"] = min(merged["cpu_quota"], spec.cpu_quota)
        merged["pids_limit"] = min(merged["pids_limit"], spec.pids_limit)
        merged["read_only_root"] = merged["read_only_root"] or spec.read_only_root
        merged["egress_allowlist"] = [
            h for h in merged["egress_allowlist"] if h in spec.egress_allowlist
        ]
    return SandboxSpec(**merged)
