"""The policy enforcement engine.

:class:`PolicyEngine` is the single place a tool call is definitively judged.
It is intentionally *small*: the expensive work lives in the compiler (rule
validation and the inverted index), the matchers (cheap structural pre-filters)
and the condition DSL (the expressive part).  The engine orchestrates them and
guarantees three properties that matter more than any individual rule:

**Fail closed.**  If anything inside evaluation raises - a corrupt bundle, a
bad obligation, a matcher fed an unexpected type - the verdict is raised to
``deny`` (configurable via ``policy.fail_closed_effect``).  A policy engine that
fails *open* is worse than no engine at all, because it creates the appearance
of control.

**Never default to allow.**  When no rule matches, the configured
``default_effect`` applies.  The shipped default is ``require_approval``: an
unknown call is a human's problem, not an automatic yes.

**Hot reload without a gap.**  Long-lived gateways get policy updates without a
restart.  The engine polls source mtimes and recompiles into a *new* object
which is swapped in atomically; a half-written or invalid file leaves the
previously-good policy serving traffic.

The hot path (:meth:`PolicyEngine.evaluate`) is cached with a short-TTL LRU
keyed on exactly the context fields that can change a verdict, so an agent
retrying the same call inside one turn costs two dict lookups.
"""

from __future__ import annotations

import os
import threading
import time
from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional, Sequence, Tuple

from ..core.config import Settings, get_settings
from ..core.crypto import sha256_hex
from ..core.errors import PolicyError
from ..core.logging import get_logger
from ..core.types import (
    Decision,
    Effect,
    EvaluationContext,
    PolicyMatch,
    utc_now,
)
from ..core.utils import LRUCache
from .bundles import load_bundle_file, load_builtin_bundles, load_bundles, load_from_settings
from .compiler import CompiledPolicy, CompiledRule, PolicyCompiler
from .effects import EffectResolution, apply_redactions, redact_paths, resolve
from .model import PolicyBundle

__all__ = ["EngineStats", "PolicyEngine", "build_engine"]

logger = get_logger(__name__)

#: How long an identical context keeps its cached verdict.  Deliberately short:
#: the cache exists to absorb retry storms, not to serve stale policy.
_DEFAULT_CACHE_TTL_S = 5.0


# --------------------------------------------------------------------------- #
# Statistics
# --------------------------------------------------------------------------- #
@dataclass
class EngineStats:
    """Rolling counters surfaced on ``/healthz`` and by ``aegis policy stats``."""

    evaluations: int = 0
    cache_hits: int = 0
    cache_misses: int = 0
    recompiles: int = 0
    reload_failures: int = 0
    errors: int = 0
    fail_closed_trips: int = 0
    by_effect: Dict[str, int] = field(default_factory=dict)
    last_reload: float = 0.0
    last_error: str = ""

    def record(self, effect: Effect) -> None:
        """Count one completed evaluation."""
        self.evaluations += 1
        self.by_effect[effect.value] = self.by_effect.get(effect.value, 0) + 1

    def as_dict(self) -> Dict[str, Any]:
        """Serialise for metrics scraping."""
        lookups = self.cache_hits + self.cache_misses
        return {
            "evaluations": self.evaluations,
            "cache_hits": self.cache_hits,
            "cache_misses": self.cache_misses,
            "cache_hit_rate": round(self.cache_hits / lookups, 4) if lookups else 0.0,
            "recompiles": self.recompiles,
            "reload_failures": self.reload_failures,
            "errors": self.errors,
            "fail_closed_trips": self.fail_closed_trips,
            "by_effect": dict(self.by_effect),
            "last_reload": round(self.last_reload, 3),
            "last_error": self.last_error,
        }


# --------------------------------------------------------------------------- #
# Engine
# --------------------------------------------------------------------------- #
class PolicyEngine:
    """Evaluate tool calls against a compiled policy set.

    Parameters
    ----------
    compiled:
        A pre-compiled policy.  Pass ``None`` to start empty and call
        :meth:`load` later.
    default_effect:
        Applied when no rule matches.  ``None`` means "take it from the packs'
        ``defaults.effect``, else ``require_approval``".
    fail_closed:
        When True (the default) an internal error raises the verdict to
        ``fail_closed_effect`` instead of letting the call through.
    fail_closed_effect:
        The floor applied on error.  ``deny`` unless overridden.
    hot_reload / reload_interval_s:
        Poll ``source_paths`` for mtime changes and recompile in place.
    cache_size / cache_ttl_s:
        Verdict memoisation.  Set ``cache_size=0`` to disable.
    """

    def __init__(
        self,
        compiled: Optional[CompiledPolicy] = None,
        *,
        default_effect: Optional[Effect] = None,
        fail_closed: bool = True,
        fail_closed_effect: Effect = Effect.DENY,
        hot_reload: bool = False,
        reload_interval_s: float = 15.0,
        cache_size: int = 4096,
        cache_ttl_s: float = _DEFAULT_CACHE_TTL_S,
        source_paths: Optional[Sequence[str]] = None,
        strict: bool = True,
        name: str = "default",
    ) -> None:
        self.name = name
        self.strict = bool(strict)
        self.fail_closed = bool(fail_closed)
        self.fail_closed_effect = fail_closed_effect
        self.hot_reload = bool(hot_reload)
        self.reload_interval_s = float(reload_interval_s)

        self._explicit_default = default_effect
        self._lock = threading.RLock()
        self._compiler = PolicyCompiler(strict=strict)
        self._compiled: CompiledPolicy = compiled or CompiledPolicy(policy_ids=[name])
        self._bundles: List[PolicyBundle] = []
        self._source_paths: List[str] = [str(p) for p in (source_paths or [])]
        self._mtimes: Dict[str, float] = {}
        self._cache = LRUCache(maxsize=max(cache_size, 1), ttl_s=cache_ttl_s)
        self._cache_enabled = cache_size > 0
        self._stats = EngineStats()
        self._last_check = 0.0
        self._snapshot_mtimes()

    # ------------------------------------------------------------------ #
    # Construction
    # ------------------------------------------------------------------ #
    @classmethod
    def from_bundles(
        cls,
        bundles: Sequence[PolicyBundle],
        *,
        settings: Optional[Settings] = None,
        name: str = "bundles",
        **kwargs: Any,
    ) -> "PolicyEngine":
        """Build an engine from in-memory bundles."""
        engine = cls(**_engine_kwargs(settings, name=name, **kwargs))
        engine.load(bundles)
        return engine

    @classmethod
    def from_directory(
        cls,
        directory: Any,
        *,
        settings: Optional[Settings] = None,
        names: Optional[Sequence[str]] = None,
        name: str = "directory",
        **kwargs: Any,
    ) -> "PolicyEngine":
        """Build an engine from every pack found in ``directory``."""
        bundles = load_bundles(directory, names=names, missing_ok=True)
        return cls.from_bundles(bundles, settings=settings, name=name, **kwargs)

    @classmethod
    def from_builtins(
        cls,
        names: Optional[Sequence[str]] = None,
        *,
        settings: Optional[Settings] = None,
        name: str = "builtin",
        **kwargs: Any,
    ) -> "PolicyEngine":
        """Build an engine from the packs shipped inside the package."""
        return cls.from_bundles(
            load_builtin_bundles(names), settings=settings, name=name, **kwargs
        )

    @classmethod
    def from_settings(
        cls,
        settings: Optional[Settings] = None,
        *,
        name: str = "settings",
        **kwargs: Any,
    ) -> "PolicyEngine":
        """Build an engine from configuration: built-ins plus operator packs."""
        settings = settings or get_settings()
        return cls.from_bundles(
            load_from_settings(settings), settings=settings, name=name, **kwargs
        )

    # ------------------------------------------------------------------ #
    # Loading / reloading
    # ------------------------------------------------------------------ #
    def load(self, bundles: Sequence[PolicyBundle]) -> CompiledPolicy:
        """Compile ``bundles`` and swap the result in atomically."""
        compiled = self._compiler.compile(list(bundles))
        with self._lock:
            self._compiled = compiled
            self._bundles = list(bundles)
            self._source_paths = [b.source for b in bundles if b.source]
            self._stats.recompiles += 1
            self._stats.last_reload = utc_now()
            self._snapshot_mtimes()
            self._cache.clear()
        logger.info(
            "policy.engine_loaded",
            extra={
                "engine": self.name,
                "bundles": len(bundles),
                "rules": compiled.rule_count,
                "warnings": len(compiled.warnings),
                "default_effect": self.default_effect.value,
            },
        )
        return compiled

    def reload(self) -> bool:
        """Recompile from ``source_paths``; keep the old policy on failure.

        Returns True when a new policy was installed.
        """
        paths = list(self._source_paths)
        if not paths:
            return False
        try:
            bundles = [load_bundle_file(p) for p in paths if os.path.exists(p)]
            if not bundles:
                return False
            self.load(bundles)
            return True
        except Exception as exc:  # pragma: no cover - never break live traffic
            with self._lock:
                self._stats.reload_failures += 1
                self._stats.last_error = str(exc)
            logger.error(
                "policy.reload_failed",
                extra={"engine": self.name, "error": str(exc)},
            )
            return False

    def maybe_reload(self) -> bool:
        """Reload if hot reload is on, the interval elapsed and a file changed."""
        if not self.hot_reload or not self._source_paths:
            return False
        now = time.time()
        if now - self._last_check < self.reload_interval_s:
            return False
        self._last_check = now
        if not self._sources_changed():
            return False
        return self.reload()

    def _sources_changed(self) -> bool:
        """True when any known source file has a different mtime."""
        for path in self._source_paths:
            try:
                mtime = os.path.getmtime(path)
            except OSError:
                continue
            if self._mtimes.get(path) != mtime:
                return True
        return False

    def _snapshot_mtimes(self) -> None:
        """Record current mtimes so the next poll can detect a change."""
        self._last_check = time.time()
        for path in self._source_paths:
            try:
                self._mtimes[path] = os.path.getmtime(path)
            except OSError:
                self._mtimes.pop(path, None)

    # ------------------------------------------------------------------ #
    # Evaluation
    # ------------------------------------------------------------------ #
    @property
    def default_effect(self) -> Effect:
        """Effect applied when nothing matches."""
        if self._explicit_default is not None:
            return self._explicit_default
        return self._compiled.default_effect or Effect.REQUIRE_APPROVAL

    @property
    def bundle_version(self) -> str:
        """Stable identifier of the compiled rule set, stamped on every decision.

        Two gateways with the same effective rules produce the same version, so
        an auditor can prove which exact pack produced a given verdict.
        """
        return self._compiled.version

    def evaluate(self, ctx: EvaluationContext) -> Tuple[Effect, List[PolicyMatch]]:
        """Judge one call.  Returns ``(effect, matches)``.

        This is the function every enforcement point calls.  It never raises:
        an internal failure is converted into the fail-closed effect and
        recorded, because a crashing policy check must not become an implicit
        allow.
        """
        resolution = self.resolve(ctx)
        return resolution.effect, list(resolution.contributing)

    def resolve(self, ctx: EvaluationContext) -> EffectResolution:
        """Full arbitration result: effect, obligations, decisive rule, reason."""
        self.maybe_reload()

        try:
            key = self._cache_key(ctx) if self._cache_enabled else ""
            if key:
                cached = self._cache.get(key)
                if cached is not None:
                    self._stats.cache_hits += 1
                    return cached
                self._stats.cache_misses += 1

            matches = self._collect_matches(ctx)
            resolution = resolve(matches, default=self.default_effect)
        except Exception as exc:  # pragma: no cover - defensive by design
            with self._lock:
                self._stats.errors += 1
                self._stats.last_error = str(exc)
            logger.error(
                "policy.evaluation_failed",
                extra={"engine": self.name, "error": str(exc)},
            )
            if not self.fail_closed:
                return EffectResolution(
                    effect=self.default_effect,
                    reason=f"evaluation error ({exc}); applied default effect",
                )
            self._stats.fail_closed_trips += 1
            return EffectResolution(
                effect=self.fail_closed_effect,
                reason=f"evaluation error ({exc}); failed closed",
            )

        self._stats.record(resolution.effect)
        if key:
            self._cache.set(key, resolution)
        return resolution

    def decide(self, ctx: EvaluationContext) -> Decision:
        """Evaluate and package the verdict as an auditable :class:`Decision`."""
        started = time.perf_counter()
        resolution = self.resolve(ctx)
        return Decision(
            call_id=ctx.call.id,
            session_id=ctx.session.id,
            agent_id=ctx.agent.id,
            tenant_id=ctx.agent.tenant_id,
            effect=resolution.effect,
            risk=ctx.risk,
            risk_score=ctx.risk_score,
            categories=list(ctx.categories),
            provenance=ctx.provenance,
            findings=list(ctx.findings),
            matches=list(resolution.contributing),
            obligations=dict(resolution.obligations),
            reason=resolution.reason,
            duration_ms=(time.perf_counter() - started) * 1000.0,
            policy_bundle_version=self._compiled.version,
        )

    def _collect_matches(self, ctx: EvaluationContext) -> List[PolicyMatch]:
        """Run every candidate rule for this call and collect the ones that fire."""
        with self._lock:
            compiled = self._compiled
        candidates = compiled.candidates(ctx.call.qualified_name, ctx.call.tool)
        matches: List[PolicyMatch] = []
        for rule in candidates:
            if rule.evaluate(ctx):
                matches.append(rule.to_match(ctx))
        return matches

    # ------------------------------------------------------------------ #
    # Obligations
    # ------------------------------------------------------------------ #
    def obligations_for(self, ctx: EvaluationContext) -> Dict[str, Any]:
        """The merged obligation bag for this call's verdict."""
        return dict(self.resolve(ctx).obligations)

    def redacted_arguments(self, ctx: EvaluationContext) -> Tuple[Dict[str, Any], List[str]]:
        """Apply the ``redact`` obligation to the call arguments.

        Returns ``(redacted_copy, applied_paths)``; the original arguments are
        left untouched so the audit trail keeps the true payload.
        """
        obligations = self.obligations_for(ctx)
        return apply_redactions(ctx.call.arguments, redact_paths(obligations))

    # ------------------------------------------------------------------ #
    # Introspection
    # ------------------------------------------------------------------ #
    def explain(self, ctx: EvaluationContext) -> str:
        """Human-readable rendering of a verdict and why it was reached."""
        resolution = self.resolve(ctx)
        lines = [
            f"[policy:{self.name}] {ctx.call.qualified_name} -> {resolution.effect.value}",
            f"  {resolution.reason}",
        ]
        for match in sorted(
            resolution.contributing, key=lambda m: (-m.priority, m.rule_id)
        ):
            marker = "*" if resolution.decisive is match else "-"
            lines.append(
                f"  {marker} {match.rule_id} [{match.policy_id}] "
                f"effect={match.effect.value} priority={match.priority}"
            )
            if match.reason:
                lines.append(f"      {match.reason}")
        if resolution.obligations:
            for key in sorted(resolution.obligations):
                lines.append(f"  obligation {key}: {resolution.obligations[key]}")
        return "\n".join(lines)

    def rule(self, rule_id: str) -> Optional[CompiledRule]:
        """Look up a loaded rule by id."""
        return self._compiled.rule(rule_id)

    def rules(self) -> List[CompiledRule]:
        """Every loaded rule, in evaluation order."""
        return list(self._compiled.rules)

    @property
    def compiled(self) -> CompiledPolicy:
        """The currently active compiled policy."""
        return self._compiled

    @property
    def bundles(self) -> List[PolicyBundle]:
        """The bundles behind the active policy."""
        return list(self._bundles)

    @property
    def warnings(self) -> List[str]:
        """Non-fatal problems recorded at compile time."""
        return list(self._compiled.warnings)

    def stats(self) -> Dict[str, Any]:
        """Engine counters merged with compilation statistics."""
        data = self._stats.as_dict()
        data.update(
            {
                "engine": self.name,
                "default_effect": self.default_effect.value,
                "fail_closed": self.fail_closed,
                "hot_reload": self.hot_reload,
                "policy": self._compiled.stats(),
            }
        )
        return data

    def clear_cache(self) -> None:
        """Drop memoised verdicts - call after mutating policy out of band."""
        self._cache.clear()

    # ------------------------------------------------------------------ #
    # Cache key
    # ------------------------------------------------------------------ #
    @staticmethod
    def _cache_key(ctx: EvaluationContext) -> str:
        """Digest of every context field a rule is able to read.

        Anything omitted here would let a stale verdict leak across calls that
        policy should distinguish, so the key errs on the side of more inputs.
        """
        provenance = ctx.provenance.status.value if ctx.provenance else "none"
        parts = [
            ctx.call.qualified_name,
            ctx.call.source,
            ctx.call.caller_ip,
            ctx.agent.id,
            ctx.agent.trust_tier,
            ctx.session.id,
            str(ctx.session.quarantined),
            ctx.environment,
            ctx.risk.value,
            f"{ctx.risk_score:.2f}",
            provenance,
            ",".join(sorted(c.value for c in ctx.categories)),
            ",".join(sorted(f.kind.value for f in ctx.findings)),
            sha256_hex(ctx.call.arguments or {}),
            sha256_hex(ctx.extra or {}),
        ]
        return sha256_hex("|".join(parts))


# --------------------------------------------------------------------------- #
# Construction helpers
# --------------------------------------------------------------------------- #
def _engine_kwargs(settings: Optional[Settings], *, name: str, **overrides: Any) -> Dict[str, Any]:
    """Translate the ``policy`` config section into constructor arguments."""
    settings = settings or get_settings()
    kwargs: Dict[str, Any] = {
        "name": name,
        "default_effect": _effect_setting(settings, "policy.default_effect", None),
        "fail_closed": bool(settings.get("policy.fail_closed", True)),
        "fail_closed_effect": _effect_setting(
            settings, "policy.fail_closed_effect", Effect.DENY
        )
        or Effect.DENY,
        "hot_reload": bool(settings.get("policy.hot_reload", False)),
        "reload_interval_s": float(settings.get("policy.reload_interval_s", 15) or 15),
        "cache_size": int(settings.get("policy.cache_size", 4096) or 0),
        "cache_ttl_s": float(settings.get("policy.cache_ttl_s", _DEFAULT_CACHE_TTL_S)),
        "strict": bool(settings.get("policy.strict", True)),
    }
    kwargs.update(overrides)
    return kwargs


def _effect_setting(settings: Settings, path: str, default: Optional[Effect]) -> Optional[Effect]:
    """Read an :class:`Effect` from settings, tolerating a missing/bad value."""
    raw = settings.get(path)
    if raw is None:
        return default
    try:
        return Effect(str(raw).strip().lower())
    except ValueError:
        logger.warning("policy.bad_effect_setting", extra={"path": path, "value": raw})
        return default


def build_engine(
    settings: Optional[Settings] = None,
    *,
    name: str = "default",
) -> PolicyEngine:
    """The recommended entry point for application code.

    Loads configured packs; if that fails for any reason the built-ins are used,
    because shipping *some* policy beats shipping none.
    """
    settings = settings or get_settings()
    try:
        return PolicyEngine.from_settings(settings, name=name)
    except (PolicyError, OSError) as exc:
        logger.warning(
            "policy.settings_load_failed_using_builtins",
            extra={"error": str(exc)},
        )
        return PolicyEngine.from_builtins(settings=settings, name=name)
