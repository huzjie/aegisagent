"""Federation of every detection module behind one entry point.

The registry is the seam between the policy engine / gateway and the individual
detectors.  It is responsible for:

* wiring up the concrete detectors (optionally from configuration),
* running them (in parallel, with per-detector timeouts so one stuck or
  crashing detector can never block the enforcement decision), and
* collecting their :class:`Finding` objects into a single, ordered list.

Detectors are intentionally *isolated*: each runs in its own worker thread and a
slow detector is abandoned on its deadline rather than stalling the whole
pipeline.  Crashes are contained by :class:`~aegis.detect.base.Detector.run`.
"""

from __future__ import annotations

import threading
from concurrent.futures import Future, ThreadPoolExecutor
from typing import Any, Dict, Iterable, List, Optional, Sequence

from ..core.config import Settings
from ..core.logging import get_logger
from ..core.types import EvaluationContext, Finding
from .anomaly import AnomalyDetector
from .base import Detector, DetectorResult
from .content import ContentDetector
from .egress import EgressDetector
from .exfiltration import ExfiltrationDetector
from .prompt_injection.ensemble import EnsembleInjectionDetector
from .schema_drift import SchemaDriftDetector
from .secrets import SecretLeakDetector
from .supply_chain import SupplyChainDetector
from .tool_poisoning import ToolPoisoningDetector

LOGGER = get_logger("detect.registry")

#: Config key (under ``detection.detectors``) -> detector factory.  The factory
#: receives the per-detector enabled flag and the raw sub-config dict.
_DETECTOR_FACTORIES: Dict[str, Any] = {
    "prompt_injection": EnsembleInjectionDetector,
    "exfiltration": ExfiltrationDetector,
    "secret_leak": SecretLeakDetector,
    "tool_poisoning": ToolPoisoningDetector,
    "schema_drift": SchemaDriftDetector,
    "anomaly": AnomalyDetector,
    "egress": EgressDetector,
    "supply_chain": SupplyChainDetector,
    "content": ContentDetector,
}


class DetectorRegistry:
    """Named collection of detectors run as a unit.

    Examples:
        >>> registry = DetectorRegistry.from_settings(get_settings())
        >>> detectors = registry.all()
        >>> findings = registry.run(ctx)
    """

    def __init__(
        self,
        *,
        parallel: bool = True,
        timeout_ms: float = 750,
        default_min_confidence: float = 0.35,
        max_workers: Optional[int] = None,
    ) -> None:
        """Args:
        parallel: Run detectors concurrently via a thread pool.
        timeout_ms: Wall-clock budget per detector; overruns are abandoned.
        default_min_confidence: Findings below this are dropped by :meth:`run`.
        max_workers: Override the thread-pool size (defaults to detector count).
        """
        self.parallel = bool(parallel)
        self.timeout_ms = float(timeout_ms)
        self.default_min_confidence = float(default_min_confidence)
        self._detectors: Dict[str, Detector] = {}
        self._order: List[str] = []
        self._lock = threading.RLock()
        self._stats: Dict[str, Dict[str, Any]] = {}
        self._executor: Optional[ThreadPoolExecutor] = None
        if self.parallel:
            self._executor = ThreadPoolExecutor(
                max_workers=max(1, max_workers or 8),
                thread_name_prefix="aegis-detect",
            )

    # ------------------------------------------------------------------ #
    # Registration
    # ------------------------------------------------------------------ #
    def register(self, detector: Detector) -> "DetectorRegistry":
        """Add (or replace) a detector, preserving insertion order."""
        with self._lock:
            self._detectors[detector.name] = detector
            if detector.name not in self._order:
                self._order.append(detector.name)
            self._stats.setdefault(detector.name, {"runs": 0, "errors": 0, "timeouts": 0})
        return self

    def unregister(self, name: str) -> bool:
        """Remove a detector by name; return whether one was removed."""
        with self._lock:
            if name in self._detectors:
                self._detectors.pop(name, None)
                self._order = [n for n in self._order if n != name]
                self._stats.pop(name, None)
                return True
            return False

    def get(self, name: str) -> Optional[Detector]:
        """Return a registered detector or ``None``."""
        with self._lock:
            return self._detectors.get(name)

    def __contains__(self, name: str) -> bool:
        with self._lock:
            return name in self._detectors

    def names(self) -> List[str]:
        """Ordered list of registered detector names."""
        with self._lock:
            return list(self._order)

    def all(self) -> List[Detector]:
        """Ordered list of every registered detector instance."""
        with self._lock:
            return [self._detectors[name] for name in self._order]

    def enabled_names(self) -> List[str]:
        """Names of currently-enabled detectors, in order."""
        with self._lock:
            return [n for n in self._order if self._detectors[n].enabled]

    def describe(self) -> List[Dict[str, Any]]:
        """Machine-readable description of every registered detector."""
        with self._lock:
            return [d.describe() for d in self._detectors.values()]

    # ------------------------------------------------------------------ #
    # Execution
    # ------------------------------------------------------------------ #
    def run(self, ctx: EvaluationContext, *, min_confidence: Optional[float] = None) -> List[Finding]:
        """Run all enabled detectors and return merged, deduplicated findings.

        Args:
            ctx: The evaluation context under judgement.
            min_confidence: Floor confidence; defaults to the registry's.

        Returns:
            Findings from every detector (already self-filtered), dropped below
            ``min_confidence`` and concatenated in detector order.
        """
        threshold = self.default_min_confidence if min_confidence is None else float(min_confidence)
        findings: List[Finding] = []
        for result in self.run_detailed(ctx):
            for finding in result.findings:
                if finding.confidence >= threshold:
                    findings.append(finding)
        return findings

    def run_detailed(self, ctx: EvaluationContext) -> List[DetectorResult]:
        """Run every enabled detector, returning per-detector results.

        Crashes and timeouts are captured on the result objects rather than
        raised, so the caller always gets a complete picture plus metadata.
        """
        with self._lock:
            targets = [(name, self._detectors[name]) for name in self._order if self._detectors[name].enabled]

        results: List[DetectorResult]
        if self.parallel and self._executor is not None:
            results = self._run_parallel(targets, ctx)
        else:
            results = [detector.run(ctx) for _, detector in targets]
            for (name, _), result in zip(targets, results):
                self._record_stats(name, result)
        return results

    def _run_parallel(
        self, targets: List[tuple[str, Detector]], ctx: EvaluationContext
    ) -> List[DetectorResult]:
        futures: List[tuple[str, Future[DetectorResult]]] = []
        with self._lock:
            executor = self._executor
        assert executor is not None
        for name, detector in targets:
            futures.append((name, executor.submit(detector.run, ctx)))
        results: List[DetectorResult] = []
        deadline = self.timeout_ms / 1000.0
        for name, future in futures:
            try:
                result = future.result(timeout=deadline)
            except TimeoutError:
                result = DetectorResult(detector=name, timed_out=True, error="deadline exceeded")
                future.cancel()  # best-effort; a running task finishes in background
                LOGGER.warning("detector timed out", detector=name, timeout_ms=self.timeout_ms)
            except Exception as exc:  # noqa: BLE001 - never leak into the caller
                result = DetectorResult(detector=name, error=f"{type(exc).__name__}: {exc}")
            self._record_stats(name, result)
            results.append(result)
        return results

    def _record_stats(self, name: str, result: DetectorResult) -> None:
        with self._lock:
            bucket = self._stats.setdefault(name, {"runs": 0, "errors": 0, "timeouts": 0})
            bucket["runs"] += 1
            if result.error:
                bucket["errors"] += 1
            if result.timed_out:
                bucket["timeouts"] += 1

    # ------------------------------------------------------------------ #
    # Introspection
    # ------------------------------------------------------------------ #
    def stats(self) -> Dict[str, Any]:
        """Return run counters, enabled/registered counts and total findings."""
        with self._lock:
            enabled = sum(1 for n in self._order if self._detectors[n].enabled)
            return {
                "registered": len(self._order),
                "enabled": enabled,
                "parallel": self.parallel,
                "timeout_ms": self.timeout_ms,
                "default_min_confidence": self.default_min_confidence,
                "detectors": dict(self._stats),
            }

    def close(self) -> None:
        """Release the worker pool, if any."""
        with self._lock:
            executor = self._executor
            self._executor = None
        if executor is not None:
            executor.shutdown(wait=False)

    # ------------------------------------------------------------------ #
    # Construction
    # ------------------------------------------------------------------ #
    @classmethod
    def from_settings(cls, settings: Settings) -> "DetectorRegistry":
        """Build a registry from ``detection`` configuration.

        The ``detection.detectors`` mapping toggles each named detector; unknown
        keys are ignored and detectors absent from the mapping keep their default
        (enabled) state so new capabilities are on by default.
        """
        detection = settings.section("detection")
        toggles: Dict[str, Any] = detection.get("detectors", {}) or {}
        parallel = bool(detection.get("parallel", True))
        timeout_ms = float(detection.get("timeout_ms", 750))
        min_confidence = float(detection.get("min_confidence", 0.35))
        registry = cls(parallel=parallel, timeout_ms=timeout_ms, default_min_confidence=min_confidence)

        # prompt_injection is special: it may embed the LLM judge.
        judge_cfg = detection.get("llm_judge", {}) or {}
        ensemble_enabled = _toggle(toggles, "prompt_injection", True)
        judge_enabled = bool(judge_cfg.get("enabled", False))
        registry.register(
            EnsembleInjectionDetector(enabled=ensemble_enabled, judge_enabled=judge_enabled)
        )

        for key, factory in _DETECTOR_FACTORIES.items():
            if key == "prompt_injection":
                continue
            enabled = _toggle(toggles, key, True)
            try:
                registry.register(factory(enabled=enabled))  # type: ignore[operator]
            except Exception as exc:  # noqa: BLE001 - a broken detector must not abort startup
                LOGGER.error("failed to construct detector", detector=key, error=str(exc))
        return registry

    @classmethod
    def default(cls) -> "DetectorRegistry":
        """Build a registry with every bundled detector enabled."""
        registry = cls()
        registry.register(EnsembleInjectionDetector(enabled=True))
        for key, factory in _DETECTOR_FACTORIES.items():
            if key == "prompt_injection":
                continue
            registry.register(factory(enabled=True))  # type: ignore[operator]
        return registry


def _toggle(toggles: Dict[str, Any], key: str, default: bool) -> bool:
    """Resolve a per-detector enable flag, tolerating missing/odd values."""
    if key not in toggles:
        return default
    value = toggles[key]
    if isinstance(value, bool):
        return value
    if isinstance(value, dict):
        return bool(value.get("enabled", default))
    return bool(value)
