"""AegisAgent policy subsystem.

The policy layer turns authored YAML packs into a fast, fail-closed verdict for
every tool call.  The data model (:mod:`~aegis.policy.model`) is inert; the
:mod:`~aegis.policy.conditions` DSL and the :mod:`~aegis.policy.matchers`
pre-filter are compiled (:mod:`~aegis.policy.compiler`) into an indexed,
priority-sorted form that the :mod:`~aegis.policy.engine` evaluates against an
:class:`~aegis.core.types.EvaluationContext`.  Obligations are folded by
:mod:`~aegis.policy.effects`; authors preview and diff changes with
:mod:`~aegis.policy.simulator`; bundles are loaded, merged and signed via
:mod:`~aegis.policy.bundles`; and the agent's capability surface is tracked by
:mod:`~aegis.policy.catalog`.

Typical use::

    from aegis.policy import build_engine

    engine = build_engine()
    effect, matches = engine.evaluate(ctx)
"""

from __future__ import annotations

from .bundles import (
    BUILTIN_PACKS,
    bundle_digest,
    builtin_pack_dir,
    dump_bundle,
    load_bundle_file,
    load_builtin_bundles,
    load_bundles,
    load_from_settings,
    merge_bundles,
    parse_policy_document,
    sign_bundle,
    verify_bundle,
    verify_bundle_detailed,
)
from .catalog import (
    SchemaDrift,
    ToolCatalog,
    descriptor_from_dict,
    descriptor_to_dict,
    schema_hash,
)
from .compiler import CompiledPolicy, CompiledRule, PolicyCompiler, compile_bundles
from .conditions import (
    AllCondition,
    AlwaysCondition,
    AnyCondition,
    Condition,
    LeafCondition,
    NotCondition,
    OPERATORS,
    VALID_OPS,
    compile_condition,
    resolve_field,
)
from .effects import (
    EffectResolution,
    REDACTION_MASK,
    apply_redactions,
    approval_spec,
    effect_from_string,
    explain_effect,
    merge_obligations,
    redact_paths,
    resolve,
    resolve_effect,
    sandbox_spec,
    throttle_spec,
)
from .engine import EngineStats, PolicyEngine, build_engine
from .matchers import (
    AgentMatcher,
    ArgumentMatcher,
    CategoryMatcher,
    CidrMatcher,
    EnvironmentMatcher,
    Matcher,
    ProvenanceMatcher,
    RiskMatcher,
    TimeWindowMatcher,
    ToolMatcher,
    build_matchers,
    match_all,
    match_any,
)
from .model import (
    KNOWN_OBLIGATIONS,
    Policy,
    PolicyBundle,
    PolicyRule,
    RuleMatch,
    VALID_EFFECTS,
    validate_bundle,
    validate_policy,
    validate_rule,
)
from .packs import PolicyPackInfo, list_packs, pack_id_of, pack_info
from .simulator import (
    ChangeType,
    CoverageReport,
    DiffReport,
    WhatIfResult,
    coverage,
    replay,
    what_if,
)

#: Alias kept because "load the packs we ship" reads better at call sites.
builtin_bundles = load_builtin_bundles

__all__ = [
    # model
    "PolicyRule",
    "Policy",
    "PolicyBundle",
    "RuleMatch",
    "validate_rule",
    "validate_policy",
    "validate_bundle",
    "VALID_EFFECTS",
    "KNOWN_OBLIGATIONS",
    # conditions
    "Condition",
    "LeafCondition",
    "AllCondition",
    "AnyCondition",
    "NotCondition",
    "AlwaysCondition",
    "compile_condition",
    "resolve_field",
    "OPERATORS",
    "VALID_OPS",
    # matchers
    "Matcher",
    "ToolMatcher",
    "ArgumentMatcher",
    "CategoryMatcher",
    "RiskMatcher",
    "AgentMatcher",
    "EnvironmentMatcher",
    "ProvenanceMatcher",
    "TimeWindowMatcher",
    "CidrMatcher",
    "build_matchers",
    "match_all",
    "match_any",
    # effects
    "EffectResolution",
    "REDACTION_MASK",
    "resolve",
    "resolve_effect",
    "effect_from_string",
    "merge_obligations",
    "apply_redactions",
    "redact_paths",
    "explain_effect",
    "throttle_spec",
    "sandbox_spec",
    "approval_spec",
    # compiler
    "CompiledRule",
    "CompiledPolicy",
    "PolicyCompiler",
    "compile_bundles",
    # engine
    "PolicyEngine",
    "EngineStats",
    "build_engine",
    # simulator
    "what_if",
    "replay",
    "coverage",
    "ChangeType",
    "DiffReport",
    "CoverageReport",
    "WhatIfResult",
    # bundles
    "BUILTIN_PACKS",
    "builtin_pack_dir",
    "parse_policy_document",
    "load_bundle_file",
    "load_bundles",
    "load_builtin_bundles",
    "builtin_bundles",
    "load_from_settings",
    "merge_bundles",
    "sign_bundle",
    "verify_bundle",
    "verify_bundle_detailed",
    "bundle_digest",
    "dump_bundle",
    # catalog
    "ToolCatalog",
    "SchemaDrift",
    "schema_hash",
    "descriptor_from_dict",
    "descriptor_to_dict",
    # packs
    "PolicyPackInfo",
    "list_packs",
    "pack_info",
    "pack_id_of",
]
