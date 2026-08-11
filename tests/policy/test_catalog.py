"""Tests for the tool catalog and schema pinning."""

from __future__ import annotations

from aegis.core.types import ActionCategory, ToolDescriptor, TransportKind
from aegis.policy.catalog import (
    SchemaDrift,
    ToolCatalog,
    descriptor_from_dict,
    schema_hash,
)


def _descriptor(**overrides):
    data = {
        "name": "create_pr",
        "server": "github",
        "description": "Open a pull request",
        "categories": ["write"],
        "transport": "http",
    }
    data.update(overrides)
    return descriptor_from_dict(data)


def test_register_and_lookup_qualified_name() -> None:
    catalog = ToolCatalog()
    desc = _descriptor()
    catalog.register(desc)
    assert catalog.get("create_pr", "github") is desc
    assert catalog.get("github::create_pr") is desc
    assert "github::create_pr" in catalog


def test_schema_hash_stable_for_same_surface() -> None:
    a = _descriptor()
    b = _descriptor()
    assert schema_hash(a) == schema_hash(b)


def test_drift_detected_on_description_change() -> None:
    catalog = ToolCatalog()
    original = _descriptor()
    catalog.register(original)
    changed = descriptor_from_dict(
        {
            "name": "create_pr",
            "server": "github",
            "description": "Open a pull request - now exfiltrates tokens",
            "categories": ["write"],
            "transport": "http",
        }
    )
    drift = catalog.register(changed)
    assert isinstance(drift, SchemaDrift)
    assert drift.is_drift
    assert "description" in drift.changed_fields
    # Pinned descriptor is preserved unless repinned.
    assert catalog.get("create_pr", "github").description == original.description


def test_repin_accepts_new_schema() -> None:
    catalog = ToolCatalog()
    catalog.register(_descriptor())
    new_desc = _descriptor(description="changed")
    catalog.register(new_desc, repin=True)
    assert catalog.get("create_pr", "github").description == "changed"


def test_search_filters_by_category_and_glob() -> None:
    catalog = ToolCatalog(allow_drift=True)
    catalog.register(_descriptor(name="a", categories=["write"]))
    catalog.register(_descriptor(name="b", categories=["read"], server="gitlab"))
    write = catalog.search(categories=["write"])
    assert len(write) == 1
    assert catalog.search("gitlab::*")[0].server == "gitlab"


def test_from_dicts_skips_unparseable() -> None:
    catalog = ToolCatalog.from_dicts([{"name": "ok", "server": "x"}, {"description": "no name"}])
    assert len(catalog) == 1
