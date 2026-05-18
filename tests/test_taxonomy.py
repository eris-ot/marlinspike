"""Tests for marlinspike.taxonomy.

Covers: enum completeness, visual mapping integrity, i18n key uniqueness,
chip helpers, severity chip mapping, and JSON export round-trip.
"""

import json

from marlinspike.taxonomy import (
    ENTITY_VISUALS,
    EntityType,
    EntityVisual,
    RelationshipType,
    chip_for,
    chip_for_full,
    label,
    severity_chip_class,
    taxonomy_export,
    taxonomy_export_json,
)

# ---------------------------------------------------------------------------
# 1. Every EntityType has a visual entry
# ---------------------------------------------------------------------------

def test_entity_visuals_complete():
    """Every EntityType must have a corresponding EntityVisual."""
    for et in EntityType:
        assert et in ENTITY_VISUALS, f"Missing EntityVisual for {et}"


# ---------------------------------------------------------------------------
# 2. EntityVisual field types are correct
# ---------------------------------------------------------------------------

def test_entity_visuals_fields():
    """All EntityVisual fields are non-empty strings."""
    for et, visual in ENTITY_VISUALS.items():
        assert isinstance(visual, EntityVisual), f"{et} visual is not EntityVisual"
        for field in ("color_var", "icon", "node_shape", "chip_class",
                      "i18n_label_key", "i18n_plural_key"):
            val = getattr(visual, field)
            assert isinstance(val, str) and val.strip(), (
                f"EntityVisual.{field} is empty for {et}"
            )


# ---------------------------------------------------------------------------
# 3. i18n label keys are unique (no two entities share a key)
# ---------------------------------------------------------------------------

def test_i18n_label_keys_unique():
    label_keys = [v.i18n_label_key for v in ENTITY_VISUALS.values()]
    assert len(label_keys) == len(set(label_keys)), "Duplicate i18n label keys found"


def test_i18n_plural_keys_unique():
    plural_keys = [v.i18n_plural_key for v in ENTITY_VISUALS.values()]
    assert len(plural_keys) == len(set(plural_keys)), "Duplicate i18n plural keys found"


# ---------------------------------------------------------------------------
# 4. i18n key namespace follows taxonomy.<entity>.label convention
# ---------------------------------------------------------------------------

def test_i18n_key_namespace():
    for et, visual in ENTITY_VISUALS.items():
        assert visual.i18n_label_key.startswith("taxonomy."), (
            f"{et} label key does not start with 'taxonomy.'"
        )
        assert visual.i18n_plural_key.startswith("taxonomy."), (
            f"{et} plural key does not start with 'taxonomy.'"
        )
        assert visual.i18n_label_key.endswith(".label"), (
            f"{et} label key does not end with '.label'"
        )
        assert visual.i18n_plural_key.endswith(".label_plural"), (
            f"{et} plural key does not end with '.label_plural'"
        )


# ---------------------------------------------------------------------------
# 5. chip_for() returns JSON-serialisable dict with required keys
# ---------------------------------------------------------------------------

CHIP_REQUIRED_KEYS = {
    "entity_type", "color_var", "node_shape", "chip_class",
    "i18n_label_key", "i18n_plural_key",
}

def test_chip_for_structure():
    for et in EntityType:
        chip = chip_for(et)
        assert CHIP_REQUIRED_KEYS.issubset(chip.keys()), (
            f"chip_for({et}) missing keys: {CHIP_REQUIRED_KEYS - chip.keys()}"
        )
        assert chip["entity_type"] == et.value


def test_chip_for_json_serialisable():
    for et in EntityType:
        chip = chip_for(et)
        # Must not raise
        serialised = json.dumps(chip)
        assert isinstance(serialised, str)


def test_chip_for_full_includes_icon():
    for et in EntityType:
        chip = chip_for_full(et)
        assert "icon" in chip, f"chip_for_full({et}) missing 'icon'"
        assert "<svg" in chip["icon"], f"icon for {et} is not an SVG string"


# ---------------------------------------------------------------------------
# 6. node_shape values are from the allowed set
# ---------------------------------------------------------------------------

ALLOWED_SHAPES = {"circle", "diamond", "square", "hex", "triangle"}

def test_node_shapes_valid():
    for et, visual in ENTITY_VISUALS.items():
        assert visual.node_shape in ALLOWED_SHAPES, (
            f"{et} has unknown node_shape '{visual.node_shape}'"
        )


# ---------------------------------------------------------------------------
# 7. chip_class values reference real CSS classes from base.html
# ---------------------------------------------------------------------------

ALLOWED_CHIP_CLASSES = {
    "chip-critical", "chip-high", "chip-medium", "chip-low",
    "chip-info", "chip-accent", "chip-cyan", "chip-success", "chip-muted",
}

def test_chip_classes_valid():
    for et, visual in ENTITY_VISUALS.items():
        assert visual.chip_class in ALLOWED_CHIP_CLASSES, (
            f"{et} references unknown chip_class '{visual.chip_class}'"
        )


# ---------------------------------------------------------------------------
# 8. severity_chip_class() handles all engine severity tokens
# ---------------------------------------------------------------------------

def test_severity_chip_class_uppercase():
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        cls = severity_chip_class(sev)
        assert cls.startswith("chip-"), f"severity_chip_class({sev}) = {cls}"


def test_severity_chip_class_lowercase():
    """Malware findings emit lowercase severity tokens."""
    for sev in ("critical", "high", "medium", "low"):
        cls = severity_chip_class(sev)
        assert cls.startswith("chip-")


def test_severity_chip_class_unknown_fallback():
    assert severity_chip_class("") == "chip-info"
    assert severity_chip_class("unknown") == "chip-info"
    assert severity_chip_class(None) == "chip-info"


# ---------------------------------------------------------------------------
# 9. taxonomy_export() is fully JSON-serialisable and structurally complete
# ---------------------------------------------------------------------------

def test_taxonomy_export_structure():
    export = taxonomy_export()
    assert "entity_types" in export
    assert "relationship_types" in export
    assert "severity_chips" in export

    # Every EntityType must appear
    for et in EntityType:
        assert et.value in export["entity_types"], (
            f"EntityType.{et.name} missing from taxonomy_export()"
        )

    # Every RelationshipType must appear
    for rt in RelationshipType:
        assert rt.value in export["relationship_types"], (
            f"RelationshipType.{rt.name} missing from taxonomy_export()"
        )


def test_taxonomy_export_json_round_trip():
    raw = taxonomy_export_json()
    reparsed = json.loads(raw)
    # Round-trip must preserve all EntityType values
    for et in EntityType:
        assert et.value in reparsed["entity_types"]


# ---------------------------------------------------------------------------
# 10. label() returns non-empty strings; does not crash without Flask context
# ---------------------------------------------------------------------------

def test_label_returns_string():
    """label() must work without a Flask app context."""
    for et in EntityType:
        singular = label(et, "en", plural=False)
        plural   = label(et, "en", plural=True)
        assert isinstance(singular, str) and singular
        assert isinstance(plural, str) and plural


def test_label_french_does_not_crash():
    """French locale must not raise; may fall back to English gracefully."""
    for et in EntityType:
        result = label(et, "fr", plural=False)
        assert isinstance(result, str) and result


# ---------------------------------------------------------------------------
# 11. Enum coverage — no stray entity types or relationship types
# ---------------------------------------------------------------------------

def test_entity_type_count():
    """If a new EntityType is added, this test should update too.
    This makes regressions visible at review time."""
    assert len(EntityType) == 12, (
        f"EntityType count changed: got {len(EntityType)}, expected 12. "
        "Update this assertion and ENTITY_VISUALS when adding a new entity type."
    )


def test_relationship_type_count():
    assert len(RelationshipType) == 12, (
        f"RelationshipType count changed: got {len(RelationshipType)}, expected 12. "
        "Update this assertion when modifying relationship types."
    )


# ---------------------------------------------------------------------------
# 12. SVG icons are inline-safe (no external refs, no script tags)
# ---------------------------------------------------------------------------

def test_icons_no_external_refs():
    forbidden = ("http://", "https://", "xlink:href", "src=", "<script")
    for et, visual in ENTITY_VISUALS.items():
        for token in forbidden:
            assert token not in visual.icon, (
                f"{et} icon contains forbidden string '{token}' (CSP violation)"
            )
