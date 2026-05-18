"""MarlinSpike entity taxonomy.

Defines the canonical set of entity types and relationship types that the
platform recognises, together with their visual treatment and i18n keys.

Design goals
------------
- Zero non-stdlib dependencies beyond marlinspike.i18n (already in-tree).
- Safe to import at module level — no db.session, no app context required.
- Exports a JSON-serialisable view so a Flask endpoint can serve it to JS.
- Acts as the single source of truth for the next agent that reshapes the
  viewer/workbench; it should never need to invent visual rules.

Entity scope
------------
Only entities that exist in the codebase are defined here.  Administrative
entities (User, AuditLog, PasswordResetToken) are deliberately excluded from
the analyst graph; they have no visual treatment in this module.

Relationship scope
------------------
Relationships describe analyst-meaningful connections between entities, derived
from the edges / affected_nodes / c2 links the engine emits.  IOC matches are
modelled as relationships (MATCHED_BY_IOC) rather than as a standalone entity
type because IocEntry and IocList are the persisted objects; the *match* is
always an association between an existing entity and an IOC, not a new node.
"""

from __future__ import annotations

import json
from dataclasses import dataclass
from enum import Enum

# ---------------------------------------------------------------------------
# Entity types
# ---------------------------------------------------------------------------

class EntityType(Enum):
    """Canonical analyst-graph entity types.

    Each value is the stable string identifier used in JSON payloads, i18n
    keys, and CSS class names.  Do not rename values without a migration.
    """
    ASSET           = "asset"
    CONVERSATION    = "conversation"
    FINDING         = "finding"
    ANOMALY         = "anomaly"
    C2_INDICATOR    = "c2_indicator"
    MALWARE_FINDING = "malware_finding"
    IOC_LIST        = "ioc_list"
    IOC_ENTRY       = "ioc_entry"
    PROJECT         = "project"
    REPORT          = "report"
    CAPTURE_SESSION = "capture_session"
    PROTOCOL        = "protocol"


# ---------------------------------------------------------------------------
# Relationship types
# ---------------------------------------------------------------------------

class RelationshipType(Enum):
    """Directional relationships between entities.

    Convention: RelationshipType.value is the snake_case label used in JSON
    edge objects.  Directionality is (source → target) as documented in the
    cardinality table below.
    """
    # Asset ↔ Asset (via network traffic)
    COMMUNICATES_WITH   = "communicates_with"   # Asset → Asset (bidirectional by convention)

    # Asset ← Finding / Anomaly / C2Indicator / MalwareFinding
    AFFECTED_BY         = "affected_by"         # Asset → Finding  (many Assets, many Findings)
    FLAGGED_BY_ANOMALY  = "flagged_by_anomaly"  # Asset → Anomaly
    FLAGGED_BY_C2       = "flagged_by_c2"       # Asset → C2Indicator
    FLAGGED_BY_MALWARE  = "flagged_by_malware"  # Asset → MalwareFinding

    # Asset ← IOC
    MATCHED_BY_IOC      = "matched_by_ioc"      # Asset → IocEntry  (N:M)

    # Conversation → Asset (source/destination)
    INITIATED_BY        = "initiated_by"        # Conversation → Asset (src)
    RECEIVED_BY         = "received_by"         # Conversation → Asset (dst)

    # Conversation → Finding / C2Indicator / MalwareFinding
    GENERATES           = "generates"           # Conversation → Finding|C2Indicator|MalwareFinding

    # Grouping / container relationships
    BELONGS_TO_PROJECT  = "belongs_to_project"  # Report|Asset|IocList → Project
    CONTAINED_IN_REPORT = "contained_in_report" # Asset|Finding|Conversation → Report
    IOC_IN_LIST         = "ioc_in_list"         # IocEntry → IocList


# ---------------------------------------------------------------------------
# Cardinality table (documentation only — not enforced at runtime)
# ---------------------------------------------------------------------------
#
# RelationshipType       | Source        | Target          | Cardinality
# -----------------------|---------------|-----------------|------------
# COMMUNICATES_WITH      | Asset         | Asset           | M:N
# AFFECTED_BY            | Finding       | Asset           | M:N
# FLAGGED_BY_ANOMALY     | Anomaly       | Asset           | M:N
# FLAGGED_BY_C2          | C2Indicator   | Asset           | 1:N
# FLAGGED_BY_MALWARE     | MalwareFinding| Asset           | M:N
# MATCHED_BY_IOC         | IocEntry      | Asset           | M:N
# INITIATED_BY           | Conversation  | Asset (src)     | N:1
# RECEIVED_BY            | Conversation  | Asset (dst)     | N:1
# GENERATES              | Conversation  | Finding|C2|Malw | 1:M
# BELONGS_TO_PROJECT     | Report|Asset  | Project         | N:1
# CONTAINED_IN_REPORT    | Asset|Finding | Report          | M:N
# IOC_IN_LIST            | IocEntry      | IocList         | N:1


# ---------------------------------------------------------------------------
# Visual treatment
# ---------------------------------------------------------------------------

@dataclass(frozen=True)
class EntityVisual:
    """Visual treatment for one entity type.

    All colour references are CSS custom property *names* (e.g. ``--sev-critical``),
    not raw hex values.  Consumers must resolve them against the token system
    defined in ``base.html``.

    icon
        Inline SVG string — 16 × 16 viewBox, no external refs, stroke-based.
        Consumers embed directly into HTML; no img/src allowed (CSP constraint).

    node_shape
        Hint to the graph renderer.  One of: ``circle``, ``diamond``,
        ``square``, ``hex``, ``triangle``.

    chip_class
        CSS class from the ``chip-*`` family in base.html.  Applied to
        ``<span class="chip {chip_class}">`` elements.
    """
    color_var:        str   # e.g. "--accent-cyan"
    icon:             str   # inline SVG (16×16 viewBox)
    node_shape:       str   # graph renderer hint
    chip_class:       str   # CSS class suffix e.g. "chip-cyan"
    i18n_label_key:   str   # e.g. "taxonomy.asset.label"
    i18n_plural_key:  str   # e.g. "taxonomy.asset.label_plural"


# Inline SVG icons — 16×16 viewBox, stroke-based, no fills except where noted.
# These are minimal and legible at small sizes (graph nodes, table chips).
_ICON = {
    "asset": (
        '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"'
        ' stroke-linecap="round" stroke-linejoin="round">'
        '<rect x="2" y="3" width="12" height="9" rx="1.5"/>'
        '<line x1="5" y1="14" x2="11" y2="14"/>'
        '<line x1="8" y1="12" x2="8" y2="14"/>'
        "</svg>"
    ),
    "conversation": (
        '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"'
        ' stroke-linecap="round" stroke-linejoin="round">'
        '<line x1="2" y1="8" x2="14" y2="8"/>'
        '<polyline points="10,4 14,8 10,12"/>'
        "</svg>"
    ),
    "finding": (
        '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"'
        ' stroke-linecap="round" stroke-linejoin="round">'
        '<path d="M8 2L14 13H2L8 2z"/>'
        '<line x1="8" y1="7" x2="8" y2="10"/>'
        '<circle cx="8" cy="12" r="0.6" fill="currentColor"/>'
        "</svg>"
    ),
    "anomaly": (
        '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"'
        ' stroke-linecap="round" stroke-linejoin="round">'
        '<circle cx="8" cy="8" r="5.5"/>'
        '<line x1="8" y1="5" x2="8" y2="9"/>'
        '<circle cx="8" cy="11" r="0.6" fill="currentColor"/>'
        "</svg>"
    ),
    "c2_indicator": (
        '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"'
        ' stroke-linecap="round" stroke-linejoin="round">'
        '<path d="M8 2c3.3 0 6 2.7 6 6s-2.7 6-6 6S2 11.3 2 8"/>'
        '<polyline points="2,5 2,8 5,8"/>'
        '<line x1="8" y1="5.5" x2="8" y2="8"/>'
        '<circle cx="8" cy="9.5" r="0.6" fill="currentColor"/>'
        "</svg>"
    ),
    "malware_finding": (
        '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"'
        ' stroke-linecap="round" stroke-linejoin="round">'
        '<path d="M8 1.5l1.5 3 3.3.5-2.4 2.3.6 3.2L8 9l-3 1.5.6-3.2L3.2 5l3.3-.5z"/>'
        "</svg>"
    ),
    "ioc_list": (
        '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"'
        ' stroke-linecap="round" stroke-linejoin="round">'
        '<rect x="2" y="2" width="12" height="12" rx="1.5"/>'
        '<line x1="5" y1="6" x2="11" y2="6"/>'
        '<line x1="5" y1="9" x2="9" y2="9"/>'
        "</svg>"
    ),
    "ioc_entry": (
        '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"'
        ' stroke-linecap="round" stroke-linejoin="round">'
        '<circle cx="8" cy="8" r="2.5"/>'
        '<line x1="8" y1="2" x2="8" y2="5"/>'
        '<line x1="8" y1="11" x2="8" y2="14"/>'
        '<line x1="2" y1="8" x2="5" y2="8"/>'
        '<line x1="11" y1="8" x2="14" y2="8"/>'
        "</svg>"
    ),
    "project": (
        '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"'
        ' stroke-linecap="round" stroke-linejoin="round">'
        '<path d="M2 6h12v7a1 1 0 01-1 1H3a1 1 0 01-1-1V6z"/>'
        '<path d="M2 6l1.5-3h4L9 6"/>'
        "</svg>"
    ),
    "report": (
        '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"'
        ' stroke-linecap="round" stroke-linejoin="round">'
        '<rect x="3" y="1.5" width="10" height="13" rx="1"/>'
        '<line x1="5.5" y1="5.5" x2="10.5" y2="5.5"/>'
        '<line x1="5.5" y1="8" x2="10.5" y2="8"/>'
        '<line x1="5.5" y1="10.5" x2="8.5" y2="10.5"/>'
        "</svg>"
    ),
    "capture_session": (
        '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"'
        ' stroke-linecap="round" stroke-linejoin="round">'
        '<circle cx="8" cy="8" r="5.5"/>'
        '<polyline points="8,5 8,8 10.5,9.5"/>'
        "</svg>"
    ),
    "protocol": (
        '<svg viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="1.4"'
        ' stroke-linecap="round" stroke-linejoin="round">'
        '<rect x="1.5" y="5" width="5" height="4" rx="1"/>'
        '<rect x="9.5" y="5" width="5" height="4" rx="1"/>'
        '<line x1="6.5" y1="7" x2="9.5" y2="7"/>'
        "</svg>"
    ),
}

ENTITY_VISUALS: dict[EntityType, EntityVisual] = {
    EntityType.ASSET: EntityVisual(
        color_var="--accent-cyan",
        icon=_ICON["asset"],
        node_shape="circle",
        chip_class="chip-cyan",
        i18n_label_key="taxonomy.asset.label",
        i18n_plural_key="taxonomy.asset.label_plural",
    ),
    EntityType.CONVERSATION: EntityVisual(
        color_var="--accent",
        icon=_ICON["conversation"],
        node_shape="diamond",
        chip_class="chip-accent",
        i18n_label_key="taxonomy.conversation.label",
        i18n_plural_key="taxonomy.conversation.label_plural",
    ),
    EntityType.FINDING: EntityVisual(
        color_var="--sev-high",
        icon=_ICON["finding"],
        node_shape="triangle",
        chip_class="chip-high",
        i18n_label_key="taxonomy.finding.label",
        i18n_plural_key="taxonomy.finding.label_plural",
    ),
    EntityType.ANOMALY: EntityVisual(
        color_var="--sev-medium",
        icon=_ICON["anomaly"],
        node_shape="diamond",
        chip_class="chip-medium",
        i18n_label_key="taxonomy.anomaly.label",
        i18n_plural_key="taxonomy.anomaly.label_plural",
    ),
    EntityType.C2_INDICATOR: EntityVisual(
        color_var="--sev-critical",
        icon=_ICON["c2_indicator"],
        node_shape="hex",
        chip_class="chip-critical",
        i18n_label_key="taxonomy.c2_indicator.label",
        i18n_plural_key="taxonomy.c2_indicator.label_plural",
    ),
    EntityType.MALWARE_FINDING: EntityVisual(
        color_var="--sev-critical",
        icon=_ICON["malware_finding"],
        node_shape="hex",
        chip_class="chip-critical",
        i18n_label_key="taxonomy.malware_finding.label",
        i18n_plural_key="taxonomy.malware_finding.label_plural",
    ),
    EntityType.IOC_LIST: EntityVisual(
        color_var="--accent-amber",
        icon=_ICON["ioc_list"],
        node_shape="square",
        chip_class="chip-muted",
        i18n_label_key="taxonomy.ioc_list.label",
        i18n_plural_key="taxonomy.ioc_list.label_plural",
    ),
    EntityType.IOC_ENTRY: EntityVisual(
        color_var="--accent-amber",
        icon=_ICON["ioc_entry"],
        node_shape="circle",
        chip_class="chip-muted",
        i18n_label_key="taxonomy.ioc_entry.label",
        i18n_plural_key="taxonomy.ioc_entry.label_plural",
    ),
    EntityType.PROJECT: EntityVisual(
        color_var="--accent-green",
        icon=_ICON["project"],
        node_shape="square",
        chip_class="chip-success",
        i18n_label_key="taxonomy.project.label",
        i18n_plural_key="taxonomy.project.label_plural",
    ),
    EntityType.REPORT: EntityVisual(
        color_var="--text-dim",
        icon=_ICON["report"],
        node_shape="square",
        chip_class="chip-muted",
        i18n_label_key="taxonomy.report.label",
        i18n_plural_key="taxonomy.report.label_plural",
    ),
    EntityType.CAPTURE_SESSION: EntityVisual(
        color_var="--accent-rose",
        icon=_ICON["capture_session"],
        node_shape="circle",
        chip_class="chip-muted",
        i18n_label_key="taxonomy.capture_session.label",
        i18n_plural_key="taxonomy.capture_session.label_plural",
    ),
    EntityType.PROTOCOL: EntityVisual(
        color_var="--accent",
        icon=_ICON["protocol"],
        node_shape="circle",
        chip_class="chip-info",
        i18n_label_key="taxonomy.protocol.label",
        i18n_plural_key="taxonomy.protocol.label_plural",
    ),
}


# ---------------------------------------------------------------------------
# Severity → chip class mapping
# ---------------------------------------------------------------------------

# Severity tokens come from both the engine (uppercase: CRITICAL/HIGH/MEDIUM/LOW/INFO)
# and from malware_findings (lowercase: critical/high/medium/low).
# Normalise to uppercase before lookup.

SEVERITY_CHIP: dict[str, str] = {
    "CRITICAL": "chip-critical",
    "HIGH":     "chip-high",
    "MEDIUM":   "chip-medium",
    "LOW":      "chip-low",
    "INFO":     "chip-info",
}


def severity_chip_class(severity: str) -> str:
    """Return the chip CSS class for a severity string.

    Accepts both uppercase engine tokens (``CRITICAL``) and lowercase
    malware-finding tokens (``critical``).  Unknown values map to ``chip-info``.
    """
    return SEVERITY_CHIP.get(str(severity or "").upper().strip(), "chip-info")


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def chip_for(entity_type: EntityType) -> dict:
    """Return a JSON-serialisable chip spec for client-side rendering.

    The returned dict is safe to pass directly to ``json.dumps`` and to
    the JS chip renderer.  It intentionally does *not* include the icon
    SVG by default (too large for inline transport); the caller can request
    it by checking ``include_icon=True`` via ``chip_for_full``.

    Example output::

        {
            "entity_type": "asset",
            "color_var": "--accent-cyan",
            "node_shape": "circle",
            "chip_class": "chip-cyan",
            "i18n_label_key": "taxonomy.asset.label",
            "i18n_plural_key": "taxonomy.asset.label_plural"
        }
    """
    visual = ENTITY_VISUALS[entity_type]
    return {
        "entity_type":     entity_type.value,
        "color_var":       visual.color_var,
        "node_shape":      visual.node_shape,
        "chip_class":      visual.chip_class,
        "i18n_label_key":  visual.i18n_label_key,
        "i18n_plural_key": visual.i18n_plural_key,
    }


def chip_for_full(entity_type: EntityType) -> dict:
    """Like ``chip_for`` but includes the inline SVG icon."""
    base = chip_for(entity_type)
    base["icon"] = ENTITY_VISUALS[entity_type].icon
    return base


def label(entity_type: EntityType, locale: str = "en", plural: bool = False) -> str:
    """Resolve a human-readable label via the existing i18n loader.

    Falls back gracefully: locale → English → i18n key → entity type value.
    """
    from marlinspike.i18n import t  # deferred to avoid import cycles
    visual = ENTITY_VISUALS[entity_type]
    key = visual.i18n_plural_key if plural else visual.i18n_label_key
    resolved = t(key, locale)
    # t() returns the key itself if not found — detect and fall back to value
    if resolved == key:
        return entity_type.value.replace("_", " ").title() + ("s" if plural else "")
    return resolved


def taxonomy_export() -> dict:
    """Return a JSON-serialisable snapshot of the full taxonomy.

    Intended to be served as ``/api/taxonomy`` so JS can render chips and
    graph nodes consistently with server-side Jinja templates.

    Structure::

        {
            "entity_types": { "<value>": { ...chip_for_full()... }, ... },
            "relationship_types": [ "<value>", ... ],
            "severity_chips": { "CRITICAL": "chip-critical", ... }
        }
    """
    return {
        "entity_types": {
            et.value: chip_for_full(et)
            for et in EntityType
        },
        "relationship_types": [rt.value for rt in RelationshipType],
        "severity_chips": dict(SEVERITY_CHIP),
    }


def taxonomy_export_json() -> str:
    """Return ``taxonomy_export()`` serialised as a JSON string."""
    return json.dumps(taxonomy_export(), ensure_ascii=False, indent=2)
