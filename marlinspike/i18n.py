"""Tiny home-grown i18n layer.

JSON dictionaries under ``translations/<locale>.json``. No new pip deps.
Lookups fall back to English; missing keys return the key itself so
untranslated surfaces are visible during migration rather than blank.
"""

import json
import logging
import os
from pathlib import Path

log = logging.getLogger("marlinspike.i18n")

DEFAULT_LOCALE = "en"
SUPPORTED_LOCALES = ("en", "fr")

# Display names shown in the language picker (in their own language).
LOCALE_LABELS = {
    "en": "English",
    "fr": "Français",
}

_translations: dict[str, dict[str, str]] = {}
_loaded = False


def _translations_dir() -> Path:
    return Path(__file__).resolve().parent / "translations"


def load_translations(force: bool = False) -> dict[str, dict[str, str]]:
    """Load every supported locale's JSON dictionary into memory."""
    global _loaded
    if _loaded and not force:
        return _translations
    _translations.clear()
    base = _translations_dir()
    for locale in SUPPORTED_LOCALES:
        path = base / f"{locale}.json"
        if not path.exists():
            log.warning("translations file missing: %s", path)
            _translations[locale] = {}
            continue
        try:
            with path.open("r", encoding="utf-8") as fh:
                _translations[locale] = json.load(fh)
        except Exception as exc:
            log.error("failed to load %s: %s", path, exc)
            _translations[locale] = {}
    _loaded = True
    return _translations


def normalise_locale(value: str | None) -> str:
    """Coerce arbitrary input to a supported locale, falling back to default."""
    if not value:
        return DEFAULT_LOCALE
    v = value.strip().lower().replace("_", "-")
    # ``fr-CA`` → ``fr``
    if "-" in v:
        v = v.split("-", 1)[0]
    if v in SUPPORTED_LOCALES:
        return v
    return DEFAULT_LOCALE


def t(key: str, locale: str = DEFAULT_LOCALE, **kwargs) -> str:
    """Translate ``key`` for ``locale``.

    Substitution uses ``str.format(**kwargs)``. If the key is missing
    from the requested locale it falls back to English; if still missing,
    returns the key itself so the gap is visible.
    """
    if not _loaded:
        load_translations()
    bundle = _translations.get(locale) or {}
    value = bundle.get(key)
    if value is None and locale != DEFAULT_LOCALE:
        value = (_translations.get(DEFAULT_LOCALE) or {}).get(key)
    if value is None:
        value = key
    if kwargs:
        try:
            return value.format(**kwargs)
        except (KeyError, IndexError, ValueError):
            return value
    return value


def merged_for_locale(locale: str) -> dict[str, str]:
    """Return a flat dict of every key resolved for ``locale``.

    Starts from the English baseline and overlays the requested locale so
    callers (e.g. JS in viewer.html) get a single dict to look up against
    without re-implementing the English fallback rule.
    """
    if not _loaded:
        load_translations()
    locale = normalise_locale(locale)
    base = dict(_translations.get(DEFAULT_LOCALE) or {})
    if locale != DEFAULT_LOCALE:
        base.update(_translations.get(locale) or {})
    return base


def resolve_locale(session_value: str | None, accept_language: str | None) -> str:
    """Pick a locale: session override → Accept-Language → default."""
    if session_value:
        return normalise_locale(session_value)
    if accept_language:
        for chunk in accept_language.split(","):
            tag = chunk.split(";", 1)[0].strip()
            picked = normalise_locale(tag)
            if picked != DEFAULT_LOCALE or tag.lower().startswith("en"):
                return picked
    return DEFAULT_LOCALE
