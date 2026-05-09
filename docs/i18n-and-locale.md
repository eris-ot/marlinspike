# Bilingual Workbench (English / Français)

MarlinSpike's UI ships in both English and French. The locale
picker is in the global nav, between **About** and your username.
Pick a locale → it persists for the session and re-applies to
every page.

This document covers what flips, what doesn't, how the picker
works, and how to add or override translations.

---

## What flips

When you switch locale, the following surfaces re-render in the
chosen locale:

- **All Jinja chrome** — every label, every button, every header,
  every empty state. ~1090 keys covering all server-rendered
  surfaces.
- **All JS-rendered surfaces in the workbench** — every pane
  (Dashboard, Map, Traffic, Findings, Protocols, Evidence,
  Assets, Intel, Risk, Reports), every sidebar panel, every
  modal, every prompt. The JS bridge ships the full dictionary
  via `tjs()` so client-side rendering never needs a round trip.
- **Engine-emitted finding categories, descriptions, and
  remediations** — the eight highest-frequency engine categories
  have full FR translations as of v3.1.0; the rest fall back to
  English finding text but with FR category labels and FR
  remediations.
- **Capture provenance chips** — labels flip; values are
  field-collected and stay as captured.
- **MITRE ATT&CK chips** — technique IDs are language-neutral
  (T1071); technique *names* and tactic labels flip.
- **Asset roles and Purdue band labels** — the role taxonomy
  (Engineering Workstation / HMI / PLC / RTU / Switch / Router /
  …) has FR equivalents.

## What doesn't flip

These stay as-collected or as-authored regardless of locale:

- **Field-collected values**: hostnames, DNS queries, MAC
  addresses, IPs, ports, protocol names (Modbus stays Modbus).
- **Vendor names**: Schneider, Siemens, Allen-Bradley, etc.
- **Filenames**: report names, PCAP names.
- **Asset tag values you wrote in EN** — the field is free-text;
  if you wrote "main control room poller" in EN, that's what
  every locale sees. Re-edit per-locale if needed.
- **Finding note bodies** you wrote in EN — same reasoning.
- **IOC list names + entries** — same.
- **Project names** — same.

The pattern is: structural / framing text is locale-aware,
analyst-authored content is not.

---

## How the picker works

The picker is a button in the global nav with a caret. Click → list
of supported locales (currently EN and FR). Pick → the page
reloads in the new locale and the locale persists.

### Persistence

Locale resolution order on every request:

1. **Session cookie** — the `locale` key, if set. Survives navigation
   within the session.
2. **`Accept-Language` header** — first matching locale from the
   browser's preference list. Used for the first request of a fresh
   session.
3. **Default** — English.

The picker writes to `/i18n/set/<locale>?next=...`. The route
validates the locale against the supported list, sets the session
cookie, and redirects to `next` (with same-host validation to
prevent open-redirect abuse).

### Per-session, not per-user

Locale persists for the session, not the user account. Logging in
on a different device starts fresh — falls back to
`Accept-Language` then English. There's no per-user locale
preference stored against the User row.

This is intentional: most analysts work in one language but might
read a French-language vendor advisory and want to flip locale for
that session without rebuilding their workspace. Per-user locale
is roadmap.

---

## Coverage in numbers (as of v3.2.0)

- 1086 keys covering Jinja chrome and JS-rendered surfaces.
- 38 + 7 = 45 keys for the v3.3.0 live-capture surface (added in
  this release).
- 21 engine finding categories with FR labels.
- 12 plugin finding categories with FR labels.
- 8 highest-frequency engine categories with full FR description +
  remediation text.
- 100% EN/FR parity on key counts (every key in `en.json` exists
  in `fr.json` and vice versa — checked at app boot).

---

## Adding a new translation

Two cases:

### Adding a new locale

Currently EN and FR are baked-in. Adding a new locale (DE, ES,
JP, …) requires:

1. Adding the locale code to `marlinspike/i18n.py` `SUPPORTED_LOCALES`
   and `LOCALE_LABELS` dicts.
2. Creating `marlinspike/translations/<lc>.json` with every key
   from `en.json` translated.
3. Adding the locale code to the picker option list (covered by
   the supported-locales loop in `base.html`).

There's no plugin / dynamic-locale loader yet. Locales are
compiled in at build time.

### Adding a new key to existing locales

When adding a new feature with new UI text:

1. Add the key + EN value to `marlinspike/translations/en.json`,
   alphabetized (keep the file sorted to ease diffs).
2. Add the same key to `marlinspike/translations/fr.json`, also
   alphabetized.
3. Use it in the template via `{{ t('your.key') }}` (Jinja) or
   `tjs('your.key')` (JS via the `I18N` global).

Boot validates EN/FR parity. A missing key on either side won't
break the app (lookups fall back to the EN value, then to the key
itself), but it'll log at WARN level.

### Style notes for FR translations

- Use the formal "vous" form for analyst-facing instructional
  text. The tool is for professionals.
- Match the EN's terseness — *"Live Capture"* → *"Capture en
  direct"*, not *"Capture des paquets en direct"*.
- Preserve protocol / vendor names as proper nouns (Modbus,
  Siemens stay as-is).
- French quotation marks: « » with non-breaking spaces, not "".
- Match capitalization conventions: title-case in EN headers
  becomes sentence-case in FR (`Live Capture` → `Capture en
  direct`, not `Capture En Direct`).

---

## Implementation details

### Where it lives

| file | purpose |
|---|---|
| `marlinspike/i18n.py` | locale resolver, `t()` Jinja global, `i18n_dict()` for the JS bridge |
| `marlinspike/translations/en.json` | English dictionary |
| `marlinspike/translations/fr.json` | French dictionary |

### How the JS bridge works

In `base.html`, the i18n dictionary is dumped into a JS global:

```html
<script>
var I18N = {{ i18n_dict() | tojson }};
function tjs(key) { return I18N[key] || key; }
</script>
```

Client-side code uses `tjs('some.key')` to look up a string. The
viewer template, IOC template, capture template, and several
others rely on this for JS-rendered surfaces.

`tojson` is the safe form (escapes for embedding in JS); never use
the `safe` filter on translation output (XSS risk).

### Why not gettext / Flask-Babel

Two reasons:

- **Zero new pip deps.** Every dependency is operational debt;
  the homegrown JSON-dictionary approach is ~150 LOC and has no
  release / vulnerability surface.
- **No plural / msgid complexity.** MarlinSpike's UI doesn't have
  enough plural-form complexity to justify gettext machinery.
  Ad-hoc `{count} items` interpolation handles what we need.

If we ever ship 5+ locales with serious plural / context
complexity, we'd reconsider. For 2 locales, the JSON dictionary is
the right tradeoff.

---

## Testing

The CI runs both:

```bash
python -m pytest tests/test_i18n.py
```

Tests verify:

- Every key in `en.json` exists in `fr.json` (and vice versa).
- All values are non-empty.
- All keys are sorted alphabetically (catches merge conflicts
  early).
- The locale resolver picks correctly given session / header /
  default.
- The `/i18n/set/<lc>` redirect target validates against the host.
