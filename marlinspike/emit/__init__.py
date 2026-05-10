"""Pluggable emit pipeline for MarlinSpike report artifacts.

The engine's primary output is ``report.json`` (the internal contract
between the engine and the workbench). Additional emit formats sit
alongside it as transformers from the canonical report shape:

* ``ocsf`` — OCSF v1.4.0 Detection Finding records (NDJSON), one per
  application-layer finding (risk_findings, c2_indicators,
  malware_findings, mitre_classifications). Wire-derived events
  (Bronze ProtocolTransaction, AssetObservation, ParseAnomaly) are
  emitted by ``marlinspike-dpi`` itself and concatenated into the same
  NDJSON file when the ``--format ocsf`` CLI surface lands there.

Future formats (STIX 2.1, MITRE ATT&CK Navigator, Sigma) plug in here
the same way: a module that consumes the report dict and produces a
serialised artifact.
"""
