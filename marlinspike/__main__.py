"""MarlinSpike engine CLI entry point.

Invoked as a subprocess by the web app to run the analysis engine on a PCAP:

    python -m marlinspike <args>

Replaces the legacy top-level `marlinspike.py` script that existed in v2.x.
"""

from marlinspike.engine import main

if __name__ == "__main__":
    main()
