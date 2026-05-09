"""Live-capture integration with the capd sidecar daemon.

The web app never opens raw sockets; it talks to capd over a uds. This
package contains the client, session bookkeeping, rotation consumer,
and Flask blueprint that together turn capd into a first-class
MarlinSpike capability.
"""
