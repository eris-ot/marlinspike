FROM python:3.12-slim-bookworm

# dumpcap (wireshark-common) + libpcap. The image must be small — capd
# itself is only ~600 LOC of Python and pulls a single pip dep.
RUN apt-get update \
 && DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends \
      wireshark-common \
      libpcap0.8 \
      ca-certificates \
 && rm -rf /var/lib/apt/lists/*

# dumpcap ships with cap_net_raw,cap_net_admin file capabilities on
# Debian-based images, but only when invoked by a member of the
# `wireshark` group. Inside the container we run as root with those
# caps inherited from `cap_add`, so dumpcap works directly.

WORKDIR /opt/capd
COPY pyproject.toml README.md ./
COPY capd/ ./capd/
RUN pip install --no-cache-dir .

# Pre-create the socket and capture roots so volume mounts have the
# right ownership without an entrypoint script.
RUN mkdir -p /var/run/marlinspike-capd /var/lib/marlinspike/captures

ENTRYPOINT ["python", "-m", "capd"]
CMD ["serve", "--socket=/var/run/marlinspike-capd/marlinspike-capd.sock", "--capture-root=/var/lib/marlinspike/captures"]
