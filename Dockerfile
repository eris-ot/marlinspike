# ── marlinspike-dpi builder ───────────────────────────────────
FROM rust:1.85-slim-bookworm AS dpi-builder

ARG MARLINSPIKE_DPI_REPO=https://github.com/riverrisk/marlinspike-dpi.git
ARG MARLINSPIKE_DPI_REF=de7ed06a28096a3da482831bc674ef0652c0e479

WORKDIR /build

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    git && \
    rm -rf /var/lib/apt/lists/*

RUN git clone "$MARLINSPIKE_DPI_REPO" marlinspike-dpi && \
    cd marlinspike-dpi && \
    git checkout "$MARLINSPIKE_DPI_REF" && \
    cargo build --locked --release --bin marlinspike-dpi

# ── marlinspike-mitre builder ─────────────────────────────────
FROM python:3.12-slim AS mitre-builder

ARG MARLINSPIKE_MITRE_REPO=https://github.com/riverrisk/marlinspike-mitre.git
ARG MARLINSPIKE_MITRE_REF=c3583ec2d189b8cde69f2160da6a5e8e5b643f7b

WORKDIR /build

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    git && \
    rm -rf /var/lib/apt/lists/*

RUN git clone "$MARLINSPIKE_MITRE_REPO" marlinspike-mitre && \
    cd marlinspike-mitre && \
    git checkout "$MARLINSPIKE_MITRE_REF"

# ── marlinspike-malware builder ───────────────────────────────
FROM rust:1.85-slim-bookworm AS malware-builder

ARG MARLINSPIKE_MALWARE_REPO=https://github.com/riverrisk/marlinspike-malware.git
ARG MARLINSPIKE_MALWARE_REF=4a008211cad7e56609e8a667b95f1c09b790c1b4

WORKDIR /build

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    git && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/marlinspike-malware/bin /opt/marlinspike-malware/rules && \
    if [ -n "$MARLINSPIKE_MALWARE_REPO" ]; then \
        git clone "$MARLINSPIKE_MALWARE_REPO" marlinspike-malware && \
        cd marlinspike-malware && \
        if [ -n "$MARLINSPIKE_MALWARE_REF" ]; then git checkout "$MARLINSPIKE_MALWARE_REF"; fi && \
        cargo build --locked --release --bin marlinspike-malware && \
        cp target/release/marlinspike-malware /opt/marlinspike-malware/bin/marlinspike-malware; \
    fi

# ── marlinspike-malware-rules builder ─────────────────────────
FROM python:3.12-slim AS malware-rules-builder

ARG MARLINSPIKE_MALWARE_RULES_REPO=https://github.com/riverrisk/marlinspike-malware-rules.git
ARG MARLINSPIKE_MALWARE_RULES_REF=99cbe9358d0a5047d9b5e57a7e4ff5eafdee9bd4

WORKDIR /build

RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    ca-certificates \
    git && \
    rm -rf /var/lib/apt/lists/*

RUN mkdir -p /opt/marlinspike-malware-rules/packs \
             /opt/marlinspike-malware-rules/manifests \
             /opt/marlinspike-malware-rules/build && \
    if [ -n "$MARLINSPIKE_MALWARE_RULES_REPO" ]; then \
        git clone "$MARLINSPIKE_MALWARE_RULES_REPO" marlinspike-malware-rules && \
        cd marlinspike-malware-rules && \
        if [ -n "$MARLINSPIKE_MALWARE_RULES_REF" ]; then git checkout "$MARLINSPIKE_MALWARE_RULES_REF"; fi && \
        cp -R packs/. /opt/marlinspike-malware-rules/packs/ && \
        if [ -d manifests ]; then cp -R manifests/. /opt/marlinspike-malware-rules/manifests/; fi && \
        if [ -d build ]; then cp -R build/. /opt/marlinspike-malware-rules/build/; fi; \
    fi

# ── Runtime ───────────────────────────────────────────────────
FROM python:3.12-slim

WORKDIR /app

# System deps: tshark for PCAP dissection, libpq for psycopg2
RUN apt-get update && \
    apt-get install -y --no-install-recommends \
    gcc \
    libpq-dev \
    tshark && \
    rm -rf /var/lib/apt/lists/*

COPY requirements.txt .
RUN pip install --no-cache-dir -r requirements.txt

COPY --from=dpi-builder /build/marlinspike-dpi/target/release/marlinspike-dpi /usr/local/bin/marlinspike-dpi

# Application source
COPY _ms_engine.py _auth.py _audit.py _models.py _config.py ./
COPY auth.py config.py models.py app.py marlinspike.py ./

COPY templates/ ./templates/
COPY static/ ./static/
COPY presets/ ./presets/
COPY plugins/ ./plugins/
COPY rules/ ./rules/

COPY --from=mitre-builder /build/marlinspike-mitre/plugins/marlinspike_mitre ./plugins/marlinspike_mitre
COPY --from=mitre-builder /build/marlinspike-mitre/rules/mitre ./rules/mitre
COPY --from=malware-builder /opt/marlinspike-malware/bin /opt/marlinspike-malware/bin
COPY --from=malware-rules-builder /opt/marlinspike-malware-rules /usr/share/marlinspike-malware/rules

# OUI database (outside volume mount so it persists in image)
COPY data/oui.json ./oui.json

# Data dirs (will be overridden by volume mount)
RUN mkdir -p data/reports data/uploads data/submissions

# Create non-root user (needs NET_RAW for tshark)
RUN useradd -m -u 1000 marlinspike && \
    chown -R marlinspike:marlinspike /app

ENV PATH="/opt/marlinspike-malware/bin:${PATH}" \
    MARLINSPIKE_DPI_BIN=/usr/local/bin/marlinspike-dpi \
    MARLINSPIKE_MALWARE_BIN=/opt/marlinspike-malware/bin/marlinspike-malware \
    MARLINSPIKE_MALWARE_RULES=/usr/share/marlinspike-malware/rules/packs

USER marlinspike

EXPOSE 5001/tcp

CMD ["python3", "app.py"]
