# soken-doc-fetch: sandboxed project-document fetcher (context ingestion spec 2026-10-23, section 3),
# used by the `context` step only. Debian trixie slim, python3, trafilatura (HTML text), pdfminer.six
# (PDF text), charset-normalizer (encoding sniff); no browser, no JS execution, no git. The program is
# src/soken_review/context/fetcher.py (standard library plus those three), copied in like the git
# materializer. Build from the repo root:
#   docker build -f docker/doc-fetch/Dockerfile -t ghcr.io/soken-ltd/doc-fetch:0.1.0-dev .
# debian:trixie-slim multi-arch index digest, pinned 2026-10-10 (same base as git-fetch).
FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
RUN apt-get update \
    && apt-get install -y --no-install-recommends python3 python3-venv ca-certificates \
    && rm -rf /var/lib/apt/lists/* \
    && python3 -m venv /opt/venv \
    && /opt/venv/bin/pip install --no-cache-dir --require-virtualenv \
         "trafilatura==2.3.1" "pdfminer.six==20260107" "charset-normalizer==3.5.2" \
    && /opt/venv/bin/python3 -c "import trafilatura, pdfminer, charset_normalizer" \
    && groupadd -g 10001 soken && useradd -u 10001 -g 10001 -M -s /usr/sbin/nologin soken \
    && python3 --version
COPY src/soken_review/context/fetcher.py /usr/local/bin/soken-doc-fetch
RUN sed -i "1i #!/opt/venv/bin/python3 -I" /usr/local/bin/soken-doc-fetch \
    && chmod 0755 /usr/local/bin/soken-doc-fetch && soken-doc-fetch --help >/dev/null
ENV HOME=/tmp PYTHONDONTWRITEBYTECODE=1
USER 10001:10001
WORKDIR /work
