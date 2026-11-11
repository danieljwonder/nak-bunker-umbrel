# nak bunker for Umbrel: upstream nak release binary (unmodified, checksum-pinned)
# plus a small Python stdlib web shim for unlocking and status.
FROM python:3.13-slim-bookworm@sha256:a5a7017efc5969e00ae2b91c8eb0631049a569652aa4ffc4501769049ae45c72

# Bump these together (see README "Updating nak"). Digests are GitHub's published
# asset digests for https://github.com/fiatjaf/nak/releases/tag/${NAK_VERSION}
ARG NAK_VERSION=v0.22.3
ARG NAK_SHA256_AMD64=a0d2b7be59572cddeb63f216fd5b0d4b63f73b4a0ae2216114ffc35a3e6c4b2b
ARG NAK_SHA256_ARM64=24c79abcfc6360e41b83422302e07e202a8c5d988f68dfb7fd41567eeab26375
ARG TARGETARCH

LABEL org.opencontainers.image.source="https://github.com/danieljwonder/nak-bunker-umbrel" \
      org.opencontainers.image.description="nak bunker (NIP-46 remote signer) packaged for Umbrel" \
      org.opencontainers.image.licenses="MIT"

RUN set -eu; \
    case "${TARGETARCH}" in \
      amd64) sum="${NAK_SHA256_AMD64}" ;; \
      arm64) sum="${NAK_SHA256_ARM64}" ;; \
      *) echo "unsupported arch ${TARGETARCH}" >&2; exit 1 ;; \
    esac; \
    url="https://github.com/fiatjaf/nak/releases/download/${NAK_VERSION}/nak-nodb-${NAK_VERSION}-linux-${TARGETARCH}"; \
    python3 -c "import urllib.request,sys; urllib.request.urlretrieve(sys.argv[1], '/usr/local/bin/nak')" "$url"; \
    echo "${sum}  /usr/local/bin/nak" | sha256sum -c -; \
    chmod 0755 /usr/local/bin/nak; \
    /usr/local/bin/nak --version

COPY shim/nakbunker.py /app/nakbunker.py

ENV NAK_HOME=/data PORT=8080 PYTHONUNBUFFERED=1
USER 1000:1000
WORKDIR /data
EXPOSE 8080
ENTRYPOINT ["python3", "-I", "/app/nakbunker.py"]
