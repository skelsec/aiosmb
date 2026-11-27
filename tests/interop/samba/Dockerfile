FROM debian:12.11-slim@sha256:b1a741487078b369e78119849663d7f1a5341ef2768798f7b7406c4240f86aef

ARG DEBIAN_SNAPSHOT=20250811T000000Z
ARG SAMBA_PACKAGE_VERSION=2:4.17.12+dfsg-0+deb12u2

LABEL org.opencontainers.image.title="aiosmb Samba interoperability lab" \
      org.opencontainers.image.description="Disposable, test-only Samba target" \
      org.opencontainers.image.version="${SAMBA_PACKAGE_VERSION}"

RUN printf '%s\n' \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT} bookworm main" \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian-security/${DEBIAN_SNAPSHOT} bookworm-security main" \
      "deb [check-valid-until=no] http://snapshot.debian.org/archive/debian/${DEBIAN_SNAPSHOT} bookworm-updates main" \
      > /etc/apt/sources.list \
    && rm -f /etc/apt/sources.list.d/debian.sources \
    && apt-get -o Acquire::Check-Valid-Until=false update \
    && DEBIAN_FRONTEND=noninteractive apt-get install --yes --no-install-recommends \
      "samba=${SAMBA_PACKAGE_VERSION}" \
      "samba-common-bin=${SAMBA_PACKAGE_VERSION}" \
      "samba-vfs-modules=${SAMBA_PACKAGE_VERSION}" \
      "smbclient=${SAMBA_PACKAGE_VERSION}" \
    && rm -rf /var/lib/apt/lists/*

COPY smb.conf /etc/samba/smb.conf.template
COPY entrypoint.sh /usr/local/bin/aiosmb-samba-entrypoint

RUN chmod 0755 /usr/local/bin/aiosmb-samba-entrypoint \
    && mkdir -p /srv/samba/interop

EXPOSE 445

HEALTHCHECK --interval=2s --timeout=2s --start-period=5s --retries=30 \
    CMD ["smbcontrol", "smbd", "ping"]

ENTRYPOINT ["/usr/local/bin/aiosmb-samba-entrypoint"]
