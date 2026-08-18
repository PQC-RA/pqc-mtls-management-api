# Dockerfile for ghcr.io/pqc-ra/pqc-mtls-management-api.
#
# This lived in the gateway repository as docker/management-api/Dockerfile and built
# this repo through a git submodule. That made a clean `git clone` of the
# gateway undeployable – without --recursive the build dies on a missing
# pnpm-lock.yaml, and every lab host hid it by already having the submodule
# checked out. The image is now built by the repo that owns the source.
#
# The only content change from the gateway version is the build context: paths
# were prefixed with `pqc-mtls-management-api/` and now sit at the repo root.
#
# PQ OpenSSL is still required at RUNTIME, not just to build. Signing and
# revocation moved to the pqc-ca-custodian sidecar, but certs.service.ts still
# shells out to `openssl x509` to parse and fingerprint certificates, and stock
# distro OpenSSL cannot parse an ML-DSA-65 certificate at all. Dropping the base
# image would leave every certificate-inspection endpoint broken.

# The PQ-OpenSSL runtime is COPY --from'd from the shared base image, aliased as
# a named stage (lint-clean vs a build-arg in --from). CI passes the pinned GHCR
# digest via --build-arg BASE_OPENSSL_IMAGE=ghcr.io/pqc-ra/pqc-mtls-openssl-base@sha256:...
# read from base.lock; local builds default to the tag the gateway's
# scripts/fetch-base-image.sh produces.
ARG BASE_OPENSSL_IMAGE=pqc-mtls-openssl-base:local
FROM ${BASE_OPENSSL_IMAGE} AS opensslbase

FROM node:22-bookworm-slim@sha256:6c74791e557ce11fc957704f6d4fe134a7bc8d6f5ca4403205b2966bd488f6b3 AS builder

WORKDIR /usr/src/app

# Install pnpm – pinned (not `latest`) for reproducible builds. 11.15.1
# matches this repo's pnpm-lock.yaml (lockfileVersion 9.0) and package.json's
# packageManager field; bump all three together.
RUN npm install -g pnpm@11.15.1

# Dependency manifests only, so the install layer is cached independently of
# source edits. pnpm-workspace.yaml carries allowBuilds and must be present or
# pnpm resolves a different config than the one this lockfile was written under.
COPY package.json pnpm-lock.yaml pnpm-workspace.yaml ./

RUN pnpm config set ignore-scripts true && pnpm install --frozen-lockfile

COPY . ./

RUN pnpm build

# Runtime stage – ubuntu:24.04 provides glibc 2.39 required by PQ OpenSSL build
FROM ubuntu:24.04@sha256:4fbb8e6a8395de5a7550b33509421a2bafbc0aab6c06ba2cef9ebffbc7092d90

WORKDIR /usr/src/app

# Install Node.js 22 + minimal runtime deps.
# pipefail ensures a failed NodeSource fetch aborts the build instead of being
# masked by the pipe to bash – otherwise apt silently falls back to Ubuntu's
# stock Node 18, which cannot require() the ESM-only `jose` dep (ERR_REQUIRE_ESM).
SHELL ["/bin/bash", "-o", "pipefail", "-c"]
RUN apt-get update && apt-get install -y --no-install-recommends \
	ca-certificates \
	curl \
	gnupg \
	&& curl -fsSL https://deb.nodesource.com/gpgkey/nodesource-repo.gpg.key | gpg --dearmor -o /usr/share/keyrings/nodesource.gpg \
	&& echo "deb [signed-by=/usr/share/keyrings/nodesource.gpg] https://deb.nodesource.com/node_22.x nodistro main" > /etc/apt/sources.list.d/nodesource.list \
	&& apt-get update \
	&& apt-get install -y --no-install-recommends nodejs=22.23.1-1nodesource1 \
	&& node -v | grep -qE '^v22\.' \
	&& rm -rf /var/lib/apt/lists/*

# PQ OpenSSL runtime from the shared base image (pqc-mtls-openssl-base) – no local
# tarball in the build context anymore.
#
# The versioned path is deliberate. A versionless /opt/openssl alias is the
# agreed direction, but it is not in the published base image yet (verified
# against the digest in base.lock: only /opt/openssl-3.6.2 exists). Adopting it
# here first would break this build, and migrating one consumer ahead of the
# others is exactly the drift that decision is meant to remove – it lands for
# every consumer at once or not at all.
COPY --from=opensslbase /opt/openssl-3.6.2 /opt/openssl-3.6.2

# Make the PQ OpenSSL libs discoverable for child processes used by cert parsing.
ENV LD_LIBRARY_PATH=/opt/openssl-3.6.2/lib64:/opt/openssl-3.6.2/lib
RUN echo "/opt/openssl-3.6.2/lib64" > /etc/ld.so.conf.d/openssl.conf && \
	echo "/opt/openssl-3.6.2/lib" >> /etc/ld.so.conf.d/openssl.conf && \
	ldconfig

# The base image does not ship $prefix/ssl/openssl.cnf, and `openssl req` loads
# its config unconditionally – even for read-only operations like -subject and
# -verify. Without this the three CSR-validation calls in certs.service.ts all
# fail with "Can't open /opt/openssl-3.6.2/ssl/openssl.cnf for reading".
#
# The gateway's docker-compose sets this same value, which is why the defect has
# never been seen: the deployment supplies it. That made compose load-bearing for
# image correctness. Now that the image is published for others to pull and run,
# it has to be right on its own – `docker run ghcr.io/pqc-ra/pqc-mtls-management-api`
# must not have a broken CSR path. Compose's setting becomes a redundant
# override of an identical value.
#
# Ubuntu's stock config is the correct target: it is only needed for the [req]
# section defaults, and nothing PQ-specific lives in it. Verified in-image –
# `req -verify` on an ML-DSA-65 CSR returns "self-signature verify OK".
ENV OPENSSL_CONF=/etc/ssl/openssl.cnf

# Fail the build here rather than at runtime if the base was built without PQC
# or without a usable config. Without this a silently non-PQ base produces an
# image that starts cleanly and then 500s on the first certificate lookup.
#
# The CSR round-trip is the assertion that matters: `list -signature-algorithms`
# passes on an image whose `req` path is entirely broken, which is exactly the
# state this image shipped in before OPENSSL_CONF was set above.
RUN set -eux; \
	O=/opt/openssl-3.6.2/bin/openssl; \
	"$O" list -signature-algorithms | grep -qi 'ml-dsa'; \
	"$O" list -kem-algorithms | grep -qi 'ml-kem'; \
	printf '[req]\ndistinguished_name=dn\nprompt=no\n[dn]\nCN=build-probe\n' > /tmp/probe.cnf; \
	"$O" req -new -newkey ML-DSA-65 -keyout /tmp/probe.key -out /tmp/probe.csr \
		-nodes -config /tmp/probe.cnf; \
	"$O" req -verify -in /tmp/probe.csr -noout; \
	"$O" req -in /tmp/probe.csr -noout -subject | grep -q 'build-probe'; \
	rm -f /tmp/probe.cnf /tmp/probe.key /tmp/probe.csr

# ── Dedicated low-privilege service account ──────────────────────────────────
# The API must NOT run as root: it holds (read-only) access to the intermediate
# CA signing key, so a compromised root worker could exfiltrate or tamper with
# the key. Create a fixed, well-known uid/gid (1001:1001) so host-side volume
# ownership (see the gateway's scripts/setup-pki.sh + docker-compose) can be
# granted precisely.
RUN groupadd --system --gid 1001 appuser \
	&& useradd --system --uid 1001 --gid 1001 --no-create-home --shell /usr/sbin/nologin appuser

# Copy from builder, owned by root (read+exec, not writable by the service account).
COPY --from=builder --chown=root:root /usr/src/app/package.json ./
COPY --from=builder --chown=root:root /usr/src/app/node_modules ./node_modules
COPY --from=builder --chown=root:root /usr/src/app/dist ./dist

# Point HOME at a tmpfs-backed path so any library that writes under $HOME does
# not fail against the read-only root filesystem used in production.
ENV HOME=/tmp

# Pre-create the route-persistence dir owned by the service account. When an
# EMPTY named volume is first mounted here, Docker copies this directory's
# ownership (1001:1001) onto the volume – so route persistence works on a fresh
# deploy even if the gateway's scripts/init-volumes.sh was not run (e.g. after
# `compose down -v`). init-volumes.sh remains the fix for volumes that already
# exist as root:root.
RUN mkdir -p /var/lib/pqc-mgmt && chown 1001:1001 /var/lib/pqc-mgmt

# Drop to the unprivileged account for the entire runtime. The CA signing key is
# mounted read-only (see docker-compose) so the app can sign but never rewrite it.
USER 1001:1001

EXPOSE 3000

CMD ["node", "dist/main.js"]
