# Family egress proxy (09 4.3, S9): stripe/smokescreen v0.1.0 built from its tagged commit.
# Config and ACL are rendered from contract/ops/limits.yaml by soken_review.sandbox.egress and
# bind-mounted read-only at /etc/smokescreen; nothing is baked in, so one image serves all families.
#
#   docker build -f docker/smokescreen/Dockerfile -t ghcr.io/soken-ltd/smokescreen:0.1.0 .
#
# golang 1.26-bookworm and debian trixie-slim: multi-arch index digests, pinned 2026-10-10.
FROM golang:1.26-bookworm@sha256:d9c68c2c51161e12fd77e4c6320687c9cd86e1af1e3ad6e6cd63ff970641453c AS build
ARG SMOKESCREEN_COMMIT=609eb8931420453daf5893509be0b25b21bd9edb
ENV CGO_ENABLED=0 GOFLAGS=-mod=vendor GOTOOLCHAIN=local
WORKDIR /src
RUN git init -q . \
    && git fetch -q --depth 1 https://github.com/stripe/smokescreen "${SMOKESCREEN_COMMIT}" \
    && git checkout -q FETCH_HEAD \
    && test "$(git rev-parse HEAD)" = "${SMOKESCREEN_COMMIT}" \
    && go build -trimpath -ldflags='-s -w' -o /out/smokescreen . \
    && /out/smokescreen --help >/dev/null

FROM debian:trixie-slim@sha256:a29215f6a35e51e22adffa17f89e9d2ef06214e64a2bad10d765c46aea49f11f
RUN apt-get update \
    && apt-get install -y --no-install-recommends ca-certificates \
    && rm -rf /var/lib/apt/lists/*
COPY --from=build /out/smokescreen /usr/local/bin/smokescreen
USER 65532:65532
EXPOSE 4750
ENTRYPOINT ["/usr/local/bin/smokescreen"]
CMD ["--config-file", "/etc/smokescreen/config.yaml"]
