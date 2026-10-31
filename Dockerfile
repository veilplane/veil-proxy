# SPDX-License-Identifier: FSL-1.1-ALv2
# Copyright 2026 Julian Siebert. See LICENSE.md.
#
# docker buildx build --platform linux/amd64,linux/arm64 --build-arg VERSION=v0.1.0 -t veil-proxy:v0.1.0 .
#
# The final image contains only the static binary and the license texts:
# no shell, no libc, no package manager. TLS trust comes from the CA files
# passed with -backend-ca / -peer-ca, so no system CA bundle is needed.

# The build stage always runs natively; Go cross-compiles for the target.
FROM --platform=$BUILDPLATFORM golang:1.24-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY *.go ./
ARG VERSION=dev
ARG TARGETOS
ARG TARGETARCH
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH \
    go build -trimpath -ldflags "-s -w -X main.buildVersion=${VERSION}" -o /veil-proxy .

FROM scratch
COPY --from=build /veil-proxy /veil-proxy
COPY LICENSE.md NOTICE.md /licenses/
USER 65532:65532
VOLUME /var/lib/veil
ENTRYPOINT ["/veil-proxy"]
CMD ["-state-file", "/var/lib/veil/state", "-key-file", "/var/lib/veil/master.sealed"]
