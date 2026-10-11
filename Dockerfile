ARG BUILDER_IMAGE=registry.access.redhat.com/hi/go:1.27-builder
FROM $BUILDER_IMAGE AS builder
COPY . /build
WORKDIR /build
RUN --mount=type=cache,target=/go/pkg/mod \
    --mount=type=cache,target=/root/.cache/go-build \
    CGO_ENABLED=0 go build ./cmd/scep-bridge
FROM scratch
COPY --from=builder /build/scep-bridge /usr/local/bin/scep-bridge
USER 65534
ENTRYPOINT ["/usr/local/bin/scep-bridge"]
VOLUME /etc/scep-bridge
EXPOSE 8080