FROM --platform=$BUILDPLATFORM golang:1.26.3-alpine AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod main.go ./
COPY public ./public
RUN test -n "$TARGETOS" && test -n "$TARGETARCH" \
    && CGO_ENABLED=0 GOOS="$TARGETOS" GOARCH="$TARGETARCH" go build -buildvcs=false -trimpath -ldflags='-s -w' -o /out/warp-web .

FROM alpine:3.23
ARG TARGETARCH
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 app
COPY --from=build /out/warp-web /usr/local/bin/warp-web

# Compare the ELF machine field with the target image architecture.
RUN set -eu; \
    case "$TARGETARCH" in \
      amd64) expected=3e00 ;; \
      arm64) expected=b700 ;; \
      *) echo "Unsupported image architecture: $TARGETARCH" >&2; exit 1 ;; \
    esac; \
    machine="$(od -An -tx1 -j18 -N2 /usr/local/bin/warp-web | tr -d '[:space:]')"; \
    if [ "$machine" != "$expected" ]; then \
      echo "warp-web ELF machine bytes ($machine) do not match $TARGETARCH ($expected)" >&2; \
      exit 1; \
    fi

USER 10001
ENV LISTEN_ADDR=0.0.0.0:8080
# Check that the entrypoint starts as the container user on each target platform.
RUN set -eu; \
    /usr/local/bin/warp-web & pid=$!; \
    trap 'kill "$pid" 2>/dev/null || true' EXIT; \
    for attempt in 1 2 3 4 5 6 7 8 9 10; do \
      kill -0 "$pid"; \
      if wget -q -T 1 -O /dev/null http://127.0.0.1:8080/api/health; then exit 0; fi; \
      sleep 1; \
    done; \
    echo "warp-web health check failed" >&2; exit 1

EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/warp-web"]
