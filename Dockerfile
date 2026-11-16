FROM --platform=$BUILDPLATFORM golang:1.26.3-alpine AS build
ARG TARGETOS=linux
ARG TARGETARCH=amd64
WORKDIR /src
COPY go.mod main.go ./
COPY public ./public
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -buildvcs=false -trimpath -ldflags='-s -w' -o /out/warp-web .
FROM alpine:3.23
RUN apk add --no-cache ca-certificates && adduser -D -u 10001 app
COPY --from=build /out/warp-web /usr/local/bin/warp-web
USER 10001
ENV LISTEN_ADDR=0.0.0.0:8080
EXPOSE 8080
ENTRYPOINT ["/usr/local/bin/warp-web"]
