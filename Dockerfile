FROM golang:1.26-alpine AS build
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 go build -trimpath -ldflags="-s -w" -o /out/gateway ./cmd/gateway

# Runtime needs ffmpeg to remux Frigate's fragmented, zero-duration event clips
# into plain faststart MP4s that AVPlayer can play. The gateway binary is static
# (CGO_ENABLED=0), so Alpine works fine; ca-certificates is needed for the
# outbound HTTPS calls to Apple (JWKS + APNs).
FROM alpine:3.20
RUN apk add --no-cache ffmpeg ca-certificates tzdata \
    && adduser -D -H -u 65532 nonroot
WORKDIR /app
COPY --from=build /out/gateway /app/gateway
EXPOSE 8080
USER nonroot
ENTRYPOINT ["/app/gateway"]
