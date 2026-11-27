FROM --platform=$BUILDPLATFORM golang:1.27-alpine AS build
ARG TARGETOS
ARG TARGETARCH
WORKDIR /src
COPY go.mod go.sum ./
RUN go mod download
COPY . .
RUN CGO_ENABLED=0 GOOS=$TARGETOS GOARCH=$TARGETARCH go build -trimpath -ldflags="-s -w" -o /out/gateway ./cmd/gateway

# The gateway runs ffmpeg and ffprobe to remux Frigate's fragmented,
# zero-duration event clips into plain faststart MP4s that AVPlayer can play.
# A distribution package carries hundreds of codecs, formats and network
# protocols, with a steady stream of vulnerabilities in code never used here, so
# build only what that remux needs: local files, MP4 in and out, copied video,
# AAC audio. The checksum is of a tarball whose release signature was verified
# (key FCF9 86EA 15E6 E293 A564 4F10 B432 2F04 D676 58D8); update both together.
FROM alpine:3.24 AS ffmpeg
ARG FFMPEG_VERSION=9.1
ARG FFMPEG_SHA256=1a4d394ae63d190a526cd052eb4415c156b5c5e2df37efab41a7de0b8fde2433
RUN apk add --no-cache build-base nasm
WORKDIR /build
ADD https://ffmpeg.org/releases/ffmpeg-${FFMPEG_VERSION}.tar.xz ffmpeg.tar.xz
RUN echo "${FFMPEG_SHA256}  ffmpeg.tar.xz" | sha256sum -c - \
    && tar -xf ffmpeg.tar.xz --strip-components=1 \
    && ./configure \
        --disable-everything --disable-autodetect --disable-network \
        --disable-doc --disable-debug --disable-ffplay --disable-avdevice \
        --disable-swscale --enable-static --disable-shared \
        --extra-ldflags=-static \
        --enable-protocol=file \
        --enable-demuxer=mov --enable-muxer=mp4 \
        --enable-parser=aac,h264,hevc,opus \
        --enable-decoder=aac,opus,pcm_alaw,pcm_mulaw,pcm_s16le \
        --enable-encoder=aac \
        --enable-filter=aformat,anull,aresample,asetpts,atrim,format,null,trim \
        --enable-bsf=aac_adtstoasc,extract_extradata,setts \
    && make -j"$(nproc)" ffmpeg ffprobe \
    && strip ffmpeg ffprobe

# The gateway binary is static (CGO_ENABLED=0), so Alpine works fine;
# ca-certificates is needed for the outbound HTTPS calls to Apple (JWKS + APNs).
FROM alpine:3.24
RUN apk upgrade --no-cache \
    && apk add --no-cache ca-certificates tzdata \
    && adduser -D -H -u 65532 nonroot
COPY --from=ffmpeg /build/ffmpeg /build/ffprobe /usr/local/bin/
WORKDIR /app
COPY --from=build /out/gateway /app/gateway
EXPOSE 8080
USER nonroot
ENTRYPOINT ["/app/gateway"]
