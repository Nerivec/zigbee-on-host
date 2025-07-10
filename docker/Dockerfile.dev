ARG TARGETPLATFORM

FROM alpine:3.22 AS base

ENV NODE_ENV=development
WORKDIR /app

RUN apk add --no-cache tzdata eudev nodejs npm git

COPY . ./

ARG DATE
ARG VERSION
LABEL org.opencontainers.image.authors="Nerivec"
LABEL org.opencontainers.image.title="ZigBee on Host - Dev"
LABEL org.opencontainers.image.description="Open Source ZigBee stack designed to run on a host and communicate with a radio co-processor (RCP)"
LABEL org.opencontainers.image.url="https://github.com/Nerivec/zigbee-on-host"
LABEL org.opencontainers.image.documentation="https://github.com/Nerivec/zigbee-on-host"
LABEL org.opencontainers.image.source="https://github.com/Nerivec/zigbee-on-host"
LABEL org.opencontainers.image.licenses="GPL-3.0-or-later"
LABEL org.opencontainers.image.created=${DATE}
LABEL org.opencontainers.image.version=${VERSION}

ENTRYPOINT ["tail", "-f", "/dev/null"]
