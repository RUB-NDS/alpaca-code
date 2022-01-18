ARG VERSION=3.15
FROM alpine:${VERSION}
RUN apk add \
    git \
    linux-headers \
    cmake \
    make \
    wget \
    bash \
    autoconf \
    automake \
    coreutils \
    patch \
    gettext-dev \
    gperf \
    pkgconf \
    libtool \
    g++ \
    gcc \
    perl \
    python3 \
    go
COPY ./certs/ca.crt /etc/ssl/certs/
COPY ./certs /etc/ssl/cert-data
COPY client.sh /client.sh
RUN mkdir /src
RUN mkdir /build
WORKDIR /src/
