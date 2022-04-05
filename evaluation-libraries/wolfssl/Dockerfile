# syntax=docker/dockerfile:1
FROM tls-baseimage as tls-wolfssl
ARG VERSION=4.8.1-stable
WORKDIR /build
RUN git clone --depth=1 --branch=v${VERSION} https://github.com/wolfSSL/wolfssl
WORKDIR /build/wolfssl
RUN ./autogen.sh
RUN ./configure --prefix=/build/ --enable-static --enable-sni --enable-alpn
RUN make
WORKDIR /build
ADD server /build/server
ADD client /build/client
ADD CMakeLists.txt /build/CMakeLists.txt
RUN cmake . .. && make
RUN mv /build/server/server /
RUN mv /build/client/client /
COPY --from=tls-openssl /openssl-client /openssl-client
WORKDIR /
CMD ["/server"]
