# syntax=docker/dockerfile:1
FROM tls-baseimage as tls-mbedtls
ARG VERSION=2.18
WORKDIR /build
RUN git clone --depth=1 --branch=archive/mbedtls-${VERSION} https://github.com/ARMmbed/mbedtls
WORKDIR /build/mbedtls
RUN git submodule update --init --recursive
RUN cmake -DCMAKE_BUILD_TYPE=Debug . && make install
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