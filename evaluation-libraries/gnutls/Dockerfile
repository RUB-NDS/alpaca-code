# syntax=docker/dockerfile:1
FROM tls-baseimage as tls-gnutls
ARG VERSION=3.7.2
# RUN git clone --depth=1 -b ${VERSION} https://gitlab.com/gnutls/gnutls.git
# RUN apk add guile-dev
# ENV PKG_CONFIG_PATH=/build/lib/pkgconfig/
# # RUN apk add flex gmp-dev libunistring-dev libffi-dev gc-dev
# # RUN git clone https://github.com/cky/guile.git
# # WORKDIR /src/guile
# # RUN ./autogen.sh
# # RUN ./configure
# # RUN make

# RUN wget https://ftp.gnu.org/gnu/autogen/rel5.18.12/autogen-5.18.12.tar.gz
# RUN tar -xzf autogen-5.18.12.tar.gz
# WORKDIR /src/autogen-5.18.12/
# RUN ./configure
# RUN make && make install

# WORKDIR /src/gnutls
# RUN git submodule update --init --no-fetch
# RUN ./bootstrap
# RUN ./configure --with-included-libtasn1 --with-included-unistring --disable-maintainer-mode --disable-doc --disable-full-test-suite --disable-cxx --disable-padlock --without-p11-kit --without-tpm
# RUN make

RUN apk add --no-cache gnutls-dev

ADD cmake /build/cmake
ADD server /build/server
ADD client /build/client
ADD CMakeLists.txt /build/CMakeLists.txt
WORKDIR /build
RUN cmake . .. && make
RUN mv /build/server/server /
RUN mv /build/client/client /
COPY --from=tls-openssl /openssl-client /openssl-client
WORKDIR /
CMD ["/server"]
