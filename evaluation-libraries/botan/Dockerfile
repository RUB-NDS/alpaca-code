# syntax=docker/dockerfile:1
FROM tls-baseimage as tls-botan
ARG VERSION=2.18.1
RUN wget https://botan.randombit.net/releases/Botan-${VERSION}.tar.xz  
RUN tar -xf Botan-${VERSION}.tar.xz
WORKDIR /src/Botan-${VERSION}
RUN apk add python2
RUN ./configure.py --prefix=/build/ 
RUN  make 
RUN  make install
RUN mv libbotan-2.a /lib/libbotan-2.a
RUN mv /build/include/* /usr/include/

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
