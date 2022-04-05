# syntax=docker/dockerfile:1
FROM tls-openssl as tls-bearssl
ARG VERSION=0.6

RUN apk add sed

WORKDIR /build
RUN git clone --depth=1 --branch=v${VERSION} https://www.bearssl.org/git/BearSSL
WORKDIR /build/BearSSL
RUN make




WORKDIR /build
ADD server /build/server
ADD client /build/client
ADD CMakeLists.txt /build/CMakeLists.txt

# generate c code from private keys and certs
RUN ls /build/server/
RUN /build/BearSSL/build/brssl ta /etc/ssl/cert-data/ca.crt | tail -n +2 >> /build/client/client.h
RUN /build/BearSSL/build/brssl chain /etc/ssl/cert-data/tls-server.com-chain.crt | tail -n +2 >> /build/server/server.h
RUN /build/BearSSL/build/brssl skey -C /etc/ssl/cert-data/tls-server.com.key | tail -n +2 >> /build/server/server.h

# wrong-cn.com key&cert need different variable names
RUN /build/BearSSL/build/brssl chain /etc/ssl/cert-data/wrong-cn.com-chain.crt | tail -n +2 | sed "s/\(\(CERT[01]\)\|\(CHAIN\(_LEN\)\?\)\|\(RSA\(_[DIPQ]\*\)\?\)\)/WRONG_\1/g" >> /build/server/server.h
RUN /build/BearSSL/build/brssl skey -C /etc/ssl/cert-data/wrong-cn.com.key | tail -n +2 | sed "s/\(\(CERT[01]\)\|\(CHAIN\(_LEN\)\?\)\|\(RSA\(_[DIPQ]\*\)\?\)\)/WRONG_\1/g"  >> /build/server/server.h


RUN cmake . .. && make
RUN mv /build/server/server /
RUN mv /build/client/client /
COPY --from=tls-openssl /openssl-client /openssl-client


WORKDIR /
CMD ["/server"]