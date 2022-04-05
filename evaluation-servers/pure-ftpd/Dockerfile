FROM tls-baseimage
ARG VERSION=1.0.49
RUN apk add openssl-dev
WORKDIR /build
RUN wget https://github.com/jedisct1/pure-ftpd/releases/download/${VERSION}/pure-ftpd-${VERSION}.tar.gz
RUN tar -xvf pure-ftpd-${VERSION}.tar.gz
WORKDIR /build/pure-ftpd-${VERSION}
RUN ./configure --with-tls --without-capabilities
RUN make
RUN mv src/pure-ftpd /bin/

RUN mkdir /etc/ssl/private

RUN cat /etc/ssl/cert-data/tls-server.com.key >> /etc/ssl/private/pure-ftpd.pem
RUN cat /etc/ssl/cert-data/tls-server.com-chain.crt >> /etc/ssl/private/pure-ftpd.pem

CMD ["pure-ftpd", "-Y" , "2"]