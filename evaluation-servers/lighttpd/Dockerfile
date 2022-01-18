FROM tls-openssl


# RUN cat /etc/ssl/cert-data/tls-server.com.key >> /etc/ssl/private/pure-ftpd.pem
# RUN cat /etc/ssl/cert-data/tls-server.com-chain.crt >> /etc/ssl/private/pure-ftpd.pem
RUN apk add pcre-dev zlib-dev bsd-compat-headers

ARG VERSION=1.4.63
WORKDIR /build
RUN wget https://download.lighttpd.net/lighttpd/releases-1.4.x/lighttpd-${VERSION}.tar.gz
RUN tar -xvf lighttpd-${VERSION}.tar.gz
WORKDIR /build/lighttpd-${VERSION}
RUN ./autogen.sh
RUN ./configure -C --with-openssl
RUN make check
RUN make install

ADD lighttpd.conf /etc/lighttpd.conf

CMD ["lighttpd", "-D", "-f", "/etc/lighttpd.conf"]