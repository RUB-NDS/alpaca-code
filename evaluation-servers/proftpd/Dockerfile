FROM tls-baseimage
ARG VERSION=1.3.8rc2
ARG TLS_SERVER_NAME=tls-server.com
RUN apk add openssl-dev
WORKDIR /build
RUN wget https://github.com/proftpd/proftpd/archive/refs/tags/v${VERSION}.tar.gz
RUN tar -xvf v${VERSION}.tar.gz
WORKDIR /build/proftpd-${VERSION}
RUN ./configure --with-modules=mod_tls --with-virtualhosts
RUN make
RUN mv proftpd /bin/

#fix errors on start
RUN mkdir /usr/local/var/

RUN echo "tls-server.com" > /etc/hostname
RUN echo "tls-server.com 127.0.0.1" > /etc/hosts

ADD proftpd.conf /etc/proftpd.conf


CMD ["proftpd", "-d", "10", "-n" , "-c" , "/etc/proftpd.conf"]