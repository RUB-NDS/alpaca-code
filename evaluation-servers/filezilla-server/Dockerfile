FROM tls-baseimage


# RUN cat /etc/ssl/cert-data/tls-server.com.key >> /etc/ssl/private/pure-ftpd.pem
# RUN cat /etc/ssl/cert-data/tls-server.com-chain.crt >> /etc/ssl/private/pure-ftpd.pem
RUN apk add gnutls-dev wxgtk-dev pugixml-dev libexecinfo-dev

ARG LIBVERSION=0.34.2
WORKDIR /build
RUN wget https://download.filezilla-project.org/libfilezilla/libfilezilla-${LIBVERSION}.tar.bz2
RUN tar -xvf libfilezilla-${LIBVERSION}.tar.bz2
WORKDIR /build/libfilezilla-${LIBVERSION}
RUN ./configure --prefix=/usr
RUN make 
RUN make install
#RUN mv lib/.libs/libfilezilla.a /usr/lib/

ARG VERSION=1.1.0
WORKDIR /build
RUN wget https://download.filezilla-project.org/server/FileZilla_Server_${VERSION}_src.tar.bz2
RUN tar -xvf FileZilla_Server_${VERSION}_src.tar.bz2
WORKDIR /build/filezilla-server-${VERSION}
RUN ./configure --prefix=/usr
RUN make 
RUN mv src/server/filezilla-server /bin/

CMD ["filezilla-server"]