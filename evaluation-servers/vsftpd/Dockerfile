FROM tls-baseimage
ARG VERSION=3.0.5
RUN apk add vsftpd
#RUN apk add openssl-dev
#WORKDIR /build
#RUN wget https://security.appspot.com/downloads/vsftpd-${VERSION}.tar.gz
#RUN tar -xvf vsftpd-${VERSION}.tar.gz
#WORKDIR /build/vsftpd-${VERSION}
#RUN ./configure --with-modules=mod_tls --with-virtualhosts
#RUN make
#RUN mv proftpd /bin/

RUN mkdir /var/ftp
RUN chmod 777 /var/ftp

RUN echo "tls-server.com" > /etc/hostname
RUN echo "tls-server.com 127.0.0.1" > /etc/hosts

ADD vsftpd.conf /etc/vsftpd/vsftpd.conf

ADD start.sh /root/
RUN chmod +x /root/start.sh
CMD ["/root/start.sh"]

#CMD ["/usr/sbin/vsftpd", "/etc/vsftpd/vsftpd.conf"]