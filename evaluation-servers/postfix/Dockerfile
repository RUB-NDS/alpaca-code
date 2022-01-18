FROM tls-baseimage as tls-apache
RUN apk add postfix
COPY main.cf /etc/postfix/
COPY master.cf /etc/postfix/

CMD ["/usr/sbin/postfix", "start-fg"]