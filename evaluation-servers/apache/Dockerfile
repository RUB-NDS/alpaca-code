FROM httpd:2.4.51 as tls-apache
COPY ./apache.conf /usr/local/apache2/conf/httpd.conf
COPY --from=tls-baseimage /etc/ssl/cert-data/tls-server.com-chain.crt /usr/local/apache2/conf/server-chain.crt
COPY --from=tls-baseimage /etc/ssl/cert-data/tls-server.com.crt /usr/local/apache2/conf/server.crt
COPY --from=tls-baseimage /etc/ssl/cert-data/tls-server.com.key /usr/local/apache2/conf/server.key