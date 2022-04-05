FROM tls-baseimagedebian

RUN apt-get update && apt-get install -yq sendmail openssl libsasl2-2 sasl2-bin

RUN echo "tls-server.com" >> /etc/hostname
RUN echo "tls-server.com 127.0.0.1" >> /etc/hosts

RUN echo "include(\`/etc/mail/tls/starttls.m4')dnl" >> /etc/mail/sendmail.mc
RUN echo "include(\`/etc/mail/tls/starttls.m4')dnl" >> /etc/mail/submit.mc

RUN echo "define(\`confCACERT_PATH', \`/etc/ssl/cert-data/')dnl" >> /etc/mail/sendmail.mc
RUN echo "define(\`confLOG_LEVEL', \`14')" >> /etc/mail/sendmail.mc

RUN echo "define(\`SMART_HOST', \`tls-server.com')dnl" >> /etc/mail/sendmail.mc

RUN echo "define(\`confSERVER_CERT', \`/etc/ssl/cert-data/tls-server.com-chain.crt')dnl" >> /etc/mail/sendmail.mc
RUN echo "define(\`confSERVER_KEY', \`/etc/ssl/cert-data/tls-server.com.key')dnl" >> /etc/mail/sendmail.mc
RUN echo "define(\`confCLIENT_CERT', \`/etc/ssl/cert-data/tls-server.com-chain.crt')dnl" >> /etc/mail/sendmail.mc
RUN echo "define(\`confCLIENT_KEY', \`/etc/ssl/cert-data/tls-server.com.key')dnl" >> /etc/mail/sendmail.mc

RUN echo "GreetPause:192.16 0" >> /etc/mail/access
RUN echo "ClientRate:172.16 0" >> /etc/mail/access
RUN echo "GreetPause:172.16 0" >> /etc/mail/access

RUN sed -i 's/127.0.0.1/0.0.0.0/' /etc/mail/sendmail.mc

RUN chmod 600 /etc/ssl/cert-data/*

RUN yes 'y' | sendmailconfig

RUN chmod 777 /etc/ssl/cert-data/tls-server.com-chain.crt
RUN chmod 777 /etc/ssl/cert-data/tls-server.com.key

USER sendmail
#CMD ["exim", "-bd",  "-d-all+pid", "-q30m"]
ADD start.sh /root/
RUN chmod +x /root/start.sh
CMD ["/root/start.sh"]
#CMD ["sendmail", "-bD", "-d0.14"]