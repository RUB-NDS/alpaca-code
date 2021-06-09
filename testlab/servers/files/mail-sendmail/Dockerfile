FROM debian:latest

RUN echo "deb http://ftp.debian.org/debian experimental main contrib non-free" >> /etc/apt/sources.list

RUN apt-get update && apt-get install -y openssl sendmail
RUN apt-get update && apt-get install -y -t experimental sendmail sendmail-bin sendmail-base sendmail-cf

ADD entrypoint.sh /opt/entrypoint.sh
RUN chmod +x /opt/entrypoint.sh

RUN echo "target.com" > /etc/hostname
RUN echo "include(\`/etc/mail/tls/starttls.m4')dnl" >> /etc/mail/sendmail.mc
RUN echo "include(\`/etc/mail/tls/starttls.m4')dnl" >> /etc/mail/submit.mc

RUN echo "define(\`confCACERT_PATH', \`/opt/certs/')dnl" >> /etc/mail/sendmail.mc
RUN echo "define(\`confSERVER_CERT', \`/opt/certs/target.com.crt')dnl" >> /etc/mail/sendmail.mc
RUN echo "define(\`confSERVER_KEY', \`/opt/certs/target.com.key')dnl" >> /etc/mail/sendmail.mc
RUN echo "define(\`confCLIENT_CERT', \`/opt/certs/target.com.crt')dnl" >> /etc/mail/sendmail.mc
RUN echo "define(\`confCLIENT_KEY', \`/opt/certs/target.com.key')dnl" >> /etc/mail/sendmail.mc
RUN echo "define(\`confLOG_LEVEL', \`14')" >> /etc/mail/sendmail.mc

RUN sed -i 's/127.0.0.1/0.0.0.0/' /etc/mail/sendmail.mc

RUN apt-get update && apt-get install -y nano netcat rsyslog

ENTRYPOINT /opt/entrypoint.sh