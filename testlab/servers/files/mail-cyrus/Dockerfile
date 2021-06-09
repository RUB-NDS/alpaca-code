FROM linagora/cyrus-imap:latest

RUN apt-get update && apt-get install -y rsyslog

ADD cyrus.conf /etc/cyrus.conf
ADD imapd.conf /etc/imapd.conf

ADD mails/1.eml /var/spool/cyrus/mail/b/user/bob/1.
RUN chown -R cyrus:mail /var/spool/cyrus/mail/b/user/bob/

ADD cyradm_commands /tmp/cyradm_commands
RUN service rsyslog start

RUN /usr/sbin/cyrmaster & \
    sleep 1;\
    export TERM=xterm;cyradm -u cyrus -w cyrus localhost < /tmp/cyradm_commands

# CMD bash
# Admin: cyrus:cyrus
# User:   bob:bob    alice:alice