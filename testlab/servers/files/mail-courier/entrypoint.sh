#!/bin/sh
cat /opt/ssl/target.com.key /opt/ssl/target.com.crt > /etc/courier/pop3d.pem
chmod 700 /etc/courier/pop3d.pem
chown courier /etc/courier/pop3d.pem
cp /etc/courier/pop3d.pem /etc/courier/imapd.pem
/usr/lib/courier/courier-authlib/authdaemond &
/sbin/rpcbind -w &
/usr/sbin/famd -T 0
service rsyslog start
service courier-pop start
service courier-pop-ssl start
service courier-imap start
service courier-imap-ssl start
bash
