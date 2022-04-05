#!/bin/bash
# /etc/init.d/sendmail start
# echo Started sendmail
# 

cat /etc/hostname
echo "tls-server" > /etc/hostname
echo "127.0.0.1 tls-server.com tls-server localdev localhost" > /etc/hosts

touch /var/log/mail.info
sendmail -bD -d0.14