#!/bin/bash
#echo test
touch /var/log/vsftpd.log
/usr/sbin/vsftpd /etc/vsftpd/vsftpd.conf & tail -f /var/log/vsftpd.log
#rc-update add vsftpd default
#rc-service vsftpd restart
#tail -f /var/log/vsftpd.log