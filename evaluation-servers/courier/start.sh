#!/bin/bash
mkdir -p /run/courier/authdaemon
touch /run/courier/authdaemon/pid.lock
touch /run/courier/imapd-ssl.pid.lock
makeimapaccess
/usr/sbin/authdaemond start
/usr/sbin/imapd start
/usr/sbin/imapd-ssl start
while true; do sleep 1000; done