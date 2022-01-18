# alpaca-server
Testing TLS Servers ALPN and SNI Implementation.

Scans each Server with TLS-Scanner https://github.com/tls-attacker/TLS-Scanner

## Requirements
- docker and docker-compose
- baseimage Docker containers from evaluation-libraries

----------------
## Running Servers
1. Build the baseimage from evaluation-libraries.
2. Build the TLS-Scanner container with ``./build.sh``
3. Go into any subdirectory and do ``./run.sh``

## Server overview and versions tested
'strict' means the server rejects the connection if he doesn't recognize the ALPN or SNI sent.
| Server        | ALPN          |SNI            |
| ------------- | ------------- | ------------- |
| apache 2.4.51 | not strict    | not strict    |
| nginx  1.21.4 | strict    | not strict    |
| lighttpd 1.4.63 | strict        | not strict    |
| postfix/smtpd 3.6.2 | ------------  | not strict    |
| openSMTPD  6.8.0    | ------------  | ------------  |
| sendmail 8.17.1  | ------------  | ------------  |
| exim 4.95     | strict        | ------------  |
| Courier 5.10  | strict        | not strict    |
| Dovecot 2.3.13  | ------------  | not strict    |
| pure-ftpd 1.0.49    | ------------  | not strict    |
| cyrus 3.4.2-1 | strict in master only https | not strict    |
| ProFTPD 1.3.8rc2      | ------------  | strict        |
| vsftpd 3.0.5 | strict        | strict        |
| filezilla server 1.1.0 | strict        | not strict    |


