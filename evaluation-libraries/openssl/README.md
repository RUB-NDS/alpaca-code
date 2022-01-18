# openssl and boringssl example with strict sni and strict alpn

This library creates containers for openssl and boringssl since they are almost code-compatible.

needs tls-baseimage already in docker

Tested openSSL 1.1.0, 1.1.1, 3.0 and BoringSSL/master from November 2021

roughly based on https://wiki.openssl.org/index.php/SSL/TLS_Client and https://wiki.openssl.org/index.php/Simple_TLS_Server

```bash
./run.sh
```