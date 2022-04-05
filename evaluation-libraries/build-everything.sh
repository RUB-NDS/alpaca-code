#!/bin/bash
for library in baseimage openssl bearssl botan java gnutls golang mbedtls wolfssl rustls; do 
    (cd "$library" 
    ./build.sh);
done
