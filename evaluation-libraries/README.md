# evaluation-libraries
TLS-library examples with strict SNI and strict ALPN implemented to prevent the cross-protocol attacks demonstrated in the [ALPACA-Attack](https://alpaca-attack.com/index.html).

DISCLAIMER: The implementations only focused on the ALPN&SNI TLS-Extensions, i can't guarantee that they are otherwise securely implemented.

## Containers
Each library example starts the following containers
- ``server`` with SNI=tls-server.com , ALPN=http/1.1 written in the library
- ``server-openssl-wrong-cn`` with SNI=tls-server.com , ALPN=http/1.1 and a certificate that has a wrong common name
- ``server-openssl-malicious-alpn`` with SNI=tls-server.com and always sends back ALPN=invalid
- ``client`` runs a bash script that does the following tests

## Tests
1. send correct SNI and ALPN to ``server`` and send application data
2. send wrong SNI to ``server`` (tests SNI on server)
3. send wrong ALPN to ``server`` (tests ALPN on server)
4. send correct SNI and ALPN to ``server-openssl-wrong-cn`` (tests strict SNI on client)
5. send correct SNI and ALPN to ``server-openssl-malicious-alpn`` (tests strict ALPN on client)

The first test needs to succeed and every other tests needs to return a non-null value.

## How to run
Requires docker, docker-compose and easy-rsa

This builds all containers, runs all test and puts the results in a file called ``results``
```
./run-everything.sh
```

----------------
### Running single libraries
First build the baseimage and the openssl image. (The openssl image is required for tests 4 and 5)
```
cd baseimage && ./build.sh && cd ..
cd openssl && ./build.sh && cd ..
```

Then go into any of the library folders and start the tests
```
./run.sh
```

