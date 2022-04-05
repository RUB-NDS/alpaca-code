# syntax=docker/dockerfile:1
FROM tls-baseimage as tls-rustls
RUN apk add cargo
WORKDIR /build
ADD server /build/server
ADD client /build/client
ADD Cargo.toml /build/Cargo.toml
RUN cargo build --release

RUN mv /build/target/release/server /server
RUN mv /build/target/release/client /client

COPY --from=tls-openssl /openssl-client /openssl-client
WORKDIR /
CMD ["/server"]
