# syntax=docker/dockerfile:1
FROM tls-baseimage
WORKDIR .
ADD server /build/server
ADD client /build/client
WORKDIR /build/server
RUN go build server.go
RUN mv server /
WORKDIR /build/client
RUN go build client.go
RUN mv client /
WORKDIR /
COPY --from=tls-openssl /openssl-client /openssl-client
CMD ["/server"]
