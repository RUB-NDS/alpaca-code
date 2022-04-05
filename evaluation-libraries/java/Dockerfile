# syntax=docker/dockerfile:1
FROM tls-baseimage as tls-java
ARG VERSION=4.8.1-stable
RUN apk add openjdk11-jdk
ADD client /client
ADD server /server
WORKDIR /client/bin
RUN javac -cp ../lib/java-getopt-1.0.14.jar -d . ../src/Client.java       
RUN jar cmf ../manifest Client.jar Client.class
WORKDIR /server/bin
RUN javac -cp ../lib/java-getopt-1.0.14.jar -d . ../src/Server.java       
RUN jar cmf ../manifest Server.jar Server.class
WORKDIR /
COPY --from=tls-openssl /openssl-client /openssl-client
CMD ["java", "-jar", "/server/bin/Server.jar"]
