FROM tls-baseimage
RUN apk add exim
ADD exim.conf /etc/exim/exim.conf

RUN chmod 777 /etc/ssl/cert-data/tls-server.com-chain.crt
RUN chmod 777 /etc/ssl/cert-data/tls-server.com.key

USER exim
#CMD ["exim", "-bd",  "-d-all+pid", "-q30m"]
ENTRYPOINT ["exim"]
CMD ["-bd", "-v", "-oP", "/dev/null"]