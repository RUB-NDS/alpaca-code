FROM tls-baseimagedebian
ARG DEBIAN_FRONTEND=noninteractive
RUN apt-get update && apt-get install -yq opensmtpd
ADD smtpd.conf /etc/
RUN chmod 600 /etc/ssl/cert-data/*
CMD ["smtpd", "-d"]