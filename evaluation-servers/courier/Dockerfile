FROM tls-baseimage-archlinux

# Avoid ERROR: invoke-rc.d: policy-rc.d denied execution of start.
#RUN echo "#!/bin/sh\nexit 0" > /usr/sbin/policy-rc.d

RUN pacman -Syu --noconfirm

USER build

## Version 1.1.5-2

WORKDIR /src/
RUN git clone https://aur.archlinux.org/courier-unicode.git
WORKDIR /src/courier-unicode
RUN git checkout b08066fde2b4147076cb3201888fc2ee68eed19c
RUN makepkg -si --noconfirm

WORKDIR /src/
RUN git clone https://aur.archlinux.org/courier-authlib.git
WORKDIR /src/courier-authlib
RUN git checkout 125c9823c551500428857a503f2d4a3b795aa589
RUN makepkg -si --noconfirm

WORKDIR /src/
RUN git clone https://aur.archlinux.org/courier-mta.git
WORKDIR /src/courier-mta
RUN git checkout 359ca3946091a4634d1c6aab60df2e079cdde08
RUN makepkg -si --noconfirm

USER root
#ARG DEBIAN_FRONTEND=noninteractive
#RUN apt-get update && apt-get install -yq courier-imap
RUN cp /etc/ssl/cert-data/tls-server.com-chain.crt /etc/courier/imapd.cert
RUN cp /etc/ssl/cert-data/tls-server.com-chain.crt /etc/courier/pop3d.cert
RUN cp /etc/ssl/cert-data/tls-server.com.key /etc/courier/imapd.key
RUN cp /etc/ssl/cert-data/tls-server.com.key /etc/courier/pop3d.key
ADD start.sh /root/
ADD imapd-ssl /etc/courier/
RUN chmod +x /root/start.sh
CMD ["/root/start.sh"]