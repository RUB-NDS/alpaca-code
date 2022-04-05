FROM tls-baseimage-archlinux

RUN pacman -Syu --noconfirm

USER build

#Fixed to Version 3.4.2

WORKDIR /src/
RUN git clone https://aur.archlinux.org/perl-pod-pom.git
WORKDIR /src/perl-pod-pom
RUN git checkout 2699d4b77c2fb0573b1445968afaca4aa36299d4
RUN makepkg -si --noconfirm

WORKDIR /src/
RUN git clone https://aur.archlinux.org/perl-pod-pom-view-restructured.git
WORKDIR /src/perl-pod-pom-view-restructured
RUN git checkout 80138742fbb711e3a56b4018ce4dcc7f0ec1b212
RUN makepkg -si --noconfirm

WORKDIR /src/
RUN git clone https://aur.archlinux.org/cyrus-imapd.git
WORKDIR /src/cyrus-imapd
RUN git checkout a1e53ee172fc37431080dd3ff3685ffd2a2378e5
#remove pgp key from PKGBUILD
RUN sed -i '/^validpgpkeys/d' PKGBUILD
RUN sed -i 's/{,.sig}//g' PKGBUILD
RUN sed -i '/'SKIP'/d' PKGBUILD
RUN makepkg -si --noconfirm

USER root 

RUN echo "tls-server" >> /etc/hostname
RUN echo "tls-server 127.0.0.1" >> /etc/hosts

ADD cyrus.conf /etc/cyrus/cyrus.conf
ADD imapd.conf /etc/cyrus/imapd.conf

CMD ["/usr/lib/cyrus/master"]

