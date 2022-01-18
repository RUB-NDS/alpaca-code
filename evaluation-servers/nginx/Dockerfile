FROM tls-baseimage as tls-nginx
ARG VERSION=1.21.4
RUN apk add pcre-dev openssl-dev
WORKDIR /build
RUN wget http://nginx.org/download/nginx-${VERSION}.tar.gz
RUN tar -xvf nginx-${VERSION}.tar.gz
WORKDIR /build/nginx-${VERSION}
#ADD patch.diff /build/nginx-${VERSION}/patch.diff
#RUN patch src/http/modules/ngx_http_ssl_module.c
RUN mkdir /usr/local/nginx
RUN mkdir /usr/local/nginx/logs
RUN ./configure --conf-path=/etc/nginx.conf --with-http_ssl_module --without-http_gzip_module --with-http_v2_module
RUN make
ADD nginx.conf /etc/nginx.conf
RUN mv objs/nginx /usr/bin/nginx
CMD ["nginx", "-g", "daemon off;"]
