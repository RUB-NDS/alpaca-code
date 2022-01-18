(cd certs 
    ./generate-ca.sh);

docker build -t tls-baseimage .
docker build -t tls-baseimagedebian -f Dockerfile-debian .
docker build -t tls-baseimage-archlinux -f Dockerfile-archlinux .
