./build.sh
docker-compose up --exit-code-from openssl-client --remove-orphans
docker-compose -f docker-compose-boringssl.yml -p "boringssl" up --exit-code-from boringssl-client --remove-orphans