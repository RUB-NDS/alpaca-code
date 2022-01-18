#!/bin/bash

# validate current path
CURRENT=`pwd`
BASENAME=`basename "$CURRENT"`
if [ "$BASENAME" != "evaluation-libraries" ]; then
    echo "Please start from the evaluation-libraries folder"
    exit
fi

RED='\033[0;31m '
GREEN='\033[0;32m '
NC='\033[0m' # No Color


./build-everything.sh

# go into every library folder
# 1. run containers and tests
# 2. get results file from docker container
# 3. append them to the results file on the host
rm results
for library in bearssl botan gnutls java golang mbedtls openssl wolfssl rustls ; do 
    (cd "$library" 
    ./run.sh
    containerid=$(docker-compose ps -q $library-client)
    echo "Getting results file from container :$containerid"
    docker cp $containerid:/results results-temp
    echo -e "${NC}$library" >> ../results
    cat results-temp >> ../results
    rm results-temp
    );
done

# boringssl is included in the openssl folder so we need to get the file manually
cd openssl
containerid=$(docker-compose -f docker-compose-boringssl.yml -p "boringssl" ps -q boringssl-client)
echo "Getting results file from container :$containerid"
docker cp $containerid:/results results-temp
echo -e "${NC}boringssl" >> ../results
cat results-temp >> ../results
rm results-temp
cd ..

cat results
#remove colors from output 
sed -r "s/\x1B\[([0-9]{1,3}(;[0-9]{1,2})?)?[mGK]//g" results > results-temp
mv results-temp results
