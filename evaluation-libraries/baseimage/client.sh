#!/bin/bash
#$1 command to run
#$2 server1 to connect
#$3 server2 to connect
#$4 openssl-malicious-alpn server
#$5 wait seconds before starting

results=()

sleep $5

echo "------------  Test 1: SNI=tls-server.com   ALPN=http/1.1 ------------------"
$1 -h $2 -s tls-server.com -a http/1.1
results+=($?)

echo "------------  Test 2: SNI=example.com ALPN=http/1.1 ------------------"
/openssl-client -h $2 -s example.com -a http/1.1
results+=($?)

echo "------------  Test 3: SNI=tls-server.com   ALPN=invalid  ------------------"
/openssl-client -h $2 -s tls-server.com -a invalid
results+=($?)

echo "------------  Test 4: wrong certificate by server   ------------------"
$1 -h $3 -s tls-server.com -a http/1.1
results+=($?)

echo "------------  Test 5: server sends wrong alpn       ------------------"
$1 -h $4 -s tls-server.com -a http/1.1
results+=($?)

RED='\033[0;31m '
GREEN='\033[0;32m '
NC='\033[0m' # No Color

echo "" > results

for i in "${!results[@]}"; do 
  test=$((i+1))
  if [ $i = "0" ]; then #first test needs to return 0
    if [ ${results[$i]} = "0" ];
    then 
      echo -e "${GREEN}Test$test success! exitcode:${results[$i]}" >> results;
    else 
      echo -e "${RED}Test$test FAILED! exitcode:${results[$i]}" >> results;
    fi
  else #every other test needs to return non-zero value
    if [ ${results[$i]} = "0" ]; 
    then 
      echo -e "${RED}Test$test FAILED! exitcode:${results[$i]}" >> results;
    else 
      echo -e "${GREEN}Test$test success! exitcode:${results[$i]}" >> results;
    fi
  fi
done

cat results