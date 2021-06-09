DIR="`pwd`/`dirname "$0"`/../servers/docker-compose.yml"
docker-compose -f $DIR exec vsftp tail -f  /var/log/vsftpd.log /home/vsftpd/bob/leak