DIR="`pwd`/`dirname "$0"`/"
GREEN="\033[0;32m"
NC="\033[0m"

cat << "EOF"
    _     _      ____    _     ____     _
   / \   | |    |  _ \  / \   / ___|   / \
  / _ \  | |    | |_) |/ _ \ | |      / _ \
 / ___ \ | |___ |  __// ___ \| |___  / ___ \
/_/   \_\|_____||_|  /_/   \_\\____|/_/   \_\

USE WITH CAUTION!

EOF

echo -e "${GREEN}Building docker images (THIS WILL TAKE A WHILE!)${NC}"
docker-compose -f servers/docker-compose.yml build --pull -q
docker-compose -f servers/docker-compose.yml pull -q 2> /dev/null

echo -e "${GREEN}Adding additional loopback IP${NC}"
ip addr add 172.0.0.2/8 dev lo

echo -e "${GREEN}Installing dependencies${NC}"

apt-get install -y easy-rsa

echo -e "${GREEN}[CERT] Creating PKI${NC}"
/usr/share/easy-rsa/easyrsa init-pki --pki-dir = "$DIR/pki"
cat << EOF > "$DIR/pki/vars"
set_var EASYRSA_DN     "cn_only"
set_var EASYRSA_DIGEST "sha512"
set_var EASYRSA_BATCH	 "1"
set_var EASYRSA_REQ_CN "alpaca.poc"
EOF
dd if=/dev/urandom of="$DIR/pki/.rnd" bs=256 count=1 2> /dev/null
echo -e "${GREEN}[CERT] Build CA${NC}"
/usr/share/easy-rsa/easyrsa build-ca nopass

#echo -e "${GREEN}[CERT] If you proceed, the generated CA will be added to your trusted CAs. Press any key to proceed${NC}"
#read
#cp "$DIR/pki/ca.crt" /usr/local/share/ca-certificates/alpaca.crt
#update-ca-certificates

echo -e "${GREEN}[CERT] Generating Certificates${NC}"
/usr/share/easy-rsa/easyrsa --req-cn="attacker.com" gen-req attacker.com nopass
/usr/share/easy-rsa/easyrsa sign-req server attacker.com

cp "$DIR/pki/issued/attacker.com.crt" "$DIR/servers/files/cert"
cp "$DIR/pki/private/attacker.com.key" "$DIR/servers/files/cert"

/usr/share/easy-rsa/easyrsa --req-cn="target.com" gen-req target.com nopass
/usr/share/easy-rsa/easyrsa sign-req server target.com

cp "$DIR/pki/issued/target.com.crt" "$DIR/servers/files/cert"
cp "$DIR/pki/private/target.com.key" "$DIR/servers/files/cert"


echo -e "${GREEN}[HOST] Alter host file${NC}"

sed -i '/# ALPACA/,/# END ALPACA/d' /etc/hosts
echo "# ALPACA" >> /etc/hosts
echo "127.0.0.1    attacker.com" >> /etc/hosts
echo "127.0.0.2    target.com" >> /etc/hosts
echo "# END ALPACA" >> /etc/hosts
