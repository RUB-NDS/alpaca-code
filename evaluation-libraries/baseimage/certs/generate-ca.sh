DIR="`pwd`/`dirname "$0"`/"

echo $DIR

if [ "$OS" = "Darwin" ]; then
   brew install easy-rsa
else
   apt-get install -y easy-rsa
fi

path="/usr/share/easy-rsa/"
if [ "$OS" = "Darwin" ]; then
   path=""
   DIR_MAC="/usr/local/etc/"
fi
echo -e "${GREEN}[CERT] Creating PKI${NC}"
${path}easyrsa init-pki --pki-dir = "$DIR/pki"
cat << EOF > "$DIR/pki/vars"
set_var EASYRSA_DN     "cn_only"
set_var EASYRSA_DIGEST "sha512"
set_var EASYRSA_BATCH    "1"
set_var EASYRSA_REQ_CN "alpaca.poc"
EOF
dd if=/dev/urandom of="$DIR/pki/.rnd" bs=256 count=1 2> /dev/null
echo -e "${GREEN}[CERT] Build CA${NC}"
${path}easyrsa build-ca nopass

echo -e "${GREEN}[CERT] Generating Certificates${NC}"
${path}easyrsa --req-cn="tls-server.com" gen-req tls-server.com nopass
${path}easyrsa sign-req server tls-server.com

${path}easyrsa --req-cn="wrong-cn.com" gen-req wrong-cn.com nopass
${path}easyrsa sign-req server wrong-cn.com

#copy certs
cp "$DIR/pki/issued/tls-server.com.crt" "$DIR"
cp "$DIR/pki/private/tls-server.com.key" "$DIR"
cp "$DIR/pki/issued/wrong-cn.com.crt" "$DIR"
cp "$DIR/pki/private/wrong-cn.com.key" "$DIR"
cp "$DIR/pki/ca.crt" "$DIR"

#generate chains
cat  "$DIR/tls-server.com.crt" >>  "$DIR/tls-server.com-chain.crt"
cat  "$DIR/ca.crt" >>  "$DIR/tls-server.com-chain.crt"

#generate chains
cat  "$DIR/wrong-cn.com.crt" >>  "$DIR/wrong-cn.com-chain.crt"
cat  "$DIR/ca.crt" >>  "$DIR/wrong-cn.com-chain.crt"

#generate p12
openssl pkcs12 -export -in "$DIR/tls-server.com.crt" -inkey "$DIR/tls-server.com.key" -out "$DIR/tls-server.com.p12" -password pass:123456
openssl pkcs12 -export -in "$DIR/wrong-cn.com.crt" -inkey "$DIR/wrong-cn.com.key" -out "$DIR/wrong-cn.com.p12" -password pass:123456

openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in tls-server.com.key -out tls-server.com.pkcs8.key
openssl pkcs8 -topk8 -inform PEM -outform PEM -nocrypt -in wrong-cn.com.key -out wrong-cn.com.pkcs8.key

#if [ "$OS" = "Darwin" ]; then
#   DIR_MAC="/usr/local/etc"
#else
#   DIR_MAC=${DIR}
#fi
#
#mkdir -p "$DIR/servers/files/cert/" 2> /dev/null
#cp "$DIR_MAC/pki/issued/attacker.com.crt" "$DIR/servers/files/cert/"
#cp "$DIR_MAC/pki/private/attacker.com.key" "$DIR/servers/files/cert/"
#
#${path}easyrsa --req-cn="target.com" gen-req target.com nopass
#${path}easyrsa sign-req server target.com
#
#cp "$DIR_MAC/pki/issued/target.com.crt" "$DIR/servers/files/cert/"
#cp "$DIR_MAC/pki/private/target.com.key" "$DIR/servers/files/cert/"
