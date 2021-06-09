# Cross-Protocol Testlab

Currenty only the attacks on vsftp works in the lab as the provided email servers in the docker images are the latest version and alpaca is already fixed there.
We are currently working on adding the old server versions to the repository.

All code provided is experimental and may harm your system. Please use a fresh ubuntu maschine.

## Setup

**1. PLEASE USE A FRESH UBUNTU!**

2. Install docker as described on https://docs.docker.com/engine/install/ubuntu/

3. Install python3 and docker-compose
```
apt-get install python3 python3-pip
pip3 install docker-compose
```

4. Run ```./setup.sh```
```
chmod +x setup.sh
./setup.sh
```

5. Add ./pki/ca.crt to your Firefox trusted CAs

The setup is now completed and can be used.

Important: If you reboot after the setup, you have to manually add a second IP to loopback:
```
ip addr add 172.0.0.2/8 dev lo
```
## FTPS

Make sure, that:
 1. you have installed the CA-Certificate as described above into your firefox!

 2. your loopback interface has a second IP-Address (127.0.0.2/8)!


Start the docker services
```
docker-compose -f servers/docker-compose.yml up -d nginx-target nginx-attacker vsftp
```
Run the MitM-Proxy
```
cd mitmproxy
python3 main.py --proto FTP --attacker_ip 127.0.0.2 127.0.0.1 21
```

The Proxy is now running in unarmed mode. You can open Firefox and visit https://target.com. 
The server on target.com will set a cookie with the displayed session ID.

After that, switch the proxy to armed mode by pressing any key in the console window. 

Open a second console window and execute ```scripts/show_vsftp_log.sh``` to display the ftp log.

Navigate in Firefox to https://attacker.com.
Here you can choose between two attacks (Upload und Download)

1. Download

If you click on download, you will see a white page for aprox. 5 seconds, then the browser redirects to target.com and show an alert box.

2. Upload

If you click on Upload, the browser will navigate to the attack page and than, after 5 seconds redirect to target.com.
In the second console windows with the logs you can now also see the uploaded GET request of the browser including the cookie.
 
