#!/usr/bin/python3
import argparse

from proxy.socket.mitmsocket import MITMSocketProxy
from utils.logging import init_logging, _info

parser = argparse.ArgumentParser(prog='MITMProxy')
parser.add_argument('target_ip', help='Target IP')
parser.add_argument('target_port', type=int, help='Target PORT')
parser.add_argument('--attacker_ip', help='Attacker IP', required=False)
parser.add_argument('--attacker_port', type=int, help='Attacker Port', required=False)
parser.add_argument('--log_level', choices=['DEBUG', 'INFO'], help='Log Level', required=False)
parser.add_argument('--protocol', choices=['FTP', 'POP3', 'POP3S', 'IMAP', 'IMAPS', 'SMTP'], help='Protocol', required=False)

parser.set_defaults(attacker_ip="127.0.0.2", attacker_port=443, log_level='INFO', protocol='FTP')
args = parser.parse_args()
init_logging(args.log_level)

_info("main",
      f"Starting socket proxy redirecting from {args.attacker_ip}:{args.attacker_port} to {args.target_ip}:{args.target_port} for protocol {args.protocol}")

proxy = MITMSocketProxy(args.attacker_ip, args.attacker_port, args.target_ip, args.target_port, args.protocol)
proxy.run()
