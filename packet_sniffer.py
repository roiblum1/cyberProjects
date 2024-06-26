#!/usr/bin/python3
import scapy.all as scapy
from scapy.layers import http
import argparse
import re


def sniff(interface):
    scapy.sniff(iface=interface, store=False, prn=process_sniffed_packet, filter="tcp port 80 or tcp port 443")


def geturl(packet):
    return packet[http.HTTPRequest].Host + packet[http.HTTPRequest].Path


def get_login_info(packet):
    if packet.haslayer(scapy.Raw):
        load = packet[scapy.Raw].load.decode(errors='ignore')
        keywords = [
            'login', 'LOGIN', 'user', 'username', 'USER', 'USERNAME',
            'pass', 'password', 'PASS', 'PASSWORD', 'Login', 'User',
            'Pass', 'Password', 'uname', 'pwd', 'id', 'credential',
            'credentials', 'email', 'Email', 'EMAIL', 'auth', 'Auth',
            'AUTH', 'authentication', 'Authentication', 'AUTHENTICATION'
        ]
        pattern = '|'.join(keywords)
        match = re.search(pattern, load, re.IGNORECASE)
        if match:
            return match.group()


def process_sniffed_packet(packet):
    if packet.haslayer(http.HTTPRequest):
        url = geturl(packet)
        print("[+] HTTPRequest > " + url.decode())

        login_info = get_login_info(packet)
        if login_info:
            print("\n\n[+] Possible username and password: " + login_info + "\n\n")


def main():
    parser = argparse.ArgumentParser(
        description="A simple packet sniffer script to capture HTTP requests and possible login information.",
        epilog="Example usage: python3 packet_sniffer.py -i eth0"
    )
    parser.add_argument("-i", "--interface", dest="interface", help="Specify the interface to capture packets")
    options = parser.parse_args()

    if not options.interface:
        parser.error("[-] Please specify an interface to capture packets. Use the --help flag for more details.")

    sniff(options.interface)


if __name__ == '__main__':
    main()
