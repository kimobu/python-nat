import subprocess, json, random, threading, argparse, time, sys, sqlite3, socket, netifaces, time
from scapy.all import *
from datetime import datetime

parser = argparse.ArgumentParser(description="Scapy based NAT")
parser.add_argument('--interior', '-i', dest="interior", default="ens34", help="The interior interface.")
parser.add_argument('--exterior', '-e', dest="exterior", default="ens33", help="The exterior interface.")
args = parser.parse_args()

def init_database():
    """ In-memory sqlite3 database to track NAT entries.
        source_ip: text field with IP address of internal host
        dest_ip: text field with IP address of external host
        source_port: int field with source port of internal host
        nat_port: int field with randint() port created by NAT device
                  overloaded for ICMP packets - ICMP sequence number
        protocol: text field of [icmp, tcp, udp]
        time: int field of timestamp when packet was translated
    """
    db = sqlite3.connect(':memory:')
    cur = db.cursor()
    cur.execute('CREATE TABLE nat_entries (source_ip text, dest_ip text, source_port int, nat_port int, protocol text, time int)')
    db.commit()
    return db

def process_external_packet(packet):
    """ Un-NAT packets received from the internal interface """
    if packet.getlayer(Ether).src in [args.exterior, args.interior]:
        return
    if packet.haslayer(IP):
        source_ip = packet.getlayer(IP).src
        dest_ip = packet.getlayer(IP).dst
        if packet.haslayer(UDP):
            protocol = "udp"
            source_port = packet.getlayer(UDP).sport
            dest_port = packet.getlayer(UDP).dport
            del packet.getlayer(UDP).chksum
        elif packet.haslayer(TCP):
            protocol = "tcp"
            source_port = packet.getlayer(TCP).sport
            dest_port = packet.getlayer(TCP).dport
            del packet.getlayer(TCP).chksum
        elif packet.haslayer(ICMP):
            if not packet.getlayer(ICMP).type == 0:
                return
            protocol = "icmp"
            source_port = packet.getlayer(ICMP).type
            dest_port = packet.getlayer(ICMP).seq
        else:
            return
        
        """
        Check for a NAT entry. If we have a NAT entry, we un-NAT. Otherwise, do nothing.
        """
        cur = db.cursor()
        cur.execute('SELECT * FROM nat_entries WHERE protocol = ? AND nat_port = ? ORDER BY time DESC', (protocol, dest_port))
        nat_entry = cur.fetchone()
        if nat_entry != None:
            orig_ip = nat_entry[0]
            orig_port = nat_entry[2]
            packet.getlayer(IP).dst = orig_ip
            if protocol == "tcp":
                packet.getlayer(TCP).dport = orig_port
            elif protocol == "udp":
                packet.getlayer(UDP).dport = orig_port
            del packet.getlayer(IP).chksum
            send(packet.getlayer(IP), iface=args.interior, verbose=0)
            print("<{0} {1}:{2} -> {3}:{4} == {5}:{6} -> {7}:{8}".format(protocol, source_ip, source_port, dest_ip, dest_port, source_ip, source_port, orig_ip, orig_port ))
        else:
            pass

def process_internal_packet(packet):
    """ NAT packets received from the internal interface """
    if packet.getlayer(Ether).src in [args.exterior, args.interior]:
        # Ignore packets that this device has generated
        return
    if packet.haslayer(IP):
        if packet.getlayer(IP).src == NAT_IP or packet.getlayer(IP).dst == NAT_IP or packet.getlayer(IP).src == packet.getlayer(IP).dst:
            # Ignore packets that should be external facing
            return
        source_ip = packet.getlayer(IP).src
        dest_ip = packet.getlayer(IP).dst
        packet.getlayer(IP).src = NAT_IP
        if packet.haslayer(TCP):
            source_port = packet.getlayer(TCP).sport
            dest_port = packet.getlayer(TCP).dport
            protocol = "tcp"
            """ We want to re-use NAT ports for TCP so that streams are not broken.
                If a NAT entry exists for this (protocol, dest_ip, source_port) and it's relatively recent (60 seconds), re-use it.
                Otherwise, we'll make a new one.
            """
            cur = db.cursor()
            cur.execute('SELECT * FROM nat_entries WHERE protocol = ? AND dest_ip = ? AND source_port = ? ORDER BY time DESC', (protocol, dest_ip, source_port))
            nat_entry = cur.fetchone()
            if nat_entry:
                timenow = time.mktime(datetime.now().timetuple())
                if timenow - nat_entry[5] < 60:
                    nat_port = nat_entry[3]
                else:
                    nat_port = random.randint(LOW_PORT, HIGH_PORT)
                if packet.getlayer(IP).src == nat_entry[1] and packet.getlayer(IP).dst == nat_entry[0]:
                    return
            else:
                nat_port = random.randint(LOW_PORT, HIGH_PORT)
            packet.getlayer(TCP).sport = nat_port
            del packet.getlayer(TCP).chksum
        elif packet.haslayer(UDP):
            source_port = packet.getlayer(UDP).sport
            dest_port = packet.getlayer(UDP).dport
            protocol = "udp"
            nat_port = random.randint(LOW_PORT, HIGH_PORT)
            packet.getlayer(UDP).sport = nat_port
            del packet.getlayer(UDP).chksum
        elif packet.haslayer(ICMP):
            source_port = packet.getlayer(ICMP).type
            dest_port = packet.getlayer(ICMP).seq
            nat_port = packet.getlayer(ICMP).seq
            protocol = "icmp"

        if packet.getlayer(Ether).src == INT_MAC and packet.getlayer(IP).src == NAT_IP:
            # stop scapy from retransmitting packets it just sent out
            return
        del packet.getlayer(IP).chksum
        send(packet.getlayer(IP), iface=args.exterior, verbose=0)

        """ Now save the NAT action for later """
        cur = db.cursor()
        timestamp = time.mktime(datetime.now().timetuple())
        cur.execute("INSERT INTO nat_entries VALUES (?, ?, ?, ?, ?, ?)", (source_ip, dest_ip, source_port, nat_port, protocol, timestamp))
        db.commit()
        print(">{0} {1}:{2} -> {3}:{4} == {5}:{6} -> {7}:{8}".format(protocol, source_ip, source_port, dest_ip, dest_port, NAT_IP, nat_port, dest_ip, dest_port ))

def packet_callback(packet):
    db = sqlite3.connect(':memory:')
    if packet.sniffed_on == args.exterior:
        process_external_packet(packet)
    else:
        process_internal_packet(packet)

def exterior_callback(packet):
    pass

if __name__ == '__main__':
    """
    Initialize globals
    """
    global NAT_IP
    global LOW_PORT
    global HIGH_PORT
    global EXT_MAC
    global INT_MAC
    NAT_IP = netifaces.ifaddresses(args.exterior)[netifaces.AF_INET][0]['addr']
    with open('/proc/sys/net/ipv4/ip_local_port_range') as f:
        ports = f.read().split('\t')
    LOW_PORT = int(ports[0])
    HIGH_PORT = int(ports[1])
    EXT_MAC = netifaces.ifaddresses(args.exterior)[netifaces.AF_LINK][0]['addr']
    INT_MAC = netifaces.ifaddresses(args.interior)[netifaces.AF_LINK][0]['addr']

    print("[+] Initializing database")
    db = init_database()

    print("[+] Starting sniffer")    
    sniff(iface=[args.interior, args.exterior], prn=packet_callback, store=0)
