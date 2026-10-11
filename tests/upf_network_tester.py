from scapy.layers.inet import IP, Ether
from scapy.all import raw, ICMP, ARP, Raw
from socket import socket, AF_PACKET, SOCK_RAW

UPF_MAC = "bb:00:00:00:00:01"

ues = [
    {
        "mac": "aa:00:00:00:00:01",
        "ip": "192.168.7.1"
    }
]

macs_by_ip = {}

for ue in ues:
    macs_by_ip[ue["ip"]] = ue["mac"]


def handle_arp_packet(packet):
    if packet[ARP].op == 1:
        print("Someone is asking about " + packet.pdst)
        
        if packet.pdst in macs_by_ip:
            print("Sending ARP response for " + packet.pdst)
            reply = ARP(op=2, hwsrc=UPF_MAC, psrc=packet.pdst, hwdst=packet[ARP].hwsrc, pdst=packet[ARP].psrc)
            return Ether(dst=packet.src, src=UPF_MAC) / reply

    return None


def handle_ping(packet):
    ip_request = packet[IP]
    if ip_request.dst in macs_by_ip:
        print(f"Handle ping request from: {ip_request.src}")

        icmp_request = ip_request[ICMP]        
        # type = 0 code = 0 is the echo reply
        if icmp_request.haslayer(Raw):
            return Ether(dst=packet.src, src=UPF_MAC) / IP(src=ip_request.dst, dst=ip_request.src) /ICMP(type=0, code=0, id=icmp_request.id, seq=icmp_request.seq) / Raw(icmp_request[Raw].load)
        else:
            print("Echo w/o data")
            return Ether(dst=packet.src, src=UPF_MAC) / IP(src=ip_request.dst, dst=ip_request.src) /ICMP(type=0, code=0, id=icmp_request.id, seq=icmp_request.seq)
    else:
        print(f"Handle ping request to unknown IP: {ip_request.dst}")
    return None


dn = socket(AF_PACKET, SOCK_RAW, 0x0300) # 0x0300 = htons(ETH_P_ALL)
dn.bind(("upf_cn_veth", 0))
dn.settimeout(5.0)

handled_ping_requests = 0

while True:
    dnPacket = dn.recvfrom(2000)
    print("recevied from DN")
    eth = Ether(dnPacket[0])
    if eth.haslayer(ARP):
        # eth[ARP].show()
        resp = handle_arp_packet(eth)
        if resp is not None:
            dn.send(raw(resp))
    elif eth.haslayer(IP):
        ip = eth[IP]
        if ip.haslayer(ICMP):
            resp = handle_ping(eth)
            if resp is not None:
                handled_ping_requests += 1
                dn.send(raw(resp))
        else:
            print(f"Unsupported proto")
            eth.show()

    if handled_ping_requests >= 7:
        break

