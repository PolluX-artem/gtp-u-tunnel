from scapy.contrib.gtp import GTP_U_Header as GTPHeader
from scapy.all import raw, IP, Raw, Ether, ARP
import socket
import asyncio
import logging
import sys
import time


logging.basicConfig(
    stream=sys.stdout,
    format='FakeUpf: %(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)


NEXT_HOP_IP = "192.168.5.1" # We have no router, just DN connected directly. So, DN simulator IP = Next Hop in this case
GNB_IP = "192.168.9.2"
UPF_IP = "192.168.5.2"
UPF_MAC = "bb:00:00:00:00:01"
BCAST_MAC = "ff:ff:ff:ff:ff:ff" # Broadcast MAC address
htons_ETH_P_ALL = 0x0300 # htons(ETH_P_ALL)


class ArpTableEntry:
    LIFETIME_S = 60

    def __init__(self, mac, ip):
        self.mac = mac
        self.ip = ip
        self.used()

    def expired(self):
        return self.expireAt <= time.monotonic()

    def used(self):
        self.expireAt = time.monotonic() + self.LIFETIME_S


class ArpTable:
    def __init__(self):
        self._by_ip = {}
        self._by_mac = {}
        self._not_found = set({})

    def getMac(self, ip, default=None):
        entry = self._by_ip.get(ip)
        if entry is not None:
            if not entry.expired():
                return entry.mac
            else:
                logging.info(f"Expired ARP table entry: {entry.mac} {entry.ip}")
                self._not_found.add(ip)

        logging.info(f"Arp table has no: {ip}")
        self._not_found.add(ip)
        return default

    def getNotFoundIps(self):
        return self._not_found

    def macIsUsed(self, mac):
        entry = self._by_mac.get(mac)
        if entry is not None:
            entry.used()

    def create(self, mac, ip):
        entry = ArpTableEntry(mac, ip)
        self._by_ip[ip] = entry
        self._by_mac[mac] = entry
        if ip in self._not_found:
            self._not_found.remove(ip)


class GTPUCodec:
    gtp_version = 1
    gtp_type = 0xff  # T-PDU

    def encodeTpdu(self, gtp_teid, payload):
        return raw(GTPHeader(gtp_type=self.gtp_type, teid=gtp_teid) / Raw(load=payload))

    def parseTpdu(self, packet):
        gtp = GTPHeader(packet)
        assert gtp.haslayer(IP)
        return gtp.teid, gtp[IP]


class Ue:
    def __init__(self, ip, teid_dl, teid_ul):
        self.ip = ip
        self.teid_dl = teid_dl
        self.teid_ul = teid_ul


class UeStorage:
    def __init__(self):
        self.ues_by_teid = {}
        self.ues_by_ip = {}

        for i in range(1, 5):
            ue = Ue(f"192.168.7.{i}", teid_dl=i*2, teid_ul=i*2+1)
            logging.info(f"Created UE {ue.ip} TEID_dl={ue.teid_dl} TEID_ul={ue.teid_ul}")
            self.ues_by_teid[ue.teid_ul] = ue
            self.ues_by_ip[ue.ip] = ue


class ArpHandler:
    REQUEST_TIMEOUT_S = 5

    def __init__(self, ueStorage, arpTable, dnSock):
        self.ueStorage = ueStorage
        self.dnSock = dnSock
        self.arpTable = arpTable
        self._pendingRequests = {}
        self._updateLoop = asyncio.ensure_future(self._run())

    async def _run(self):
        while True:
            await asyncio.sleep(1) # Update interval
            self._tick()

    def _tick(self):
        for ip in self.arpTable.getNotFoundIps():
            pending = self._pendingRequests.get(ip)

            if pending and time.monotonic() >= pending:
                logging.info(f"ARP request timeout for: {ip}")
                pending = None

            # If has no pending request for such ip or request timeout is expired
            if pending is None:
                logging.info(f"ARP request for: {ip}")
                self.dnSock.send(raw(Ether(dst=BCAST_MAC, src=UPF_MAC) / ARP(op=1, hwsrc=UPF_MAC, psrc=UPF_IP, hwdst=BCAST_MAC, pdst=ip)))
                self._pendingRequests[ip] = time.monotonic() + self.REQUEST_TIMEOUT_S

    def stop(self):
        self._updateLoop.cancel()

    def onPacketFromDn(self, ethPacket):
        self.arpTable.macIsUsed(ethPacket.src)

    def handleArp(self, packet):
        if packet[ARP].op == 1:
            logging.info("Someone is asking about " + packet.pdst)

            if packet.pdst in self.ueStorage.ues_by_ip:
                logging.info("Sending ARP response for " + packet.pdst)
                reply = ARP(op=2, hwsrc=UPF_MAC, psrc=packet.pdst, hwdst=packet[ARP].hwsrc, pdst=packet[ARP].psrc)
                self.dnSock.send(raw(Ether(dst=packet.src, src=UPF_MAC) / reply))
            else:
                logging.error(f"ARP: Unknown IP {packet.pdst}")

        elif packet[ARP].op == 2:
            logging.info(f"ARP answer received for: {packet.psrc}")
            self.arpTable.create(packet[ARP].hwsrc, packet.psrc)
            self._pendingRequests.pop(packet.psrc)


class GTPUService:
    def __init__(self, ueStorage, arpTable, gtpuCodec, dnSock):
        self.ueStorage = ueStorage
        self.dnSock = dnSock
        self.arpTable = arpTable
        self.gtpuCodec = gtpuCodec

    def connection_made(self, transport):
        self.transport = transport

    def connection_lost(self, _):
        self.transport = None

    def datagram_received(self, message, addr):
        logging.info(f"Received GTP-U message from {addr}")
        teid, payload = self.gtpuCodec.parseTpdu(message)

        ue = self.ueStorage.ues_by_teid.get(teid)
        if ue is None:
            logging.error(f"Can't find UE for TEID: {teid}")
            return

        self.dnSock.send(raw(Ether(src=UPF_MAC, dst=self.arpTable.getMac(NEXT_HOP_IP, BCAST_MAC)) / payload))


async def main():
    loop = asyncio.get_running_loop()

    dn = socket.socket(socket.AF_PACKET, socket.SOCK_RAW, htons_ETH_P_ALL)
    dn.bind(("upf_cn_veth", 0))
    dn.setblocking(False)

    ueStorage = UeStorage()

    arpTable = ArpTable()
    arp = ArpHandler(ueStorage, arpTable, dn)

    gtpuCodec = GTPUCodec()

    transport, protocol = await loop.create_datagram_endpoint(
        lambda: GTPUService(ueStorage, arpTable, gtpuCodec, dn),
        local_addr=('192.168.9.1', 2152)
    )
    try:
        while True:
            dnPacket = await loop.sock_recv(dn, 1024)
            ethPkt = Ether(dnPacket)
            arp.onPacketFromDn(ethPkt)

            if ethPkt.haslayer(ARP):
                arp.handleArp(ethPkt)
            elif ethPkt.haslayer(IP):
                ipPkt = ethPkt[IP]
                ue = ueStorage.ues_by_ip.get(ipPkt.dst)
                if ue:
                    transport.sendto(gtpuCodec.encodeTpdu(ue.teid_dl, raw(ipPkt)), (GNB_IP, 2152))
    finally:
        arp.stop()
        transport.close()
        dn.close()


asyncio.run(main())
