from scapy.contrib.gtp import GTP_U_Header as GTPHeader
from scapy.all import raw, IP, ICMP, Raw
import asyncio
import logging
import sys


logging.basicConfig(
    stream=sys.stdout,
    format='FakeUe: %(asctime)s - %(levelname)s - %(message)s',
    level=logging.INFO
)


def is_checksum_valid(pkt: IP | ICMP):
    # Workaround to calculate "real" checksum
    pktCopy = pkt.copy()
    del pktCopy.chksum
    pktCopy = pkt.__class__(pktCopy.build())
    if pkt.chksum != pktCopy.chksum:
        logging.error(f"Packet has invalid checksum expected({pktCopy.chksum}) != got({pkt.chksum})\n{pkt.show(dump=True)}")
        return False
    return True


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

    def handleIcmp(self, packet, gtpuSender):
        ip_request = packet[IP]
        if ip_request.dst in self.ip:
            logging.info(f"Handle ping request from: {ip_request.src} on {self.ip}")

            icmp_request = ip_request[ICMP]

            # type = 0 code = 0 is the echo reply
            if icmp_request.haslayer(Raw):
                gtpuSender.send(self.teid_ul, raw(IP(src=ip_request.dst, dst=ip_request.src) / ICMP(type=0, code=0, id=icmp_request.id, seq=icmp_request.seq) / Raw(icmp_request[Raw].load)))
            else:
                gtpuSender.send(self.teid_ul, raw(IP(src=ip_request.dst, dst=ip_request.src) / ICMP(type=0, code=0, id=icmp_request.id, seq=icmp_request.seq)))
        else:
            logging.error(f"Destination is unknown: {ip_request.dst}. Expected: {self.ip}")

    def handleIpPacket(self, packet: IP, gtpuSender):
        if packet.haslayer(ICMP):
            if not is_checksum_valid(packet[ICMP]):
                return

            self.handleIcmp(packet, gtpuSender)
        else:
            logging.warning(f"Unsupported packet received for {self.ip}:\n{packet.show(dump=True)}")



class GTPUSender:
    def __init__(self, transport, upfIp, codec):
        self.transport = transport
        self.upfIp = upfIp # IP+port
        self.codec = codec

    def send(self, teid_ul, packet):
        self.transport.sendto(self.codec.encodeTpdu(teid_ul, packet), self.upfIp)
        logging.info(f"Send to {self.upfIp}")


class GTPUServiceGnb:
    def connection_made(self, transport):
        self.transport = transport
        self.ues = {}
        self.codec = GTPUCodec()

        for i in range(1, 5):
            ue = Ue(f"192.168.7.{i}", teid_dl=i*2, teid_ul=i*2+1)
            logging.info(f"Created UE {ue.ip} TEID_dl={ue.teid_dl} TEID_ul={ue.teid_ul}")
            self.ues[ue.teid_dl] = ue

    def connection_lost(self, _):
        self.transport = None

    def datagram_received(self, message, addr):
        logging.info(f"Received GTP-U message from {addr}")
        teid, payload = self.codec.parseTpdu(message)

        if not is_checksum_valid(payload):
            return

        ue = self.ues.get(teid)
        if ue is None:
            logging.error(f"Can't find UE for TEID: {teid}")
            return

        ue.handleIpPacket(payload, GTPUSender(self.transport, addr, self.codec))


async def main():
    logging.info("Fake ue started")
    loop = asyncio.get_running_loop()
    transport, protocol = await loop.create_datagram_endpoint(
        lambda: GTPUServiceGnb(),
        local_addr=('192.168.9.2', 2152)
    )
    try:
        await asyncio.sleep(3600)
    finally:
        transport.close()


asyncio.run(main())
