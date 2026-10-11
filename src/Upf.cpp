#include "Upf.hpp"

#include <algorithm>
#include <cerrno>
#include <cstring>
#include <iomanip>
#include <chrono>
#include <iostream>
#include <optional>
#include <system_error>

#include <arpa/inet.h>
#include <linux/if_packet.h>
#include <net/if.h>
#include <net/if_arp.h>
#include <sys/ioctl.h>

#include "Utils.hpp"

namespace {

constexpr std::size_t BufferSize = 65536;
constexpr auto ArpEntryLifetime = std::chrono::seconds(60);
constexpr auto ArpTimerPeriod = std::chrono::seconds(1);     // how often the table is checked

// Builds an asio endpoint from sockaddr_ll: AF_PACKET, all EtherTypes, this interface
boost::asio::generic::raw_protocol::endpoint make_dn_endpoint(const std::string& interface) {
    unsigned int ifindex = if_nametoindex(interface.c_str());
    if (ifindex == 0) {
        throw std::system_error(errno, std::generic_category(), "if_nametoindex(" + interface + ")");
    }

    sockaddr_ll addr{};
    addr.sll_family = AF_PACKET;
    addr.sll_protocol = htons(ETH_P_ALL);
    addr.sll_ifindex = static_cast<int>(ifindex);

    return boost::asio::generic::raw_protocol::endpoint(&addr, sizeof(addr), htons(ETH_P_ALL));
}

std::array<uint8_t, ETH_ALEN> get_interface_mac(int fd, const std::string& interface) {
    ifreq interface_request{};
    std::strncpy(interface_request.ifr_name, interface.c_str(), IFNAMSIZ - 1);
    if (ioctl(fd, SIOCGIFHWADDR, &interface_request) < 0) {
        throw std::system_error(errno, std::generic_category(), "ioctl(SIOCGIFHWADDR, " + interface + ")");
    }
    std::array<uint8_t, ETH_ALEN> mac{};
    for (int i = 0; i < ETH_ALEN; ++i) {
        mac[i] = static_cast<uint8_t>(interface_request.ifr_hwaddr.sa_data[i]);
    }
    return mac;
}

ArpTable::Ipv4Address parse_ipv4(const std::string& text) {
    const auto bytes = boost::asio::ip::make_address_v4(text).to_bytes();
    return {bytes[0], bytes[1], bytes[2], bytes[3]};
}

}  // namespace

Upf::Upf(boost::asio::io_context& io,
         const std::string& dn_interface,
         const std::string& gtpu_ip,
         uint16_t gtpu_port,
         const std::string& gnb_ip,
         const std::string& upf_dn_ip,
         const std::string& dn_next_hop_ip)
    : dn_socket_(io, make_dn_endpoint(dn_interface)),
      dn_buffer_(BufferSize),
      upf_dn_ip_(parse_ipv4(upf_dn_ip)),
      dn_next_hop_ip_(parse_ipv4(dn_next_hop_ip)),
      arp_table_(ArpEntryLifetime),
      arp_timer_(io),
      gnb_socket_(io, boost::asio::ip::udp::endpoint(boost::asio::ip::make_address(gtpu_ip), gtpu_port)),
      gnb_buffer_(BufferSize),
      gnb_peer_(boost::asio::ip::make_address(gnb_ip), gtpu_port),
      ue_table_(4) {
    upf_mac_ = get_interface_mac(dn_socket_.native_handle(), dn_interface);
    //                                    get file descriptor
}

void Upf::start() {
    receive_from_dn();
    receive_from_gnb();
    on_arp_timer();        // ask for the MAC of the next hop right away
    schedule_arp_timer();  // then check the table once a second
}

// ======================= DN side =======================

void Upf::receive_from_dn() {
    // Returns immediately. The lambda is called later by io_context::run()
    // when a frame has arrived (or an error happened).
    dn_socket_.async_receive_from(
                // pair of data(), size(): to avoid
                // overloading for different containers      sender info from core
     boost::asio::buffer(dn_buffer_), dn_sender_,
            // asio remembers buffer to write into it later, when frame arrived, that's why it is a field, not local varitable
        [this](const boost::system::error_code& ec, std::size_t length) {
            if (ec == boost::asio::error::operation_aborted) {
                return;  // socket closed / program is stopping: do not re bid to queue
            }
            if (ec) {
                std::cerr << "receive from DN failed: " << ec.message() << '\n';
            } else {
                handle_dn_frame(length);
            }
            receive_from_dn();  // wait for the next frame
        });
}

void Upf::handle_dn_frame(std::size_t length) {
    // sockaddr_ll of the received frame lives inside dn_sender_
    sockaddr_ll src{};
    std::memcpy(&src, dn_sender_.data(), std::min(dn_sender_.size(), sizeof(src)));

    // our own outgoing frames (ARP replies, uplink) come back on a ETH_P_ALL socket: skip silently
    if (src.sll_pkttype == PACKET_OUTGOING) {
        return;
    }
    const uint8_t* frame = dn_buffer_.data();

    if (length < ETH_HLEN) {
        std::cout << "DL drop: frame too short (" << length << " B)" << std::endl;
        return;
    }

    // any frame from DN proves it is alive: extend its ARP entry
    ArpTable::MacAddress source_mac{};
    std::copy_n(frame + 6, ETH_ALEN, source_mac.begin());
    arp_table_.refresh_by_mac(source_mac, ArpTable::Clock::now());

    if (src.sll_pkttype != PACKET_HOST && src.sll_pkttype != PACKET_BROADCAST) {
        std::cout << "DL drop: frame not addressed to UPF (packet type "
                  << static_cast<int>(src.sll_pkttype) << ")" << std::endl;
        return;
    }

    const uint16_t ether_type = read16_big_endian(frame, 12);
    if (ether_type == ETH_P_ARP) {
        handle_dn_arp(frame, length);
    } else if (ether_type == ETH_P_IP) {
        handle_dn_ipv4(frame, length);
    } else {
        std::cout << "DL drop: unsupported EtherType 0x" << std::hex << std::setw(4) << std::setfill('0')
                  << ether_type << std::dec << std::setfill(' ') << std::endl;
    }
}

void Upf::handle_dn_arp(const uint8_t* frame, std::size_t length) {
    // Ethernet (14) + ARP for Ethernet/IPv4 (28)
    if (length < ArpFrameLength) {
        std::cout << "DL drop: ARP too short (" << length << " B)" << std::endl;
        return;
    }

    const uint16_t hardware_type = read16_big_endian(frame, 14);
    const uint16_t protocol_type = read16_big_endian(frame, 16);
    const uint8_t hardware_length = frame[18];
    const uint8_t protocol_length = frame[19];
    const uint16_t operation = read16_big_endian(frame, 20);

    if (hardware_type != ARPHRD_ETHER || protocol_type != ETH_P_IP ||
        hardware_length != ETH_ALEN || protocol_length != 4) {
        std::cout << "DL drop: ARP is not Ethernet/IPv4" << std::endl;
        return;
    }
    if (operation == ARPOP_REPLY) {
        handle_dn_arp_reply(frame);
        return;
    }
    if (operation != ARPOP_REQUEST) {
        std::cout << "DL drop: ARP operation " << operation << " is neither request nor reply" << std::endl;
        return;
    }

    const std::array<uint8_t, 4> target_ip{frame[38], frame[39], frame[40], frame[41]};
    const std::optional<Ue> ue = ue_table_.find_by_ip(target_ip);
    if (!ue) {
        std::cout << "DL drop: ARP request for " << ip_to_string(target_ip) << " is not for a UE" << std::endl;
        return;
    }

    // reply must outlive this function: async_send finishes later
    auto frame_reply = std::make_shared<std::vector<uint8_t>>(ArpFrameLength);
    fill_ethernet_reply(frame_reply->data(), frame + 6, upf_mac_.data(), ETH_P_ARP);
    fill_arp_reply_eth_ip(frame, frame_reply->data(), upf_mac_.data());
    send_to_dn(frame_reply);

    std::cout << "ARP: " << ip_to_string(target_ip) << " is-at UPF MAC (asked by "
              << ip_to_string({frame[28], frame[29], frame[30], frame[31]}) << ")" << std::endl;
}

void Upf::handle_dn_ipv4(const uint8_t* frame, std::size_t length) {
    const uint8_t* packet = frame + ETH_HLEN;
    const std::size_t available = length - ETH_HLEN;  // safe: length >= ETH_HLEN was checked

    // version, IHL and Total Length
    const std::optional<uint16_t> total_length = validate_ipv4(packet, available);
    if (!total_length) {
        std::cout << "DL drop: bad IPv4 packet (" << available << " B after Ethernet)" << std::endl;
        return;
    }

    const std::array<uint8_t, 4> destination_ip{packet[16], packet[17], packet[18], packet[19]};
    const std::optional<Ue> ue = ue_table_.find_by_ip(destination_ip);
    if (!ue) {
        std::cout << "DL drop: no UE with IP " << ip_to_string(destination_ip) << std::endl;
        return;
    }

    // GTP-U header + exact copy of the IP packet (dn_buffer_ will be overwritten by the next frame)
    auto datagram = std::make_shared<std::vector<uint8_t>>(GtpuHeaderLength + static_cast<std::size_t>(*total_length));
    fill_gtpu_header(datagram->data(), ue->teid_dl, *total_length);
    std::copy_n(packet, *total_length, datagram->data() + GtpuHeaderLength);

    send_to_gnb(datagram);

    const std::array<uint8_t, 4> source_ip{packet[12], packet[13], packet[14], packet[15]};
    std::cout << "DL: " << ip_to_string(source_ip) << " -> " << ip_to_string(destination_ip)
              << ", TEID " << ue->teid_dl << ", IP packet " << *total_length
              << " B, GTP-U datagram " << datagram->size() << " B -> gNB" << std::endl;
}

void Upf::send_to_dn(std::shared_ptr<std::vector<uint8_t>> frame) {
    // The lambda captures the shared_ptr, so the buffer lives until sending completes
    dn_socket_.async_send(
        boost::asio::buffer(*frame),
        // copy frame to lambda
        [frame](const boost::system::error_code& ec, std::size_t) {
            if (ec) {
                std::cerr << "send to DN failed: " << ec.message() << '\n';
            }
        });
}

// -------------------- ARP table ------------------------

void Upf::handle_dn_arp_reply(const uint8_t* frame) {
    // frame: valid Ethernet/IPv4 ARP with OPER = reply (checked by handle_dn_arp)
    const ArpTable::Ipv4Address sender_ip{frame[28], frame[29], frame[30], frame[31]};
    const ArpTable::Ipv4Address target_ip{frame[38], frame[39], frame[40], frame[41]};
    ArpTable::MacAddress sender_mac{};
    std::copy_n(frame + 22, ETH_ALEN, sender_mac.begin());

    // accept only an answer to our question about the next hop:
    // unsolicited replies for other IPs could harm the table
    if (sender_ip != dn_next_hop_ip_ || target_ip != upf_dn_ip_) {
        std::cout << "DL drop: unsolicited ARP reply " << ip_to_string(sender_ip)
                  << " is-at " << mac_to_string(sender_mac) << std::endl;
        return;
    }

    const auto now = ArpTable::Clock::now();
    const bool was_known = arp_table_.lookup(sender_ip, now).has_value();
    arp_table_.update(sender_ip, sender_mac, now);
    if (!was_known) {
        std::cout << "ARP: learned " << ip_to_string(sender_ip) << " is-at " << mac_to_string(sender_mac)
                  << " (valid " << std::chrono::duration_cast<std::chrono::seconds>(ArpEntryLifetime).count()
                  << " s, extended by its traffic)" << std::endl;
    }
}

void Upf::schedule_arp_timer() {
    // same pattern as the receive loops: arm -> handler -> arm again
    arp_timer_.expires_after(ArpTimerPeriod);
    arp_timer_.async_wait([this](const boost::system::error_code& ec) {
        if (ec == boost::asio::error::operation_aborted) {
            return;  // timer cancelled: program is stopping
        }
        on_arp_timer();
        schedule_arp_timer();
    });
}

void Upf::on_arp_timer() {
    const auto now = ArpTable::Clock::now();

    for (const ArpTable::Ipv4Address& ip : arp_table_.remove_expired(now)) {
        std::cout << "ARP: entry for " << ip_to_string(ip) << " expired (no frames for "
                  << std::chrono::duration_cast<std::chrono::seconds>(ArpEntryLifetime).count() << " s)" << std::endl;
    }

    // next hop unknown -> ask again. while there is no answer this repeats every second
    if (!arp_table_.lookup(dn_next_hop_ip_, now)) {
        send_arp_request(dn_next_hop_ip_);
    }
}

void Upf::send_arp_request(const ArpTable::Ipv4Address& target_ip) {
    auto frame = std::make_shared<std::vector<uint8_t>>(ArpFrameLength);
    fill_ethernet_reply(frame->data(), BroadcastMac.data(), upf_mac_.data(), ETH_P_ARP);
    fill_arp_request_eth_ip(frame->data(), upf_mac_.data(), upf_dn_ip_, target_ip);
    send_to_dn(frame);

    std::cout << "ARP: who-has " << ip_to_string(target_ip) << "? tell " << ip_to_string(upf_dn_ip_) << std::endl;
}

// ------------------------- gNB side -------------------------

void Upf::receive_from_gnb() {
    gnb_socket_.async_receive_from(
        // pair of data(), size(): to avoid
        // overloading for different containers      sender info from core
        boost::asio::buffer(gnb_buffer_), gnb_sender_,
        [this](const boost::system::error_code& ec, std::size_t length) {
            if (ec == boost::asio::error::operation_aborted) {
                return;
            }
            if (ec) {
                std::cerr << "receive from gNB failed: " << ec.message() << '\n';
            } else {
                handle_gnb_datagram(length);
            }
            receive_from_gnb();
        });
}

void Upf::handle_gnb_datagram(std::size_t length) {
    // gnb_buffer_ holds the UDP payload: GTP-U header + inner packet.
    // UDP, outer IP and Ethernet have already been removed by the kernel
    const uint8_t* datagram = gnb_buffer_.data();

    // ---------- GTP-U header ----------
    if (length < GtpuHeaderLength) {
        std::cout << "UL drop: datagram too short (" << length << " B)" << std::endl;
        return;
    }

    const uint8_t flags = datagram[0];
    const uint8_t version = flags >> 5;
    const uint8_t pt_flag = (flags >> 4) & 1;
    const uint8_t message_type = datagram[1];
    const uint16_t gtpu_length = read16_big_endian(datagram, 2);  // bytes after the first 8
    const uint32_t teid = read32_big_endian(datagram, 4);

    if (version != 1) {
        std::cout << "UL drop: bad GTP-U version " << static_cast<int>(version) << std::endl;
        return;
    }
    if (pt_flag != 1) {
        std::cout << "UL drop: PT is not GTP" << std::endl;
        return;
    }
    if (message_type != GtpuMsgGpdu) {
        std::cout << "UL drop: message type " << static_cast<int>(message_type) << " is not G-PDU" << std::endl;
        return;
    }
    if (GtpuHeaderLength + static_cast<std::size_t>(gtpu_length) != length) {
        std::cout << "UL drop: length mismatch (GTP-U Length " << gtpu_length
                  << ", datagram " << length << " B)" << std::endl;
        return;
    }

    // E, S or PN set -> 4 more bytes (sequence number, N-PDU number, next extension type)
    std::size_t header_length = GtpuHeaderLength;
    if ((flags & GtpuFlagsOptionalMask) != 0) {
        header_length += GtpuOptionalFieldsLength;
        if (length < header_length) {
            std::cout << "UL drop: too short for optional fields" << std::endl;
            return;
        }
    }
    if ((flags & GtpuFlagE) != 0) {
        // extension header chain is not supported
        std::cout << "UL drop: extension headers not supported" << std::endl;
        return;
    }

    // ---------- tunnel -> UE ----------
    const std::optional<Ue> ue = ue_table_.find_by_teid_ul(teid);
    if (!ue) {
        std::cout << "UL drop: unknown TEID " << teid << std::endl;
        return;
    }

    // ---------- inner IPv4 ----------
    const uint8_t* inner = datagram + header_length;
    const std::size_t inner_available = length - header_length;

    const std::optional<uint16_t> total_length = validate_ipv4(inner, inner_available);
    if (!total_length) {
        std::cout << "UL drop: bad inner IPv4 packet (TEID " << teid << ")" << std::endl;
        return;
    }

    // ---------- anti-spoofing: source must be the UE that owns this TEID ----------
    const std::array<uint8_t, 4> source_ip{inner[12], inner[13], inner[14], inner[15]};
    if (source_ip != ue->ip) {
        std::cout << "UL drop: spoofed source " << ip_to_string(source_ip)
                  << " on TEID " << teid << " (expected " << ip_to_string(ue->ip) << ")" << std::endl;
        return;
    }

    // ---------- Ethernet frame towards DN ----------
    // Destination MAC: the next hop from the ARP table. broadcast while it is still unknown
    const std::optional<ArpTable::MacAddress> next_hop_mac = arp_table_.lookup(dn_next_hop_ip_, ArpTable::Clock::now());
    const ArpTable::MacAddress destination_mac = next_hop_mac ? *next_hop_mac : BroadcastMac;

    auto frame = std::make_shared<std::vector<uint8_t>>(ETH_HLEN + static_cast<std::size_t>(*total_length));
    fill_ethernet_reply(frame->data(), destination_mac.data(), upf_mac_.data(), ETH_P_IP);
    std::copy_n(inner, *total_length, frame->data() + ETH_HLEN);

    send_to_dn(frame);

    const std::array<uint8_t, 4> destination_ip{inner[16], inner[17], inner[18], inner[19]};
    std::cout << "UL: TEID " << teid << ", " << ip_to_string(source_ip) << " -> " << ip_to_string(destination_ip)
              << ", IP packet " << *total_length << " B -> DN "
              << (next_hop_mac ? mac_to_string(*next_hop_mac) : std::string("(broadcast, next hop MAC unknown)"))
              << std::endl;
}

void Upf::send_to_gnb(std::shared_ptr<std::vector<uint8_t>> datagram) {
    // datagram = GTP-U header + inner IP packet. the kernel adds UDP, IP and Ethernet.
    // The lambda keeps the buffer alive until send completes.
    gnb_socket_.async_send_to(
        boost::asio::buffer(*datagram), gnb_peer_,
        [datagram](const boost::system::error_code& ec, std::size_t /*sent*/) {
            if (ec) {
                std::cerr << "send to gNB failed: " << ec.message() << '\n';
            }
        });
}
