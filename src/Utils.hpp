#pragma once

#include <algorithm>
#include <array>
#include <cstdint>
#include <memory>
#include <optional>
#include <string>
#include <vector>
#include <linux/if_ether.h>
#include <net/if_arp.h>

// ---------------- GTP-U ----------------
constexpr uint8_t GtpuFlagsV1Pt = 0x30;              // version 1, PT = 1, no optional fields
constexpr uint8_t GtpuMsgGpdu = 0xFF;                // G-PDU: user data
constexpr std::size_t GtpuHeaderLength = 8;          // mandatory part of the header
constexpr uint8_t GtpuFlagsOptionalMask = 0x07;      // E | S | PN
constexpr uint8_t GtpuFlagE = 0x04;                  // extension headers present
constexpr std::size_t GtpuOptionalFieldsLength = 4;  // seq number (2) + N-PDU (1) + next ext type (1)

// ---------------- IPv4 / Ethernet ----------------
constexpr std::size_t Ipv4MinHeaderLength = 20;
constexpr std::size_t ArpFrameLength = 42;           // Ethernet (14) + ARP for Ethernet/IPv4 (28)
constexpr std::array<uint8_t, ETH_ALEN> BroadcastMac{0xff, 0xff, 0xff, 0xff, 0xff, 0xff};

inline uint16_t read16_big_endian(const uint8_t *frame, std::size_t i) {
    return frame[i] << 8 | frame[i + 1];
}

inline uint32_t read32_big_endian(const uint8_t *frame, std::size_t i) {
    return static_cast<uint32_t>(frame[i]) << 24 |
           static_cast<uint32_t>(frame[i + 1]) << 16 |
           static_cast<uint32_t>(frame[i + 2]) << 8 |
           static_cast<uint32_t>(frame[i + 3]);
}

inline void write16_big_endian(uint8_t *frame, std::size_t i, uint16_t value) {
    frame[i] = static_cast<uint8_t>(value >> 8);
    frame[i + 1] = static_cast<uint8_t>(value & 0xff);
}

inline void write32_big_endian(uint8_t *frame, std::size_t i, uint32_t value) {
    frame[i] = static_cast<uint8_t>(value >> 24);
    frame[i + 1] = static_cast<uint8_t>(value >> 16);
    frame[i + 2] = static_cast<uint8_t>(value >> 8);
    frame[i + 3] = static_cast<uint8_t>(value & 0xff);
}

inline std::string ip_to_string(const std::array<uint8_t, 4> &ip) {
    return std::to_string(ip[0]) + "." + std::to_string(ip[1]) + "." +
           std::to_string(ip[2]) + "." + std::to_string(ip[3]);
}

inline std::optional<uint16_t> validate_ipv4(const uint8_t *packet, std::size_t available) {
    if (available < Ipv4MinHeaderLength) {
        return std::nullopt;
    }
    const uint8_t version = packet[0] >> 4;
    const std::size_t header_length = static_cast<std::size_t>(packet[0] & 0x0F) * 4;  // IHL * 4
    const uint16_t total_length = read16_big_endian(packet, 2);

    if (version != 4 ||
        header_length < Ipv4MinHeaderLength ||
        total_length < header_length ||
        total_length > available) {
        return std::nullopt;
    }
    return total_length;
}

inline std::string mac_to_string(const std::array<uint8_t, ETH_ALEN> &mac) {
    static const char hex[] = "0123456789abcdef";
    std::string out;
    for (std::size_t i = 0; i < mac.size(); ++i) {
        if (i != 0) {
            out += ':';
        }
        out += hex[mac[i] >> 4];
        out += hex[mac[i] & 0x0F];
    }
    return out;
}

inline void fill_arp_request_eth_ip(uint8_t *frame, const uint8_t *sender_mac,
                                    const std::array<uint8_t, 4> &sender_ip,
                                    const std::array<uint8_t, 4> &target_ip) {
    write16_big_endian(frame, 14, ARPHRD_ETHER); // HTYPE
    write16_big_endian(frame, 16, ETH_P_IP); // PTYPE
    frame[18] = ETH_ALEN; // HLEN
    frame[19] = 4; // PLEN
    write16_big_endian(frame, 20, ARPOP_REQUEST); // OPER
    std::copy_n(sender_mac, ETH_ALEN, frame + 22); // SHA
    std::copy_n(sender_ip.begin(), 4, frame + 28); // SPA
    std::fill_n(frame + 32, ETH_ALEN, 0); // THA: unknown, that is what we ask for
    std::copy_n(target_ip.begin(), 4, frame + 38); // TPA
}

// frame - have at least 42 bytes, it is valid arp request ether/ip4. Frame_reply have at least 42 bytes
inline void fill_arp_reply_eth_ip(const uint8_t *frame, uint8_t *frame_reply, const uint8_t *upf_mac) {
    write16_big_endian(frame_reply, 14, ARPHRD_ETHER); // HTYPE
    write16_big_endian(frame_reply, 16, ETH_P_IP); // PTYPE
    frame_reply[18] = ETH_ALEN; // HLEN
    frame_reply[19] = 4; // PLEN
    write16_big_endian(frame_reply, 20, ARPOP_REPLY); // OPER
    std::copy_n(upf_mac, ETH_ALEN, frame_reply + 22); // SHA
    std::copy_n(frame + 38, 4, frame_reply + 28); // SPA  <- TPA of the request (IP of UE)
    std::copy_n(frame + 22, ETH_ALEN, frame_reply + 32); // THA  <- SHA of the request (MAC of DN)
    std::copy_n(frame + 28, 4, frame_reply + 38); // TPA  <- SPA of the request (IP of DN)
}

inline void fill_ethernet_reply(uint8_t *frame_reply, const uint8_t *receiver_mac, const uint8_t *sender_mac, uint16_t eth_type) {
    std::copy_n(receiver_mac, ETH_ALEN, frame_reply);
    std::copy_n(sender_mac, ETH_ALEN, frame_reply + 6);
    write16_big_endian(frame_reply, 12, eth_type);
}

// datagram has at least GtpuHeaderLength bytes
inline void fill_gtpu_header(uint8_t *datagram, uint32_t teid, uint16_t internal_pkt_length) {
    datagram[0] = GtpuFlagsV1Pt;
    datagram[1] = GtpuMsgGpdu;
    write16_big_endian(datagram, 2, internal_pkt_length);
    write32_big_endian(datagram, 4, teid);
}
