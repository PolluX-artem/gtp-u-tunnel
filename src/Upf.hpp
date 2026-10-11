#pragma once

#include <array>
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#include <boost/asio.hpp>
#include <linux/if_ether.h>

#include "ArpTable.hpp"
#include "UeTable.hpp"

class Upf {
public:
    Upf(boost::asio::io_context& io,
        const std::string& dn_interface,
        const std::string& gtpu_ip,
        uint16_t gtpu_port,
        const std::string& gnb_ip,
        const std::string& upf_dn_ip,
        const std::string& dn_next_hop_ip);

    void start();

private:
    using RawProtocol = boost::asio::generic::raw_protocol;

    // ---- DN side ----
    void receive_from_dn();
    void handle_dn_frame(std::size_t length);
    void handle_dn_arp(const uint8_t* frame, std::size_t length);
    void handle_dn_ipv4(const uint8_t* frame, std::size_t length);
    void send_to_dn(std::shared_ptr<std::vector<uint8_t>> frame);

    // ---- ARP table for the DN next hop ----
    void handle_dn_arp_reply(const uint8_t* frame);
    void schedule_arp_timer();
    void on_arp_timer();
    void send_arp_request(const ArpTable::Ipv4Address& target_ip);

    // ---- gNB side ----
    void receive_from_gnb();
    void handle_gnb_datagram(std::size_t length);
    void send_to_gnb(std::shared_ptr<std::vector<uint8_t>> datagram);

    RawProtocol::socket dn_socket_;
    RawProtocol::endpoint dn_sender_;
    std::vector<uint8_t> dn_buffer_;
    std::array<uint8_t, ETH_ALEN> upf_mac_{};
    ArpTable::Ipv4Address upf_dn_ip_{};

    ArpTable::Ipv4Address dn_next_hop_ip_{};
    ArpTable arp_table_;
    boost::asio::steady_timer arp_timer_;

    boost::asio::ip::udp::socket gnb_socket_;
    boost::asio::ip::udp::endpoint gnb_sender_;
    std::vector<uint8_t> gnb_buffer_;
    boost::asio::ip::udp::endpoint gnb_peer_;

    UeTable ue_table_;
};
