#pragma once

#include <array>
#include <chrono>
#include <cstdint>
#include <map>
#include <optional>
#include <vector>

#include <linux/if_ether.h>


class ArpTable {
public:
    using Clock = std::chrono::steady_clock;
    using Ipv4Address = std::array<uint8_t, 4>;
    using MacAddress = std::array<uint8_t, ETH_ALEN>;

    explicit ArpTable(Clock::duration lifetime);

    std::optional<MacAddress> lookup(const Ipv4Address& ip, Clock::time_point now) const;

    void update(const Ipv4Address& ip, const MacAddress& mac, Clock::time_point now);

    void refresh_by_mac(const MacAddress& mac, Clock::time_point now);

    std::vector<Ipv4Address> remove_expired(Clock::time_point now);

private:
    struct Entry {
        MacAddress mac{};
        Clock::time_point expires_at{};
    };

    Clock::duration lifetime_;
    std::map<Ipv4Address, Entry> entries_;
};
