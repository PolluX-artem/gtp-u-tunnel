#include "ArpTable.hpp"

ArpTable::ArpTable(Clock::duration lifetime) : lifetime_(lifetime) {}

std::optional<ArpTable::MacAddress> ArpTable::lookup(const Ipv4Address& ip, Clock::time_point now) const {
    const auto it = entries_.find(ip);
    if (it == entries_.end() || it->second.expires_at <= now) {
        return std::nullopt;
    }
    return it->second.mac;
}

void ArpTable::update(const Ipv4Address& ip, const MacAddress& mac, Clock::time_point now) {
    entries_[ip] = Entry{mac, now + lifetime_};
}

void ArpTable::refresh_by_mac(const MacAddress& mac, Clock::time_point now) {
    for (auto& [ip, entry] : entries_) {
        if (entry.mac == mac && entry.expires_at > now) {
            entry.expires_at = now + lifetime_;
        }
    }
}

std::vector<ArpTable::Ipv4Address> ArpTable::remove_expired(Clock::time_point now) {
    std::vector<Ipv4Address> removed;
    for (auto it = entries_.begin(); it != entries_.end();) {
        if (it->second.expires_at <= now) {
            removed.push_back(it->first);
            it = entries_.erase(it);
        } else {
            ++it;
        }
    }
    return removed;
}
