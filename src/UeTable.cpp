#include "UeTable.hpp"

UeTable::UeTable(uint8_t size) {
    table_.reserve(size);
    for (int i = 1; i <= size; ++i) {
        table_.push_back(Ue{{192, 168, 7, static_cast<uint8_t>(i)},
                                    static_cast<uint32_t>(2 * i),
                                    static_cast<uint32_t>(2 * i + 1)});
    }
}

std::optional<Ue> UeTable::find_by_ip(const std::array<uint8_t, 4> &ip) const {
    for (const Ue &ue : table_) {
        if (ue.ip == ip) {
            return ue;
        }
    }
    return std::nullopt;
}

std::optional<Ue> UeTable::find_by_teid_ul(uint32_t teid_ul) const{
    for (const Ue &ue : table_) {
        if (ue.teid_ul == teid_ul) {
            return ue;
        }
    }
    return std::nullopt;
}
