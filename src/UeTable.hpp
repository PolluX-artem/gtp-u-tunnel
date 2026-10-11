#pragma once
#include <array>
#include <cstdint>
#include <optional>
#include <vector>

struct Ue {
    std::array<uint8_t, 4> ip{};
    uint32_t teid_dl = 0;
    uint32_t teid_ul = 0;
};

class UeTable {
public:
    explicit UeTable(uint8_t size);

    std::optional<Ue> find_by_ip(const std::array<uint8_t, 4> &ip) const;
    std::optional<Ue> find_by_teid_ul(uint32_t teid_ul) const;

private:
    std::vector<Ue> table_;
};

