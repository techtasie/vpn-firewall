#pragma once

#include <fstream>
#include <cstdint>
#include <shared_mutex>
#include <vector>

namespace db {
    bool verify_db(const char* const path);
    void create_db(const char* const path);
    uint8_t get_bits(std::fstream &file, uint32_t address);
    void set_bits(std::fstream &file, uint32_t address, uint8_t value);
    std::vector<uint32_t> get_all_blocked_ips(const char* const path);
    uint32_t ip_to_decimal(const std::string &ip);
    std::string decimal_to_ip(uint32_t &decimal);

    static std::shared_mutex db_mutex;

    const uint8_t NOT_TESTED = 0;
    const uint8_t ALLOWED = 1;
    const uint8_t BLOCKED = 2;
}
