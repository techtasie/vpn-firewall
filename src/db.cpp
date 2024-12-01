#include "db.hpp"

#include <mutex>
#include <iostream>
#include <shared_mutex>
#include <sstream>
#include <sys/stat.h>
#include <cstdint>
#include <string>
#include <stdexcept>
#include <fstream>
#include <vector>
#include <arpa/inet.h>

const uint64_t TOTAL_IPV4_ADDRESSES = 4294967296; // 2^32
const uint64_t BITS_PER_ADDRESS = 2;
const uint64_t BITS_IN_BYTE = 8;
const uint64_t TOTAL_BITS = TOTAL_IPV4_ADDRESSES * BITS_PER_ADDRESS;
const uint64_t TOTAL_BYTES = TOTAL_BITS / BITS_IN_BYTE; // Total size in bytes
const size_t BUFFER_SIZE = 4096; // Number of bytes to read at a time

const uint8_t NOT_TESTED = 0;
const uint8_t ALLOWED = 1;
const uint8_t BLOCKED = 2;

bool db::verify_db(const char *const path) {
    struct stat file_stat;
    if (stat(path, &file_stat) != 0) {
        std::cerr << "Failed to get file status. for file " << path << std::endl;
        return false;
    }
    return file_stat.st_size == TOTAL_BYTES;
}

void db::gen_db(const char *const path) {
    std::ofstream file(path, std::ios::binary | std::ios::trunc);
    std::vector<char> buffer(TOTAL_BYTES, 0);
    file.write(buffer.data(), buffer.size());
}

uint8_t db::get_bits(std::fstream &file, uint32_t address) {
    std::shared_lock<std::shared_mutex> lock(db_mutex);

    uint64_t bitPosition = address * BITS_PER_ADDRESS;
    uint64_t bytePosition = bitPosition / BITS_IN_BYTE;
    uint8_t bitOffset = bitPosition % BITS_IN_BYTE;

    // Read the byte containing the bits
    file.seekg(bytePosition, std::ios::beg);
    char byte;
    file.read(&byte, 1);

    // Extract the 2 bits
    return (byte >> bitOffset) & 0b11;
}

void db::set_bits(std::fstream &file, uint32_t address, uint8_t value) {
    std::unique_lock<std::shared_mutex> lock(db_mutex);
    if (value > 3) {
        throw std::runtime_error("Value must be between 0 and 3");
    }

    uint64_t bitPosition = address * BITS_PER_ADDRESS;
    uint64_t bytePosition = bitPosition / BITS_IN_BYTE;
    uint8_t bitOffset = bitPosition % BITS_IN_BYTE;

    // Read the byte containing the bits
    file.seekg(bytePosition, std::ios::beg);
    unsigned char byte = 0;
    file.read(reinterpret_cast<char *>(&byte), 1);

    uint8_t mask = 0b11 << bitOffset;
    byte = (byte & ~mask) | (value << bitOffset);

    file.seekg(bytePosition, std::ios::beg);
    file.write(reinterpret_cast<char *>(&byte), 1);
}

uint32_t db::ip_to_decimal(const std::string &ip) {
    std::stringstream ss(ip);
    std::string segment;
    uint32_t decimalIP = 0;
    int shift = 24;

    while (std::getline(ss, segment, '.')) {
        int octet = std::stoi(segment);
        if (octet < 0 || octet > 255) {
            throw std::runtime_error("Invalid IP address");
        }
        decimalIP |= (octet << shift);
        shift -= 8;
    }

    return decimalIP;
}

std::string db::decimal_to_ip(uint32_t &ip) {
    struct in_addr addr;
    addr.s_addr = htonl(ip);
    return std::string(inet_ntoa(addr));
}

std::vector<uint32_t> db::get_all_blocked_ips(const char *const path) {
    std::unique_lock<std::shared_mutex> lock(db_mutex);
    std::fstream file(path);

    if(!file.is_open()) {
        throw std::runtime_error("Failed to open file" + std::string(path));
    }

    std::vector<char> buffer(BUFFER_SIZE, NOT_TESTED);
    std::vector<uint32_t> blocked_ips;

    uint64_t address = 0;
    while(file.read(buffer.data(), BUFFER_SIZE) || file.gcount() > 0 ) {
        size_t bytes_read = file.gcount();

        for (size_t i = 0; i < bytes_read; ++i) {
            char byte = buffer[i];
            for (uint8_t bit_offset = 0; bit_offset < BITS_IN_BYTE; bit_offset += BITS_PER_ADDRESS) {
                if (address >= TOTAL_IPV4_ADDRESSES) {
                    break;
                }

                uint8_t value = (byte >> bit_offset) & 0b11;

                if (value == BLOCKED) {
                    blocked_ips.push_back(address);
                }

                ++address;
            }
        }
    }
    file.close();

    return blocked_ips;
}
