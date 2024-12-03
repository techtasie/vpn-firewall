#include "db.hpp"

#include <iostream>
#include <fstream>
#include <string>
#include <cstdint>

const uint64_t BITS_PER_ADDRESS = 2;
const uint64_t BITS_IN_BYTE = 8;
const char FILENAME[] = "/var/lib/vpn-firewall/db.sqlite.db";

int main() {
    // Open the file in read mode
    std::fstream file(FILENAME, std::ios::in | std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open the file! Make sure the file exists and is initialized." << std::endl;
        return 1;
    }

    // Input: IPv4 address in dotted-decimal notation
    std::string ipAddress;
    std::cout << "Enter the IPv4 address in dotted-decimal format (e.g., 192.168.1.0): ";
    std::cin >> ipAddress;

    try {
        // Convert the IPv4 address to a 32-bit integer
        uint32_t address = db::ip_to_decimal(ipAddress);

        // Read and print the value for the given address
        uint8_t value = db::get_bits(file, address);
        std::cout << "The value for IPv4 address " << ipAddress << " (decimal: " << address << ") is: " 
                  << static_cast<int>(value) << std::endl;
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    file.close();
    return 0;
}
