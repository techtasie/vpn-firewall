#include "db.hpp"

#include <iostream>
#include <fstream>
#include <string>
#include <stdexcept>
#include <cstdint>

const uint64_t BITS_PER_ADDRESS = 2;
const uint64_t BITS_IN_BYTE = 8;
//TODO Correct Path
const char FILENAME[] = "ipv4_tracker.bin";

int main() {
    // Open the file in read/write mode
    std::fstream file(FILENAME, std::ios::in | std::ios::out | std::ios::binary);
    if (!file) {
        std::cerr << "Failed to open the file! Make sure the file exists and is initialized." << std::endl;
        return 1;
    }

    try {
        // Input: IPv4 address in dotted-decimal notation
        std::string ipAddress;
        std::cout << "Enter the IPv4 address in dotted-decimal format (e.g., 192.168.1.0): ";
        std::cin >> ipAddress;

        // Convert the IPv4 address to a 32-bit integer
        uint32_t address = db::ip_to_decimal(ipAddress);

        // Input: Value to set (0-3)
        std::string valueInput;
        uint8_t value;
        std::cout << "Enter the value to set (0-3): ";
        std::cin >> valueInput;

        // Convert the input to an integer and validate
        try {
            value = std::stoi(valueInput);
            if (value > 3) {
                throw std::invalid_argument("Value must be between 0 and 3 (2 bits).");
            }
        } catch (const std::exception&) {
            throw std::invalid_argument("Invalid input. Value must be an integer between 0 and 3.");
        }

        // Set the value for the given address
        db::set_bits(file, address, value);
        std::cout << "Successfully set value " << static_cast<int>(value)
                  << " for IPv4 address " << ipAddress << "." << std::endl;
    } catch (const std::exception &e) {
        std::cerr << "Error: " << e.what() << std::endl;
    }

    file.close();
    return 0;
}
