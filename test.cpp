#include <iostream>
#include <pcap.h>
#include <queue>
#include <mutex>
#include <thread>
#include <netinet/in.h>
#include <netinet/ip.h> // For struct ip
#include <arpa/inet.h> // For inet_ntoa()

bool isPublicIP(const std::string& ip) {
    struct in_addr ipAddress;
    if (!inet_aton(ip.c_str(), &ipAddress)) {
        std::cerr << "Invalid IP address format." << std::endl;
        return false;
    }

    uint32_t ipNum = ntohl(ipAddress.s_addr);

    // List of private and reserved IP ranges
    struct IPRange {
        uint32_t start;
        uint32_t end;
    };

    const IPRange reservedIPs[] = {
        {0x00000000, 0x00FFFFFF}, // 0.0.0.0/8
        {0x0A000000, 0x0AFFFFFF}, // 10.0.0.0/8
        {0x64400000, 0x647FFFFF}, // 100.64.0.0/10
        {0x7F000000, 0x7FFFFFFF}, // 127.0.0.0/8
        {0xA9FE0000, 0xA9FEFFFF}, // 169.254.0.0/16
        {0xAC100000, 0xAC1FFFFF}, // 172.16.0.0/12
        {0xC0000000, 0xC00000FF}, // 192.0.0.0/24
        {0xC0000200, 0xC00002FF}, // 192.0.2.0/24
        {0xC0586300, 0xC05863FF}, // 192.88.99.0/24
        {0xC0A80000, 0xC0A8FFFF}, // 192.168.0.0/16
        {0xC6120000, 0xC613FFFF}, // 198.18.0.0/15
        {0xC6336400, 0xC63364FF}, // 198.51.100.0/24
        {0xCB007100, 0xCB0071FF}, // 203.0.113.0/24
        {0xE0000000, 0xEFFFFFFF}, // 224.0.0.0/4
        {0xE9FC0000, 0xE9FC00FF}, // 233.252.0.0/24
        {0xF0000000, 0xFFFFFFFE}, // 240.0.0.0/4
        {0xFFFFFFFF, 0xFFFFFFFF}  // 255.255.255.255/32
    };

    for (const auto& range : reservedIPs) {
        if (ipNum >= range.start && ipNum <= range.end) {
            return false; // IP is not public
        }
    }

    return true; // IP is public
}
std::queue<std::string> ipQueue;
std::mutex queueMutex;

void packetHandler(u_char *userData, const struct pcap_pkthdr* pkthdr, const u_char* packet) {
    const struct ip* ipHeader;
    ipHeader = (struct ip*)(packet + 14); // Skip Ethernet header

    std::string destIp = inet_ntoa(ipHeader->ip_dst);

    {
        std::lock_guard<std::mutex> guard(queueMutex);
        ipQueue.push(destIp);
    }
    if(isPublicIP(destIp)){
	    // For demonstration, let's print the IP address
	    std::cout << destIp << std::endl;
    }
}

int main() {
    char errbuf[PCAP_ERRBUF_SIZE];
    char* device = "wlp2s0";
    pcap_t* handle;

    handle = pcap_open_live(device, BUFSIZ, 0, 1000, errbuf);
    if (handle == nullptr) {
        std::cerr << "Could not open device " << device << ": " << errbuf << std::endl;
        return 2;
    }

    if (pcap_loop(handle, 0, packetHandler, nullptr) < 0) {
        std::cerr << "pcap_loop() failed: " << pcap_geterr(handle);
        return 2;
    }

    pcap_close(handle);
    return 0;
}
