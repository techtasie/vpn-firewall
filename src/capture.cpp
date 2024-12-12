#include "capture.hpp"
#include "db.hpp"
#include "router.hpp"

#include <cstdint>
#include <fstream>
#include <netinet/in.h>
#include <netinet/ip.h>
#include <netinet/ip.h>
#include <netinet/tcp.h>
#include <arpa/inet.h>
#include <stdexcept>
#include <iostream>
#include <thread>

bool capture::is_public_ip(const uint32_t *decimal_ip) {
    for (const IPRange& range : reserved_ips) {
        if (*decimal_ip >= range.start && *decimal_ip <= range.end) {
            return false;
        }
    }

    return true;
}

void capture::worker_loop(int socketfd, const char* path) {
    CURL *curl = init_curl();
    std::fstream file(path);
    while (true) {
        std::optional<uint32_t> ip = queue->pop();

        try {
            if(ip.has_value()) {
                std::string ip_str = db::decimal_to_ip(ip.value());
                std::cout << "Checking IP: " << ip_str << " on thread: " << std::this_thread::get_id() << std::endl;
                if (lookup_ip_header(curl, ip_str)) {
                    // Synchronous handling logic for ZyWALL response
                    router::add_route(ip_str.c_str(), socketfd);
                    db::set_bits(file, ip.value(), db::BLOCKED);
                } else {
                    std::cout << "IP OK: " << ip_str << std::endl;
                    db::set_bits(file, ip.value(), db::ALLOWED);
                }
            }
        } catch (std::exception &e) {
            std::cerr << "Error: " << e.what() << std::endl;
        } catch (...) {
            std::cerr << "Unknown error occurred" << std::endl;
        }
        queue->mark_done(ip.value());
    }

    file.close();
}

void capture::loop(const char *device, const int* socketfd) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;
    handle = pcap_open_live(device, 96, 0, 10, errbuf);
    if (handle == nullptr) {
        std::cerr << "Could not open device " << device << ": " << errbuf << std::endl;
        pcap_close(handle);
        throw std::runtime_error("Failed to open device" + std::string(device) + ": " + errbuf);
    }

    std::cout << "Starting to capture" << std::endl;
    if (pcap_loop(handle, 0, packet_handler, reinterpret_cast<u_char *>(&socketfd)) < 0) {
        std::cerr << "pcap_loop() failed: " << pcap_geterr(handle);
        pcap_close(handle);
        throw std::runtime_error("Failed to loop through packets" + std::string(pcap_geterr(handle)));
    }

    pcap_close(handle);
}

void capture::packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr,
                             const u_char *packet) {
    int socketfd = *reinterpret_cast<int*>(user);

    // Check that we have enough bytes for Ethernet + IP header
    if (pkthdr->len < 14) {
        return;
    }

    // Parse Ethernet header to get the EtherType
    const uint16_t eth_type = ntohs(*(uint16_t*)(packet + 12));
    // Only handle IPv4 packets
    if (eth_type != 0x0800) { 
        return; 
    }

    // IP header starts after Ethernet (14 bytes)
    const struct ip* ip_header = (struct ip*)(packet + 14);

    // Check that we have enough bytes for the IP header
    uint8_t ip_header_length = ip_header->ip_hl * 4;
    if (pkthdr->len < 14 + ip_header_length) {
        return;
    }

    // Only handle TCP packets
    if (ip_header->ip_p != IPPROTO_TCP) {
        return;
    }

    // TCP header starts after IP header
    const struct tcphdr* tcp_header = (struct tcphdr*)((u_char*)ip_header + ip_header_length);

    // Check we have enough bytes for TCP header
    uint8_t tcp_header_length = tcp_header->th_off * 4;
    if (pkthdr->len < 14 + ip_header_length + tcp_header_length) {
        return;
    }

    // Now apply the conditions:
    // 1) RST flag set
    bool rst_set = (tcp_header->th_flags & TH_RST) != 0;

    // 2) TCP sequence number == 1
    bool seq_is_one = (ntohl(tcp_header->th_seq) == 1);

    // 3) Window size == 0
    bool win_zero = (ntohs(tcp_header->th_win) == 0);

    // 4) TCP len == 0
    // TCP payload length = IP total length - IP header length - TCP header length
    uint16_t ip_total_len = ntohs(ip_header->ip_len);
    uint16_t payload_len = ip_total_len - ip_header_length - tcp_header_length;
    bool no_payload = (payload_len == 0);

    if (!(rst_set && seq_is_one && win_zero && no_payload)) {
        // Doesn't match our criteria, do nothing
        return;
    }

    // If we reach here, the packet matches the conditions
    uint32_t dst_ip = ntohl(ip_header->ip_dst.s_addr);

    if (!is_public_ip(&dst_ip)) {
        return;
    }

    std::string ip = db::decimal_to_ip(dst_ip);
    router::add_route(ip.c_str(), socketfd);
}

size_t capture::header_callback(char* buffer, size_t size, size_t nitems, std::string* serverHeader) {
    if (serverHeader) {
        serverHeader->append(buffer, size * nitems);
    }
    return size * nitems;
}

size_t capture::write_callback(char *ptr, size_t size, size_t nmemb, void *userdata) {
    return size * nmemb; // Ignore the body
}

bool capture::lookup_ip_header(CURL* curl, const std::string &ip) {
    std::string serverHeader;
    curl_easy_setopt(curl, CURLOPT_URL, ip.c_str());
    curl_easy_setopt(curl, CURLOPT_HEADERDATA, &serverHeader);

    CURLcode res = curl_easy_perform(curl);
    if (res != CURLE_OK) {
        throw std::runtime_error("Failed to perform curl request");
    }

    // std::cout << "HEADER: " << serverHeader << std::endl;
    if (serverHeader.find("ZyWALL") != std::string::npos) {
        std::cout << "ZyWall found for IP: " << ip << std::endl;
        // Synchronous handling logic for ZyWALL response
        return true;
    }
    return false;
}

CURL *capture::init_curl() {
    CURL *curl = curl_easy_init();
    if (!curl) {
        throw std::runtime_error("Failed to initialize curl");
    }

	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);

    // Specify that we want to make a HEAD request
    curl_easy_setopt(curl, CURLOPT_NOBODY, 1L);
    curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);
    curl_easy_setopt(curl, CURLOPT_CONNECTTIMEOUT, 10L);
    curl_easy_setopt(curl, CURLOPT_TIMEOUT, 20L);

    return curl;
}
