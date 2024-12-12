#pragma once

#include <cstdint>
#include <pcap.h>
#include <curl/curl.h>
#include <string>
#include <memory>
#include "unique_thread_safe_queue.hpp"

namespace capture {
	static std::shared_ptr<UniqueThreadSafeQueue<uint32_t>> queue = std::make_shared<UniqueThreadSafeQueue<uint32_t>>();

    void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr,
                    const u_char *packet);
    // Needs to be wrapped in a try catch
    void loop(const char *device, const int* socketfd);
    size_t header_callback(char* buffer, size_t size, size_t nitems, std::string* serverHeader);
    size_t write_callback(char *ptr, size_t size, size_t nmemb, void *userdata);

    void worker_loop(int socketfd, const char* path);
    // Needs to be wrapped in a try catch
    bool lookup_ip_header(CURL* curl, const std::string &ip);
    bool is_public_ip(const uint32_t *decimal_ip);
    CURL *init_curl();

    struct IPRange {
        uint32_t start;
        uint32_t end;
    };

    const IPRange reserved_ips[] = {
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
}
