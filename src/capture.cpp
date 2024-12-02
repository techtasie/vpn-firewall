#include "capture.hpp"
#include "db.hpp"
#include "router.hpp"

#include <cstdint>
#include <fstream>
#include <netinet/in.h>
#include <netinet/ip.h>
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

        if(ip.has_value()) {
            std::string ip_str = db::decimal_to_ip(ip.value());
            std::cout << "Checking IP: " << ip_str << " on thread: " << std::this_thread::get_id() << std::endl;
            if (lookup_ip_header(curl, ip_str)) {
                // Synchronous handling logic for ZyWALL response
                router::add_route(ip_str.c_str(), socketfd);
                db::set_bits(file, ip.value(), db::BLOCKED);
            } else {
                db::set_bits(file, ip.value(), db::ALLOWED);
            }

            queue->mark_done(ip.value());
        }
    }

    file.close();
}

void capture::loop(const char *device, const char* path) {
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t* handle;
    handle = pcap_open_live(device, 96, 0, 10, errbuf);
    if (handle == nullptr) {
        std::cerr << "Could not open device " << device << ": " << errbuf << std::endl;
        pcap_close(handle);
        throw std::runtime_error("Failed to open device" + std::string(device) + ": " + errbuf);
    }

    std::fstream file(path);

    if (pcap_loop(handle, 0, packet_handler, reinterpret_cast<u_char *>(&file)) < 0) {
        std::cerr << "pcap_loop() failed: " << pcap_geterr(handle);
        pcap_close(handle);
        throw std::runtime_error("Failed to loop through packets" + std::string(pcap_geterr(handle)));
    }

    file.close();
    pcap_close(handle);
}

void capture::packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr,
                             const u_char *packet) {
    std::fstream *file = reinterpret_cast<std::fstream*>(user);
    const struct ip* ip_header = (struct ip*)(packet + 14);

    uint32_t dst_ip = ntohl(ip_header->ip_dst.s_addr);

    if (!is_public_ip(&dst_ip)) {
        return;
    }
    if(db::get_bits(*file, dst_ip) == db::NOT_TESTED) {
        queue->push(dst_ip);
    }
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
        return false;
        // TODO
        // throw std::runtime_error("Failed to perform curl request");
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
