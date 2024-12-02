#include "db.hpp"
#include "capture.hpp"
#include "router.hpp"

#include <iostream>
#include <chrono>
#include <cstdint>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <curl/curl.h>
#include <vector>
#include <thread>

const char FILENAME[] = "routes.db";
const char INTERFACE[] = "wlp2s0";
const uint16_t NUM_WORKER = 1;

int main () {
	if(!db::verify_db(FILENAME)) {
		db::create_db(FILENAME);
	}

	if(!db::verify_db(FILENAME)) {
		throw std::runtime_error("Failed to create database");
	}

	int socketfd = router::open_socket();

	{
		std::vector<uint32_t> blocked_ips = db::get_all_blocked_ips(FILENAME);
		for(uint32_t ip : blocked_ips) {
			router::add_route(db::decimal_to_ip(ip).c_str(), socketfd);
		}
	}

	std::cout << "Finished restoring routes" << std::endl;

	std::thread capture_thread([]() {
		//TODO TERMINATE THREAD
		while(true) {
			try {
				capture::loop(INTERFACE, FILENAME);
			} catch(const std::exception& e) {
				std::cerr << e.what() << std::endl;
			} catch (...) {
				std::cerr << "Unknown exception caught in thread." << std::endl;
			}
			std::this_thread::sleep_for(std::chrono::milliseconds(200));
		}
	});

	std::vector<std::thread> worker_threads;

	for(uint16_t i = 0; i < NUM_WORKER; i++) {
		worker_threads.push_back(std::thread([socketfd]() {
			while(true) {
				try {
					capture::worker_loop(socketfd, FILENAME);
				} catch(const std::exception& e) {
					std::cerr << e.what() << std::endl;
				} catch (...) {
					std::cerr << "Unknown exception caught in thread." << std::endl;
				}
				std::this_thread::sleep_for(std::chrono::milliseconds(200));
			}
		}));
	}

	while(true) {
		std::this_thread::sleep_for(std::chrono::milliseconds(10000));
	}

	close(socketfd);
	return 0;
}
