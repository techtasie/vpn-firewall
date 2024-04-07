#include <iostream>
#include <string>
#include <mutex>
#include <vector>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <thread>
#include <functional>
#include <curl/curl.h>

#include "rocksdb/db.h"

rocksdb::DB* db;
rocksdb::Status status;
std::mutex db_mutex;
std::vector<std::string> current_lookups;
std::mutex vector_mutex;

void enque_ip(std::string ip) {
	std::scoped_lock scope_lock(vector_mutex);

	current_lookups.push_back(ip);
}

size_t header_callback(char *buffer, size_t size, size_t nitems, std::string *userdata) {
    // Calculate the real size of the incoming header
    size_t real_size = nitems * size;
    std::string temp(buffer, real_size);

    // Look for the Server header
    if(temp.find("Server:") != std::string::npos) {
        *userdata = temp; // Save the Server header
    }

    return real_size;
}

void remove_ip(std::string ip) {
	std::scoped_lock scope_lock(vector_mutex);

	current_lookups.erase(remove(current_lookups.begin(), current_lookups.end(),
						ip.c_str()), current_lookups.end());
}

size_t write_callback(char *buffer, size_t size, size_t nitems, void *userdata) {
    return size * nitems; // Simply return the number of bytes to indicate success
}

void getServerHeader(std::string ip) {
	CURL *curl;
	CURLcode res;

	curl = curl_easy_init();
	if(!curl) {
		std::cout << "Curl init failed" << std::endl;
		remove_ip(ip);
		return;
	}

	std::string serverHeader;

	curl_easy_setopt(curl, CURLOPT_URL, ip.c_str());
	curl_easy_setopt(curl, CURLOPT_HEADERFUNCTION, header_callback);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYPEER, 0L);
	curl_easy_setopt(curl, CURLOPT_SSL_VERIFYHOST, 0L);
	curl_easy_setopt(curl, CURLOPT_HEADERDATA, &serverHeader);

	curl_easy_setopt(curl, CURLOPT_NOBODY, 0L);
	curl_easy_setopt(curl, CURLOPT_WRITEFUNCTION, write_callback);

	res = curl_easy_perform(curl);
	if(res != CURLE_OK) {
		std::cout << "Curl perform failed" << std::endl;
		remove_ip(ip);
		return;
	}

	std::cout << "HEADER: " << serverHeader << std::endl;
	if (serverHeader.empty()) {
		remove_ip(ip);
		return;
	}
	if(serverHeader.find("ZyWALL") != std::string::npos) {
		std::cout << "ZyWall found" << std::endl;
		std::string command = "ip route add " + ip +" via 10.8.0.1 dev tun0";
		system(command.c_str());
		std::scoped_lock scope_lock_(db_mutex);
		status = db->Put(rocksdb::WriteOptions(), ip, "b" + std::to_string(time(0)));
		remove_ip(ip);
		return;
	}
	curl_easy_cleanup(curl);

	std::scoped_lock scope_lock_(db_mutex);
	status = db->Put(rocksdb::WriteOptions(), ip, "n" + std::to_string(time(0)));
	remove_ip(ip);
}


int main() {
	std::vector<std::thread> threads;

	db_mutex.lock();
	rocksdb::Options options;
	options.create_if_missing = true;
	status = rocksdb::DB::Open(options, "/tmp/testdb", &db);
	assert(status.ok());
	std::cout << "Database opened" << std::endl;
	db_mutex.unlock();

	std::string ip_in;

	while (std::cin >> ip_in) {
		std::string value;
		db_mutex.lock();
		status = db->Get(rocksdb::ReadOptions(), ip_in, &value);
		if (status.ok()) {
			db_mutex.unlock();
			std::cout << ip_in << " " << value << std::endl;
		} else {
			db_mutex.unlock();
			std::cout << ip_in << " not found" << std::endl;
			//check if ip_in is in current_lookups
			std::scoped_lock scope_lock(vector_mutex);
			if (std::find(current_lookups.begin(), current_lookups.end(), ip_in) != current_lookups.end()) {
				continue;
			}
			threads.emplace_back([ip_in]() {
				getServerHeader(ip_in);
			}).detach();
		}
	}
	return 0;
}
