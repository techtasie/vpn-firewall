#include "db.hpp"
#include "router.hpp"

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <curl/curl.h>

int main () {
	int socketfd = router::open_socket();
	router::remove_route("89.36.33.33", socketfd);

	close(socketfd);
	return 0;
}
