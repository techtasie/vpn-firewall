#pragma once

#include <mutex>

#include <stdlib.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/if.h>

namespace router {
    bool add_route(const char* const dst, int socketfd);
    bool remove_route(const char* const dst, int socketfd);
    int open_socket();
    void close_socket(int socketfd);

    static std::mutex route_mutex;

    struct req {
        struct nlmsghdr nlmsg;
        struct rtmsg rt;
        char buf[1024];
    };
}
