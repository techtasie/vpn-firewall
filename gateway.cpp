#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <linux/rtnetlink.h>
#include <arpa/inet.h>
#include <unistd.h>
#include <net/if.h>
#include <errno.h>

int main() {
    struct {
        struct nlmsghdr nlmsg;
        struct rtmsg rt;
        char buf[1024];
    } req;

    struct rtattr *rta;
    int sockfd;
    struct sockaddr_nl sa;

    // Create socket
    sockfd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);
    if (sockfd < 0) {
        perror("Socket creation failed");
        return EXIT_FAILURE;
    }

    memset(&req, 0, sizeof(req));
    req.nlmsg.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
    req.nlmsg.nlmsg_type = RTM_NEWROUTE;
    req.nlmsg.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK;
    req.nlmsg.nlmsg_seq = 0;
    req.nlmsg.nlmsg_pid = getpid();
    req.rt.rtm_family = AF_INET;
    req.rt.rtm_table = RT_TABLE_MAIN;
    req.rt.rtm_protocol = RTPROT_BOOT;
    req.rt.rtm_scope = RT_SCOPE_UNIVERSE;
    req.rt.rtm_type = RTN_UNICAST;
    req.rt.rtm_dst_len = 24;  // Network prefix for destination

    // Destination IP (network)
    rta = (struct rtattr *)req.buf;
    rta->rta_type = RTA_DST;
    rta->rta_len = RTA_LENGTH(4);
    inet_pton(AF_INET, "192.168.100.0", RTA_DATA(rta));  // Destination network

    // Gateway IP address
    rta = (struct rtattr *)((char *)rta + RTA_ALIGN(rta->rta_len));
    rta->rta_type = RTA_GATEWAY;
    rta->rta_len = RTA_LENGTH(4);
    inet_pton(AF_INET, "149.201.37.1", RTA_DATA(rta));  // Gateway

    // Output interface index
    rta = (struct rtattr *)((char *)rta + RTA_ALIGN(rta->rta_len));
    rta->rta_type = RTA_OIF;
    rta->rta_len = RTA_LENGTH(4);
    int index = if_nametoindex("wlp2s0");
    if (index == 0) {
        perror("Interface not found");
        close(sockfd);
        return EXIT_FAILURE;
    }
    *((int *)RTA_DATA(rta)) = index;

    req.nlmsg.nlmsg_len = (char *)rta + RTA_ALIGN(rta->rta_len) - (char *)&req;

    memset(&sa, 0, sizeof(sa));
    sa.nl_family = AF_NETLINK;

    if (sendto(sockfd, &req, req.nlmsg.nlmsg_len, 0, (struct sockaddr *)&sa, sizeof(sa)) < 0) {
        perror("Send failed");
        close(sockfd);
        return EXIT_FAILURE;
    }

    // Read the response from the Netlink socket
    int read_len;
    char buffer[4096];
    struct iovec iov = { buffer, sizeof(buffer) };
    struct msghdr msg = { &sa, sizeof(sa), &iov, 1, NULL, 0, 0 };
    read_len = recvmsg(sockfd, &msg, 0);
    if (read_len < 0) {
        perror("Read response failed");
        close(sockfd);
        return EXIT_FAILURE;
    }

    if (NLMSG_ERROR == ((struct nlmsghdr *)buffer)->nlmsg_type) {
        struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(buffer);
        fprintf(stderr, "Error received: %s\n", strerror(-err->error));
        close(sockfd);
        return EXIT_FAILURE;
    }

    close(sockfd);
    printf("Route added successfully.\n");
    return EXIT_SUCCESS;
}
