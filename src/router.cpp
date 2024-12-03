#include "router.hpp"

#include <cerrno>
#include <cstdio>
#include <linux/netlink.h>
#include <linux/rtnetlink.h>
#include <mutex>
#include <stdexcept>
#include <string.h>
#include <iostream>

int router::open_socket() {
  int sockfd = socket(AF_NETLINK, SOCK_DGRAM, NETLINK_ROUTE);

  if (sockfd < 0) {
    throw std::runtime_error("Failed to open socket");
  }

  return sockfd;
}

void router::close_socket(int sockfd) { close(sockfd); }

const char gateway_ip[] = "10.0.0.1";

bool router::add_route(const char *const dst, int socketfd) {
  std::lock_guard<std::mutex> lock(route_mutex);
  req request;

  std::cout << "Adding route to " << dst << std::endl;

  struct rtattr *rta;
  struct sockaddr_nl sa;

  memset(&request, 0, sizeof(request));
  request.nlmsg.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
  request.nlmsg.nlmsg_type = RTM_NEWROUTE;
  request.nlmsg.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK;
  request.nlmsg.nlmsg_seq = 0;
  request.nlmsg.nlmsg_pid = getpid();
  request.rt.rtm_family = AF_INET;
  request.rt.rtm_table = RT_TABLE_MAIN;
  request.rt.rtm_protocol = RTPROT_BOOT;
  request.rt.rtm_scope = RT_SCOPE_UNIVERSE;
  request.rt.rtm_type = RTN_UNICAST;
  request.rt.rtm_dst_len = 32;
  // 32 bits as subnet for dst network (just this ip)

  // Destination IP
  rta = (struct rtattr *)request.buf;
  rta->rta_type = RTA_DST;
  rta->rta_len = RTA_LENGTH(4);
  inet_pton(AF_INET, dst, RTA_DATA(rta));

  // Gateway IP
  rta = (struct rtattr *)((char *)rta + RTA_ALIGN(rta->rta_len));
  rta->rta_type = RTA_GATEWAY;
  rta->rta_len = RTA_LENGTH(4);
  inet_pton(AF_INET, gateway_ip, RTA_DATA(rta));

  // Output interface (vpn)
  rta = (struct rtattr *)((char *)rta + RTA_ALIGN(rta->rta_len));
  rta->rta_type = RTA_OIF;
  rta->rta_len = RTA_LENGTH(4);

  int if_index = if_nametoindex("wg0");
  if (if_index == 0) {
    throw std::runtime_error("Failed to get interface index");
  }

  *((int *)RTA_DATA(rta)) = if_index;

  request.nlmsg.nlmsg_len =
      (char *)rta + RTA_ALIGN(rta->rta_len) - (char *)&request;

  if (send(socketfd, &request, request.nlmsg.nlmsg_len, 0) < 0) {
    throw std::runtime_error("Failed to send route request");
  }

  int read_len;
  char buffer[4096];

  struct iovec iov = {.iov_base = buffer, .iov_len = sizeof(buffer)};
  struct msghdr msg = {.msg_name = &sa,
                       .msg_namelen = sizeof(sa),
                       .msg_iov = &iov,
                       .msg_iovlen = 1,
                       .msg_controllen = 0,
                       .msg_flags = 0};

  read_len = recvmsg(socketfd, &msg, 0);

  if (read_len < 0) {
    throw std::runtime_error("Failed to receive route response");
  }

  struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;
  if (nlh->nlmsg_type == NLMSG_ERROR) {
    struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
    if (err->error == 0 || err->error == -EEXIST) {
      // 0: No error
      // EEXIST: Route already exists
      return true;
    } else {
      fprintf(stderr, "Error %i received: %s\n", err->error,
              strerror(-err->error));
      return false;
    }
  }
  return true;
}

bool router::remove_route(const char *const dst, int socketfd) {
  std::lock_guard<std::mutex> lock(route_mutex);
  req request;

  struct rtattr *rta;
  struct sockaddr_nl sa;

  memset(&request, 0, sizeof(request));
  request.nlmsg.nlmsg_len = NLMSG_LENGTH(sizeof(struct rtmsg));
  request.nlmsg.nlmsg_type = RTM_DELROUTE;
  request.nlmsg.nlmsg_flags = NLM_F_REQUEST | NLM_F_CREATE | NLM_F_ACK;
  request.nlmsg.nlmsg_seq = 0;
  request.nlmsg.nlmsg_pid = getpid();
  request.rt.rtm_family = AF_INET;
  request.rt.rtm_table = RT_TABLE_MAIN;
  request.rt.rtm_protocol = RTPROT_BOOT;
  request.rt.rtm_scope = RT_SCOPE_UNIVERSE;
  request.rt.rtm_type = RTN_UNICAST;
  request.rt.rtm_dst_len = 32;
  // 32 bits as subnet for dst network (just this ip)

  // Destination IP
  rta = (struct rtattr *)request.buf;
  rta->rta_type = RTA_DST;
  rta->rta_len = RTA_LENGTH(4);
  inet_pton(AF_INET, dst, RTA_DATA(rta));

  // Gateway IP
  rta = (struct rtattr *)((char *)rta + RTA_ALIGN(rta->rta_len));
  rta->rta_type = RTA_GATEWAY;
  rta->rta_len = RTA_LENGTH(4);
  inet_pton(AF_INET, gateway_ip, RTA_DATA(rta));

  // Output interface (vpn)
  rta = (struct rtattr *)((char *)rta + RTA_ALIGN(rta->rta_len));
  rta->rta_type = RTA_OIF;
  rta->rta_len = RTA_LENGTH(4);

  int if_index = if_nametoindex("wg0");
  if (if_index == 0) {
    throw std::runtime_error("Failed to get interface index");
  }

  *((int *)RTA_DATA(rta)) = if_index;

  request.nlmsg.nlmsg_len =
      (char *)rta + RTA_ALIGN(rta->rta_len) - (char *)&request;

  if (send(socketfd, &request, request.nlmsg.nlmsg_len, 0) < 0) {
    throw std::runtime_error("Failed to send route request");
  }

  int read_len;
  char buffer[4096];

  struct iovec iov = {.iov_base = buffer, .iov_len = sizeof(buffer)};
  struct msghdr msg = {.msg_name = &sa,
                       .msg_namelen = sizeof(sa),
                       .msg_iov = &iov,
                       .msg_iovlen = 1,
                       .msg_controllen = 0,
                       .msg_flags = 0};

  read_len = recvmsg(socketfd, &msg, 0);

  if (read_len < 0) {
    throw std::runtime_error("Failed to receive route response");
  }

  struct nlmsghdr *nlh = (struct nlmsghdr *)buffer;
  if (nlh->nlmsg_type == NLMSG_ERROR) {
    struct nlmsgerr *err = (struct nlmsgerr *)NLMSG_DATA(nlh);
    if (err->error == 0 || err->error == -ENOENT || err->error == -ESRCH) {
      // 0: No error
      // ENOENT: Route does not exist
      return true;
    } else {
      fprintf(stderr, "Error %i received: %s\n", err->error,
              strerror(-err->error));
      return false;
    }
  }
  return true;
}
