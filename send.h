#ifndef AMTMS_SEND_H
#define AMTMS_SEND_H

#include <cstring>
#include <cstdio>
#include <arpa/inet.h>
#include <thread>
#include <atomic>
#include <iostream>
#include <vector>
#include <pcap.h>
#include <unordered_set>
#include <functional>
#include <string>
#include <mutex>
#include <queue>
#include <netinet/ip.h>
#include <netinet/udp.h>
#include <netinet/ip_icmp.h>
#include <unistd.h>

#include "ipv4.h"
#include "udp.h"
#include "tcp.h"
#include "icmp.h"
#include "data_structure.h"
#include "tool.h"


int send_ipv4_udp(int socket_id, IPv4_UDP *ipv4_udp, const bool *blk);

int send_ipv6_udp(int socket_id, IPv6_UDP *ipv6_udp, const bool *blk);

int send_ipv4_tcp(int socket_id, IPv4_TCP *ipv4_tcp, const bool *blk);

int send_ipv6_tcp(int socket_id, IPv6_TCP *ipv6_tcp, const bool *blk);

int send_ipv6_icmpv6(int socket_id, IPv6_ICMPv6 *ipv6_icmpv6, const bool *blk);

void run_proto_preprobe_ipv4(std::atomic<bool>* isCaptureDone, const int *pre_round, in_addr *ipv4_sip, std::vector<in_addr> *ipv4_dip_list, const int *max_ttl, const int *band_speed_limit, const bool *blk);

void run_proto_preprobe_ipv6(std::atomic<bool>* isCaptureDone, const int *pre_round, in6_addr *ipv6_sip, std::vector<in6_addr> *ipv6_dip_list, const int *max_ttl, const int *band_speed_limit, const bool *blk);

void packet_process_proto_preprobe_ipv4(std::atomic<bool>* isCaptureDone, std::queue<Packet_Information *> *check_queue, std::mutex *check_queue_mutex, in_addr *s_addrv4, std::unordered_map<in_addr, IPv4_Pre_Probe, V4AddrHash, V4AddrEqual> *pre_probe_map, std::mutex *pre_probe_map_mutex);

void packet_process_proto_preprobe_ipv6(std::atomic<bool>* isCaptureDone, std::queue<Packet_Information *> *check_queue, std::mutex *check_queue_mutex, in6_addr *s_addrv6, std::unordered_map<in6_addr, IPv6_Pre_Probe, V6AddrHash, V6AddrEqual> *pre_probe_map, std::mutex *pre_probe_map_mutex);

void run_field_preprobe_ipv4(std::unordered_map<in_addr, IPv4_Field_Adapt, V4AddrHash, V4AddrEqual> *ipv4_adapt_map, std::atomic<bool>* isCaptureDone, const int *pre_round, in_addr *ipv4_sip, std::vector<in_addr> *ipv4_dip_list, const int *max_ttl, const int *band_speed_limit, const bool *blk);

void run_field_preprobe_ipv6(std::unordered_map<in6_addr, IPv6_Field_Adapt, V6AddrHash, V6AddrEqual> *ipv6_adapt_map, std::atomic<bool>* isCaptureDone, const int *pre_round, in6_addr *ipv6_sip, std::vector<in6_addr> *ipv6_dip_list, const int *max_ttl, const int *band_speed_limit, const bool *blk);

void packet_process_field_preprobe_ipv4(std::atomic<bool>* isCaptureDone, std::queue<Packet_Information *> *check_queue, std::mutex *check_queue_mutex, in_addr *s_addrv4, std::unordered_map<in_addr, IPv4_Pre_Probe, V4AddrHash, V4AddrEqual> *pre_probe_map, std::mutex *pre_probe_map_mutex);

void packet_process_field_preprobe_ipv6(std::atomic<bool>* isCaptureDone, std::queue<Packet_Information *> *check_queue, std::mutex *check_queue_mutex, in6_addr *s_addrv6, std::unordered_map<in6_addr, IPv6_Pre_Probe, V6AddrHash, V6AddrEqual> *pre_probe_map, std::mutex *pre_probe_map_mutex);

void run_send_ipv4(std::unordered_map<in_addr, IPv4_Probe, V4AddrHash, V4AddrEqual> *ipv4_probe_map, std::mutex *ipv4_probe_map_mutex, std::unordered_map<in_addr, IPv4_Field_Adapt, V4AddrHash, V4AddrEqual> *ipv4_adapt_map, std::mutex *ipv4_adapt_map_mutex, std::atomic<bool>* isCaptureDone, in_addr *ipv4_sip, std::vector<in_addr> *ipv4_dip_list, const int *max_ttl, const int *band_speed_limit, const bool *blk);

void run_send_ipv6(std::unordered_map<in6_addr, IPv6_Probe, V6AddrHash, V6AddrEqual> *ipv6_probe_map, std::mutex *ipv6_probe_map_mutex, std::unordered_map<in6_addr, IPv6_Field_Adapt, V6AddrHash, V6AddrEqual> *ipv6_adapt_map, std::mutex *ipv6_adapt_map_mutex, std::atomic<bool>* isCaptureDone, in6_addr *ipv6_sip, std::vector<in6_addr> *ipv6_dip_list, const int *max_ttl, const int *band_speed_limit, const bool *blk);

void packet_process_ipv4(std::atomic<bool> *isCaptureDone, std::queue<Packet_Information *> *check_queue, std::mutex *check_queue_mutex, std::unordered_map<in_addr, IPv4_Probe, V4AddrHash, V4AddrEqual> *ipv4_probe_map, std::mutex *ipv4_probe_map_mutex, std::unordered_map<in_addr, IPv4_Field_Adapt, V4AddrHash, V4AddrEqual> *ipv4_adapt_map, std::mutex *ipv4_adapt_map_mutex, std::unordered_set<in_addr, V4AddrHash, V4AddrEqual> *response_ip_set, std::mutex *response_ip_set_mutex, in_addr *s_addrv4, std::unordered_map<in_addr, IPv4_Pre_Probe, V4AddrHash, V4AddrEqual> *pre_probe_map, std::mutex *pre_probe_map_mutex, std::string *txt_path, const int *n_thread);

void packet_process_ipv6(std::atomic<bool> *isCaptureDone, std::queue<Packet_Information *> *check_queue, std::mutex *check_queue_mutex, std::unordered_map<in6_addr, IPv6_Probe, V6AddrHash, V6AddrEqual> *ipv6_probe_map, std::mutex *ipv6_probe_map_mutex, std::unordered_map<in6_addr, IPv6_Field_Adapt, V6AddrHash, V6AddrEqual> *ipv6_adapt_map, std::mutex *ipv6_adapt_map_mutex, std::unordered_set<in6_addr, V6AddrHash, V6AddrEqual> *response_ip_set, std::mutex *response_ip_set_mutex, in6_addr *s_addrv6, std::unordered_map<in6_addr, IPv6_Pre_Probe, V6AddrHash, V6AddrEqual> *pre_probe_map, std::mutex *pre_probe_map_mutex, std::string *txt_path, const int *n_thread);

#endif //AMTMS_SEND_H
