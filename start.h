#ifndef AMTMS_START_H
#define AMTMS_START_H

#include "tool.h"
#include "send.h"
#include "capture.h"
#include <sys/stat.h>
#include <cstdio>


std::unordered_set<in_addr, V4AddrHash, V4AddrEqual> start_ipv4(const int *band_speed_limit, char *dev, std::string *sipv4, in_addr *in_ipv4, std::vector<in_addr> *dipv4_list, bool *probe_pcap_store, const int *nthread, int *max_ttl, int *pre_round, const int *begin_lower_bound, const int *begin_upper_bound, const bool *field_default, const bool *blk, const int *pool_size);

std::unordered_set<in6_addr, V6AddrHash, V6AddrEqual> start_ipv6(const int *band_speed_limit, char *dev, std::string *sipv6, in6_addr *in_ipv6, std::vector<in6_addr> *dipv6_list, bool *probe_pcap_store, const int *nthread, int *max_ttl, int *pre_round, const int *begin_lower_bound, const int *begin_upper_bound, const bool *field_default, const bool *blk, const int *pool_size);

#endif //AMTMS_START_H
