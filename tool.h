#ifndef AMTMS_TOOL_H
#define AMTMS_TOOL_H

#include <sys/time.h>
#include <ctime>

#include <iostream>
#include <ifaddrs.h>
#include <netdb.h>
#include <cstring>
#include <arpa/inet.h>
#include <string>
#include <net/if.h>
#include <fstream>
#include <vector>
#include <cstdlib>
#include <unistd.h>
#include <chrono>
#include <random>

#include <algorithm>

#include <functional>
#include <netinet/icmp6.h>
#include <sstream>
#include <sys/stat.h>
#include "data_structure.h"


long long get_nanoseconds();

void getNetworkInfo(std::string &interfaceName, std::string &ipv4Address, std::string &ipv6Address);

void readIPv4Addresses(std::vector<in_addr> &ipv4Addresses, Trie* v4preTrie, const std::string &filename);

void contructIPv4Addresses(std::vector<in_addr> &ipv4Addresses, const std::string &filename);

Trie* v4Prefix_tire_construct(const std::string &filename);

Trie* v4Prefix_trie_find(Trie* v4preTrie, long long &ipv4_int, int &pre);

void readIPv6Addresses(std::vector<in6_addr> &ipv6Addresses, Trie* v6preTrie, const std::string &filename);

void constructIPv6Addresses(std::vector<in6_addr> &ipv6Addresses, const std::string &filename);

Trie* v6Prefix_tire_construct(const std::string &filename);

Trie* v6Prefix_trie_find(Trie* v6preTrie, in6_addr &ipv6, int &pre);

void shutffleIPv4Addresses(std::vector<in_addr> &addressesVector);

void shutffleIPv6Addresses(std::vector<in6_addr> &addressesVector);

in_addr_t ipv4_string_to_inaddr(std::string &sipv4_s);

long long ipv4_inaddr_to_int(in_addr_t &ipv4);

long long ipv4_string_to_int(std::string &sipv4_s);

bool ipv4_address_equal(in_addr &ipv4_v1, in_addr &ipv4_v2);

void ipv6_string_to_inaddr6(std::string &sipv6_s, in6_addr &sipv6_i);

bool ipv6_address_equal(in6_addr &ipv6_v1, in6_addr &ipv6_v2);

std::string generate_pcap_filename(std::string &base_filename, int &file_index);

std::string generate_txt_filename(std::string &base_filename, int &file_index);

bool file_size_exceeded(const char *filename, long long &max_file_size);

std::vector<int> string_split(std::string s_str, const std::string& p_str);

void printProgress(int percentage, int total, const std::string& other);

#endif //AMTMS_TOOL_H
