#ifndef AMTMS_DATA_STRUCTURE_H
#define AMTMS_DATA_STRUCTURE_H

#include <pcap.h>
#include <iostream>
#include <mutex>
#include <queue>
#include <unordered_set>
#include <unordered_map>
#include <arpa/inet.h>



struct V4AddrHash {
    std::size_t operator()(const in_addr& addr) const {
        return std::hash<uint32_t>{}(addr.s_addr);
    }
};

struct V4AddrEqual {
    bool operator()(const in_addr& lhs, const in_addr& rhs) const {
        return lhs.s_addr == rhs.s_addr;
    }
};

struct V6AddrHash {
    std::size_t operator()(const in6_addr& addr6) const {
        std::size_t result = 0;

        int ln = sizeof(addr6.s6_addr)/sizeof(addr6.s6_addr[0]);
        std::size_t const hash_combiner = 31;

        for (int i = 0; i < ln; ++i) {
            std::size_t const h(std::hash<uint64_t>()(addr6.s6_addr[i]));
            result = result * hash_combiner + h;
        }
        return result;
    }
};

struct V6AddrEqual {
    bool operator()(const in6_addr& lhs, const in6_addr& rhs) const {
        int ln = sizeof(lhs.s6_addr)/sizeof(lhs.s6_addr[0]);
        for (int i = 0; i < ln; ++i) {
            if (lhs.s6_addr[i] != rhs.s6_addr[i]) {
                return false;
            }
        }
        return true;
    }
};

inline bool operator==(const std::pair<in_addr, in_addr>& lhs, const std::pair<in_addr, in_addr>& rhs) {
    return lhs.first.s_addr == rhs.first.s_addr && lhs.second.s_addr == rhs.second.s_addr;
}

namespace std {
    template <>
    struct hash<std::pair<in_addr, in_addr>> {
        std::size_t operator()(const std::pair<in_addr, in_addr>& p) const noexcept {
            std::size_t h1 = std::hash<uint32_t>{}(p.first.s_addr);
            std::size_t h2 = std::hash<uint32_t>{}(p.second.s_addr);
            return h1 ^ (h2 << 1);
        }
    };
}

inline bool operator==(const std::pair<in6_addr, in6_addr>& lhs, const std::pair<in6_addr, in6_addr>& rhs) {
    int ln = sizeof(lhs.first.s6_addr)/sizeof(lhs.first.s6_addr[0]);

    for (int i = 0; i < ln; ++i) {
        if (lhs.first.s6_addr[i] != rhs.first.s6_addr[i]) {
            return false;
        }
        if (lhs.second.s6_addr[i] != rhs.second.s6_addr[i]) {
            return false;
        }
    }
    return true;
}

namespace std {
    template <>
    struct hash<std::pair<in6_addr, in6_addr>> {
        std::size_t operator()(const std::pair<in6_addr, in6_addr>& p) const noexcept {

            std::size_t r1 = 0;
            std::size_t r2 = 0;

            int ln = sizeof(p.first.s6_addr)/sizeof(p.first.s6_addr[0]);
            std::size_t const hash_combiner = 31;

            for (int i = 0; i < ln; ++i) {
                std::size_t const h1(std::hash<uint64_t>()(p.first.s6_addr[i]));
                std::size_t const h2(std::hash<uint64_t>()(p.second.s6_addr[i]));

                r1 = r1 * hash_combiner + h1;
                r2 = r2 * hash_combiner + h2;
            }
            return r1 ^ (r2 << 1);
        }
    };
}

struct IPv4_Probe {
    bool finished;
    int current_ttl;
    std::vector<int> ipv4_pool_cnt;
    int ipv4_pool_cur;
    std::unordered_set<in_addr, V4AddrHash, V4AddrEqual> ipv4_pool;
    uint16_t balanced_value;
    int sended_flow_num;
    int begin_upper_bound;
    int flow_upper_bound;
    int begin_lower_bound;
    std::unordered_map<int, std::unordered_set<in_addr, V4AddrHash, V4AddrEqual> > ttl_ipv4_pool;


    std::unordered_map<uint16_t, std::unordered_map<int, in_addr> > flow_ttl_ipv4_pool;
    std::unordered_set<std::pair<in_addr, in_addr> > connect_pool;
    std::vector<int> connect_pool_cnt;
    int connect_pool_cur;
    int pool_size;
};



struct IPv6_Probe {
    bool finished;
    int current_ttl;
    std::vector<int> ipv6_pool_cnt;
    int ipv6_pool_cur;
    std::unordered_set<in6_addr, V6AddrHash, V6AddrEqual> ipv6_pool;
    uint16_t balanced_value;
    int sended_flow_num;
    int begin_upper_bound;
    int flow_upper_bound;
    int begin_lower_bound;
    std::unordered_map<int, std::unordered_set<in6_addr, V6AddrHash, V6AddrEqual> > ttl_ipv6_pool;

    std::unordered_map<uint16_t, std::unordered_map<int, in6_addr> > flow_ttl_ipv6_pool;
    std::unordered_set<std::pair<in6_addr, in6_addr> > connect_pool;
    std::vector<int> connect_pool_cnt;
    int connect_pool_cur;
    int pool_size;
};

struct IPv4_Pre_Probe {
    std::unordered_map<std::string, std::unordered_set<in_addr, V4AddrHash, V4AddrEqual> > proto_response;
    std::unordered_map<std::string, std::unordered_set<in_addr, V4AddrHash, V4AddrEqual> > flow_response;
};

struct IPv6_Pre_Probe {
    std::unordered_map<std::string, std::unordered_set<in6_addr, V6AddrHash, V6AddrEqual> > proto_response;
    std::unordered_map<std::string, std::unordered_set<in6_addr, V6AddrHash, V6AddrEqual> > flow_response;
};

struct IPv4_Field_Adapt {
    std::string target_proto;
    std::unordered_set<std::string> balanced_field;
    std::unordered_set<std::string> information_field;
    std::string balanced_field_selected;
    std::string ttl_field_selected;
    std::string timestamp_field_selected;
};

struct IPv6_Field_Adapt {
    std::string target_proto;
    std::unordered_set<std::string> balanced_field;
    std::unordered_set<std::string> information_field;
    std::string balanced_field_selected;
    std::string ttl_field_selected;
    std::string timestamp_field_selected;
};

struct Packet_Information {
    u_char *packet;
    uint16_t arrive_time;
};

struct CallbackArgs {
    pcap_dumper_t *dumper;
    std::queue<Packet_Information *> *check_queue;
    std::mutex *check_queue_mutex;
    bool *pcap_store;
};

struct IPv4_Header {
#if __BYTE_ORDER == __LITTLE_ENDIAN
    uint8_t ihl:4;
    uint8_t version:4;
#elif __BYTE_ORDER == __BIG_ENDIAN
    uint8_t version:4;
	uint8_t ihl:4;
#endif
    uint8_t tos;
    uint16_t tlen;
    uint16_t ident;
    uint16_t flags_offset;

    uint8_t ttl;
    uint8_t proto;
    uint16_t crc;
    struct in_addr sip;
    struct in_addr dip;
};

struct IPv6_Header {
    uint32_t vtf;
    uint16_t payload_length;
    uint8_t next_header;
    uint8_t hop_limit;
    in6_addr sip;
    in6_addr dip;
};

struct UDP_Header {
    uint16_t sport;
    uint16_t dport;
    uint16_t len;
    uint16_t crc;
};

struct UDP_TSDv4_Header {
    in_addr sip;
    in_addr dip;
    uint8_t mbz;
    uint8_t ptcl;
    uint16_t plen;
};

struct IPv4_UDP {
    uint8_t ipv4_ttl;
    in_addr ipv4_sip;
    in_addr ipv4_dip;
    uint16_t ipv4_ident;
    uint16_t udp_sport;
    uint16_t udp_dport;
    uint16_t udp_crc;
};

struct UDP_TSDv6_Header {
    in6_addr sip;
    in6_addr dip;
    uint32_t plen;
    uint8_t zeros[3];
    uint8_t next_header;
};

struct IPv6_UDP {
    uint32_t ipv6_flow_label;
    uint8_t ipv6_hop_limit;
    in6_addr ipv6_sip;
    in6_addr ipv6_dip;
    uint16_t udp_sport;
    uint16_t udp_dport;
    uint16_t udp_crc;
    uint16_t udp_content;
};

struct TCP_Header {
    uint16_t sport;
    uint16_t dport;
    uint32_t seq_number;
    uint32_t ack_number;
    uint8_t ofn;
    uint8_t flag;
    uint16_t window_size;
    uint16_t crc;
    uint16_t urgent_pointer;
};

struct TCP_OPT_Header {
    uint8_t mss;
    uint8_t mss_len;
    uint16_t mss_value;
    uint8_t sack;
    uint8_t sack_len;
    uint8_t tso;
    uint8_t tso_len;
    uint32_t ts_value;
    uint32_t ts_reply;
    uint8_t nop;
    uint8_t ws;
    uint8_t ws_len;
    uint8_t ws_sc;
};

struct TCP_TSDv4_Header {
    in_addr sip;
    in_addr dip;
    uint8_t mbz;
    uint8_t ptcl;
    uint16_t plen;
};

struct TCP_TSDv6_Header {
    in6_addr sip;
    in6_addr dip;
    uint32_t plen;
    uint8_t zeros[3];
    uint8_t next_header;
};

struct IPv4_TCP {
    uint8_t ipv4_ttl;
    in_addr ipv4_sip;
    in_addr ipv4_dip;
    uint16_t ipv4_ident;
    uint16_t tcp_sport;
    uint16_t tcp_dport;
    uint32_t tcp_seq;
};

struct IPv6_TCP {
    uint8_t ipv6_hop_limit;
    uint32_t ipv6_flow_label;
    in6_addr ipv6_sip;
    in6_addr ipv6_dip;
    uint16_t tcp_sport;
    uint16_t tcp_dport;
    uint32_t tcp_seq;
};

struct ICMPv4_Header {
    uint8_t type;
    uint8_t code;
    uint16_t crc;
    uint16_t ident;
    uint16_t seq_number;
};

struct IPv4_ICMPv4 {
    uint8_t ipv4_ttl;
    in_addr ipv4_sip;
    in_addr ipv4_dip;
};

struct ICMPv6_Header {
    uint8_t type;
    uint8_t code;
    uint16_t crc;
    uint16_t ident;
    uint16_t seq_number;
};

struct ICMPv6_TSDv6_Header {
    in6_addr sip;
    in6_addr dip;
    uint32_t plen;
    uint8_t zeros[3];
    uint8_t next_header;
};

struct IPv6_ICMPv6 {
    uint32_t ipv6_flow_label;
    uint8_t ipv6_hop_limit;
    in6_addr ipv6_sip;
    in6_addr ipv6_dip;
    uint16_t icmpv6_ident;
    uint16_t icmpv6_seq;
    uint16_t icmpv6_content;
};

struct Trie {
    int current_layer = 0;
    int prefix_mark = 0;
    int probe_done = 0;
    Trie* child_0 = nullptr;
    Trie* child_1 = nullptr;
};

#endif //AMTMS_DATA_STRUCTURE_H
