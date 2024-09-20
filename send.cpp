#include "send.h"

int send_ipv4_udp(int socket_id, IPv4_UDP *ipv4_udp, const bool *blk) {
    uint16_t udp_crc = htons(ipv4_udp->udp_crc);
    uint16_t udp_content_len = sizeof(udp_crc);
    uint16_t udp_header_len = sizeof(UDP_Header);
    uint16_t udp_len = udp_header_len + udp_content_len;


    sockaddr_in sin_d{};
    sin_d.sin_family = AF_INET;
    sin_d.sin_port = 0;
    sin_d.sin_addr.s_addr = ipv4_udp->ipv4_dip.s_addr;

    UDP_Header udp_header{};
    udp_header.sport = htons(ipv4_udp->udp_sport);
    udp_header.dport = htons(ipv4_udp->udp_dport);
    udp_header.len = htons(udp_len);
    udp_header.crc = 0;

    UDP_TSDv4_Header udp_tsdv4_header{};
    uint16_t udp_tsdv4_header_len = sizeof(UDP_TSDv4_Header);
    udp_tsdv4_header.sip.s_addr = ipv4_udp->ipv4_sip.s_addr;
    udp_tsdv4_header.dip.s_addr = sin_d.sin_addr.s_addr;
    udp_tsdv4_header.mbz = 0;
    udp_tsdv4_header.ptcl = IPPROTO_UDP;
    udp_tsdv4_header.plen = udp_header.len;

    uint16_t udp_check_len = udp_tsdv4_header_len + udp_len;
    uint16_t udp_alloc_len = udp_check_len;
    if (udp_check_len&1) {
        ++udp_alloc_len;
    }
    auto *udp_check = new uint16_t[udp_alloc_len>>1];
    if (udp_check_len&1) {
        memset(udp_check+(udp_check_len>>1), 0, sizeof(uint16_t));
    }
    memcpy(udp_check, &udp_tsdv4_header, udp_tsdv4_header_len);
    memcpy(udp_check+(udp_tsdv4_header_len>>1), &udp_header, udp_header_len);
    memcpy(udp_check+((udp_tsdv4_header_len+udp_header_len)>>1), &udp_crc, udp_content_len);
    uint16_t embed_crc = udp_checksum(udp_check, udp_alloc_len>>1);
    udp_header.crc = udp_crc;
    udp_crc = embed_crc;

    IPv4_Header ipv4_header{};
    uint16_t ipv4_header_len = sizeof(IPv4_Header);
    uint16_t ipv4_len = ipv4_header_len + udp_len;
    ipv4_header.ihl = 5;
    ipv4_header.version = 4;
    ipv4_header.tos = 0;
    ipv4_header.tlen = htons(ipv4_len);
    ipv4_header.ident = htons(ipv4_udp->ipv4_ident);
    ipv4_header.flags_offset = htons(0x0000);
    ipv4_header.ttl = ipv4_udp->ipv4_ttl;
    ipv4_header.proto = IPPROTO_UDP;
    ipv4_header.crc = 0;
    ipv4_header.sip.s_addr = ipv4_udp->ipv4_sip.s_addr;
    ipv4_header.dip.s_addr = sin_d.sin_addr.s_addr;

    ipv4_header.crc = ipv4_checksum((uint16_t *)&ipv4_header, sizeof(ipv4_header)>>1);

    char *buffer = new char[ipv4_len];
    memcpy(buffer, &ipv4_header, ipv4_header_len);
    memcpy(buffer+ipv4_header_len, &udp_header, udp_header_len);
    memcpy(buffer+ipv4_header_len+udp_header_len, &udp_crc, udp_content_len);

    int send_flag = 0;
    if (!(*blk)) {
        send_flag = MSG_DONTWAIT;
    }
    if(sendto(socket_id, buffer, ipv4_len, send_flag, (sockaddr *)&sin_d, sizeof(sin_d)) < 0) {
        perror("sendto() error");
        exit(-1);
    }

    delete[] udp_check;
    delete[] buffer;

    return 0;
}

int send_ipv6_udp(int socket_id, IPv6_UDP *ipv6_udp, const bool *blk) {

    uint16_t udp_crc = htons(ipv6_udp->udp_crc);
    uint16_t udp_content = htons(ipv6_udp->udp_content);
    uint16_t udp_content_len = sizeof(ipv6_udp->udp_crc)+sizeof(ipv6_udp->udp_content);
    uint16_t udp_header_len = sizeof(UDP_Header);
    uint16_t udp_len = udp_header_len + udp_content_len;

    sockaddr_in6 sin_d{};
    memset(&sin_d, 0, sizeof(sin_d));
    sin_d.sin6_family = AF_INET6;
    sin_d.sin6_port = 0;
    sin_d.sin6_addr = ipv6_udp->ipv6_dip;

    UDP_Header udp_header{};
    udp_header.sport = htons(ipv6_udp->udp_sport);
    udp_header.dport = htons(ipv6_udp->udp_dport);
    udp_header.len = htons(udp_len);
    udp_header.crc = 0;

    UDP_TSDv6_Header udp_tsdv6_header{};
    uint16_t udp_tsdv6_header_len = sizeof(UDP_TSDv6_Header);
    udp_tsdv6_header.sip = ipv6_udp->ipv6_sip;
    udp_tsdv6_header.dip = ipv6_udp->ipv6_dip;
    udp_tsdv6_header.plen = udp_header.len;
    udp_tsdv6_header.zeros[0] = 0;
    udp_tsdv6_header.zeros[1] = 0;
    udp_tsdv6_header.zeros[2] = 0;
    udp_tsdv6_header.next_header = IPPROTO_UDP;


    uint16_t udp_check_len = udp_tsdv6_header_len + udp_len;
    uint16_t udp_alloc_len = udp_check_len;
    if (udp_check_len&1) {
        ++udp_alloc_len;
    }
    auto *udp_check = new uint16_t[udp_alloc_len>>1];
    if (udp_check_len&1) {
        memset(udp_check+(udp_check_len>>1), 0, sizeof(uint16_t));
    }
    memcpy(udp_check, &udp_tsdv6_header, udp_tsdv6_header_len);
    memcpy(udp_check+(udp_tsdv6_header_len>>1), &udp_header, udp_header_len);
    memcpy(udp_check+((udp_tsdv6_header_len+udp_header_len)>>1), &udp_content, sizeof(udp_content));
    memcpy(udp_check+((udp_tsdv6_header_len+udp_header_len)>>1)+sizeof(udp_content), &udp_crc, sizeof(udp_crc));
    uint16_t embed_crc = udp_checksum(udp_check, udp_alloc_len>>1);
    udp_header.crc = udp_crc;
    udp_crc = embed_crc;


    IPv6_Header ipv6_header{};
    uint16_t ipv6_header_len = sizeof(IPv6_Header);
    uint16_t ipv6_len = ipv6_header_len + udp_len;
    uint8_t version = 6;
    uint8_t traffic_class = 0;
    uint32_t flow_label = ipv6_udp->ipv6_flow_label;
    uint32_t vtf = 0;
    vtf |= ((version&0xf)<<28);
    vtf |= ((traffic_class&0xff)<<20);
    vtf |= (flow_label&0xfffff);
    ipv6_header.vtf = ntohl(vtf);
    ipv6_header.payload_length = udp_header.len;
    ipv6_header.next_header = IPPROTO_UDP;
    ipv6_header.hop_limit = ipv6_udp->ipv6_hop_limit;
    ipv6_header.sip = ipv6_udp->ipv6_sip;
    ipv6_header.dip = ipv6_udp->ipv6_dip;


    char *buffer = new char[ipv6_len];
    memcpy(buffer, &ipv6_header, ipv6_header_len);
    memcpy(buffer+ipv6_header_len, &udp_header, udp_header_len);
    memcpy(buffer+ipv6_header_len+udp_header_len, &udp_content, sizeof(udp_content));
    memcpy(buffer+ipv6_header_len+udp_header_len+sizeof(udp_content), &udp_crc, sizeof(udp_crc));

    int send_flag = 0;
    if (!(*blk)) {
        send_flag = MSG_DONTWAIT;
    }
    if(sendto(socket_id, buffer, ipv6_len, send_flag, (sockaddr *)&sin_d, sizeof(sin_d)) < 0) {
        perror("sendto() error");
        exit(-1);
    }

    delete[] udp_check;
    delete[] buffer;

    return 0;

}

int send_ipv4_tcp(int socket_id, IPv4_TCP *ipv4_tcp, const bool *blk) {
    auto now = std::chrono::high_resolution_clock::now();
    auto now_s = std::chrono::time_point_cast<std::chrono::seconds>(now).time_since_epoch().count();
    auto now_ms = std::chrono::time_point_cast<std::chrono::milliseconds>(now).time_since_epoch().count();

    sockaddr_in sin_d{};
    sin_d.sin_family = AF_INET;
    sin_d.sin_port = 0;
    sin_d.sin_addr.s_addr = ipv4_tcp->ipv4_dip.s_addr;

    TCP_Header tcp_header{};
    uint16_t tcp_len = 40, tcp_header_len = 20, tcp_opt_len = 20;
    tcp_header.sport = htons(ipv4_tcp->tcp_sport);
    tcp_header.dport = htons(ipv4_tcp->tcp_dport);

    tcp_header.seq_number = htonl(ipv4_tcp->tcp_seq);
    tcp_header.ack_number = htonl(0);
    tcp_header.ofn = tcp_len<<2;
    tcp_header.flag = 0x002;
    tcp_header.window_size = htons(5840);
    tcp_header.crc = 0;
    tcp_header.urgent_pointer = 0;

    TCP_OPT_Header tcp_opt_header{};
    tcp_opt_header.mss = 2;
    tcp_opt_header.mss_len = 4;
    tcp_opt_header.mss_value = htons(1460);
    tcp_opt_header.sack = 4;
    tcp_opt_header.sack_len = 2;
    tcp_opt_header.tso = 8;
    tcp_opt_header.tso_len = 10;
    tcp_opt_header.ts_value = ntohl(now_ms);
    tcp_opt_header.ts_reply = ntohl(0);
    tcp_opt_header.nop = 1;
    tcp_opt_header.ws = 3;
    tcp_opt_header.ws_len = 3;
    tcp_opt_header.ws_sc = 2;

    TCP_TSDv4_Header tcp_tsdv4_header{};
    uint16_t tcp_tsdv4_header_len = sizeof(TCP_TSDv4_Header);
    tcp_tsdv4_header.sip.s_addr = ipv4_tcp->ipv4_sip.s_addr;
    tcp_tsdv4_header.dip.s_addr = sin_d.sin_addr.s_addr;
    tcp_tsdv4_header.mbz = 0;
    tcp_tsdv4_header.ptcl = IPPROTO_TCP;
    tcp_tsdv4_header.plen = htons(tcp_len);

    uint16_t tcp_check_len = tcp_tsdv4_header_len + tcp_len;
    uint16_t tcp_alloc_len = tcp_check_len;
    if (tcp_check_len&1) {
        ++tcp_alloc_len;
    }
    auto *tcp_check = new uint16_t[tcp_alloc_len>>1];
    if (tcp_check_len&1) {
        memset(tcp_check+(tcp_check_len>>1), 0, sizeof(uint16_t));
    }
    memcpy(tcp_check, &tcp_tsdv4_header, tcp_tsdv4_header_len);
    memcpy(tcp_check+(tcp_tsdv4_header_len>>1), &tcp_header, tcp_header_len);
    memcpy(tcp_check+((tcp_tsdv4_header_len+tcp_header_len)>>1), &tcp_opt_header, tcp_opt_len);
    tcp_header.crc = tcp_checksum(tcp_check, tcp_alloc_len>>1);

    IPv4_Header ipv4_header{};
    uint16_t ipv4_header_len = sizeof(IPv4_Header);
    uint16_t ipv4_len = ipv4_header_len + tcp_len;
    ipv4_header.ihl = 5;
    ipv4_header.version = 4;
    ipv4_header.tos = 0;
    ipv4_header.tlen = htons(ipv4_len);
    ipv4_header.ident = htons(ipv4_tcp->ipv4_ident);
    ipv4_header.flags_offset = htons(0x0000);
    ipv4_header.ttl = ipv4_tcp->ipv4_ttl;
    ipv4_header.proto = IPPROTO_TCP;
    ipv4_header.crc = 0;
    ipv4_header.sip.s_addr = ipv4_tcp->ipv4_sip.s_addr;
    ipv4_header.dip.s_addr = sin_d.sin_addr.s_addr;

    ipv4_header.crc = ipv4_checksum((uint16_t *)&ipv4_header, sizeof(ipv4_header)>>1);

    char *buffer = new char[ipv4_len];
    memcpy(buffer, &ipv4_header, ipv4_header_len);
    memcpy(buffer+ipv4_header_len, &tcp_header, tcp_header_len);
    memcpy(buffer+ipv4_header_len+tcp_header_len, &tcp_opt_header, tcp_opt_len);

    int send_flag = 0;
    if (!(*blk)) {
        send_flag = MSG_DONTWAIT;
    }
    if(sendto(socket_id, buffer, ipv4_len, send_flag, (sockaddr *)&sin_d, sizeof(sin_d)) < 0) {
        perror("sendto() error");
        exit(-1);
    }

    delete[] tcp_check;
    delete[] buffer;

    return 0;
}

int send_ipv6_tcp(int socket_id, IPv6_TCP *ipv6_tcp, const bool *blk) {
    auto now = std::chrono::high_resolution_clock::now();
    auto now_s = std::chrono::time_point_cast<std::chrono::seconds>(now).time_since_epoch().count();
    auto now_ms = std::chrono::time_point_cast<std::chrono::milliseconds>(now).time_since_epoch().count();

    sockaddr_in6 sin_d{};
    memset(&sin_d, 0, sizeof(sin_d));
    sin_d.sin6_family = AF_INET6;
    sin_d.sin6_port = 0;
    sin_d.sin6_addr = ipv6_tcp->ipv6_dip;


    TCP_Header tcp_header{};
    uint16_t tcp_len = 40, tcp_header_len = 20, tcp_opt_len = 20;
    tcp_header.sport = htons(ipv6_tcp->tcp_sport);
    tcp_header.dport = htons(ipv6_tcp->tcp_dport);
    tcp_header.seq_number = htonl(ipv6_tcp->tcp_seq);
    tcp_header.ack_number = htonl(0);
    tcp_header.ofn = tcp_len<<2;
    tcp_header.flag = 0x002;
    tcp_header.window_size = htons(5760);
    tcp_header.crc = 0;
    tcp_header.urgent_pointer = 0;

    TCP_OPT_Header tcp_opt_header{};
    tcp_opt_header.mss = 2;
    tcp_opt_header.mss_len = 4;
    tcp_opt_header.mss_value = htons(1440);
    tcp_opt_header.sack = 4;
    tcp_opt_header.sack_len = 2;
    tcp_opt_header.tso = 8;
    tcp_opt_header.tso_len = 10;
    tcp_opt_header.ts_value = ntohl(now_ms);
    tcp_opt_header.ts_reply = ntohl(0);
    tcp_opt_header.nop = 1;
    tcp_opt_header.ws = 3;
    tcp_opt_header.ws_len = 3;
    tcp_opt_header.ws_sc = 2;

    TCP_TSDv6_Header tcp_tsdv6_header{};
    uint16_t tcp_tsdv6_header_len = sizeof(TCP_TSDv6_Header);
    tcp_tsdv6_header.sip = ipv6_tcp->ipv6_sip;
    tcp_tsdv6_header.dip = ipv6_tcp->ipv6_dip;
    tcp_tsdv6_header.plen = htons(tcp_len);
    tcp_tsdv6_header.zeros[0] = 0;
    tcp_tsdv6_header.zeros[1] = 0;
    tcp_tsdv6_header.zeros[2] = 0;
    tcp_tsdv6_header.next_header = IPPROTO_TCP;


    uint16_t tcp_check_len = tcp_tsdv6_header_len + tcp_len;
    uint16_t tcp_alloc_len = tcp_check_len;
    if (tcp_check_len&1) {
        ++tcp_alloc_len;
    }
    auto *tcp_check = new uint16_t[tcp_alloc_len>>1];
    if (tcp_check_len&1) {
        memset(tcp_check+(tcp_check_len>>1), 0, sizeof(uint16_t));
    }
    memcpy(tcp_check, &tcp_tsdv6_header, tcp_tsdv6_header_len);
    memcpy(tcp_check+(tcp_tsdv6_header_len>>1), &tcp_header, tcp_header_len);
    memcpy(tcp_check+((tcp_tsdv6_header_len+tcp_header_len)>>1), &tcp_opt_header, tcp_opt_len);
    tcp_header.crc = tcp_checksum(tcp_check, tcp_alloc_len>>1);

    IPv6_Header ipv6_header{};
    uint16_t ipv6_header_len = sizeof(IPv6_Header);
    uint16_t ipv6_len = ipv6_header_len + tcp_len;
    uint8_t version = 6;
    uint8_t traffic_class = 0;
    uint32_t flow_label = ipv6_tcp->ipv6_flow_label;
    uint32_t vtf = 0;
    vtf |= ((version&0xf)<<28);
    vtf |= ((traffic_class&0xff)<<20);
    vtf |= (flow_label&0xfffff);
    ipv6_header.vtf = ntohl(vtf);
    ipv6_header.payload_length = ntohs(tcp_len);
    ipv6_header.next_header = IPPROTO_TCP;
    ipv6_header.hop_limit = ipv6_tcp->ipv6_hop_limit;
    ipv6_header.sip = ipv6_tcp->ipv6_sip;
    ipv6_header.dip = ipv6_tcp->ipv6_dip;

    char *buffer = new char[ipv6_len];
    memcpy(buffer, &ipv6_header, ipv6_header_len);
    memcpy(buffer+ipv6_header_len, &tcp_header, tcp_header_len);
    memcpy(buffer+ipv6_header_len+tcp_header_len, &tcp_opt_header, tcp_opt_len);

    int send_flag = 0;
    if (!(*blk)) {
        send_flag = MSG_DONTWAIT;
    }
    if(sendto(socket_id, buffer, ipv6_len, send_flag, (sockaddr *)&sin_d, sizeof(sin_d)) < 0) {
        perror("sendto() error");
        exit(-1);
    }

    delete[] tcp_check;
    delete[] buffer;

    return 0;
}

int send_ipv6_icmpv6(int socket_id, IPv6_ICMPv6 *ipv6_icmpv6, const bool *blk) {
    uint16_t embed_content = htons(ipv6_icmpv6->icmpv6_content);

    sockaddr_in6 sin_d{};
    memset(&sin_d, 0, sizeof(sin_d));
    sin_d.sin6_family = AF_INET6;
    sin_d.sin6_port = 0;
    sin_d.sin6_addr = ipv6_icmpv6->ipv6_dip;

    ICMPv6_Header icmpv6_header{};
    uint16_t icmpv6_header_len = 8, icmpv6_content_len = sizeof(embed_content);
    uint16_t icmpv6_len = icmpv6_header_len + icmpv6_content_len;
    icmpv6_header.type = 128;
    icmpv6_header.code = 0;
    icmpv6_header.crc = 0;
    icmpv6_header.ident = htons(ipv6_icmpv6->icmpv6_ident);
    icmpv6_header.seq_number = htons(ipv6_icmpv6->icmpv6_seq);


    ICMPv6_TSDv6_Header icmpv6_tsdv6_header{};
    uint16_t icmpv6_tsdv6_header_len = sizeof(ICMPv6_TSDv6_Header);
    icmpv6_tsdv6_header.sip = ipv6_icmpv6->ipv6_sip;
    icmpv6_tsdv6_header.dip = ipv6_icmpv6->ipv6_dip;
    icmpv6_tsdv6_header.zeros[0] = 0;
    icmpv6_tsdv6_header.zeros[1] = 0;
    icmpv6_tsdv6_header.zeros[2] = 0;
    icmpv6_tsdv6_header.plen = ntohl(icmpv6_len);
    icmpv6_tsdv6_header.next_header = IPPROTO_ICMPV6;


    uint16_t icmpv6_check_len = icmpv6_len + icmpv6_tsdv6_header_len;
    uint16_t icmpv6_alloc_len = icmpv6_check_len;
    if (icmpv6_check_len&1) {
        ++icmpv6_alloc_len;
    }
    auto *icmpv6_check = new uint16_t[icmpv6_alloc_len>>1];
    if (icmpv6_check_len&1) {
        memset(icmpv6_check+(icmpv6_check_len>>1), 0, sizeof(uint16_t));
    }
    memcpy(icmpv6_check, &icmpv6_tsdv6_header, icmpv6_tsdv6_header_len);
    memcpy(icmpv6_check+(icmpv6_tsdv6_header_len>>1), &icmpv6_header, icmpv6_header_len);
    memcpy(icmpv6_check+(icmpv6_tsdv6_header_len>>1)+(icmpv6_header_len>>1), &embed_content, sizeof(embed_content));

    icmpv6_header.crc = icmpv6_checksum(icmpv6_check, icmpv6_alloc_len>>1);

    IPv6_Header ipv6_header{};
    uint16_t ipv6_header_len = sizeof(IPv6_Header);
    uint16_t ipv6_len = ipv6_header_len + icmpv6_len;
    uint8_t version = 6;
    uint8_t traffic_class = 0;
    uint32_t flow_label = ipv6_icmpv6->ipv6_flow_label;
    uint32_t vtf = 0;
    vtf |= ((version&0xf)<<28);
    vtf |= ((traffic_class&0xff)<<20);
    vtf |= (flow_label&0xfffff);
    ipv6_header.vtf = ntohl(vtf);
    ipv6_header.payload_length = ntohs(icmpv6_len);
    ipv6_header.next_header = IPPROTO_ICMPV6;
    ipv6_header.hop_limit = ipv6_icmpv6->ipv6_hop_limit;
    ipv6_header.sip = ipv6_icmpv6->ipv6_sip;
    ipv6_header.dip = ipv6_icmpv6->ipv6_dip;


    char *buffer = new char[ipv6_len];
    memcpy(buffer, &ipv6_header, ipv6_header_len);
    memcpy(buffer+ipv6_header_len, &icmpv6_header, icmpv6_header_len);
    memcpy(buffer+ipv6_header_len+icmpv6_header_len, &embed_content, sizeof(embed_content));

    int send_flag = 0;
    if (!(*blk)) {
        send_flag = MSG_DONTWAIT;
    }
    if(sendto(socket_id, buffer, ipv6_len, send_flag, (sockaddr *)&sin_d, sizeof(sin_d)) < 0) {
        perror("sendto() error");
        exit(-1);
    }

    delete[] icmpv6_check;
    delete[] buffer;

    return 0;
}

void run_proto_preprobe_ipv4(std::atomic<bool>* isCaptureDone, const int *pre_round, in_addr *ipv4_sip, std::vector<in_addr> *ipv4_dip_list, const int *max_ttl, const int *band_speed_limit, const bool *blk) {
    int start_wait_time = 1;
    std::cout << "----------------------------------------------------" << std::endl;
    std::cout << "Proto preprobe will start in " << start_wait_time << " seconds..." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(start_wait_time));

    int socket_id = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    if(socket_id < 0) {
        perror("socket() error");
        exit(-1);
    }

    auto start = std::chrono::steady_clock::now();
    IPv4_UDP ipv4_udp{};
    IPv4_TCP ipv4_tcp{};


    long long sended_probe = 0, total_probe = 1ll*(*pre_round)*(ipv4_dip_list->size())*(*max_ttl)*2;
    int progress = 0;

    for (int i = 0; i < *pre_round; ++i) {
        for (auto &ipv4_dip: (*ipv4_dip_list)) {
            for (int ipv4_ttl = 1; ipv4_ttl <= *max_ttl; ++ipv4_ttl) {
                ipv4_udp.ipv4_ttl = ipv4_ttl;
                ipv4_udp.ipv4_sip = *ipv4_sip;
                ipv4_udp.ipv4_dip = ipv4_dip;
                ipv4_udp.ipv4_ident = 114;
                ipv4_udp.udp_sport = 35265;
                ipv4_udp.udp_dport = 33434;
                ipv4_udp.udp_crc = 514;

                std::chrono::duration<double> duration{};
                while (true) {
                    auto end = std::chrono::steady_clock::now();
                    duration = std::chrono::duration_cast<std::chrono::duration<double>>(end - start);
                    if ((double)sended_probe/duration.count() > *band_speed_limit) {
                        std::this_thread::sleep_for(std::chrono::nanoseconds (5));
                    }
                    else {
                        break;
                    }
                }

                send_ipv4_udp(socket_id, &ipv4_udp, blk);
                ++sended_probe;
            }
            int cur_progress = 100.0*sended_probe/total_probe;
            if (cur_progress != progress) {
                progress = cur_progress;
                auto now = std::chrono::steady_clock::now();
                double total_time = std::chrono::duration_cast<std::chrono::duration<double>>(now - start).count();
                std::string str("send speed: " + std::to_string(int(sended_probe/total_time)) + "p/s, cost time: " + std::to_string(int(total_time)) + "s.");
                printProgress(progress, 100, str);
            }
        }
        for (auto &ipv4_dip: (*ipv4_dip_list)) {
            for (int ipv4_ttl = 1; ipv4_ttl <= *max_ttl; ++ipv4_ttl) {

                ipv4_tcp.ipv4_ttl = ipv4_ttl;
                ipv4_tcp.ipv4_sip = *ipv4_sip;
                ipv4_tcp.ipv4_dip = ipv4_dip;
                ipv4_tcp.ipv4_ident = 114;
                ipv4_tcp.tcp_sport = 35265;
                ipv4_tcp.tcp_dport = 33434;
                ipv4_tcp.tcp_seq = 514;

                std::chrono::duration<double> duration{};
                while (true) {
                    auto end = std::chrono::steady_clock::now();
                    duration = std::chrono::duration_cast<std::chrono::duration<double>>(end - start);
                    if ((double)sended_probe/duration.count() > *band_speed_limit) {
                        std::this_thread::sleep_for(std::chrono::nanoseconds (5));
                    }
                    else {
                        break;
                    }
                }

                send_ipv4_tcp(socket_id, &ipv4_tcp, blk);
                ++sended_probe;
            }
            int cur_progress = 100.0*sended_probe/total_probe;
            if (cur_progress != progress) {
                progress = cur_progress;
                auto now = std::chrono::steady_clock::now();
                double total_time = std::chrono::duration_cast<std::chrono::duration<double>>(now - start).count();
                std::string str("send speed: " + std::to_string(int(sended_probe/total_time)) + "p/s, cost time: " + std::to_string(int(total_time)) + "s.");
                printProgress(progress, 100, str);
            }
        }
    }
    std::cout << "\nProto preprobe completed." << std::endl;

    int end_wait_time = 3;

    std::cout << "Proto preprobe will end in " << end_wait_time << " seconds..." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(end_wait_time));

    isCaptureDone->store(true, std::memory_order_relaxed);

    std::this_thread::sleep_for(std::chrono::seconds(1));

    close(socket_id);

}

void run_proto_preprobe_ipv6(std::atomic<bool>* isCaptureDone, const int *pre_round, in6_addr *ipv6_sip, std::vector<in6_addr> *ipv6_dip_list, const int *max_ttl, const int *band_speed_limit, const bool *blk) {
    int start_wait_time = 1;
    std::cout << "----------------------------------------------------" << std::endl;
    std::cout << "Proto preprobe will start in " << start_wait_time << " seconds..." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(start_wait_time));

    int socket_id = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);

    if(socket_id < 0) {
        perror("socket() error");
        exit(-1);
    }

    auto start = std::chrono::steady_clock::now();
    IPv6_UDP ipv6_udp{};
    IPv6_TCP ipv6_tcp{};
    IPv6_ICMPv6 ipv6_icmpv6{};

    long long sended_probe = 0, total_probe = 1ll*(*pre_round)*(ipv6_dip_list->size())*(*max_ttl)*3;
    int progress = 0;

    for (int i = 0; i < *pre_round; ++i) {
        for (auto &ipv6_dip: (*ipv6_dip_list)) {
            for (int ipv6_ttl = 1; ipv6_ttl <= *max_ttl; ++ipv6_ttl) {
                ipv6_udp.ipv6_hop_limit = ipv6_ttl;
                ipv6_udp.ipv6_sip = *ipv6_sip;
                ipv6_udp.ipv6_dip = ipv6_dip;
                ipv6_udp.ipv6_flow_label = 114;
                ipv6_udp.udp_sport = 35265;
                ipv6_udp.udp_dport = 33434;
                ipv6_udp.udp_crc = 514;
                ipv6_udp.udp_content = 0xffff;

                std::chrono::duration<double> duration{};
                while (true) {
                    auto end = std::chrono::steady_clock::now();
                    duration = std::chrono::duration_cast<std::chrono::duration<double>>(end - start);
                    if ((double)sended_probe/duration.count() > *band_speed_limit) {
                        std::this_thread::sleep_for(std::chrono::nanoseconds (5));
                    }
                    else {
                        break;
                    }
                }

                send_ipv6_udp(socket_id, &ipv6_udp, blk);
                ++sended_probe;
            }
            int cur_progress = 100.0*sended_probe/total_probe;
            if (cur_progress != progress) {
                progress = cur_progress;
                auto now = std::chrono::steady_clock::now();
                double total_time = std::chrono::duration_cast<std::chrono::duration<double>>(now - start).count();
                std::string str("send speed: " + std::to_string(int(sended_probe/total_time)) + "p/s, cost time: " + std::to_string(int(total_time)) + "s.");
                printProgress(progress, 100, str);
            }
        }
        for (auto &ipv6_dip: (*ipv6_dip_list)) {
            for (int ipv6_ttl = 1; ipv6_ttl <= *max_ttl; ++ipv6_ttl) {

                ipv6_tcp.ipv6_sip = *ipv6_sip;
                ipv6_tcp.ipv6_dip = ipv6_dip;
                ipv6_tcp.ipv6_hop_limit = ipv6_ttl;
                ipv6_tcp.ipv6_flow_label = 114;
                ipv6_tcp.tcp_sport = 35265;
                ipv6_tcp.tcp_dport = 33434;
                ipv6_tcp.tcp_seq = 514;

                std::chrono::duration<double> duration{};
                while (true) {
                    auto end = std::chrono::steady_clock::now();
                    duration = std::chrono::duration_cast<std::chrono::duration<double>>(end - start);
                    if ((double)sended_probe/duration.count() > *band_speed_limit) {
                        std::this_thread::sleep_for(std::chrono::nanoseconds (5));
                    }
                    else {
                        break;
                    }
                }

                send_ipv6_tcp(socket_id, &ipv6_tcp, blk);
                ++sended_probe;

                int cur_progress = 100.0*sended_probe/total_probe;
                if (cur_progress != progress) {
                    progress = cur_progress;
                    auto now = std::chrono::steady_clock::now();
                    double total_time = std::chrono::duration_cast<std::chrono::duration<double>>(now - start).count();
                    std::string str("send speed: " + std::to_string(int(sended_probe/total_time)) + "p/s, cost time: " + std::to_string(int(total_time)) + "s.");
                    printProgress(progress, 100, str);
                }
            }
            int cur_progress = 100.0*sended_probe/total_probe;
            if (cur_progress != progress) {
                progress = cur_progress;
                auto now = std::chrono::steady_clock::now();
                double total_time = std::chrono::duration_cast<std::chrono::duration<double>>(now - start).count();
                std::string str("send speed: " + std::to_string(int(sended_probe/total_time)) + "p/s, cost time: " + std::to_string(int(total_time)) + "s.");
                printProgress(progress, 100, str);
            }
        }
        for (auto &ipv6_dip: (*ipv6_dip_list)) {
            for (int ipv6_ttl = 1; ipv6_ttl <= *max_ttl; ++ipv6_ttl) {

                ipv6_icmpv6.ipv6_sip = *ipv6_sip;
                ipv6_icmpv6.ipv6_dip = ipv6_dip;
                ipv6_icmpv6.ipv6_hop_limit = ipv6_ttl;
                ipv6_icmpv6.ipv6_flow_label = 114;
                ipv6_icmpv6.icmpv6_ident = 35265;
                ipv6_icmpv6.icmpv6_seq = 33434;
                ipv6_icmpv6.icmpv6_content = 514;

                std::chrono::duration<double> duration{};
                while (true) {
                    auto end = std::chrono::steady_clock::now();
                    duration = std::chrono::duration_cast<std::chrono::duration<double>>(end - start);
                    if ((double)sended_probe/duration.count() > *band_speed_limit) {
                        std::this_thread::sleep_for(std::chrono::nanoseconds (5));
                    }
                    else {
                        break;
                    }
                }

                send_ipv6_icmpv6(socket_id, &ipv6_icmpv6, blk);
                ++sended_probe;

                int cur_progress = 100.0*sended_probe/total_probe;
                if (cur_progress != progress) {
                    progress = cur_progress;
                    auto now = std::chrono::steady_clock::now();
                    double total_time = std::chrono::duration_cast<std::chrono::duration<double>>(now - start).count();
                    std::string str("send speed: " + std::to_string(int(sended_probe/total_time)) + "p/s, cost time: " + std::to_string(int(total_time)) + "s.");
                    printProgress(progress, 100, str);
                }
            }
            int cur_progress = 100.0*sended_probe/total_probe;
            if (cur_progress != progress) {
                progress = cur_progress;
                auto now = std::chrono::steady_clock::now();
                double total_time = std::chrono::duration_cast<std::chrono::duration<double>>(now - start).count();
                std::string str("send speed: " + std::to_string(int(sended_probe/total_time)) + "p/s, cost time: " + std::to_string(int(total_time)) + "s.");
                printProgress(progress, 100, str);
            }
        }
    }
    std::cout << "\nProto preprobe completed." << std::endl;

    int end_wait_time = 3;

    std::cout << "Proto preprobe will end in " << end_wait_time << " seconds..." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(end_wait_time));
    isCaptureDone->store(true, std::memory_order_relaxed);

    std::this_thread::sleep_for(std::chrono::seconds(1));

    close(socket_id);
}

void packet_process_proto_preprobe_ipv4(std::atomic<bool>* isCaptureDone, std::queue<Packet_Information *> *check_queue, std::mutex *check_queue_mutex, in_addr *s_addrv4, std::unordered_map<in_addr, IPv4_Pre_Probe, V4AddrHash, V4AddrEqual> *pre_probe_map, std::mutex *pre_probe_map_mutex) {
    while (!isCaptureDone->load(std::memory_order_acquire)) {

        Packet_Information *current_packet = nullptr;

        std::unique_lock<std::mutex> check_queue_lock(*check_queue_mutex);
        if (!check_queue->empty()) {
            current_packet = check_queue->front();
            check_queue->pop();
        }
        check_queue_lock.unlock();

        if (current_packet == nullptr) {
            continue;
        }

        auto *ipv4Header = (IPv4_Header *) (current_packet->packet + 14);
        in_addr ex_d_addrv4 = ipv4Header->dip;
        in_addr ex_s_addrv4 = ipv4Header->sip;
        if (ipv4_address_equal(ex_d_addrv4, *s_addrv4) && ipv4Header->proto == IPPROTO_ICMP) {
            auto *icmpv4Header = (ICMPv4_Header *) ((u_char *) ipv4Header + ipv4Header->ihl * 4);
            if (icmpv4Header->type == ICMP_TIMXCEED) {
                auto *innerIpv4Header = (IPv4_Header *) ((u_char *) icmpv4Header + 8);
                in_addr in_d_addrv4 = innerIpv4Header->dip;
                std::unique_lock<std::mutex> pre_probe_map_lock0(*pre_probe_map_mutex);
                if (pre_probe_map->find(in_d_addrv4) != pre_probe_map->end()) {
                    if (innerIpv4Header->proto == IPPROTO_UDP) {
                        (*pre_probe_map)[in_d_addrv4].proto_response["udp"].insert(ex_s_addrv4);
                    }
                    else if (innerIpv4Header->proto == IPPROTO_TCP) {
                        (*pre_probe_map)[in_d_addrv4].proto_response["tcp"].insert(ex_s_addrv4);
                    }
                }
                pre_probe_map_lock0.unlock();
            }
        }
        delete[] current_packet->packet;
        delete current_packet;
    }
}

void packet_process_proto_preprobe_ipv6(std::atomic<bool>* isCaptureDone, std::queue<Packet_Information *> *check_queue, std::mutex *check_queue_mutex, in6_addr *s_addrv6, std::unordered_map<in6_addr, IPv6_Pre_Probe, V6AddrHash, V6AddrEqual> *pre_probe_map, std::mutex *pre_probe_map_mutex) {
    while (!isCaptureDone->load(std::memory_order_acquire)) {

        Packet_Information *current_packet = nullptr;

        std::unique_lock<std::mutex> check_queue_lock(*check_queue_mutex);
        if (!check_queue->empty()) {
            current_packet = check_queue->front();
            check_queue->pop();
        }
        check_queue_lock.unlock();

        if (current_packet == nullptr) {
            continue;
        }

        auto *ipv6Header = (IPv6_Header *) (current_packet->packet + 14);
        in6_addr ex_d_addrv6 = ipv6Header->dip;
        in6_addr ex_s_addrv6 = ipv6Header->sip;

        if (ipv6_address_equal(ex_d_addrv6, *s_addrv6) && ipv6Header->next_header == IPPROTO_ICMPV6) {
            auto *icmpv6Header = (ICMPv6_Header *) ((u_char *) ipv6Header + 40);
            if (icmpv6Header->type == ICMP6_TIME_EXCEEDED) {
                auto *innerIpv6Header = (IPv6_Header *) ((u_char *) icmpv6Header + 8);
                in6_addr in_d_addrv6 = innerIpv6Header->dip;
                std::unique_lock<std::mutex> pre_probe_map_lock0(*pre_probe_map_mutex);
                if (pre_probe_map->find(in_d_addrv6) != pre_probe_map->end()) {
                    if (innerIpv6Header->next_header == IPPROTO_UDP) {
                        (*pre_probe_map)[in_d_addrv6].proto_response["udp"].insert(ex_s_addrv6);
                    }
                    else if (innerIpv6Header->next_header == IPPROTO_TCP) {
                        (*pre_probe_map)[in_d_addrv6].proto_response["tcp"].insert(ex_s_addrv6);
                    }
                    else if (innerIpv6Header->next_header == IPPROTO_ICMPV6) {
                        (*pre_probe_map)[in_d_addrv6].proto_response["icmpv6"].insert(ex_s_addrv6);
                    }
                }
                pre_probe_map_lock0.unlock();
            }
        }
        delete[] current_packet->packet;
        delete current_packet;
    }
}

void run_field_preprobe_ipv4(std::unordered_map<in_addr, IPv4_Field_Adapt, V4AddrHash, V4AddrEqual> *ipv4_adapt_map, std::atomic<bool>* isCaptureDone, const int *pre_round, in_addr *ipv4_sip, std::vector<in_addr> *ipv4_dip_list, const int *max_ttl, const int *band_speed_limit, const bool *blk) {
    int start_wait_time = 1;
    std::cout << "----------------------------------------------------" << std::endl;
    std::cout << "Field preprobe will start in " << start_wait_time << " seconds..." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(start_wait_time));

    int socket_id = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    if(socket_id < 0) {
        perror("socket() error");
        exit(-1);
    }

    auto start = std::chrono::steady_clock::now();
    IPv4_UDP ipv4_udp{};
    IPv4_TCP ipv4_tcp{};

    long long sended_probe = 0, total_probe = 0;
    int progress = 0;

    for (auto &ipv4_dip: (*ipv4_dip_list)) {
        if ((*ipv4_adapt_map)[ipv4_dip].target_proto == "udp") {
            total_probe += 1ll*(*max_ttl)*(*pre_round+4);
        }
        else {
            total_probe += 1ll*(*max_ttl)*(*pre_round+4);
        }
    }

    for (auto &ipv4_dip: (*ipv4_dip_list)) {
        for (int ipv4_ttl = 1; ipv4_ttl <= *max_ttl; ++ipv4_ttl) {
            if ((*ipv4_adapt_map)[ipv4_dip].target_proto == "udp") {
                for (int i = 0; i < *pre_round; ++i) {
                    ipv4_udp.ipv4_ttl = ipv4_ttl;
                    ipv4_udp.ipv4_sip = *ipv4_sip;
                    ipv4_udp.ipv4_dip = ipv4_dip;
                    ipv4_udp.ipv4_ident = 114;
                    ipv4_udp.udp_sport = 35265;
                    ipv4_udp.udp_dport = 33434;
                    ipv4_udp.udp_crc = 514;
                    std::chrono::duration<double> duration{};
                    while (true) {
                        auto end = std::chrono::steady_clock::now();
                        duration = std::chrono::duration_cast<std::chrono::duration<double>>(end - start);
                        if ((double)sended_probe/duration.count() > *band_speed_limit) {
                            std::this_thread::sleep_for(std::chrono::nanoseconds (5));
                        }
                        else {
                            break;
                        }
                    }
                    send_ipv4_udp(socket_id, &ipv4_udp, blk);
                    ++sended_probe;
                }
                {
                    ipv4_udp.ipv4_ttl = ipv4_ttl;
                    ipv4_udp.ipv4_sip = *ipv4_sip;
                    ipv4_udp.ipv4_dip = ipv4_dip;
                    ipv4_udp.ipv4_ident = 411;
                    ipv4_udp.udp_sport = 35265;
                    ipv4_udp.udp_dport = 33434;
                    ipv4_udp.udp_crc = 514;
                    std::chrono::duration<double> duration{};
                    while (true) {
                        auto end = std::chrono::steady_clock::now();
                        duration = std::chrono::duration_cast<std::chrono::duration<double>>(end - start);
                        if ((double)sended_probe/duration.count() > *band_speed_limit) {
                            std::this_thread::sleep_for(std::chrono::nanoseconds (5));
                        }
                        else {
                            break;
                        }
                    }
                    send_ipv4_udp(socket_id, &ipv4_udp, blk);
                    ++sended_probe;
                }
                {
                    ipv4_udp.ipv4_ttl = ipv4_ttl;
                    ipv4_udp.ipv4_sip = *ipv4_sip;
                    ipv4_udp.ipv4_dip = ipv4_dip;
                    ipv4_udp.ipv4_ident = 114;
                    ipv4_udp.udp_sport = 35265;
                    ipv4_udp.udp_dport = 33434;
                    ipv4_udp.udp_crc = 415;
                    std::chrono::duration<double> duration{};
                    while (true) {
                        auto end = std::chrono::steady_clock::now();
                        duration = std::chrono::duration_cast<std::chrono::duration<double>>(end - start);
                        if ((double)sended_probe/duration.count() > *band_speed_limit) {
                            std::this_thread::sleep_for(std::chrono::nanoseconds (5));
                        }
                        else {
                            break;
                        }
                    }
                    send_ipv4_udp(socket_id, &ipv4_udp, blk);
                    ++sended_probe;
                }
                {
                    ipv4_udp.ipv4_ttl = ipv4_ttl;
                    ipv4_udp.ipv4_sip = *ipv4_sip;
                    ipv4_udp.ipv4_dip = ipv4_dip;
                    ipv4_udp.ipv4_ident = 114;
                    ipv4_udp.udp_sport = 46376;
                    ipv4_udp.udp_dport = 33434;
                    ipv4_udp.udp_crc = 514;
                    std::chrono::duration<double> duration{};
                    while (true) {
                        auto end = std::chrono::steady_clock::now();
                        duration = std::chrono::duration_cast<std::chrono::duration<double>>(end - start);
                        if ((double)sended_probe/duration.count() > *band_speed_limit) {
                            std::this_thread::sleep_for(std::chrono::nanoseconds (5));
                        }
                        else {
                            break;
                        }
                    }
                    send_ipv4_udp(socket_id, &ipv4_udp, blk);
                    ++sended_probe;
                }
                {
                    ipv4_udp.ipv4_ttl = ipv4_ttl;
                    ipv4_udp.ipv4_sip = *ipv4_sip;
                    ipv4_udp.ipv4_dip = ipv4_dip;
                    ipv4_udp.ipv4_ident = 114;
                    ipv4_udp.udp_sport = 35265;
                    ipv4_udp.udp_dport = 44545;
                    ipv4_udp.udp_crc = 514;
                    std::chrono::duration<double> duration{};
                    while (true) {
                        auto end = std::chrono::steady_clock::now();
                        duration = std::chrono::duration_cast<std::chrono::duration<double>>(end - start);
                        if ((double)sended_probe/duration.count() > *band_speed_limit) {
                            std::this_thread::sleep_for(std::chrono::nanoseconds (5));
                        }
                        else {
                            break;
                        }
                    }
                    send_ipv4_udp(socket_id, &ipv4_udp, blk);
                    ++sended_probe;
                }
            }
            else {
                for (int i = 0; i < *pre_round; ++i) {
                    ipv4_tcp.ipv4_ttl = ipv4_ttl;
                    ipv4_tcp.ipv4_sip = *ipv4_sip;
                    ipv4_tcp.ipv4_dip = ipv4_dip;
                    ipv4_tcp.ipv4_ident = 114;
                    ipv4_tcp.tcp_sport = 35265;
                    ipv4_tcp.tcp_dport = 33434;
                    ipv4_tcp.tcp_seq = 514;

                    std::chrono::duration<double> duration{};
                    while (true) {
                        auto end = std::chrono::steady_clock::now();
                        duration = std::chrono::duration_cast<std::chrono::duration<double>>(end - start);
                        if ((double)sended_probe/duration.count() > *band_speed_limit) {
                            std::this_thread::sleep_for(std::chrono::nanoseconds (5));
                        }
                        else {
                            break;
                        }
                    }

                    send_ipv4_tcp(socket_id, &ipv4_tcp, blk);
                    ++sended_probe;
                }
                {
                    ipv4_tcp.ipv4_ttl = ipv4_ttl;
                    ipv4_tcp.ipv4_sip = *ipv4_sip;
                    ipv4_tcp.ipv4_dip = ipv4_dip;
                    ipv4_tcp.ipv4_ident = 411;
                    ipv4_tcp.tcp_sport = 35265;
                    ipv4_tcp.tcp_dport = 33434;
                    ipv4_tcp.tcp_seq = 514;

                    std::chrono::duration<double> duration{};
                    while (true) {
                        auto end = std::chrono::steady_clock::now();
                        duration = std::chrono::duration_cast<std::chrono::duration<double>>(end - start);
                        if ((double)sended_probe/duration.count() > *band_speed_limit) {
                            std::this_thread::sleep_for(std::chrono::nanoseconds (5));
                        }
                        else {
                            break;
                        }
                    }

                    send_ipv4_tcp(socket_id, &ipv4_tcp, blk);
                    ++sended_probe;
                }
                {
                    ipv4_tcp.ipv4_ttl = ipv4_ttl;
                    ipv4_tcp.ipv4_sip = *ipv4_sip;
                    ipv4_tcp.ipv4_dip = ipv4_dip;
                    ipv4_tcp.ipv4_ident = 114;
                    ipv4_tcp.tcp_sport = 46376;
                    ipv4_tcp.tcp_dport = 33434;
                    ipv4_tcp.tcp_seq = 514;

                    std::chrono::duration<double> duration{};
                    while (true) {
                        auto end = std::chrono::steady_clock::now();
                        duration = std::chrono::duration_cast<std::chrono::duration<double>>(end - start);
                        if ((double)sended_probe/duration.count() > *band_speed_limit) {
                            std::this_thread::sleep_for(std::chrono::nanoseconds (5));
                        }
                        else {
                            break;
                        }
                    }

                    send_ipv4_tcp(socket_id, &ipv4_tcp, blk);
                    ++sended_probe;
                }
                {
                    ipv4_tcp.ipv4_ttl = ipv4_ttl;
                    ipv4_tcp.ipv4_sip = *ipv4_sip;
                    ipv4_tcp.ipv4_dip = ipv4_dip;
                    ipv4_tcp.ipv4_ident = 114;
                    ipv4_tcp.tcp_sport = 35265;
                    ipv4_tcp.tcp_dport = 44545;
                    ipv4_tcp.tcp_seq = 514;

                    std::chrono::duration<double> duration{};
                    while (true) {
                        auto end = std::chrono::steady_clock::now();
                        duration = std::chrono::duration_cast<std::chrono::duration<double>>(end - start);
                        if ((double)sended_probe/duration.count() > *band_speed_limit) {
                            std::this_thread::sleep_for(std::chrono::nanoseconds (5));
                        }
                        else {
                            break;
                        }
                    }

                    send_ipv4_tcp(socket_id, &ipv4_tcp, blk);
                    ++sended_probe;
                }
                {
                    ipv4_tcp.ipv4_ttl = ipv4_ttl;
                    ipv4_tcp.ipv4_sip = *ipv4_sip;
                    ipv4_tcp.ipv4_dip = ipv4_dip;
                    ipv4_tcp.ipv4_ident = 114;
                    ipv4_tcp.tcp_sport = 35265;
                    ipv4_tcp.tcp_dport = 33434;
                    ipv4_tcp.tcp_seq = 415;

                    std::chrono::duration<double> duration{};
                    while (true) {
                        auto end = std::chrono::steady_clock::now();
                        duration = std::chrono::duration_cast<std::chrono::duration<double>>(end - start);
                        if ((double)sended_probe/duration.count() > *band_speed_limit) {
                            std::this_thread::sleep_for(std::chrono::nanoseconds (5));
                        }
                        else {
                            break;
                        }
                    }

                    send_ipv4_tcp(socket_id, &ipv4_tcp, blk);
                    ++sended_probe;
                }
            }
        }
        int cur_progress = 100.0*sended_probe/total_probe;
        if (cur_progress != progress) {
            progress = cur_progress;
            auto now = std::chrono::steady_clock::now();
            double total_time = std::chrono::duration_cast<std::chrono::duration<double>>(now - start).count();
            std::string str("send speed: " + std::to_string(int(sended_probe/total_time)) + "p/s, cost time: " + std::to_string(int(total_time)) + "s.");
            printProgress(progress, 100, str);
        }
    }

    std::cout << "\nField preprobe completed." << std::endl;

    int end_wait_time = 3;

    std::cout << "Field preprobe will end in " << end_wait_time << " seconds..." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(end_wait_time));

    isCaptureDone->store(true, std::memory_order_relaxed);

    std::this_thread::sleep_for(std::chrono::seconds(1));

    close(socket_id);
}

void run_field_preprobe_ipv6(std::unordered_map<in6_addr, IPv6_Field_Adapt, V6AddrHash, V6AddrEqual> *ipv6_adapt_map, std::atomic<bool>* isCaptureDone, const int *pre_round, in6_addr *ipv6_sip, std::vector<in6_addr> *ipv6_dip_list, const int *max_ttl, const int *band_speed_limit, const bool *blk) {
    int start_wait_time = 1;
    std::cout << "----------------------------------------------------" << std::endl;
    std::cout << "Field preprobe will start in " << start_wait_time << " seconds..." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(start_wait_time));

    int socket_id = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);

    if(socket_id < 0) {
        perror("socket() error");
        exit(-1);
    }

    auto start = std::chrono::steady_clock::now();
    IPv6_UDP ipv6_udp{};
    IPv6_TCP ipv6_tcp{};
    IPv6_ICMPv6 ipv6_icmpv6{};

    long long sended_probe = 0, total_probe = 0;
    int progress = 0;

    for (auto &ipv4_dip: (*ipv6_dip_list)) {
        if ((*ipv6_adapt_map)[ipv4_dip].target_proto == "udp") {
            total_probe += 1ll*(*max_ttl)*(*pre_round+4);
        }
        else if ((*ipv6_adapt_map)[ipv4_dip].target_proto == "tcp") {
            total_probe += 1ll*(*max_ttl)*(*pre_round+4);
        }
        else {
            total_probe += 1ll*(*max_ttl)*(*pre_round+4);
        }
    }

    for (auto &ipv6_dip: (*ipv6_dip_list)) {
        for (int ipv6_ttl = 1; ipv6_ttl <= *max_ttl; ++ipv6_ttl) {
            if ((*ipv6_adapt_map)[ipv6_dip].target_proto == "udp") {
                for (int i = 0; i < *pre_round; ++i) {
                    ipv6_udp.ipv6_hop_limit = ipv6_ttl;
                    ipv6_udp.ipv6_sip = *ipv6_sip;
                    ipv6_udp.ipv6_dip = ipv6_dip;
                    ipv6_udp.ipv6_flow_label = 114;
                    ipv6_udp.udp_sport = 35265;
                    ipv6_udp.udp_dport = 33434;
                    ipv6_udp.udp_crc = 514;
                    ipv6_udp.udp_content = 0xffff;
                    std::chrono::duration<double> duration{};
                    while (true) {
                        auto end = std::chrono::steady_clock::now();
                        duration = std::chrono::duration_cast<std::chrono::duration<double>>(end - start);
                        if ((double)sended_probe/duration.count() > *band_speed_limit) {
                            std::this_thread::sleep_for(std::chrono::nanoseconds (5));
                        }
                        else {
                            break;
                        }
                    }
                    send_ipv6_udp(socket_id, &ipv6_udp, blk);
                    ++sended_probe;
                }
                {
                    ipv6_udp.ipv6_hop_limit = ipv6_ttl;
                    ipv6_udp.ipv6_sip = *ipv6_sip;
                    ipv6_udp.ipv6_dip = ipv6_dip;
                    ipv6_udp.ipv6_flow_label = 411;
                    ipv6_udp.udp_sport = 35265;
                    ipv6_udp.udp_dport = 33434;
                    ipv6_udp.udp_crc = 514;
                    ipv6_udp.udp_content = 0xffff;
                    std::chrono::duration<double> duration{};
                    while (true) {
                        auto end = std::chrono::steady_clock::now();
                        duration = std::chrono::duration_cast<std::chrono::duration<double>>(end - start);
                        if ((double)sended_probe/duration.count() > *band_speed_limit) {
                            std::this_thread::sleep_for(std::chrono::nanoseconds (5));
                        }
                        else {
                            break;
                        }
                    }
                    send_ipv6_udp(socket_id, &ipv6_udp, blk);
                    ++sended_probe;
                }
                {
                    ipv6_udp.ipv6_hop_limit = ipv6_ttl;
                    ipv6_udp.ipv6_sip = *ipv6_sip;
                    ipv6_udp.ipv6_dip = ipv6_dip;
                    ipv6_udp.ipv6_flow_label = 114;
                    ipv6_udp.udp_sport = 46376;
                    ipv6_udp.udp_dport = 33434;
                    ipv6_udp.udp_crc = 514;
                    ipv6_udp.udp_content = 0xffff;
                    std::chrono::duration<double> duration{};
                    while (true) {
                        auto end = std::chrono::steady_clock::now();
                        duration = std::chrono::duration_cast<std::chrono::duration<double>>(end - start);
                        if ((double)sended_probe/duration.count() > *band_speed_limit) {
                            std::this_thread::sleep_for(std::chrono::nanoseconds (5));
                        }
                        else {
                            break;
                        }
                    }
                    send_ipv6_udp(socket_id, &ipv6_udp, blk);
                    ++sended_probe;
                }
                {
                    ipv6_udp.ipv6_hop_limit = ipv6_ttl;
                    ipv6_udp.ipv6_sip = *ipv6_sip;
                    ipv6_udp.ipv6_dip = ipv6_dip;
                    ipv6_udp.ipv6_flow_label = 114;
                    ipv6_udp.udp_sport = 35265;
                    ipv6_udp.udp_dport = 44545;
                    ipv6_udp.udp_crc = 514;
                    ipv6_udp.udp_content = 0xffff;
                    std::chrono::duration<double> duration{};
                    while (true) {
                        auto end = std::chrono::steady_clock::now();
                        duration = std::chrono::duration_cast<std::chrono::duration<double>>(end - start);
                        if ((double)sended_probe/duration.count() > *band_speed_limit) {
                            std::this_thread::sleep_for(std::chrono::nanoseconds (5));
                        }
                        else {
                            break;
                        }
                    }
                    send_ipv6_udp(socket_id, &ipv6_udp, blk);
                    ++sended_probe;
                }
                {
                    ipv6_udp.ipv6_hop_limit = ipv6_ttl;
                    ipv6_udp.ipv6_sip = *ipv6_sip;
                    ipv6_udp.ipv6_dip = ipv6_dip;
                    ipv6_udp.ipv6_flow_label = 114;
                    ipv6_udp.udp_sport = 35265;
                    ipv6_udp.udp_dport = 33434;
                    ipv6_udp.udp_crc = 415;
                    ipv6_udp.udp_content = 0xffff;
                    std::chrono::duration<double> duration{};
                    while (true) {
                        auto end = std::chrono::steady_clock::now();
                        duration = std::chrono::duration_cast<std::chrono::duration<double>>(end - start);
                        if ((double)sended_probe/duration.count() > *band_speed_limit) {
                            std::this_thread::sleep_for(std::chrono::nanoseconds (5));
                        }
                        else {
                            break;
                        }
                    }
                    send_ipv6_udp(socket_id, &ipv6_udp, blk);
                    ++sended_probe;
                }
            }
            else if ((*ipv6_adapt_map)[ipv6_dip].target_proto == "tcp") {
                for (int i = 0; i < *pre_round; ++i) {

                    ipv6_tcp.ipv6_sip = *ipv6_sip;
                    ipv6_tcp.ipv6_dip = ipv6_dip;
                    ipv6_tcp.ipv6_hop_limit = ipv6_ttl;
                    ipv6_tcp.ipv6_flow_label = 114;
                    ipv6_tcp.tcp_sport = 35265;
                    ipv6_tcp.tcp_dport = 33434;
                    ipv6_tcp.tcp_seq = 514;

                    std::chrono::duration<double> duration{};
                    while (true) {
                        auto end = std::chrono::steady_clock::now();
                        duration = std::chrono::duration_cast<std::chrono::duration<double>>(end - start);
                        if ((double)sended_probe/duration.count() > *band_speed_limit) {
                            std::this_thread::sleep_for(std::chrono::nanoseconds (5));
                        }
                        else {
                            break;
                        }
                    }
                    send_ipv6_tcp(socket_id, &ipv6_tcp, blk);
                    ++sended_probe;
                }
                {
                    ipv6_tcp.ipv6_sip = *ipv6_sip;
                    ipv6_tcp.ipv6_dip = ipv6_dip;
                    ipv6_tcp.ipv6_hop_limit = ipv6_ttl;
                    ipv6_tcp.ipv6_flow_label = 411;
                    ipv6_tcp.tcp_sport = 35265;
                    ipv6_tcp.tcp_dport = 33434;
                    ipv6_tcp.tcp_seq = 514;

                    std::chrono::duration<double> duration{};
                    while (true) {
                        auto end = std::chrono::steady_clock::now();
                        duration = std::chrono::duration_cast<std::chrono::duration<double>>(end - start);
                        if ((double)sended_probe/duration.count() > *band_speed_limit) {
                            std::this_thread::sleep_for(std::chrono::nanoseconds (5));
                        }
                        else {
                            break;
                        }
                    }
                    send_ipv6_tcp(socket_id, &ipv6_tcp, blk);
                    ++sended_probe;
                }
                {
                    ipv6_tcp.ipv6_sip = *ipv6_sip;
                    ipv6_tcp.ipv6_dip = ipv6_dip;
                    ipv6_tcp.ipv6_hop_limit = ipv6_ttl;
                    ipv6_tcp.ipv6_flow_label = 114;
                    ipv6_tcp.tcp_sport = 46376;
                    ipv6_tcp.tcp_dport = 33434;
                    ipv6_tcp.tcp_seq = 514;

                    std::chrono::duration<double> duration{};
                    while (true) {
                        auto end = std::chrono::steady_clock::now();
                        duration = std::chrono::duration_cast<std::chrono::duration<double>>(end - start);
                        if ((double)sended_probe/duration.count() > *band_speed_limit) {
                            std::this_thread::sleep_for(std::chrono::nanoseconds (5));
                        }
                        else {
                            break;
                        }
                    }
                    send_ipv6_tcp(socket_id, &ipv6_tcp, blk);
                    ++sended_probe;
                }
                {
                    ipv6_tcp.ipv6_sip = *ipv6_sip;
                    ipv6_tcp.ipv6_dip = ipv6_dip;
                    ipv6_tcp.ipv6_hop_limit = ipv6_ttl;
                    ipv6_tcp.ipv6_flow_label = 114;
                    ipv6_tcp.tcp_sport = 35265;
                    ipv6_tcp.tcp_dport = 44545;
                    ipv6_tcp.tcp_seq = 514;

                    std::chrono::duration<double> duration{};
                    while (true) {
                        auto end = std::chrono::steady_clock::now();
                        duration = std::chrono::duration_cast<std::chrono::duration<double>>(end - start);
                        if ((double)sended_probe/duration.count() > *band_speed_limit) {
                            std::this_thread::sleep_for(std::chrono::nanoseconds (5));
                        }
                        else {
                            break;
                        }
                    }
                    send_ipv6_tcp(socket_id, &ipv6_tcp, blk);
                    ++sended_probe;
                }
                {
                    ipv6_tcp.ipv6_sip = *ipv6_sip;
                    ipv6_tcp.ipv6_dip = ipv6_dip;
                    ipv6_tcp.ipv6_hop_limit = ipv6_ttl;
                    ipv6_tcp.ipv6_flow_label = 114;
                    ipv6_tcp.tcp_sport = 35265;
                    ipv6_tcp.tcp_dport = 33434;
                    ipv6_tcp.tcp_seq = 415;

                    std::chrono::duration<double> duration{};
                    while (true) {
                        auto end = std::chrono::steady_clock::now();
                        duration = std::chrono::duration_cast<std::chrono::duration<double>>(end - start);
                        if ((double)sended_probe/duration.count() > *band_speed_limit) {
                            std::this_thread::sleep_for(std::chrono::nanoseconds (5));
                        }
                        else {
                            break;
                        }
                    }
                    send_ipv6_tcp(socket_id, &ipv6_tcp, blk);
                    ++sended_probe;
                }
            }
            else {
                for (int i = 0; i < *pre_round; ++i) {

                    ipv6_icmpv6.ipv6_sip = *ipv6_sip;
                    ipv6_icmpv6.ipv6_dip = ipv6_dip;
                    ipv6_icmpv6.ipv6_hop_limit = ipv6_ttl;
                    ipv6_icmpv6.ipv6_flow_label = 114;
                    ipv6_icmpv6.icmpv6_ident = 35265;
                    ipv6_icmpv6.icmpv6_seq = 33434;
                    ipv6_icmpv6.icmpv6_content = 514;

                    std::chrono::duration<double> duration{};
                    while (true) {
                        auto end = std::chrono::steady_clock::now();
                        duration = std::chrono::duration_cast<std::chrono::duration<double>>(end - start);
                        if ((double)sended_probe/duration.count() > *band_speed_limit) {
                            std::this_thread::sleep_for(std::chrono::nanoseconds (5));
                        }
                        else {
                            break;
                        }
                    }
                    send_ipv6_icmpv6(socket_id, &ipv6_icmpv6, blk);
                    ++sended_probe;
                }
                {
                    ipv6_icmpv6.ipv6_sip = *ipv6_sip;
                    ipv6_icmpv6.ipv6_dip = ipv6_dip;
                    ipv6_icmpv6.ipv6_hop_limit = ipv6_ttl;
                    ipv6_icmpv6.ipv6_flow_label = 411;
                    ipv6_icmpv6.icmpv6_ident = 35265;
                    ipv6_icmpv6.icmpv6_seq = 33434;
                    ipv6_icmpv6.icmpv6_content = 514;

                    std::chrono::duration<double> duration{};
                    while (true) {
                        auto end = std::chrono::steady_clock::now();
                        duration = std::chrono::duration_cast<std::chrono::duration<double>>(end - start);
                        if ((double)sended_probe/duration.count() > *band_speed_limit) {
                            std::this_thread::sleep_for(std::chrono::nanoseconds (5));
                        }
                        else {
                            break;
                        }
                    }
                    send_ipv6_icmpv6(socket_id, &ipv6_icmpv6, blk);
                    ++sended_probe;
                }
                {
                    ipv6_icmpv6.ipv6_sip = *ipv6_sip;
                    ipv6_icmpv6.ipv6_dip = ipv6_dip;
                    ipv6_icmpv6.ipv6_hop_limit = ipv6_ttl;
                    ipv6_icmpv6.ipv6_flow_label = 114;
                    ipv6_icmpv6.icmpv6_ident = 46376;
                    ipv6_icmpv6.icmpv6_seq = 33434;
                    ipv6_icmpv6.icmpv6_content = 514;

                    std::chrono::duration<double> duration{};
                    while (true) {
                        auto end = std::chrono::steady_clock::now();
                        duration = std::chrono::duration_cast<std::chrono::duration<double>>(end - start);
                        if ((double)sended_probe/duration.count() > *band_speed_limit) {
                            std::this_thread::sleep_for(std::chrono::nanoseconds (5));
                        }
                        else {
                            break;
                        }
                    }
                    send_ipv6_icmpv6(socket_id, &ipv6_icmpv6, blk);
                    ++sended_probe;
                }
                {
                    ipv6_icmpv6.ipv6_sip = *ipv6_sip;
                    ipv6_icmpv6.ipv6_dip = ipv6_dip;
                    ipv6_icmpv6.ipv6_hop_limit = ipv6_ttl;
                    ipv6_icmpv6.ipv6_flow_label = 114;
                    ipv6_icmpv6.icmpv6_ident = 35265;
                    ipv6_icmpv6.icmpv6_seq = 44545;
                    ipv6_icmpv6.icmpv6_content = 514;

                    std::chrono::duration<double> duration{};
                    while (true) {
                        auto end = std::chrono::steady_clock::now();
                        duration = std::chrono::duration_cast<std::chrono::duration<double>>(end - start);
                        if ((double)sended_probe/duration.count() > *band_speed_limit) {
                            std::this_thread::sleep_for(std::chrono::nanoseconds (5));
                        }
                        else {
                            break;
                        }
                    }
                    send_ipv6_icmpv6(socket_id, &ipv6_icmpv6, blk);
                    ++sended_probe;
                }
                {
                    ipv6_icmpv6.ipv6_sip = *ipv6_sip;
                    ipv6_icmpv6.ipv6_dip = ipv6_dip;
                    ipv6_icmpv6.ipv6_hop_limit = ipv6_ttl;
                    ipv6_icmpv6.ipv6_flow_label = 114;
                    ipv6_icmpv6.icmpv6_ident = 35265;
                    ipv6_icmpv6.icmpv6_seq = 33434;
                    ipv6_icmpv6.icmpv6_content = 415;

                    std::chrono::duration<double> duration{};
                    while (true) {
                        auto end = std::chrono::steady_clock::now();
                        duration = std::chrono::duration_cast<std::chrono::duration<double>>(end - start);
                        if ((double)sended_probe/duration.count() > *band_speed_limit) {
                            std::this_thread::sleep_for(std::chrono::nanoseconds (5));
                        }
                        else {
                            break;
                        }
                    }
                    send_ipv6_icmpv6(socket_id, &ipv6_icmpv6, blk);
                    ++sended_probe;
                }
            }

        }
        int cur_progress = 100.0*sended_probe/total_probe;
        if (cur_progress != progress) {
            progress = cur_progress;
            auto now = std::chrono::steady_clock::now();
            double total_time = std::chrono::duration_cast<std::chrono::duration<double>>(now - start).count();
            std::string str("send speed: " + std::to_string(int(sended_probe/total_time)) + "p/s, cost time: " + std::to_string(int(total_time)) + "s.");
            printProgress(progress, 100, str);
        }
    }

    std::cout << "\nField preprobe completed." << std::endl;

    int end_wait_time = 3;

    std::cout << "Field preprobe will end in " << end_wait_time << " seconds..." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(end_wait_time));

    isCaptureDone->store(true, std::memory_order_relaxed);

    std::this_thread::sleep_for(std::chrono::seconds(1));

    close(socket_id);
}

void packet_process_field_preprobe_ipv4(std::atomic<bool>* isCaptureDone, std::queue<Packet_Information *> *check_queue, std::mutex *check_queue_mutex, in_addr *s_addrv4, std::unordered_map<in_addr, IPv4_Pre_Probe, V4AddrHash, V4AddrEqual> *pre_probe_map, std::mutex *pre_probe_map_mutex) {
    while (!isCaptureDone->load(std::memory_order_acquire)) {

        Packet_Information *current_packet = nullptr;

        std::unique_lock<std::mutex> check_queue_lock(*check_queue_mutex);
        if (!check_queue->empty()) {
            current_packet = check_queue->front();
            check_queue->pop();
        }
        check_queue_lock.unlock();

        if (current_packet == nullptr) {
            continue;
        }

        auto *ipv4Header = (IPv4_Header *) (current_packet->packet + 14);
        in_addr ex_d_addrv4 = ipv4Header->dip;
        in_addr ex_s_addrv4 = ipv4Header->sip;
        if (ipv4_address_equal(ex_d_addrv4, *s_addrv4) && ipv4Header->proto == IPPROTO_ICMP) {
            auto *icmpv4Header = (ICMPv4_Header *) ((u_char *) ipv4Header + ipv4Header->ihl * 4);
            if (icmpv4Header->type == ICMP_TIMXCEED) {
                auto *innerIpv4Header = (IPv4_Header *) ((u_char *) icmpv4Header + 8);
                in_addr in_d_addrv4 = innerIpv4Header->dip;
                std::unique_lock<std::mutex> pre_probe_map_lock0(*pre_probe_map_mutex);
                if (pre_probe_map->find(in_d_addrv4) != pre_probe_map->end()) {
                    if (innerIpv4Header->proto == IPPROTO_UDP) {
                        auto *udpHeader = (UDP_Header *) ((u_char *) innerIpv4Header + innerIpv4Header->ihl * 4);
                        uint16_t ipv4_id = ntohs(innerIpv4Header->ident);
                        uint16_t udp_sport = ntohs(udpHeader->sport);
                        uint16_t udp_dport = ntohs(udpHeader->dport);
                        uint16_t udp_crc = ntohs(udpHeader->crc);

                        if (ipv4_id == 411) {
                            (*pre_probe_map)[in_d_addrv4].flow_response["ipv4_ident"].insert(ex_s_addrv4);
                        }
                        if (udp_sport == 46376) {
                            (*pre_probe_map)[in_d_addrv4].flow_response["udp_sport"].insert(ex_s_addrv4);
                        }
                        if (udp_dport == 44545) {
                            (*pre_probe_map)[in_d_addrv4].flow_response["udp_dport"].insert(ex_s_addrv4);
                        }
                        if (udp_crc == 415) {
                            (*pre_probe_map)[in_d_addrv4].flow_response["udp_crc"].insert(ex_s_addrv4);
                        }
                        if (ipv4_id != 411 && udp_sport != 46376 && udp_dport != 44545 && udp_crc != 415) {
                            (*pre_probe_map)[in_d_addrv4].flow_response["origin"].insert(ex_s_addrv4);
                        }

                    }
                    else if (innerIpv4Header->proto == IPPROTO_TCP) {
                        auto *tcp_header = (TCP_Header *)((u_char *) innerIpv4Header + innerIpv4Header->ihl * 4);
                        uint16_t ipv4_id = ntohs(innerIpv4Header->ident);
                        uint16_t tcp_sport = ntohs(tcp_header->sport);
                        uint16_t tcp_dport = ntohs(tcp_header->dport);
                        uint32_t tcp_seq = ntohl(tcp_header->seq_number);

                        if (ipv4_id == 411) {
                            (*pre_probe_map)[in_d_addrv4].flow_response["ipv4_ident"].insert(ex_s_addrv4);
                        }
                        if (tcp_sport == 46376) {
                            (*pre_probe_map)[in_d_addrv4].flow_response["tcp_sport"].insert(ex_s_addrv4);
                        }
                        if (tcp_dport == 44545) {
                            (*pre_probe_map)[in_d_addrv4].flow_response["tcp_dport"].insert(ex_s_addrv4);
                        }
                        if (tcp_seq == 415) {
                            (*pre_probe_map)[in_d_addrv4].flow_response["tcp_seq"].insert(ex_s_addrv4);
                        }
                        if (ipv4_id != 411 && tcp_sport != 46376 && tcp_dport != 44545 && tcp_seq != 415) {
                            (*pre_probe_map)[in_d_addrv4].flow_response["origin"].insert(ex_s_addrv4);
                        }
                    }
                }
                pre_probe_map_lock0.unlock();
            }
        }
        delete[] current_packet->packet;
        delete current_packet;
    }
}

void packet_process_field_preprobe_ipv6(std::atomic<bool>* isCaptureDone, std::queue<Packet_Information *> *check_queue, std::mutex *check_queue_mutex, in6_addr *s_addrv6, std::unordered_map<in6_addr, IPv6_Pre_Probe, V6AddrHash, V6AddrEqual> *pre_probe_map, std::mutex *pre_probe_map_mutex) {
    while (!isCaptureDone->load(std::memory_order_acquire)) {
        Packet_Information *current_packet = nullptr;

        std::unique_lock<std::mutex> check_queue_lock(*check_queue_mutex);
        if (!check_queue->empty()) {
            current_packet = check_queue->front();
            check_queue->pop();
        }
        check_queue_lock.unlock();

        if (current_packet == nullptr) {
            continue;
        }
        auto *ipv6Header = (IPv6_Header *) (current_packet->packet + 14);
        in6_addr ex_d_addrv6 = ipv6Header->dip;
        in6_addr ex_s_addrv6 = ipv6Header->sip;
        if (ipv6_address_equal(ex_d_addrv6, *s_addrv6) && ipv6Header->next_header == IPPROTO_ICMPV6) {
            auto *icmpv6Header = (ICMPv6_Header *) ((u_char *) ipv6Header + 40);
            if (icmpv6Header->type == ICMP6_TIME_EXCEEDED) {
                auto *innerIpv6Header = (IPv6_Header *) ((u_char *) icmpv6Header + 8);
                in6_addr in_d_addrv6 = innerIpv6Header->dip;
                std::unique_lock<std::mutex> pre_probe_map_lock0(*pre_probe_map_mutex);
                if (pre_probe_map->find(in_d_addrv6) != pre_probe_map->end()) {
                    if (innerIpv6Header->next_header == IPPROTO_UDP) {
                        auto *udpHeader = (UDP_Header *) ((u_char *) innerIpv6Header + 40);
                        uint32_t vtf = ntohl(innerIpv6Header->vtf);
                        uint32_t ipv6_flow_label = vtf&0xfffff;
                        uint16_t udp_sport = ntohs(udpHeader->sport);
                        uint16_t udp_dport = ntohs(udpHeader->dport);
                        uint16_t udp_crc = ntohs(udpHeader->crc);

                        if (ipv6_flow_label == 411) {
                            (*pre_probe_map)[in_d_addrv6].flow_response["ipv6_flow_label"].insert(ex_s_addrv6);
                        }
                        if (udp_sport == 46376) {
                            (*pre_probe_map)[in_d_addrv6].flow_response["udp_sport"].insert(ex_s_addrv6);
                        }
                        if (udp_dport == 44545) {
                            (*pre_probe_map)[in_d_addrv6].flow_response["udp_dport"].insert(ex_s_addrv6);
                        }
                        if (udp_crc == 415) {
                            (*pre_probe_map)[in_d_addrv6].flow_response["udp_crc"].insert(ex_s_addrv6);
                        }
                        if (ipv6_flow_label != 411 && udp_sport != 46376 && udp_dport != 44545 && udp_crc != 415) {
                            (*pre_probe_map)[in_d_addrv6].flow_response["origin"].insert(ex_s_addrv6);
                        }
                    }
                    else if (innerIpv6Header->next_header == IPPROTO_TCP) {
                        auto *tcp_header = (TCP_Header *) ((u_char *) innerIpv6Header + 40);
                        uint32_t vtf = ntohl(innerIpv6Header->vtf);
                        uint32_t ipv6_flow_label = vtf&0xfffff;
                        uint16_t tcp_sport = ntohs(tcp_header->sport);
                        uint16_t tcp_dport = ntohs(tcp_header->dport);
                        uint32_t tcp_seq = ntohl(tcp_header->seq_number);

                        if (ipv6_flow_label == 411) {
                            (*pre_probe_map)[in_d_addrv6].flow_response["ipv6_flow_label"].insert(ex_s_addrv6);
                        }
                        if (tcp_sport == 46376) {
                            (*pre_probe_map)[in_d_addrv6].flow_response["tcp_sport"].insert(ex_s_addrv6);
                        }
                        if (tcp_dport == 44545) {
                            (*pre_probe_map)[in_d_addrv6].flow_response["tcp_dport"].insert(ex_s_addrv6);
                        }
                        if (tcp_seq == 415) {
                            (*pre_probe_map)[in_d_addrv6].flow_response["tcp_seq"].insert(ex_s_addrv6);
                        }
                        if (ipv6_flow_label != 411 && tcp_sport != 46376 && tcp_dport != 44545 && tcp_seq != 415) {
                            (*pre_probe_map)[in_d_addrv6].flow_response["origin"].insert(ex_s_addrv6);
                        }

                    }
                    else if (innerIpv6Header->next_header == IPPROTO_ICMPV6) {
                        auto *inner_icmpv6_header = (struct ICMPv6_Header *) ((u_char *) innerIpv6Header + 40);
                        uint32_t vtf = ntohl(innerIpv6Header->vtf);
                        uint32_t ipv6_flow_label = vtf&0xfffff;
                        uint16_t icmpv6_id = ntohs(inner_icmpv6_header->ident);
                        uint16_t icmpv6_seq = ntohs(inner_icmpv6_header->seq_number);
                        uint16_t icmpv6_content = ntohs(*((uint16_t*)((u_char *)inner_icmpv6_header+8)));

                        if (ipv6_flow_label == 411) {
                            (*pre_probe_map)[in_d_addrv6].flow_response["ipv6_flow_label"].insert(ex_s_addrv6);
                        }
                        if (icmpv6_id == 46376) {
                            (*pre_probe_map)[in_d_addrv6].flow_response["icmpv6_id"].insert(ex_s_addrv6);
                        }
                        if (icmpv6_seq == 44545) {
                            (*pre_probe_map)[in_d_addrv6].flow_response["icmpv6_seq"].insert(ex_s_addrv6);
                        }
                        if (icmpv6_content == 415) {
                            (*pre_probe_map)[in_d_addrv6].flow_response["icmpv6_content"].insert(ex_s_addrv6);
                        }
                        if (ipv6_flow_label != 411 && icmpv6_id != 46376 && icmpv6_seq != 44545 && icmpv6_content != 415) {
                            (*pre_probe_map)[in_d_addrv6].flow_response["origin"].insert(ex_s_addrv6);
                        }
                    }
                }
                pre_probe_map_lock0.unlock();
            }
        }
    }
}

void run_send_ipv4(std::unordered_map<in_addr, IPv4_Probe, V4AddrHash, V4AddrEqual> *ipv4_probe_map, std::mutex *ipv4_probe_map_mutex, std::unordered_map<in_addr, IPv4_Field_Adapt, V4AddrHash, V4AddrEqual> *ipv4_adapt_map, std::mutex *ipv4_adapt_map_mutex, std::atomic<bool>* isCaptureDone, in_addr *ipv4_sip, std::vector<in_addr> *ipv4_dip_list, const int *max_ttl, const int *band_speed_limit, const bool *blk) {
    int start_wait_time = 1;
    std::cout << "----------------------------------------------------" << std::endl;
    std::cout << "Packet capture will start in " << start_wait_time << " seconds..." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(start_wait_time));

    int socket_id = socket(AF_INET, SOCK_RAW, IPPROTO_RAW);

    if(socket_id < 0) {
        perror("socket() error");
        exit(-1);
    }

    auto start = std::chrono::steady_clock::now();

    int total_ip = ipv4_dip_list->size();
    long long sended_probe = 0;

    int progress = 0;
    while (true) {
        if (total_ip == 0) {
            break;
        }
        int finished_ip = 0;
        double sended_num = 0;
        double total_num = 0;
        for (auto &dipv4: *ipv4_dip_list) {

            bool cur_finished = false;
            int current_ttl = 0;
            int sended_flow_num = 0;
            int begin_upper_bound = 0;
            int flow_upper_bound = 0;
            int begin_lower_bound = 0;
            uint16_t balanced_value = 0;

            std::unique_lock<std::mutex> ipv4_probe_map_lock0(*ipv4_probe_map_mutex);
            cur_finished = (*ipv4_probe_map)[dipv4].finished;
            current_ttl = (*ipv4_probe_map)[dipv4].current_ttl;
            sended_flow_num = (*ipv4_probe_map)[dipv4].sended_flow_num;
            begin_upper_bound = (*ipv4_probe_map)[dipv4].begin_upper_bound;
            flow_upper_bound = (*ipv4_probe_map)[dipv4].flow_upper_bound;
            begin_lower_bound = (*ipv4_probe_map)[dipv4].begin_lower_bound;

            balanced_value = (*ipv4_probe_map)[dipv4].balanced_value;



            ipv4_probe_map_lock0.unlock();

            total_num += begin_upper_bound;

            if (cur_finished) {
                sended_num += begin_upper_bound;
                finished_ip += 1;
                continue;
            }

            sended_num += sended_flow_num;

            if (current_ttl == 1) {

                if (sended_flow_num >= begin_upper_bound || sended_flow_num >= flow_upper_bound) {
                    std::unique_lock<std::mutex> ipv4_probe_map_lock1(*ipv4_probe_map_mutex);
                    (*ipv4_probe_map)[dipv4].finished = true;
                    ipv4_probe_map_lock1.unlock();
                    continue;
                }
                if (sended_flow_num >= begin_lower_bound) {
                    int connect_pool_cur = 0;
                    int ipv4_pool_cur = 0;
                    std::unique_lock<std::mutex> ipv4_probe_map_lock2(*ipv4_probe_map_mutex);
                    int pool_size = (*ipv4_probe_map)[dipv4].pool_size;
                    connect_pool_cur = (*ipv4_probe_map)[dipv4].connect_pool_cur;
                    connect_pool_cur = (connect_pool_cur+1)%pool_size;
                    (*ipv4_probe_map)[dipv4].connect_pool_cur = connect_pool_cur;
                    (*ipv4_probe_map)[dipv4].connect_pool_cnt[connect_pool_cur] = (*ipv4_probe_map)[dipv4].connect_pool.size();
                    ipv4_pool_cur = (*ipv4_probe_map)[dipv4].ipv4_pool_cur;
                    ipv4_pool_cur = (ipv4_pool_cur+1)%pool_size;
                    (*ipv4_probe_map)[dipv4].ipv4_pool_cur = ipv4_pool_cur;
                    (*ipv4_probe_map)[dipv4].ipv4_pool_cnt[ipv4_pool_cur] = (*ipv4_probe_map)[dipv4].ipv4_pool.size();

                    bool stop_bul = true;
                    for (int i = 0; i < pool_size; i++) {
                        if ((*ipv4_probe_map)[dipv4].connect_pool_cnt[0] != (*ipv4_probe_map)[dipv4].connect_pool_cnt[i]) {
                            stop_bul = false;
                            break;
                        }
                        if ((*ipv4_probe_map)[dipv4].connect_pool_cnt[i] == 0) {
                            stop_bul = false;
                            break;
                        }
                        if ((*ipv4_probe_map)[dipv4].ipv4_pool_cnt[0] != (*ipv4_probe_map)[dipv4].ipv4_pool_cnt[i]) {
                            stop_bul = false;
                            break;
                        }
                        if ((*ipv4_probe_map)[dipv4].ipv4_pool_cnt[i] == 0) {
                            stop_bul = false;
                            break;
                        }
                    }

                    if (stop_bul) {
                        (*ipv4_probe_map)[dipv4].finished = true;
                        ipv4_probe_map_lock2.unlock();
                        continue;
                    }
                    ipv4_probe_map_lock2.unlock();
                }
            }
            std::string target_proto;
            std::string balanced_field_selected;
            std::string ttl_field_selected;
            std::string timestamp_field_selected;
            std::unique_lock<std::mutex> ipv4_adapt_map_lock0(*ipv4_adapt_map_mutex);
            target_proto = (*ipv4_adapt_map)[dipv4].target_proto;
            balanced_field_selected = (*ipv4_adapt_map)[dipv4].balanced_field_selected;
            ttl_field_selected = (*ipv4_adapt_map)[dipv4].ttl_field_selected;
            timestamp_field_selected = (*ipv4_adapt_map)[dipv4].timestamp_field_selected;
            ipv4_adapt_map_lock0.unlock();

            std::chrono::duration<double> duration{};
            while (true) {
                auto end = std::chrono::steady_clock::now();
                duration = std::chrono::duration_cast<std::chrono::duration<double>>(end - start);
                if ((double)sended_probe/duration.count() > *band_speed_limit) {
                    std::this_thread::sleep_for(std::chrono::nanoseconds (5));
                }
                else {
                    break;
                }
            }

            if (target_proto == "udp") {
                IPv4_UDP ipv4_udp{};
                ipv4_udp.ipv4_sip = *ipv4_sip;
                ipv4_udp.ipv4_dip = dipv4;
                ipv4_udp.ipv4_ttl = current_ttl;
                if (ttl_field_selected == "udp_crc") {
                    ipv4_udp.udp_crc = ((current_ttl<<8)|current_ttl);
                }
                else {
                    ipv4_udp.ipv4_ident = ((current_ttl<<8)|current_ttl);
                }
                if (timestamp_field_selected == "ipv4_ident") {
                    auto now = std::chrono::high_resolution_clock::now();
                    auto now_ms = std::chrono::time_point_cast<std::chrono::milliseconds>(now).time_since_epoch().count();
                    uint16_t embed_time = now_ms&0xffff;
                    ipv4_udp.ipv4_ident = embed_time;
                }

                if (balanced_field_selected == "udp_sport") {
                    ipv4_udp.udp_sport = balanced_value;
                }
                else {
                    ipv4_udp.udp_dport = balanced_value;
                }

                if (ipv4_udp.udp_sport == 0) {
                    ipv4_udp.udp_sport = 35265;
                }
                if (ipv4_udp.udp_dport == 0) {
                    ipv4_udp.udp_dport = 33434;
                }
                send_ipv4_udp(socket_id, &ipv4_udp, blk);
            }
            else {
                IPv4_TCP ipv4_tcp{};
                ipv4_tcp.ipv4_sip = *ipv4_sip;
                ipv4_tcp.ipv4_dip = dipv4;
                ipv4_tcp.ipv4_ttl = current_ttl;
                if (ttl_field_selected == "tcp_seq") {
                    ipv4_tcp.tcp_seq |= ((current_ttl<<8)|current_ttl);
                }
                else {
                    ipv4_tcp.ipv4_ident = ((current_ttl<<8)|current_ttl);
                }
                if (timestamp_field_selected == "tcp_seq") {
                    auto now = std::chrono::high_resolution_clock::now();
                    auto now_ms = std::chrono::time_point_cast<std::chrono::milliseconds>(now).time_since_epoch().count();
                    uint16_t embed_time = now_ms&0xffff;
                    ipv4_tcp.tcp_seq |= (embed_time<<16);
                }

                if (balanced_field_selected == "tcp_sport") {
                    ipv4_tcp.tcp_sport = balanced_value;
                }
                else {
                    ipv4_tcp.tcp_dport = balanced_value;
                }

                if (ipv4_tcp.tcp_sport == 0) {
                    ipv4_tcp.tcp_sport = 35265;
                }
                if (ipv4_tcp.tcp_dport == 0) {
                    ipv4_tcp.tcp_dport = 33434;
                }
                send_ipv4_tcp(socket_id, &ipv4_tcp, blk);
            }
            sended_probe += 1;

            std::unique_lock<std::mutex> ipv4_probe_map_lock3(*ipv4_probe_map_mutex);
            (*ipv4_probe_map)[dipv4].current_ttl += 1;
            ipv4_probe_map_lock3.unlock();

            current_ttl += 1;

            if (current_ttl > *max_ttl) {

                balanced_value += 13;
                balanced_value = (balanced_value+65535)%65535;
                if (balanced_value == 0) {
                    balanced_value += 13;
                }

                std::unique_lock<std::mutex> ipv4_probe_map_lock4(*ipv4_probe_map_mutex);
                (*ipv4_probe_map)[dipv4].balanced_value = balanced_value;
                (*ipv4_probe_map)[dipv4].current_ttl = 1;
                (*ipv4_probe_map)[dipv4].sended_flow_num += 1;
                ipv4_probe_map_lock4.unlock();
            }
        }
        auto now = std::chrono::steady_clock::now();
        double total_time = std::chrono::duration_cast<std::chrono::duration<double>>(now - start).count();

        int cur_progress = 1000.0*sended_num/total_num;
        if (cur_progress != progress) {
            progress = cur_progress;
            std::string str("send speed: " + std::to_string(int(sended_probe/total_time)) + "p/s, cost time: " + std::to_string(int(total_time)) + "s.");
            printProgress(progress, 1000, str);
        }
        if (finished_ip == total_ip) {
            break;
        }
    }
    std::cout << "\nPacket sending completed." << std::endl;
    std::cout << "The number of sended preobe: " << sended_probe << std::endl;


    int end_wait_time = 3;

    std::cout << "Packet capture will end in " << end_wait_time << " seconds..." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(end_wait_time));

    isCaptureDone->store(true, std::memory_order_relaxed);

    std::this_thread::sleep_for(std::chrono::seconds(1));

    close(socket_id);
}

void run_send_ipv6(std::unordered_map<in6_addr, IPv6_Probe, V6AddrHash, V6AddrEqual> *ipv6_probe_map, std::mutex *ipv6_probe_map_mutex, std::unordered_map<in6_addr, IPv6_Field_Adapt, V6AddrHash, V6AddrEqual> *ipv6_adapt_map, std::mutex *ipv6_adapt_map_mutex, std::atomic<bool>* isCaptureDone, in6_addr *ipv6_sip, std::vector<in6_addr> *ipv6_dip_list, const int *max_ttl, const int *band_speed_limit, const bool *blk) {
    int start_wait_time = 1;
    std::cout << "----------------------------------------------------" << std::endl;
    std::cout << "Packet capture will start in " << start_wait_time << " seconds..." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(start_wait_time));

    int socket_id = socket(AF_INET6, SOCK_RAW, IPPROTO_RAW);

    if(socket_id < 0) {
        perror("socket() error");
        exit(-1);
    }

    auto start = std::chrono::steady_clock::now();

    int total_ip = ipv6_dip_list->size();
    long long sended_probe = 0;

    int progress = 0;
    while (true) {
        if (total_ip == 0) {
            break;
        }
        int finished_ip = 0;
        double sended_num = 0;
        double total_num = 0;
        for (auto &dipv6: *ipv6_dip_list) {

            bool cur_finished = false;
            int current_ttl = 0;
            int sended_flow_num = 0;
            int begin_upper_bound = 0;
            int flow_upper_bound = 0;
            int begin_lower_bound = 0;
            uint16_t balanced_value = 0;

            std::unique_lock<std::mutex> ipv6_probe_map_lock0(*ipv6_probe_map_mutex);
            cur_finished = (*ipv6_probe_map)[dipv6].finished;
            current_ttl = (*ipv6_probe_map)[dipv6].current_ttl;
            sended_flow_num = (*ipv6_probe_map)[dipv6].sended_flow_num;
            begin_upper_bound = (*ipv6_probe_map)[dipv6].begin_upper_bound;
            flow_upper_bound = (*ipv6_probe_map)[dipv6].flow_upper_bound;
            begin_lower_bound = (*ipv6_probe_map)[dipv6].begin_lower_bound;
            balanced_value = (*ipv6_probe_map)[dipv6].balanced_value;
            ipv6_probe_map_lock0.unlock();

            total_num += begin_upper_bound;

            if (cur_finished) {
                sended_num += begin_upper_bound;
                finished_ip += 1;
                continue;
            }

            sended_num += sended_flow_num;

            if (current_ttl == 1) {
                if (sended_flow_num >= begin_upper_bound || sended_flow_num >= flow_upper_bound) {
                    std::unique_lock<std::mutex> ipv6_probe_map_lock1(*ipv6_probe_map_mutex);
                    (*ipv6_probe_map)[dipv6].finished = true;
                    ipv6_probe_map_lock1.unlock();
                    continue;
                }
                if (sended_flow_num >= begin_lower_bound) {
                    int connect_pool_cur = 0;
                    int ipv6_pool_cur = 0;
                    std::unique_lock<std::mutex> ipv6_probe_map_lock2(*ipv6_probe_map_mutex);
                    int pool_size = (*ipv6_probe_map)[dipv6].pool_size;
                    connect_pool_cur = (*ipv6_probe_map)[dipv6].connect_pool_cur;
                    connect_pool_cur = (connect_pool_cur+1)%pool_size;
                    (*ipv6_probe_map)[dipv6].connect_pool_cur = connect_pool_cur;
                    (*ipv6_probe_map)[dipv6].connect_pool_cnt[connect_pool_cur] = (*ipv6_probe_map)[dipv6].connect_pool.size();
                    ipv6_pool_cur = (*ipv6_probe_map)[dipv6].ipv6_pool_cur;
                    ipv6_pool_cur = (ipv6_pool_cur+1)%pool_size;
                    (*ipv6_probe_map)[dipv6].ipv6_pool_cur = ipv6_pool_cur;
                    (*ipv6_probe_map)[dipv6].ipv6_pool_cnt[ipv6_pool_cur] = (*ipv6_probe_map)[dipv6].ipv6_pool.size();

                    bool stop_bul = true;
                    for (int i = 0; i < pool_size; i++) {
                        if ((*ipv6_probe_map)[dipv6].connect_pool_cnt[0] != (*ipv6_probe_map)[dipv6].connect_pool_cnt[i]) {
                            stop_bul = false;
                            break;
                        }
                        if ((*ipv6_probe_map)[dipv6].connect_pool_cnt[i] == 0) {
                            stop_bul = false;
                            break;
                        }
                        if ((*ipv6_probe_map)[dipv6].ipv6_pool_cnt[0] != (*ipv6_probe_map)[dipv6].ipv6_pool_cnt[i]) {
                            stop_bul = false;
                            break;
                        }
                        if ((*ipv6_probe_map)[dipv6].ipv6_pool_cnt[i] == 0) {
                            stop_bul = false;
                            break;
                        }
                    }

                    if (stop_bul) {
                        (*ipv6_probe_map)[dipv6].finished = true;
                        ipv6_probe_map_lock2.unlock();
                        continue;
                    }
                }
            }

            std::string target_proto;
            std::string balanced_field_selected;
            std::string ttl_field_selected;
            std::string timestamp_field_selected;
            std::unique_lock<std::mutex> ipv6_adapt_map_lock0(*ipv6_adapt_map_mutex);
            target_proto = (*ipv6_adapt_map)[dipv6].target_proto;
            balanced_field_selected = (*ipv6_adapt_map)[dipv6].balanced_field_selected;
            ttl_field_selected = (*ipv6_adapt_map)[dipv6].ttl_field_selected;
            timestamp_field_selected = (*ipv6_adapt_map)[dipv6].timestamp_field_selected;
            ipv6_adapt_map_lock0.unlock();

            std::chrono::duration<double> duration{};
            while (true) {
                auto end = std::chrono::steady_clock::now();
                duration = std::chrono::duration_cast<std::chrono::duration<double>>(end - start);
                if ((double)sended_probe/duration.count() > *band_speed_limit) {
                    std::this_thread::sleep_for(std::chrono::nanoseconds (5));
                }
                else {
                    break;
                }
            }

            if (target_proto == "udp") {
                IPv6_UDP ipv6_udp{};
                ipv6_udp.ipv6_sip = *ipv6_sip;
                ipv6_udp.ipv6_dip = dipv6;
                ipv6_udp.ipv6_hop_limit = current_ttl;
                ipv6_udp.udp_crc = ((current_ttl<<8)|current_ttl);

                auto now = std::chrono::high_resolution_clock::now();
                auto now_ms = std::chrono::time_point_cast<std::chrono::milliseconds>(now).time_since_epoch().count();
                uint16_t embed_time = now_ms&0xffff;
                ipv6_udp.udp_content = embed_time;

                if (balanced_field_selected == "udp_sport") {
                    ipv6_udp.udp_sport = balanced_value;
                }
                else if (balanced_field_selected == "udp_dport") {
                    ipv6_udp.udp_dport = balanced_value;
                }
                else {
                    ipv6_udp.ipv6_flow_label = balanced_value;
                }

                if (ipv6_udp.ipv6_flow_label == 0) {
                    ipv6_udp.ipv6_flow_label = 114;
                }
                if (ipv6_udp.udp_sport == 0) {
                    ipv6_udp.udp_sport = 35265;
                }
                if (ipv6_udp.udp_dport == 0) {
                    ipv6_udp.udp_dport = 33434;
                }

                send_ipv6_udp(socket_id, &ipv6_udp, blk);
            }
            else if (target_proto == "tcp") {
                IPv6_TCP ipv6_tcp{};
                ipv6_tcp.ipv6_sip = *ipv6_sip;
                ipv6_tcp.ipv6_dip = dipv6;
                ipv6_tcp.ipv6_hop_limit = current_ttl;
                ipv6_tcp.tcp_seq |= ((current_ttl<<8)|current_ttl);
                auto now = std::chrono::high_resolution_clock::now();
                auto now_ms = std::chrono::time_point_cast<std::chrono::milliseconds>(now).time_since_epoch().count();
                uint16_t embed_time = now_ms&0xffff;
                ipv6_tcp.tcp_seq |= (embed_time<<16);

                if (balanced_field_selected == "tcp_sport") {
                    ipv6_tcp.tcp_sport = balanced_value;
                }
                else if (balanced_field_selected == "tcp_dport") {
                    ipv6_tcp.tcp_dport = balanced_value;
                }
                else {
                    ipv6_tcp.ipv6_flow_label = balanced_value;
                }

                if (ipv6_tcp.ipv6_flow_label == 0) {
                    ipv6_tcp.ipv6_flow_label = 114;
                }
                if (ipv6_tcp.tcp_sport == 0) {
                    ipv6_tcp.tcp_sport = 35265;
                }
                if (ipv6_tcp.tcp_dport == 0) {
                    ipv6_tcp.tcp_dport = 33434;
                }

                send_ipv6_tcp(socket_id, &ipv6_tcp, blk);
            }
            else {
                IPv6_ICMPv6 ipv6_icmpv6{};
                ipv6_icmpv6.ipv6_sip = *ipv6_sip;
                ipv6_icmpv6.ipv6_dip = dipv6;
                ipv6_icmpv6.ipv6_hop_limit = current_ttl;
                ipv6_icmpv6.ipv6_flow_label = balanced_value;

                ipv6_icmpv6.icmpv6_ident = 0;
                uint16_t ttl_xor = (current_ttl&0xf)^((current_ttl&0xff)>>4);
                ipv6_icmpv6.icmpv6_ident |= (ttl_xor<<12);
                ipv6_icmpv6.icmpv6_ident |= (current_ttl<<4);
                ipv6_icmpv6.icmpv6_ident |= ((balanced_value>>16)&0xf);
                ipv6_icmpv6.icmpv6_seq = balanced_value&0xffff;
                auto now = std::chrono::high_resolution_clock::now();
                auto now_ms = std::chrono::time_point_cast<std::chrono::milliseconds>(now).time_since_epoch().count();
                uint16_t embed_time = now_ms&0xffff;
                ipv6_icmpv6.icmpv6_content = embed_time;

                send_ipv6_icmpv6(socket_id, &ipv6_icmpv6, blk);
            }
            sended_probe += 1;

            std::unique_lock<std::mutex> ipv6_probe_map_lock3(*ipv6_probe_map_mutex);
            (*ipv6_probe_map)[dipv6].current_ttl += 1;
            ipv6_probe_map_lock3.unlock();

            current_ttl += 1;

            if (current_ttl > *max_ttl) {

                balanced_value += 13;
                balanced_value = (balanced_value+65535)%65535;
                if (balanced_value == 0) {
                    balanced_value += 13;
                }

                std::unique_lock<std::mutex> ipv6_probe_map_lock4(*ipv6_probe_map_mutex);
                (*ipv6_probe_map)[dipv6].balanced_value = balanced_value;
                (*ipv6_probe_map)[dipv6].current_ttl = 1;
                (*ipv6_probe_map)[dipv6].sended_flow_num += 1;
                ipv6_probe_map_lock4.unlock();
            }
        }
        auto now = std::chrono::steady_clock::now();
        double total_time = std::chrono::duration_cast<std::chrono::duration<double>>(now - start).count();

        int cur_progress = 1000.0*sended_num/total_num;
        if (cur_progress != progress) {
            progress = cur_progress;
            std::string str("send speed: " + std::to_string(int(sended_probe/total_time)) + "p/s, cost time: " + std::to_string(int(total_time)) + "s.");
            printProgress(progress, 1000, str);
        }
        if (finished_ip == total_ip) {
            break;
        }
    }
    std::cout << "\nPacket sending completed." << std::endl;
    std::cout << "The number of sended preobe: " << sended_probe << std::endl;


    int end_wait_time = 3;

    std::cout << "Packet capture will end in " << end_wait_time << " seconds..." << std::endl;
    std::this_thread::sleep_for(std::chrono::seconds(end_wait_time));

    isCaptureDone->store(true, std::memory_order_relaxed);

    std::this_thread::sleep_for(std::chrono::seconds(1));

    close(socket_id);

}

void packet_process_ipv4(std::atomic<bool> *isCaptureDone, std::queue<Packet_Information *> *check_queue, std::mutex *check_queue_mutex, std::unordered_map<in_addr, IPv4_Probe, V4AddrHash, V4AddrEqual> *ipv4_probe_map, std::mutex *ipv4_probe_map_mutex, std::unordered_map<in_addr, IPv4_Field_Adapt, V4AddrHash, V4AddrEqual> *ipv4_adapt_map, std::mutex *ipv4_adapt_map_mutex, std::unordered_set<in_addr, V4AddrHash, V4AddrEqual> *response_ip_set, std::mutex *response_ip_set_mutex, in_addr *s_addrv4, std::unordered_map<in_addr, IPv4_Pre_Probe, V4AddrHash, V4AddrEqual> *pre_probe_map, std::mutex *pre_probe_map_mutex, std::string *txt_path, const int *n_thread) {
    std::time_t now = std::time(nullptr);
    std::tm *timeinfo;
    timeinfo = localtime(&now);
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d-%H-%M-%S", timeinfo);
    std::string base_filename = std::string(buffer) + "_nthread" + std::to_string(*n_thread);
    int file_index = 0;
    long long file_size = 512ll*1024*1024;
    std::string current_filename = *txt_path + generate_txt_filename(base_filename, file_index);

    std::ofstream outfile(current_filename);
    if (!outfile.is_open()) {
        std::cerr << "Fail to open a new log file" << std::endl;
        exit(1);
    }

    while (!isCaptureDone->load(std::memory_order_acquire)) {
        Packet_Information *current_packet = nullptr;
        std::unique_lock<std::mutex> check_queue_lock0(*check_queue_mutex);
        if (!check_queue->empty()) {
            current_packet = check_queue->front();
            check_queue->pop();
        }
        check_queue_lock0.unlock();

        if (current_packet == nullptr) {
            continue;
        }

        auto *ipv4Header = (IPv4_Header *) (current_packet->packet + 14);
        in_addr ex_s_addrv4 = ipv4Header->sip;
        in_addr ex_d_addrv4 = ipv4Header->dip;

        if (ipv4_address_equal(ex_d_addrv4, *s_addrv4)) {
            if (ipv4Header->proto == IPPROTO_ICMP) {
                auto *icmpv4Header = (ICMPv4_Header *) ((u_char *) ipv4Header + ipv4Header->ihl * 4);
                auto *innerIpv4Header = (IPv4_Header *) ((u_char *) icmpv4Header + 8);
                in_addr in_s_addrv4 = innerIpv4Header->sip;
                in_addr in_d_addrv4 = innerIpv4Header->dip;
                if (icmpv4Header->type == ICMP_TIMXCEED) {
                    std::unique_lock<std::mutex> ipv4_pre_probe_map_lock0(*pre_probe_map_mutex);
                    if (pre_probe_map->find(in_d_addrv4) != pre_probe_map->end()) {
                        ipv4_pre_probe_map_lock0.unlock();
                        if (innerIpv4Header->proto == IPPROTO_UDP) {
                            auto *udpHeader = (UDP_Header *) ((u_char *) innerIpv4Header + innerIpv4Header->ihl * 4);
                            uint16_t udp_sport = ntohs(udpHeader->sport);
                            uint16_t udp_dport = ntohs(udpHeader->dport);
                            std::string ttl_field_selected;
                            std::string timestamp_field_selected;
                            std::string balanced_field_selected;
                            std::string target_proto;
                            std::unique_lock<std::mutex> ipv4_adapt_map_lock0(*ipv4_adapt_map_mutex);
                            target_proto = (*ipv4_adapt_map)[in_d_addrv4].target_proto;
                            ttl_field_selected = (*ipv4_adapt_map)[in_d_addrv4].ttl_field_selected;
                            timestamp_field_selected = (*ipv4_adapt_map)[in_d_addrv4].timestamp_field_selected;
                            balanced_field_selected = (*ipv4_adapt_map)[in_d_addrv4].balanced_field_selected;
                            ipv4_adapt_map_lock0.unlock();

                            uint16_t ipv4_ident = ntohs(innerIpv4Header->ident);
                            uint16_t udp_crc = ntohs(udpHeader->crc);

                            uint16_t ttl = 0;
                            uint16_t ttl1 = 1;
                            uint16_t ttl2 = -1;
                            uint16_t timestamp = 0;

                            uint16_t balanced_value = 0;

                            if (ttl_field_selected == "udp_crc") {
                                ttl1 = udp_crc>>8;
                                ttl2 = udp_crc&0xff;
                            }
                            else {
                                ttl1 = ipv4_ident>>8;
                                ttl2 = ipv4_ident&0xff;
                            }
                            if (ttl1 == ttl2) {
                                ttl = ttl1;
                                if (timestamp_field_selected == "ipv4_ident") {
                                    timestamp = ipv4_ident;
                                }
                                if (balanced_field_selected == "udp_sport") {
                                    balanced_value = udp_sport;
                                }
                                else {
                                    balanced_value = udp_dport;
                                }

                                std::unique_lock<std::mutex> ipv4_probe_map_lock0(*ipv4_probe_map_mutex);
                                (*ipv4_probe_map)[in_d_addrv4].ipv4_pool.insert(ex_s_addrv4);
                                (*ipv4_probe_map)[in_d_addrv4].ttl_ipv4_pool[ttl].insert(ex_s_addrv4);

                                (*ipv4_probe_map)[in_d_addrv4].flow_ttl_ipv4_pool[balanced_value][ttl] = ex_s_addrv4;
                                auto prior = (*ipv4_probe_map)[in_d_addrv4].flow_ttl_ipv4_pool[balanced_value].find(ttl-1);
                                auto suffx = (*ipv4_probe_map)[in_d_addrv4].flow_ttl_ipv4_pool[balanced_value].find(ttl+1);
                                if (prior != (*ipv4_probe_map)[in_d_addrv4].flow_ttl_ipv4_pool[balanced_value].end()) {
                                    (*ipv4_probe_map)[in_d_addrv4].connect_pool.insert(std::make_pair(prior->second, ex_s_addrv4));
                                }
                                if (suffx != (*ipv4_probe_map)[in_d_addrv4].flow_ttl_ipv4_pool[balanced_value].end()) {
                                    (*ipv4_probe_map)[in_d_addrv4].connect_pool.insert(std::make_pair(ex_s_addrv4, suffx->second));
                                }

                                int flow_upper_bound = (*ipv4_probe_map)[in_d_addrv4].flow_upper_bound;
                                int lower_ttl1 = (*ipv4_probe_map)[in_d_addrv4].ttl_ipv4_pool[ttl-1].size();
                                int lower_ttl2 = (*ipv4_probe_map)[in_d_addrv4].ttl_ipv4_pool[ttl].size();
                                int lower_ttl3 = (*ipv4_probe_map)[in_d_addrv4].ttl_ipv4_pool[ttl+1].size();
                                if (lower_ttl1*lower_ttl2 > flow_upper_bound) {
                                    flow_upper_bound = lower_ttl1*lower_ttl2;
                                }
                                if (lower_ttl3*lower_ttl2 > flow_upper_bound) {
                                    flow_upper_bound = lower_ttl3*lower_ttl2;
                                }
                                if ((*ipv4_probe_map)[in_d_addrv4].flow_upper_bound < flow_upper_bound) {
                                    (*ipv4_probe_map)[in_d_addrv4].flow_upper_bound = flow_upper_bound;
                                }
                                ipv4_probe_map_lock0.unlock();


                                char sipv4_str[INET_ADDRSTRLEN];
                                if (inet_ntop(AF_INET, &ex_d_addrv4, sipv4_str, INET_ADDRSTRLEN) == nullptr) {
                                    perror("inet_ntop");
                                    exit(1);
                                }
                                std::string sipv4(sipv4_str);

                                char dipv4_str[INET_ADDRSTRLEN];
                                if (inet_ntop(AF_INET, &innerIpv4Header->dip, dipv4_str, INET_ADDRSTRLEN) == nullptr) {
                                    perror("inet_ntop");
                                    exit(1);
                                }
                                std::string dipv4(dipv4_str);

                                char mipv4_str[INET_ADDRSTRLEN];
                                if (inet_ntop(AF_INET, &ex_s_addrv4, mipv4_str, INET_ADDRSTRLEN) == nullptr) {
                                    perror("inet_ntop");
                                    exit(1);
                                }
                                std::string mipv4(mipv4_str);

                                uint16_t send_time = timestamp;
                                uint16_t arrive_time = current_packet->arrive_time;


                                std::ostringstream oss;
                                oss << sipv4 << "\t" << dipv4 << "\t" << target_proto << "\t" << ipv4_ident << "\t" << udp_sport << "\t" << udp_dport << "\t" << udp_crc << "\t" << ttl_field_selected << "\t" << timestamp_field_selected << "\t" << balanced_field_selected << "\t" << mipv4 << "\t" << ttl << "\t" << send_time << "\t" << arrive_time << "\n";
                                std::string output = oss.str();
                                outfile << output;

                                if (file_size_exceeded(current_filename.c_str(), file_size)) {
                                    outfile.close();
                                    current_filename = *txt_path + generate_txt_filename(base_filename, file_index);
                                    outfile = std::ofstream(current_filename);
                                    if (!outfile.is_open()) {
                                        std::cerr << "Fail to open a new log file" << std::endl;
                                        exit(1);
                                    }
                                }
                            }
                        }
                        else if (innerIpv4Header->proto == IPPROTO_TCP) {
                            auto *tcp_header = (TCP_Header *) ((u_char *) innerIpv4Header + innerIpv4Header->ihl * 4);
                            uint16_t tcp_sport = ntohs(tcp_header->sport);
                            uint16_t tcp_dport = ntohs(tcp_header->dport);
                            std::string ttl_field_selected;
                            std::string timestamp_field_selected;
                            std::string balanced_field_selected;
                            std::string target_proto;
                            std::unique_lock<std::mutex> ipv4_adapt_map_lock1(*ipv4_adapt_map_mutex);
                            target_proto = (*ipv4_adapt_map)[in_d_addrv4].target_proto;
                            ttl_field_selected = (*ipv4_adapt_map)[in_d_addrv4].ttl_field_selected;
                            timestamp_field_selected = (*ipv4_adapt_map)[in_d_addrv4].timestamp_field_selected;
                            balanced_field_selected = (*ipv4_adapt_map)[in_d_addrv4].balanced_field_selected;
                            ipv4_adapt_map_lock1.unlock();

                            uint32_t tcp_seq = ntohl(tcp_header->seq_number);

                            uint16_t ttl = 0;
                            uint16_t ttl1 = 1;
                            uint16_t ttl2 = -1;
                            uint16_t timestamp = 0;

                            uint16_t balanced_value = 0;

                            ttl1 = tcp_seq&0xff;
                            ttl2 = (tcp_seq>>8)&0xff;

                            if (ttl1 == ttl2) {
                                if (timestamp_field_selected == "tcp_seq") {
                                    timestamp = tcp_seq>>16;
                                }
                                if (balanced_field_selected == "tcp_sport") {
                                    balanced_value = tcp_sport;
                                }
                                else {
                                    balanced_value = tcp_dport;
                                }

                                ttl = ttl1;
                                std::unique_lock<std::mutex> ipv4_probe_map_lock1(*ipv4_probe_map_mutex);
                                (*ipv4_probe_map)[in_d_addrv4].ipv4_pool.insert(ex_s_addrv4);
                                (*ipv4_probe_map)[in_d_addrv4].ttl_ipv4_pool[ttl].insert(ex_s_addrv4);

                                (*ipv4_probe_map)[in_d_addrv4].flow_ttl_ipv4_pool[balanced_value][ttl] = ex_s_addrv4;
                                auto prior = (*ipv4_probe_map)[in_d_addrv4].flow_ttl_ipv4_pool[balanced_value].find(ttl-1);
                                auto suffx = (*ipv4_probe_map)[in_d_addrv4].flow_ttl_ipv4_pool[balanced_value].find(ttl+1);
                                if (prior != (*ipv4_probe_map)[in_d_addrv4].flow_ttl_ipv4_pool[balanced_value].end()) {
                                    (*ipv4_probe_map)[in_d_addrv4].connect_pool.insert(std::make_pair(prior->second, ex_s_addrv4));
                                }
                                if (suffx != (*ipv4_probe_map)[in_d_addrv4].flow_ttl_ipv4_pool[balanced_value].end()) {
                                    (*ipv4_probe_map)[in_d_addrv4].connect_pool.insert(std::make_pair(ex_s_addrv4, suffx->second));
                                }

                                int flow_upper_bound = (*ipv4_probe_map)[in_d_addrv4].flow_upper_bound;
                                int lower_ttl1 = (*ipv4_probe_map)[in_d_addrv4].ttl_ipv4_pool[ttl-1].size();
                                int lower_ttl2 = (*ipv4_probe_map)[in_d_addrv4].ttl_ipv4_pool[ttl].size();
                                int lower_ttl3 = (*ipv4_probe_map)[in_d_addrv4].ttl_ipv4_pool[ttl+1].size();
                                if (lower_ttl1*lower_ttl2 > flow_upper_bound) {
                                    flow_upper_bound = lower_ttl1*lower_ttl2;
                                }
                                if (lower_ttl3*lower_ttl2 > flow_upper_bound) {
                                    flow_upper_bound = lower_ttl3*lower_ttl2;
                                }
                                if ((*ipv4_probe_map)[in_d_addrv4].flow_upper_bound < flow_upper_bound) {
                                    (*ipv4_probe_map)[in_d_addrv4].flow_upper_bound = flow_upper_bound;
                                }
                                ipv4_probe_map_lock1.unlock();

                                char sipv4_str[INET_ADDRSTRLEN];
                                if (inet_ntop(AF_INET, &ex_d_addrv4, sipv4_str, INET_ADDRSTRLEN) == nullptr) {
                                    perror("inet_ntop");
                                    exit(1);
                                }
                                std::string sipv4(sipv4_str);

                                char dipv4_str[INET_ADDRSTRLEN];
                                if (inet_ntop(AF_INET, &innerIpv4Header->dip, dipv4_str, INET_ADDRSTRLEN) == nullptr) {
                                    perror("inet_ntop");
                                    exit(1);
                                }
                                std::string dipv4(dipv4_str);

                                char mipv4_str[INET_ADDRSTRLEN];
                                if (inet_ntop(AF_INET, &ex_s_addrv4, mipv4_str, INET_ADDRSTRLEN) == nullptr) {
                                    perror("inet_ntop");
                                    exit(1);
                                }
                                std::string mipv4(mipv4_str);

                                uint16_t send_time = timestamp;
                                uint16_t arrive_time = current_packet->arrive_time;


                                std::ostringstream oss;
                                oss << sipv4 << "\t" << dipv4 << "\t" << target_proto << "\t" << tcp_sport << "\t" << tcp_dport << "\t" << tcp_seq << "\t" << ttl_field_selected << "\t" << timestamp_field_selected << "\t" << balanced_field_selected << "\t" << mipv4 << "\t" << ttl << "\t" << send_time << "\t" << arrive_time << "\n";
                                std::string output = oss.str();
                                outfile << output;

                                if (file_size_exceeded(current_filename.c_str(), file_size)) {
                                    outfile.close();
                                    current_filename = *txt_path + generate_txt_filename(base_filename, file_index);
                                    outfile = std::ofstream(current_filename);
                                    if (!outfile.is_open()) {
                                        std::cerr << "Fail to open a new log file" << std::endl;
                                        exit(1);
                                    }
                                }
                            }
                        }
                    }
                    else {
                        ipv4_pre_probe_map_lock0.unlock();
                    }
                }
                else if (icmpv4Header->type == ICMP_UNREACH) {
                    std::unique_lock<std::mutex> ipv4_pre_probe_map_lock1(*pre_probe_map_mutex);
                    if (pre_probe_map->find(in_d_addrv4) != pre_probe_map->end()) {
                        ipv4_pre_probe_map_lock1.unlock();
                        if (innerIpv4Header->proto == IPPROTO_UDP) {
                            auto *udpHeader = (UDP_Header *) ((u_char *) innerIpv4Header + innerIpv4Header->ihl * 4);
                            std::string ttl_field_selected;
                            std::string timestamp_field_selected;
                            std::string balanced_field_selected;
                            std::string target_proto;
                            std::unique_lock<std::mutex> ipv4_adapt_map_lock2(*ipv4_adapt_map_mutex);
                            target_proto = (*ipv4_adapt_map)[in_d_addrv4].target_proto;
                            ttl_field_selected = (*ipv4_adapt_map)[in_d_addrv4].ttl_field_selected;
                            timestamp_field_selected = (*ipv4_adapt_map)[in_d_addrv4].timestamp_field_selected;
                            balanced_field_selected = (*ipv4_adapt_map)[in_d_addrv4].balanced_field_selected;
                            ipv4_adapt_map_lock2.unlock();

                            uint16_t ipv4_ident = ntohs(innerIpv4Header->ident);
                            uint16_t udp_crc = ntohs(udpHeader->crc);
                            uint16_t udp_sport = ntohs(udpHeader->sport);
                            uint16_t udp_dport = ntohs(udpHeader->dport);

                            uint16_t ttl = 0;
                            uint16_t ttl1 = 1;
                            uint16_t ttl2 = -1;
                            uint16_t timestamp = 0;

                            if (ttl_field_selected == "udp_crc") {
                                ttl1 = udp_crc>>8;
                                ttl2 = udp_crc&0xff;
                            }
                            else {
                                ttl1 = ipv4_ident>>8;
                                ttl2 = ipv4_ident&0xff;
                            }
                            if (ttl1 == ttl2) {
                                ttl = ttl1;
                                if (timestamp_field_selected == "ipv4_ident") {
                                    timestamp = ipv4_ident;
                                }

                                std::unique_lock<std::mutex> response_ip_set_lock0(*response_ip_set_mutex);
                                response_ip_set->insert(in_d_addrv4);
                                response_ip_set_lock0.unlock();

                                uint16_t current_balanced_value = 0, reviced_balanced_value = 0;
                                if (balanced_field_selected == "udp_sport") {
                                    reviced_balanced_value = udp_sport;
                                }
                                else {
                                    reviced_balanced_value = udp_dport;
                                }

                                std::unique_lock<std::mutex> ipv4_probe_map_lock2(*ipv4_probe_map_mutex);
                                current_balanced_value = (*ipv4_probe_map)[in_d_addrv4].balanced_value;

                                if (reviced_balanced_value == current_balanced_value) {
                                    current_balanced_value += 13;
                                    current_balanced_value = (current_balanced_value+65535)%65535;
                                    if (current_balanced_value == 0) {
                                        current_balanced_value += 13;
                                    }
                                    (*ipv4_probe_map)[in_d_addrv4].balanced_value = current_balanced_value;
                                    (*ipv4_probe_map)[in_d_addrv4].sended_flow_num += 1;
                                    (*ipv4_probe_map)[in_d_addrv4].current_ttl = 1;
                                }

                                ipv4_probe_map_lock2.unlock();

                                char sipv4_str[INET_ADDRSTRLEN];
                                if (inet_ntop(AF_INET, &ex_d_addrv4, sipv4_str, INET_ADDRSTRLEN) == nullptr) {
                                    perror("inet_ntop");
                                    exit(1);
                                }
                                std::string sipv4(sipv4_str);

                                char dipv4_str[INET_ADDRSTRLEN];
                                if (inet_ntop(AF_INET, &innerIpv4Header->dip, dipv4_str, INET_ADDRSTRLEN) == nullptr) {
                                    perror("inet_ntop");
                                    exit(1);
                                }
                                std::string dipv4(dipv4_str);

                                char mipv4_str[INET_ADDRSTRLEN];
                                if (inet_ntop(AF_INET, &ex_s_addrv4, mipv4_str, INET_ADDRSTRLEN) == nullptr) {
                                    perror("inet_ntop");
                                    exit(1);
                                }
                                std::string mipv4(mipv4_str);

                                uint16_t send_time = timestamp;
                                uint16_t arrive_time = current_packet->arrive_time;


                                std::ostringstream oss;
                                oss << sipv4 << "\t" << dipv4 << "\t" << target_proto << "\t" << ipv4_ident << "\t" << udp_sport << "\t" << udp_dport << "\t" << udp_crc << "\t" << ttl_field_selected << "\t" << timestamp_field_selected << "\t" << balanced_field_selected << "\t" << mipv4 << "\t" << ttl << "\t" << send_time << "\t" << arrive_time << "\n";
                                std::string output = oss.str();
                                outfile << output;

                                if (file_size_exceeded(current_filename.c_str(), file_size)) {
                                    outfile.close();
                                    current_filename = *txt_path + generate_txt_filename(base_filename, file_index);
                                    outfile = std::ofstream(current_filename);
                                    if (!outfile.is_open()) {
                                        std::cerr << "Fail to open a new log file" << std::endl;
                                        exit(1);
                                    }
                                }
                            }
                        }
                        else if (innerIpv4Header->proto == IPPROTO_TCP) {
                            auto *tcp_header = (TCP_Header *) ((u_char *) innerIpv4Header + innerIpv4Header->ihl * 4);
                            uint16_t tcp_sport = ntohs(tcp_header->sport);
                            uint16_t tcp_dport = ntohs(tcp_header->dport);
                            std::string ttl_field_selected;
                            std::string timestamp_field_selected;
                            std::string balanced_field_selected;
                            std::string target_proto;
                            std::unique_lock<std::mutex> ipv4_adapt_map_lock3(*ipv4_adapt_map_mutex);
                            target_proto = (*ipv4_adapt_map)[in_d_addrv4].target_proto;
                            ttl_field_selected = (*ipv4_adapt_map)[in_d_addrv4].ttl_field_selected;
                            timestamp_field_selected = (*ipv4_adapt_map)[in_d_addrv4].timestamp_field_selected;
                            balanced_field_selected = (*ipv4_adapt_map)[in_d_addrv4].balanced_field_selected;
                            ipv4_adapt_map_lock3.unlock();

                            uint32_t tcp_seq = ntohl(tcp_header->seq_number);

                            uint16_t ttl = 0;
                            uint16_t ttl1 = 1;
                            uint16_t ttl2 = -1;
                            uint16_t timestamp = 0;

                            ttl1 = tcp_seq&0xff;
                            ttl2 = (tcp_seq>>8)&0xff;
                            if (ttl1 == ttl2) {
                                if (timestamp_field_selected == "tcp_seq") {
                                    timestamp = tcp_seq>>16;
                                }

                                ttl = ttl1;

                                uint16_t current_balanced_value = 0, reviced_balanced_value = 0;
                                if (balanced_field_selected == "tcp_sport") {
                                    reviced_balanced_value = tcp_sport;
                                }
                                else {
                                    reviced_balanced_value = tcp_dport;
                                }

                                std::unique_lock<std::mutex> response_ip_set_lock1(*response_ip_set_mutex);
                                response_ip_set->insert(in_d_addrv4);
                                response_ip_set_lock1.unlock();

                                std::unique_lock<std::mutex> ipv4_probe_map_lock3(*ipv4_probe_map_mutex);

                                current_balanced_value = (*ipv4_probe_map)[in_d_addrv4].balanced_value;

                                if (reviced_balanced_value == current_balanced_value) {
                                    current_balanced_value += 13;
                                    current_balanced_value = (current_balanced_value+65535)%65535;
                                    if (current_balanced_value == 0) {
                                        current_balanced_value += 13;
                                    }
                                    (*ipv4_probe_map)[in_d_addrv4].balanced_value = current_balanced_value;
                                    (*ipv4_probe_map)[in_d_addrv4].sended_flow_num += 1;
                                    (*ipv4_probe_map)[in_d_addrv4].current_ttl = 1;
                                }

                                ipv4_probe_map_lock3.unlock();

                                char sipv4_str[INET_ADDRSTRLEN];
                                if (inet_ntop(AF_INET, &ex_d_addrv4, sipv4_str, INET_ADDRSTRLEN) == nullptr) {
                                    perror("inet_ntop");
                                    exit(1);
                                }
                                std::string sipv4(sipv4_str);

                                char dipv4_str[INET_ADDRSTRLEN];
                                if (inet_ntop(AF_INET, &ex_s_addrv4, dipv4_str, INET_ADDRSTRLEN) == nullptr) {
                                    perror("inet_ntop");
                                    exit(1);
                                }
                                std::string dipv4(dipv4_str);

                                char mipv4_str[INET_ADDRSTRLEN];
                                if (inet_ntop(AF_INET, &ex_s_addrv4, mipv4_str, INET_ADDRSTRLEN) == nullptr) {
                                    perror("inet_ntop");
                                    exit(1);
                                }
                                std::string mipv4(mipv4_str);

                                uint16_t send_time = timestamp;
                                uint16_t arrive_time = current_packet->arrive_time;


                                std::ostringstream oss;
                                oss << sipv4 << "\t" << dipv4 << "\t" << target_proto << "\t" << tcp_sport << "\t" << tcp_dport << "\t" << tcp_seq << "\t" << ttl_field_selected << "\t" << timestamp_field_selected << "\t" << balanced_field_selected << "\t" << mipv4 << "\t" << ttl << "\t" << send_time << "\t" << arrive_time << "\n";
                                std::string output = oss.str();
                                outfile << output;

                                if (file_size_exceeded(current_filename.c_str(), file_size)) {
                                    outfile.close();
                                    current_filename = *txt_path + generate_txt_filename(base_filename, file_index);
                                    outfile = std::ofstream(current_filename);
                                    if (!outfile.is_open()) {
                                        std::cerr << "Fail to open a new log file" << std::endl;
                                        exit(1);
                                    }
                                }
                            }
                        }
                    }
                    else {
                        ipv4_pre_probe_map_lock1.unlock();
                    }
                }
            }
            else if (ipv4Header->proto == IPPROTO_TCP) {
                std::unique_lock<std::mutex> ipv4_pre_probe_map_lock2(*pre_probe_map_mutex);
                if (pre_probe_map->find(ex_s_addrv4) != pre_probe_map->end()) {
                    ipv4_pre_probe_map_lock2.unlock();
                    auto *tcp_header = (TCP_Header *) ((u_char *) ipv4Header + ipv4Header->ihl * 4);

                    std::string ttl_field_selected;
                    std::string timestamp_field_selected;
                    std::string balanced_field_selected;
                    std::string target_proto;
                    std::unique_lock<std::mutex> ipv4_adapt_map_lock4(*ipv4_adapt_map_mutex);
                    target_proto = (*ipv4_adapt_map)[ex_s_addrv4].target_proto;
                    ttl_field_selected = (*ipv4_adapt_map)[ex_s_addrv4].ttl_field_selected;
                    timestamp_field_selected = (*ipv4_adapt_map)[ex_s_addrv4].timestamp_field_selected;
                    balanced_field_selected = (*ipv4_adapt_map)[ex_s_addrv4].balanced_field_selected;
                    ipv4_adapt_map_lock4.unlock();

                    uint32_t tcp_ack = ntohl(tcp_header->ack_number);
                    uint32_t tcp_seq = ntohl(tcp_header->ack_number)-1;
                    uint16_t tcp_sport = ntohs(tcp_header->dport);
                    uint16_t tcp_dport = ntohs(tcp_header->sport);

                    uint16_t ttl = 0;

                    uint16_t timestamp = 0;
                    uint16_t ttl1 = 0;
                    uint16_t ttl2 = 0;

                    ttl1 = tcp_seq&0xff;
                    ttl2 = (tcp_seq>>8)&0xff;

                    if (ttl1 == ttl2 && ttl1 != 0 && tcp_ack != 0) {
                        ttl = ttl1;
                        if (timestamp_field_selected == "tcp_seq") {
                            timestamp = tcp_seq>>16;
                        }

                        std::unique_lock<std::mutex> response_ip_set_lock2(*response_ip_set_mutex);
                        response_ip_set->insert(ex_s_addrv4);
                        response_ip_set_lock2.unlock();


                        uint16_t current_balanced_value = 0, reviced_balanced_value = 0;
                        if (balanced_field_selected == "tcp_sport") {
                            reviced_balanced_value = tcp_sport;
                        }
                        else {
                            reviced_balanced_value = tcp_dport;
                        }

                        std::unique_lock<std::mutex> ipv4_probe_map_lock4(*ipv4_probe_map_mutex);

                        current_balanced_value = (*ipv4_probe_map)[ex_s_addrv4].balanced_value;

                        if (reviced_balanced_value == current_balanced_value) {
                            current_balanced_value += 13;
                            current_balanced_value = (current_balanced_value+65535)%65535;
                            if (current_balanced_value == 0) {
                                current_balanced_value += 13;
                            }
                            (*ipv4_probe_map)[ex_s_addrv4].balanced_value = current_balanced_value;
                            (*ipv4_probe_map)[ex_s_addrv4].sended_flow_num += 1;
                            (*ipv4_probe_map)[ex_s_addrv4].current_ttl = 1;
                        }

                        ipv4_probe_map_lock4.unlock();

                        char sipv4_str[INET_ADDRSTRLEN];
                        if (inet_ntop(AF_INET, &ex_d_addrv4, sipv4_str, INET_ADDRSTRLEN) == nullptr) {
                            perror("inet_ntop");
                            exit(1);
                        }
                        std::string sipv4(sipv4_str);

                        char dipv4_str[INET_ADDRSTRLEN];
                        if (inet_ntop(AF_INET, &ex_s_addrv4, dipv4_str, INET_ADDRSTRLEN) == nullptr) {
                            perror("inet_ntop");
                            exit(1);
                        }
                        std::string dipv4(dipv4_str);

                        char mipv4_str[INET_ADDRSTRLEN];
                        if (inet_ntop(AF_INET, &ex_s_addrv4, mipv4_str, INET_ADDRSTRLEN) == nullptr) {
                            perror("inet_ntop");
                            exit(1);
                        }
                        std::string mipv4(mipv4_str);

                        uint16_t send_time = timestamp;
                        uint16_t arrive_time = current_packet->arrive_time;


                        std::ostringstream oss;
                        oss << sipv4 << "\t" << dipv4 << "\t" << target_proto << "\t" << tcp_sport << "\t" << tcp_dport << "\t" << tcp_seq << "\t" << ttl_field_selected << "\t" << timestamp_field_selected << "\t" << balanced_field_selected << "\t" << mipv4 << "\t" << ttl << "\t" << send_time << "\t" << arrive_time << "\n";
                        std::string output = oss.str();
                        outfile << output;

                        if (file_size_exceeded(current_filename.c_str(), file_size)) {
                            outfile.close();
                            current_filename = *txt_path + generate_txt_filename(base_filename, file_index);
                            outfile = std::ofstream(current_filename);
                            if (!outfile.is_open()) {
                                std::cerr << "Fail to open a new log file" << std::endl;
                                exit(1);
                            }
                        }
                    }
                }
                else {
                    ipv4_pre_probe_map_lock2.unlock();
                }
            }
        }

        delete[] current_packet->packet;
        delete current_packet;
    }

    std::unique_lock<std::mutex> check_queue_lock1(*check_queue_mutex);
    while (!check_queue->empty()) {
        check_queue->pop();
    }
    check_queue_lock1.unlock();
}

void packet_process_ipv6(std::atomic<bool> *isCaptureDone, std::queue<Packet_Information *> *check_queue, std::mutex *check_queue_mutex, std::unordered_map<in6_addr, IPv6_Probe, V6AddrHash, V6AddrEqual> *ipv6_probe_map, std::mutex *ipv6_probe_map_mutex, std::unordered_map<in6_addr, IPv6_Field_Adapt, V6AddrHash, V6AddrEqual> *ipv6_adapt_map, std::mutex *ipv6_adapt_map_mutex, std::unordered_set<in6_addr, V6AddrHash, V6AddrEqual> *response_ip_set, std::mutex *response_ip_set_mutex, in6_addr *s_addrv6, std::unordered_map<in6_addr, IPv6_Pre_Probe, V6AddrHash, V6AddrEqual> *pre_probe_map, std::mutex *pre_probe_map_mutex, std::string *txt_path, const int *n_thread) {
    std::time_t now = std::time(nullptr);
    std::tm *timeinfo;
    timeinfo = localtime(&now);
    char buffer[80];
    strftime(buffer, sizeof(buffer), "%Y-%m-%d-%H-%M-%S", timeinfo);
    std::string base_filename = std::string(buffer) + "_nthread" + std::to_string(*n_thread);
    int file_index = 0;
    long long file_size = 512ll*1024*1024;
    std::string current_filename = *txt_path + generate_txt_filename(base_filename, file_index);

    std::ofstream outfile(current_filename);
    if (!outfile.is_open()) {
        std::cerr << "Fail to open a new log file" << std::endl;
        exit(1);
    }

    while (!isCaptureDone->load(std::memory_order_acquire)) {
        Packet_Information *current_packet = nullptr;
        std::unique_lock<std::mutex> check_queue_lock(*check_queue_mutex);
        if (!check_queue->empty()) {
            current_packet = check_queue->front();
            check_queue->pop();
        }
        check_queue_lock.unlock();

        if (current_packet == nullptr) {
            continue;
        }

        auto *ipv6Header = (IPv6_Header *) (current_packet->packet + 14);
        in6_addr ex_d_addrv6 = ipv6Header->dip;
        in6_addr ex_s_addrv6 = ipv6Header->sip;
        if (ipv6_address_equal(ex_d_addrv6, *s_addrv6)) {
            if (ipv6Header->next_header == IPPROTO_ICMPV6) {
                auto *icmpv6Header = (ICMPv6_Header *) ((u_char *) ipv6Header + 40);
                if (icmpv6Header->type == ICMP6_TIME_EXCEEDED) {
                    auto *innerIpv6Header = (IPv6_Header *) ((u_char *) icmpv6Header + 8);
                    in6_addr in_s_addrv6 = innerIpv6Header->sip;
                    in6_addr in_d_addrv6 = innerIpv6Header->dip;
                    std::unique_lock<std::mutex> ipv6_pre_probe_map_lock0(*pre_probe_map_mutex);
                    if (pre_probe_map->find(in_d_addrv6) != pre_probe_map->end()) {
                        ipv6_pre_probe_map_lock0.unlock();
                        if (innerIpv6Header->next_header == IPPROTO_ICMPV6) {
                            auto *inner_icmpv6_header = (struct ICMPv6_Header *) ((u_char *) innerIpv6Header + 40);

                            std::string ttl_field_selected;
                            std::string timestamp_field_selected;
                            std::string balanced_field_selected;
                            std::string target_proto;
                            std::unique_lock<std::mutex> ipv6_adapt_map_lock0(*ipv6_adapt_map_mutex);
                            target_proto = (*ipv6_adapt_map)[in_d_addrv6].target_proto;
                            ttl_field_selected = (*ipv6_adapt_map)[in_d_addrv6].ttl_field_selected;
                            timestamp_field_selected = (*ipv6_adapt_map)[in_d_addrv6].timestamp_field_selected;
                            balanced_field_selected = (*ipv6_adapt_map)[in_d_addrv6].balanced_field_selected;
                            ipv6_adapt_map_lock0.unlock();

                            uint16_t icmpv6_id = ntohs(inner_icmpv6_header->ident);
                            uint16_t icmpv6_seq = ntohs(inner_icmpv6_header->seq_number);
                            uint16_t timestamp = 0;
                            uint16_t ttl = 0;
                            uint16_t ttl1 = (icmpv6_id>>4)&0xff;
                            uint16_t ttl1_xor = icmpv6_id>>12, ttl2_xor = (ttl1>>4)^(ttl1&0xf);
                            if (ttl1_xor == ttl2_xor && ttl1 != 0) {
                                ttl = ttl1;
                                timestamp = ntohs(*((uint16_t*)((u_char *)inner_icmpv6_header+8)));
                                uint32_t ipv6_flow_label = ((icmpv6_id&0xf)<<16)|(icmpv6_seq);
                                uint16_t balanced_value = ipv6_flow_label;

                                std::unique_lock<std::mutex> ipv6_probe_map_lock0(*ipv6_probe_map_mutex);
                                (*ipv6_probe_map)[in_d_addrv6].ipv6_pool.insert(ex_s_addrv6);
                                (*ipv6_probe_map)[in_d_addrv6].ttl_ipv6_pool[ttl].insert(ex_s_addrv6);

                                (*ipv6_probe_map)[in_d_addrv6].flow_ttl_ipv6_pool[balanced_value][ttl] = ex_s_addrv6;
                                auto prior = (*ipv6_probe_map)[in_d_addrv6].flow_ttl_ipv6_pool[balanced_value].find(ttl-1);
                                auto suffx = (*ipv6_probe_map)[in_d_addrv6].flow_ttl_ipv6_pool[balanced_value].find(ttl+1);
                                if (prior != (*ipv6_probe_map)[in_d_addrv6].flow_ttl_ipv6_pool[balanced_value].end()) {
                                    (*ipv6_probe_map)[in_d_addrv6].connect_pool.insert(std::make_pair(prior->second, ex_s_addrv6));
                                }
                                if (suffx != (*ipv6_probe_map)[in_d_addrv6].flow_ttl_ipv6_pool[balanced_value].end()) {
                                    (*ipv6_probe_map)[in_d_addrv6].connect_pool.insert(std::make_pair(ex_s_addrv6, suffx->second));
                                }

                                int flow_upper_bound = (*ipv6_probe_map)[in_d_addrv6].flow_upper_bound;
                                int lower_ttl1 = (*ipv6_probe_map)[in_d_addrv6].ttl_ipv6_pool[ttl-1].size();
                                int lower_ttl2 = (*ipv6_probe_map)[in_d_addrv6].ttl_ipv6_pool[ttl].size();
                                int lower_ttl3 = (*ipv6_probe_map)[in_d_addrv6].ttl_ipv6_pool[ttl+1].size();
                                if (lower_ttl1*lower_ttl2 > flow_upper_bound) {
                                    flow_upper_bound = lower_ttl1*lower_ttl2;
                                }
                                if (lower_ttl3*lower_ttl2 > flow_upper_bound) {
                                    flow_upper_bound = lower_ttl3*lower_ttl2;
                                }
                                if ((*ipv6_probe_map)[in_d_addrv6].flow_upper_bound < flow_upper_bound) {
                                    (*ipv6_probe_map)[in_d_addrv6].flow_upper_bound = flow_upper_bound;
                                }
                                ipv6_probe_map_lock0.unlock();

                                char sipv6_str[INET6_ADDRSTRLEN];
                                if (inet_ntop(AF_INET6, &ex_d_addrv6, sipv6_str, INET6_ADDRSTRLEN) == nullptr) {
                                    perror("inet_ntop");
                                    exit(1);
                                }
                                std::string sipv6(sipv6_str);
                                char dipv6_str[INET6_ADDRSTRLEN];
                                if (inet_ntop(AF_INET6, &innerIpv6Header->dip, dipv6_str, INET6_ADDRSTRLEN) == nullptr) {
                                    perror("inet_ntop");
                                    exit(1);
                                }
                                std::string dipv6(dipv6_str);
                                char mipv6_str[INET6_ADDRSTRLEN];
                                if (inet_ntop(AF_INET6, &ex_s_addrv6, mipv6_str, INET6_ADDRSTRLEN) == nullptr) {
                                    perror("inet_ntop");
                                    exit(1);
                                }
                                std::string mipv6(mipv6_str);


                                uint16_t send_time = timestamp;
                                uint16_t arrive_time = current_packet->arrive_time;

                                std::ostringstream oss;
                                oss << sipv6 << "\t" << dipv6 << "\t" << target_proto << "\t" << ipv6_flow_label << "\t" << icmpv6_id << "\t" << icmpv6_seq << "\t" << timestamp << "\t" << ttl_field_selected << "\t" << timestamp_field_selected << "\t" << balanced_field_selected << "\t" << mipv6 << "\t" << ttl << "\t" << send_time << "\t" << arrive_time << "\n";
                                std::string output = oss.str();
                                outfile << output;

                                if (file_size_exceeded(current_filename.c_str(), file_size)) {
                                    outfile.close();
                                    current_filename = *txt_path + generate_txt_filename(base_filename, file_index);
                                    outfile = std::ofstream(current_filename);
                                    if (!outfile.is_open()) {
                                        std::cerr << "Fail to open a new log file" << std::endl;
                                        exit(1);
                                    }
                                }
                            }
                        }
                        else if (innerIpv6Header->next_header == IPPROTO_UDP) {
                            auto *udpHeader = (UDP_Header *) ((u_char *) innerIpv6Header + 40);
                            uint16_t udp_sport = ntohs(udpHeader->sport);
                            uint16_t udp_dport = ntohs(udpHeader->dport);
                            std::string ttl_field_selected;
                            std::string timestamp_field_selected;
                            std::string balanced_field_selected;
                            std::string target_proto;
                            std::unique_lock<std::mutex> ipv6_adapt_map_lock1(*ipv6_adapt_map_mutex);
                            target_proto = (*ipv6_adapt_map)[in_d_addrv6].target_proto;
                            ttl_field_selected = (*ipv6_adapt_map)[in_d_addrv6].ttl_field_selected;
                            timestamp_field_selected = (*ipv6_adapt_map)[in_d_addrv6].timestamp_field_selected;
                            balanced_field_selected = (*ipv6_adapt_map)[in_d_addrv6].balanced_field_selected;
                            ipv6_adapt_map_lock1.unlock();

                            uint32_t vtf = ntohl(innerIpv6Header->vtf);
                            uint32_t ipv6_flow_label = vtf&0xfffff;
                            uint16_t udp_crc = ntohs(udpHeader->crc);

                            uint16_t ttl = 0;
                            uint16_t ttl1 = udp_crc>>8;
                            uint16_t ttl2 = udp_crc&0xff;
                            uint16_t timestamp = 0;

                            if (ttl1 == ttl2) {
                                ttl = ttl1;
                                timestamp = ntohs(*((uint16_t*)((u_char *)udpHeader+8)));

                                uint16_t balanced_value = 0;
                                if (balanced_field_selected == "udp_sport") {
                                    balanced_value = udp_sport;
                                }
                                else if (balanced_field_selected == "udp_dport") {
                                    balanced_value = udp_dport;
                                }
                                else {
                                    balanced_value = ipv6_flow_label;
                                }

                                std::unique_lock<std::mutex> ipv6_probe_map_lock1(*ipv6_probe_map_mutex);
                                (*ipv6_probe_map)[in_d_addrv6].ipv6_pool.insert(ex_s_addrv6);
                                (*ipv6_probe_map)[in_d_addrv6].ttl_ipv6_pool[ttl].insert(ex_s_addrv6);

                                (*ipv6_probe_map)[in_d_addrv6].flow_ttl_ipv6_pool[balanced_value][ttl] = ex_s_addrv6;
                                auto prior = (*ipv6_probe_map)[in_d_addrv6].flow_ttl_ipv6_pool[balanced_value].find(ttl-1);
                                auto suffx = (*ipv6_probe_map)[in_d_addrv6].flow_ttl_ipv6_pool[balanced_value].find(ttl+1);
                                if (prior != (*ipv6_probe_map)[in_d_addrv6].flow_ttl_ipv6_pool[balanced_value].end()) {
                                    (*ipv6_probe_map)[in_d_addrv6].connect_pool.insert(std::make_pair(prior->second, ex_s_addrv6));
                                }
                                if (suffx != (*ipv6_probe_map)[in_d_addrv6].flow_ttl_ipv6_pool[balanced_value].end()) {
                                    (*ipv6_probe_map)[in_d_addrv6].connect_pool.insert(std::make_pair(ex_s_addrv6, suffx->second));
                                }

                                int flow_upper_bound = (*ipv6_probe_map)[in_d_addrv6].flow_upper_bound;
                                int lower_ttl1 = (*ipv6_probe_map)[in_d_addrv6].ttl_ipv6_pool[ttl-1].size();
                                int lower_ttl2 = (*ipv6_probe_map)[in_d_addrv6].ttl_ipv6_pool[ttl].size();
                                int lower_ttl3 = (*ipv6_probe_map)[in_d_addrv6].ttl_ipv6_pool[ttl+1].size();
                                if (lower_ttl1*lower_ttl2 > flow_upper_bound) {
                                    flow_upper_bound = lower_ttl1*lower_ttl2;
                                }
                                if (lower_ttl3*lower_ttl2 > flow_upper_bound) {
                                    flow_upper_bound = lower_ttl3*lower_ttl2;
                                }
                                if ((*ipv6_probe_map)[in_d_addrv6].flow_upper_bound < flow_upper_bound) {
                                    (*ipv6_probe_map)[in_d_addrv6].flow_upper_bound = flow_upper_bound;
                                }
                                ipv6_probe_map_lock1.unlock();

                                char sipv6_str[INET6_ADDRSTRLEN];
                                if (inet_ntop(AF_INET6, &ex_d_addrv6, sipv6_str, INET6_ADDRSTRLEN) == nullptr) {
                                    perror("inet_ntop");
                                    exit(1);
                                }
                                std::string sipv6(sipv6_str);
                                char dipv6_str[INET6_ADDRSTRLEN];
                                if (inet_ntop(AF_INET6, &in_d_addrv6, dipv6_str, INET6_ADDRSTRLEN) == nullptr) {
                                    perror("inet_ntop");
                                    exit(1);
                                }
                                std::string dipv6(dipv6_str);
                                char mipv6_str[INET6_ADDRSTRLEN];
                                if (inet_ntop(AF_INET6, &ex_s_addrv6, mipv6_str, INET6_ADDRSTRLEN) == nullptr) {
                                    perror("inet_ntop");
                                    exit(1);
                                }
                                std::string mipv6(mipv6_str);

                                uint16_t send_time = timestamp;
                                uint16_t arrive_time = current_packet->arrive_time;


                                std::ostringstream oss;
                                oss << sipv6 << "\t" << dipv6 << "\t" << target_proto << "\t" << ipv6_flow_label << "\t" << udp_sport << "\t" << udp_dport << "\t" << udp_crc << "\t" << timestamp << "\t" << ttl_field_selected << "\t" << timestamp_field_selected << "\t" << balanced_field_selected << "\t" << mipv6 << "\t" << ttl << "\t" << send_time << "\t" << arrive_time << "\n";
                                std::string output = oss.str();
                                outfile << output;

                                if (file_size_exceeded(current_filename.c_str(), file_size)) {
                                    outfile.close();
                                    current_filename = *txt_path + generate_txt_filename(base_filename, file_index);
                                    outfile = std::ofstream(current_filename);
                                    if (!outfile.is_open()) {
                                        std::cerr << "Fail to open a new log file" << std::endl;
                                        exit(1);
                                    }
                                }
                            }
                        }
                        else if (innerIpv6Header->next_header == IPPROTO_TCP) {
                            auto *tcp_header = (TCP_Header *) ((u_char *) innerIpv6Header + 40);
                            uint16_t tcp_sport = ntohs(tcp_header->sport);
                            uint16_t tcp_dport = ntohs(tcp_header->dport);
                            std::string ttl_field_selected;
                            std::string timestamp_field_selected;
                            std::string balanced_field_selected;
                            std::string target_proto;
                            std::unique_lock<std::mutex> ipv6_adapt_map_lock2(*ipv6_adapt_map_mutex);
                            target_proto = (*ipv6_adapt_map)[in_d_addrv6].target_proto;
                            ttl_field_selected = (*ipv6_adapt_map)[in_d_addrv6].ttl_field_selected;
                            timestamp_field_selected = (*ipv6_adapt_map)[in_d_addrv6].timestamp_field_selected;
                            balanced_field_selected = (*ipv6_adapt_map)[in_d_addrv6].balanced_field_selected;
                            ipv6_adapt_map_lock2.unlock();

                            uint16_t ttl = 0;
                            uint32_t tcp_seq = ntohl(tcp_header->seq_number);
                            uint16_t ttl1 = tcp_seq&0xff;
                            uint16_t ttl2 = (tcp_seq>>8)&0xff;
                            uint16_t timestamp = 0;


                            if (ttl1 == ttl2 && ttl1 != 0) {
                                ttl = ttl1;
                                timestamp = (tcp_seq>>16)&0xffff;
                                uint16_t balanced_value = 0;

                                if (balanced_field_selected == "tcp_sport") {
                                    balanced_value = tcp_sport;
                                }
                                else {
                                    balanced_value = tcp_dport;
                                }

                                std::unique_lock<std::mutex> ipv6_probe_map_lock2(*ipv6_probe_map_mutex);
                                (*ipv6_probe_map)[in_d_addrv6].ipv6_pool.insert(ex_s_addrv6);
                                (*ipv6_probe_map)[in_d_addrv6].ttl_ipv6_pool[ttl].insert(ex_s_addrv6);

                                (*ipv6_probe_map)[in_d_addrv6].flow_ttl_ipv6_pool[balanced_value][ttl] = ex_s_addrv6;
                                auto prior = (*ipv6_probe_map)[in_d_addrv6].flow_ttl_ipv6_pool[balanced_value].find(ttl-1);
                                auto suffx = (*ipv6_probe_map)[in_d_addrv6].flow_ttl_ipv6_pool[balanced_value].find(ttl+1);
                                if (prior != (*ipv6_probe_map)[in_d_addrv6].flow_ttl_ipv6_pool[balanced_value].end()) {
                                    (*ipv6_probe_map)[in_d_addrv6].connect_pool.insert(std::make_pair(prior->second, ex_s_addrv6));
                                }
                                if (suffx != (*ipv6_probe_map)[in_d_addrv6].flow_ttl_ipv6_pool[balanced_value].end()) {
                                    (*ipv6_probe_map)[in_d_addrv6].connect_pool.insert(std::make_pair(ex_s_addrv6, suffx->second));
                                }

                                int flow_upper_bound = (*ipv6_probe_map)[in_d_addrv6].flow_upper_bound;
                                int lower_ttl1 = (*ipv6_probe_map)[in_d_addrv6].ttl_ipv6_pool[ttl-1].size();
                                int lower_ttl2 = (*ipv6_probe_map)[in_d_addrv6].ttl_ipv6_pool[ttl].size();
                                int lower_ttl3 = (*ipv6_probe_map)[in_d_addrv6].ttl_ipv6_pool[ttl+1].size();
                                if (lower_ttl1*lower_ttl2 > flow_upper_bound) {
                                    flow_upper_bound = lower_ttl1*lower_ttl2;
                                }
                                if (lower_ttl3*lower_ttl2 > flow_upper_bound) {
                                    flow_upper_bound = lower_ttl3*lower_ttl2;
                                }
                                if ((*ipv6_probe_map)[in_d_addrv6].flow_upper_bound < flow_upper_bound) {
                                    (*ipv6_probe_map)[in_d_addrv6].flow_upper_bound = flow_upper_bound;
                                }
                                ipv6_probe_map_lock2.unlock();

                                char sipv6_str[INET6_ADDRSTRLEN];
                                if (inet_ntop(AF_INET6, &ex_d_addrv6, sipv6_str, INET6_ADDRSTRLEN) == nullptr) {
                                    perror("inet_ntop");
                                    exit(1);
                                }
                                std::string sipv6(sipv6_str);
                                char dipv6_str[INET6_ADDRSTRLEN];
                                if (inet_ntop(AF_INET6, &in_d_addrv6, dipv6_str, INET6_ADDRSTRLEN) == nullptr) {
                                    perror("inet_ntop");
                                    exit(1);
                                }
                                std::string dipv6(dipv6_str);
                                char mipv6_str[INET6_ADDRSTRLEN];
                                if (inet_ntop(AF_INET6, &ex_s_addrv6, mipv6_str, INET6_ADDRSTRLEN) == nullptr) {
                                    perror("inet_ntop");
                                    exit(1);
                                }
                                std::string mipv6(mipv6_str);

                                uint16_t send_time = timestamp;
                                uint16_t arrive_time = current_packet->arrive_time;


                                std::ostringstream oss;
                                oss << sipv6 << "\t" << dipv6 << "\t" << target_proto << "\t" <<  tcp_sport << "\t" << tcp_dport << "\t" << tcp_seq << "\t" << ttl_field_selected << "\t" << timestamp_field_selected << "\t" << balanced_field_selected << "\t" << mipv6 << "\t" << ttl << "\t" << send_time << "\t" << arrive_time << "\n";
                                std::string output = oss.str();
                                outfile << output;

                                if (file_size_exceeded(current_filename.c_str(), file_size)) {
                                    outfile.close();
                                    current_filename = *txt_path + generate_txt_filename(base_filename, file_index);
                                    outfile = std::ofstream(current_filename);
                                    if (!outfile.is_open()) {
                                        std::cerr << "Fail to open a new log file" << std::endl;
                                        exit(1);
                                    }
                                }
                            }
                        }
                    }
                    else {
                        ipv6_pre_probe_map_lock0.unlock();
                    }

                }
                else if (icmpv6Header->type == ICMP6_ECHO_REPLY) {
                    std::unique_lock<std::mutex> ipv6_pre_probe_map_lock1(*pre_probe_map_mutex);
                    if (pre_probe_map->find(ex_s_addrv6) != pre_probe_map->end()) {
                        ipv6_pre_probe_map_lock1.unlock();
                        std::string ttl_field_selected;
                        std::string timestamp_field_selected;
                        std::string balanced_field_selected;
                        std::string target_proto;
                        std::unique_lock<std::mutex> ipv6_adapt_map_lock3(*ipv6_adapt_map_mutex);
                        target_proto = (*ipv6_adapt_map)[ex_s_addrv6].target_proto;
                        ttl_field_selected = (*ipv6_adapt_map)[ex_s_addrv6].ttl_field_selected;
                        timestamp_field_selected = (*ipv6_adapt_map)[ex_s_addrv6].timestamp_field_selected;
                        balanced_field_selected = (*ipv6_adapt_map)[ex_s_addrv6].balanced_field_selected;
                        ipv6_adapt_map_lock3.unlock();

                        uint16_t icmpv6_id = ntohs(icmpv6Header->ident);
                        uint16_t icmpv6_seq = ntohs(icmpv6Header->seq_number);
                        uint16_t timestamp = 0;
                        uint16_t ttl = 0;
                        uint16_t ttl1 = (icmpv6_id>>4)&0xff;
                        uint16_t ttl1_xor = icmpv6_id>>12, ttl2_xor = (ttl1>>4)^(ttl1&0xf);
                        uint32_t ipv6_flow_label = ((icmpv6_id&0xf)<<16)|(icmpv6_seq);

                        if (ttl1_xor == ttl2_xor && ttl1 != 0) {
                            ttl = ttl1;
                            timestamp = ntohs(*((uint16_t*)((u_char *)icmpv6Header+8)));

                            std::unique_lock<std::mutex> response_ip_set_lock0(*response_ip_set_mutex);
                            response_ip_set->insert(ex_s_addrv6);
                            response_ip_set_lock0.unlock();

                            uint16_t current_balanced_value = 0, reviced_balanced_value = 0;
                            reviced_balanced_value = ipv6_flow_label;

                            std::unique_lock<std::mutex> ipv6_probe_map_lock3(*ipv6_probe_map_mutex);

                            current_balanced_value = (*ipv6_probe_map)[ex_s_addrv6].balanced_value;

                            if (reviced_balanced_value == current_balanced_value) {
                                current_balanced_value += 13;
                                current_balanced_value = (current_balanced_value+65535)%65535;
                                if (current_balanced_value == 0) {
                                    current_balanced_value += 13;
                                }
                                (*ipv6_probe_map)[ex_s_addrv6].balanced_value = current_balanced_value;
                                (*ipv6_probe_map)[ex_s_addrv6].sended_flow_num += 1;
                                (*ipv6_probe_map)[ex_s_addrv6].current_ttl = 1;
                            }
                            ipv6_probe_map_lock3.unlock();

                            char sipv6_str[INET6_ADDRSTRLEN];
                            if (inet_ntop(AF_INET6, &ex_d_addrv6, sipv6_str, INET6_ADDRSTRLEN) == nullptr) {
                                perror("inet_ntop");
                                exit(1);
                            }
                            std::string sipv6(sipv6_str);

                            char dipv6_str[INET6_ADDRSTRLEN];
                            if (inet_ntop(AF_INET6, &ex_s_addrv6, dipv6_str, INET6_ADDRSTRLEN) == nullptr) {
                                perror("inet_ntop");
                                exit(1);
                            }
                            std::string dipv6(dipv6_str);

                            char mipv6_str[INET6_ADDRSTRLEN];
                            if (inet_ntop(AF_INET6, &ex_s_addrv6, mipv6_str, INET6_ADDRSTRLEN) == nullptr) {
                                perror("inet_ntop");
                                exit(1);
                            }
                            std::string mipv6(mipv6_str);


                            uint16_t send_time = timestamp;
                            uint16_t arrive_time = current_packet->arrive_time;

                            std::ostringstream oss;
                            oss << sipv6 << "\t" << dipv6 << "\t" << target_proto << "\t" << ipv6_flow_label << "\t" << icmpv6_id << "\t" << icmpv6_seq << "\t" << timestamp << "\t" << ttl_field_selected << "\t" << timestamp_field_selected << "\t" << balanced_field_selected << "\t" << mipv6 << "\t" << ttl << "\t" << send_time << "\t" << arrive_time << "\n";
                            std::string output = oss.str();
                            outfile << output;

                            if (file_size_exceeded(current_filename.c_str(), file_size)) {
                                outfile.close();
                                current_filename = *txt_path + generate_txt_filename(base_filename, file_index);
                                outfile = std::ofstream(current_filename);
                                if (!outfile.is_open()) {
                                    std::cerr << "Fail to open a new log file" << std::endl;
                                    exit(1);
                                }
                            }
                        }
                    }
                    else {
                        ipv6_pre_probe_map_lock1.unlock();
                    }

                }
                else if (icmpv6Header->type == ICMP6_DST_UNREACH) {
                    auto *innerIpv6Header = (IPv6_Header *) ((u_char *) icmpv6Header + 8);
                    in6_addr in_s_addrv6 = innerIpv6Header->sip;
                    in6_addr in_d_addrv6 = innerIpv6Header->dip;
                    std::unique_lock<std::mutex> ipv6_pre_probe_map_lock2(*pre_probe_map_mutex);
                    if (pre_probe_map->find(in_d_addrv6) != pre_probe_map->end()) {
                        ipv6_pre_probe_map_lock2.unlock();
                        if (innerIpv6Header->next_header == IPPROTO_ICMPV6) {
                            auto *inner_icmpv6_header = (struct ICMPv6_Header *) ((u_char *) innerIpv6Header + 40);
                            std::string ttl_field_selected;
                            std::string timestamp_field_selected;
                            std::string balanced_field_selected;
                            std::string target_proto;
                            std::unique_lock<std::mutex> ipv6_adapt_map_lock4(*ipv6_adapt_map_mutex);
                            target_proto = (*ipv6_adapt_map)[in_d_addrv6].target_proto;
                            ttl_field_selected = (*ipv6_adapt_map)[in_d_addrv6].ttl_field_selected;
                            timestamp_field_selected = (*ipv6_adapt_map)[in_d_addrv6].timestamp_field_selected;
                            balanced_field_selected = (*ipv6_adapt_map)[in_d_addrv6].balanced_field_selected;
                            ipv6_adapt_map_lock4.unlock();

                            uint16_t icmpv6_id = ntohs(inner_icmpv6_header->ident);
                            uint16_t icmpv6_seq = ntohs(inner_icmpv6_header->seq_number);
                            uint16_t timestamp = 0;
                            uint16_t ttl = 0;
                            uint16_t ttl1 = (icmpv6_id>>4)&0xff;
                            uint16_t ttl1_xor = icmpv6_id>>12, ttl2_xor = (ttl1>>4)^(ttl1&0xf);
                            uint32_t ipv6_flow_label = ((icmpv6_id&0xf)<<16)|(icmpv6_seq);

                            if (ttl1_xor == ttl2_xor && ttl1 != 0) {
                                ttl = ttl1;
                                timestamp = ntohs(*((uint16_t*)((u_char *)inner_icmpv6_header+8)));

                                std::unique_lock<std::mutex> response_ip_set_lock1(*response_ip_set_mutex);
                                response_ip_set->insert(in_d_addrv6);
                                response_ip_set_lock1.unlock();

                                uint16_t current_balanced_value = 0, reviced_balanced_value = 0;
                                reviced_balanced_value = ipv6_flow_label;

                                std::unique_lock<std::mutex> ipv6_probe_map_lock4(*ipv6_probe_map_mutex);

                                current_balanced_value = (*ipv6_probe_map)[in_d_addrv6].balanced_value;

                                if (reviced_balanced_value == current_balanced_value) {
                                    current_balanced_value += 13;
                                    current_balanced_value = (current_balanced_value+65535)%65535;
                                    if (current_balanced_value == 0) {
                                        current_balanced_value += 13;
                                    }
                                    (*ipv6_probe_map)[in_d_addrv6].balanced_value = current_balanced_value;
                                    (*ipv6_probe_map)[in_d_addrv6].sended_flow_num += 1;
                                    (*ipv6_probe_map)[in_d_addrv6].current_ttl = 1;
                                }
                                ipv6_probe_map_lock4.unlock();

                                char sipv6_str[INET6_ADDRSTRLEN];
                                if (inet_ntop(AF_INET6, &ex_d_addrv6, sipv6_str, INET6_ADDRSTRLEN) == nullptr) {
                                    perror("inet_ntop");
                                    exit(1);
                                }
                                std::string sipv6(sipv6_str);
                                char dipv6_str[INET6_ADDRSTRLEN];
                                if (inet_ntop(AF_INET6, &ex_s_addrv6, dipv6_str, INET6_ADDRSTRLEN) == nullptr) {
                                    perror("inet_ntop");
                                    exit(1);
                                }
                                std::string dipv6(dipv6_str);
                                char mipv6_str[INET6_ADDRSTRLEN];
                                if (inet_ntop(AF_INET6, &ex_s_addrv6, mipv6_str, INET6_ADDRSTRLEN) == nullptr) {
                                    perror("inet_ntop");
                                    exit(1);
                                }
                                std::string mipv6(mipv6_str);


                                uint16_t send_time = timestamp;
                                uint16_t arrive_time = current_packet->arrive_time;

                                std::ostringstream oss;
                                oss << sipv6 << "\t" << dipv6 << "\t" << target_proto << "\t" << ipv6_flow_label << "\t" << icmpv6_id << "\t" << icmpv6_seq << "\t" << timestamp << "\t" << ttl_field_selected << "\t" << timestamp_field_selected << "\t" << balanced_field_selected << "\t" << mipv6 << "\t" << ttl << "\t" << send_time << "\t" << arrive_time << "\n";
                                std::string output = oss.str();
                                outfile << output;

                                if (file_size_exceeded(current_filename.c_str(), file_size)) {
                                    outfile.close();
                                    current_filename = *txt_path + generate_txt_filename(base_filename, file_index);
                                    outfile = std::ofstream(current_filename);
                                    if (!outfile.is_open()) {
                                        std::cerr << "Fail to open a new log file" << std::endl;
                                        exit(1);
                                    }
                                }
                            }
                        }
                        else if (innerIpv6Header->next_header == IPPROTO_UDP) {
                            auto *udpHeader = (UDP_Header *) ((u_char *) innerIpv6Header + 40);
                            uint16_t udp_sport = ntohs(udpHeader->sport);
                            uint16_t udp_dport = ntohs(udpHeader->dport);

                            std::string ttl_field_selected;
                            std::string timestamp_field_selected;
                            std::string balanced_field_selected;
                            std::string target_proto;
                            std::unique_lock<std::mutex> ipv6_adapt_map_lock5(*ipv6_adapt_map_mutex);
                            target_proto = (*ipv6_adapt_map)[in_d_addrv6].target_proto;
                            ttl_field_selected = (*ipv6_adapt_map)[in_d_addrv6].ttl_field_selected;
                            timestamp_field_selected = (*ipv6_adapt_map)[in_d_addrv6].timestamp_field_selected;
                            balanced_field_selected = (*ipv6_adapt_map)[in_d_addrv6].balanced_field_selected;
                            ipv6_adapt_map_lock5.unlock();

                            uint32_t vtf = ntohl(innerIpv6Header->vtf);
                            uint32_t ipv6_flow_label = vtf&0xfffff;
                            uint16_t udp_crc = ntohs(udpHeader->crc);

                            uint16_t ttl = 0;
                            uint16_t ttl1 = udp_crc>>8;
                            uint16_t ttl2 = udp_crc&0xff;
                            uint16_t timestamp = 0;

                            if (ttl1 == ttl2) {
                                ttl = ttl1;
                                timestamp = ntohs(*((uint16_t*)((u_char *)udpHeader+8)));

                                std::unique_lock<std::mutex> response_ip_set_lock2(*response_ip_set_mutex);
                                response_ip_set->insert(in_d_addrv6);
                                response_ip_set_lock2.unlock();


                                uint16_t current_balanced_value = 0, reviced_balanced_value = 0;
                                if (balanced_field_selected == "udp_sport") {
                                    reviced_balanced_value = udp_sport;
                                }
                                else if (balanced_field_selected == "udp_dport") {
                                    reviced_balanced_value = udp_dport;
                                }
                                else {
                                    reviced_balanced_value = ipv6_flow_label;
                                }

                                std::unique_lock<std::mutex> ipv6_probe_map_lock5(*ipv6_probe_map_mutex);
                                current_balanced_value = (*ipv6_probe_map)[in_d_addrv6].balanced_value;

                                if (reviced_balanced_value == current_balanced_value) {
                                    current_balanced_value += 13;
                                    current_balanced_value = (current_balanced_value+65535)%65535;
                                    if (current_balanced_value == 0) {
                                        current_balanced_value += 13;
                                    }
                                    (*ipv6_probe_map)[in_d_addrv6].balanced_value = current_balanced_value;
                                    (*ipv6_probe_map)[in_d_addrv6].sended_flow_num += 1;
                                    (*ipv6_probe_map)[in_d_addrv6].current_ttl = 1;
                                }
                                ipv6_probe_map_lock5.unlock();

                                char sipv6_str[INET6_ADDRSTRLEN];
                                if (inet_ntop(AF_INET6, &ex_d_addrv6, sipv6_str, INET6_ADDRSTRLEN) == nullptr) {
                                    perror("inet_ntop");
                                    exit(1);
                                }
                                std::string sipv6(sipv6_str);
                                char dipv6_str[INET6_ADDRSTRLEN];
                                if (inet_ntop(AF_INET6, &ex_s_addrv6, dipv6_str, INET6_ADDRSTRLEN) == nullptr) {
                                    perror("inet_ntop");
                                    exit(1);
                                }
                                std::string dipv6(dipv6_str);
                                char mipv6_str[INET6_ADDRSTRLEN];
                                if (inet_ntop(AF_INET6, &ex_s_addrv6, mipv6_str, INET6_ADDRSTRLEN) == nullptr) {
                                    perror("inet_ntop");
                                    exit(1);
                                }
                                std::string mipv6(mipv6_str);

                                uint16_t send_time = timestamp;
                                uint16_t arrive_time = current_packet->arrive_time;


                                std::ostringstream oss;
                                oss << sipv6 << "\t" << dipv6 << "\t" << target_proto << "\t" << ipv6_flow_label << "\t" << udp_sport << "\t" << udp_dport << "\t" << udp_crc << "\t" << timestamp << "\t" << ttl_field_selected << "\t" << timestamp_field_selected << "\t" << balanced_field_selected << "\t" << mipv6 << "\t" << ttl << "\t" << send_time << "\t" << arrive_time << "\n";
                                std::string output = oss.str();
                                outfile << output;

                                if (file_size_exceeded(current_filename.c_str(), file_size)) {
                                    outfile.close();
                                    current_filename = *txt_path + generate_txt_filename(base_filename, file_index);
                                    outfile = std::ofstream(current_filename);
                                    if (!outfile.is_open()) {
                                        std::cerr << "Fail to open a new log file" << std::endl;
                                        exit(1);
                                    }
                                }
                            }
                        }
                        else if (innerIpv6Header->next_header == IPPROTO_TCP) {
                            auto *tcp_header = (TCP_Header *) ((u_char *) innerIpv6Header + 40);
                            uint16_t tcp_sport = ntohs(tcp_header->sport);
                            uint16_t tcp_dport = ntohs(tcp_header->dport);
                            std::string ttl_field_selected;
                            std::string timestamp_field_selected;
                            std::string balanced_field_selected;
                            std::string target_proto;
                            std::unique_lock<std::mutex> ipv6_adapt_map_lock6(*ipv6_adapt_map_mutex);
                            target_proto = (*ipv6_adapt_map)[in_d_addrv6].target_proto;
                            ttl_field_selected = (*ipv6_adapt_map)[in_d_addrv6].ttl_field_selected;
                            timestamp_field_selected = (*ipv6_adapt_map)[in_d_addrv6].timestamp_field_selected;
                            balanced_field_selected = (*ipv6_adapt_map)[in_d_addrv6].balanced_field_selected;
                            ipv6_adapt_map_lock6.unlock();

                            uint16_t ttl = 0;
                            uint32_t tcp_seq = ntohl(tcp_header->seq_number);
                            uint16_t ttl1 = tcp_seq&0xff;
                            uint16_t ttl2 = (tcp_seq>>8)&0xff;
                            uint16_t timestamp = 0;


                            if (ttl1 == ttl2 && ttl1 != 0) {
                                ttl = ttl1;
                                timestamp = (tcp_seq>>16)&0xffff;

                                std::unique_lock<std::mutex> response_ip_set_lock3(*response_ip_set_mutex);
                                response_ip_set->insert(in_d_addrv6);
                                response_ip_set_lock3.unlock();


                                uint16_t current_balanced_value = 0, reviced_balanced_value = 0;
                                if (balanced_field_selected == "tcp_sport") {
                                    reviced_balanced_value = tcp_sport;
                                }
                                else {
                                    reviced_balanced_value = tcp_dport;
                                }

                                std::unique_lock<std::mutex> ipv6_probe_map_lock6(*ipv6_probe_map_mutex);
                                current_balanced_value = (*ipv6_probe_map)[in_d_addrv6].balanced_value;
                                if (reviced_balanced_value == current_balanced_value) {
                                    current_balanced_value += 13;
                                    current_balanced_value = (current_balanced_value+65535)%65535;
                                    if (current_balanced_value == 0) {
                                        current_balanced_value += 13;
                                    }
                                    (*ipv6_probe_map)[in_d_addrv6].balanced_value = current_balanced_value;
                                    (*ipv6_probe_map)[in_d_addrv6].sended_flow_num += 1;
                                    (*ipv6_probe_map)[in_d_addrv6].current_ttl = 1;
                                }
                                ipv6_probe_map_lock6.unlock();

                                char sipv6_str[INET6_ADDRSTRLEN];
                                if (inet_ntop(AF_INET6, &ex_d_addrv6, sipv6_str, INET6_ADDRSTRLEN) == nullptr) {
                                    perror("inet_ntop");
                                    exit(1);
                                }
                                std::string sipv6(sipv6_str);
                                char dipv6_str[INET6_ADDRSTRLEN];
                                if (inet_ntop(AF_INET6, &ex_s_addrv6, dipv6_str, INET6_ADDRSTRLEN) == nullptr) {
                                    perror("inet_ntop");
                                    exit(1);
                                }
                                std::string dipv6(dipv6_str);
                                char mipv6_str[INET6_ADDRSTRLEN];
                                if (inet_ntop(AF_INET6, &ex_s_addrv6, mipv6_str, INET6_ADDRSTRLEN) == nullptr) {
                                    perror("inet_ntop");
                                    exit(1);
                                }
                                std::string mipv6(mipv6_str);

                                uint16_t send_time = timestamp;
                                uint16_t arrive_time = current_packet->arrive_time;

                                std::ostringstream oss;
                                oss << sipv6 << "\t" << dipv6 << "\t" << target_proto << "\t" <<  tcp_sport << "\t" << tcp_dport << "\t" << tcp_seq << "\t" << ttl_field_selected << "\t" << timestamp_field_selected << "\t" << balanced_field_selected << "\t" << mipv6 << "\t" << ttl << "\t" << send_time << "\t" << arrive_time << "\n";
                                std::string output = oss.str();
                                outfile << output;

                                if (file_size_exceeded(current_filename.c_str(), file_size)) {
                                    outfile.close();
                                    current_filename = *txt_path + generate_txt_filename(base_filename, file_index);
                                    outfile = std::ofstream(current_filename);
                                    if (!outfile.is_open()) {
                                        std::cerr << "Fail to open a new log file" << std::endl;
                                        exit(1);
                                    }
                                }
                            }
                        }
                    }
                    else {
                        ipv6_pre_probe_map_lock2.unlock();
                    }

                }
            }
            else if (ipv6Header->next_header == IPPROTO_TCP) {
                std::unique_lock<std::mutex> ipv6_pre_probe_map_lock3(*pre_probe_map_mutex);
                if (pre_probe_map->find(ex_s_addrv6) != pre_probe_map->end()) {
                    ipv6_pre_probe_map_lock3.unlock();
                    auto *tcp_header = (TCP_Header *)((u_char *) ipv6Header + 40);
                    std::string ttl_field_selected;
                    std::string timestamp_field_selected;
                    std::string balanced_field_selected;
                    std::string target_proto;
                    std::unique_lock<std::mutex> ipv6_adapt_map_lock7(*ipv6_adapt_map_mutex);
                    target_proto = (*ipv6_adapt_map)[ex_s_addrv6].target_proto;
                    ttl_field_selected = (*ipv6_adapt_map)[ex_s_addrv6].ttl_field_selected;
                    timestamp_field_selected = (*ipv6_adapt_map)[ex_s_addrv6].timestamp_field_selected;
                    balanced_field_selected = (*ipv6_adapt_map)[ex_s_addrv6].balanced_field_selected;
                    ipv6_adapt_map_lock7.unlock();

                    uint32_t tcp_ack = ntohl(tcp_header->ack_number);
                    uint32_t tcp_seq = ntohl(tcp_header->ack_number)-1;
                    uint16_t ttl = 0;
                    uint16_t timestamp = 0;
                    uint16_t ttl1 = tcp_seq&0xff;
                    uint16_t ttl2 = (tcp_seq>>8)&0xff;
                    uint16_t tcp_sport = ntohs(tcp_header->dport);
                    uint16_t tcp_dport = ntohs(tcp_header->sport);
                    if (ttl1 == ttl2 && ttl1 != 0 && tcp_ack != 0) {
                        ttl = ttl1;
                        timestamp = tcp_seq>>16;

                        std::unique_lock<std::mutex> response_ip_set_lock4(*response_ip_set_mutex);
                        response_ip_set->insert(ex_s_addrv6);
                        response_ip_set_lock4.unlock();

                        uint16_t current_balanced_value = 0, reviced_balanced_value = 0;
                        if (balanced_field_selected == "tcp_sport") {
                            reviced_balanced_value = tcp_sport;
                        }
                        else {
                            reviced_balanced_value = tcp_dport;
                        }

                        std::unique_lock<std::mutex> ipv6_probe_map_lock7(*ipv6_probe_map_mutex);

                        current_balanced_value = (*ipv6_probe_map)[ex_s_addrv6].balanced_value;
                        if (current_balanced_value == reviced_balanced_value) {
                            current_balanced_value += 13;
                            current_balanced_value = (current_balanced_value+65535)%65535;
                            if (current_balanced_value == 0) {
                                current_balanced_value += 13;
                            }

                            (*ipv6_probe_map)[ex_s_addrv6].balanced_value = current_balanced_value;
                            (*ipv6_probe_map)[ex_s_addrv6].sended_flow_num += 1;
                            (*ipv6_probe_map)[ex_s_addrv6].current_ttl = 1;
                        }
                        ipv6_probe_map_lock7.unlock();

                        char sipv6_str[INET6_ADDRSTRLEN];
                        if (inet_ntop(AF_INET6, &ex_d_addrv6, sipv6_str, INET6_ADDRSTRLEN) == nullptr) {
                            perror("inet_ntop");
                            exit(1);
                        }
                        std::string sipv6(sipv6_str);

                        char dipv6_str[INET6_ADDRSTRLEN];
                        if (inet_ntop(AF_INET6, &ex_s_addrv6, dipv6_str, INET6_ADDRSTRLEN) == nullptr) {
                            perror("inet_ntop");
                            exit(1);
                        }
                        std::string dipv6(dipv6_str);

                        char mipv6_str[INET6_ADDRSTRLEN];
                        if (inet_ntop(AF_INET6, &ex_s_addrv6, mipv6_str, INET6_ADDRSTRLEN) == nullptr) {
                            perror("inet_ntop");
                            exit(1);
                        }
                        std::string mipv6(mipv6_str);

                        uint16_t send_time = timestamp;
                        uint16_t arrive_time = current_packet->arrive_time;


                        std::ostringstream oss;
                        oss << sipv6 << "\t" << dipv6 << "\t" << target_proto << "\t" <<  tcp_sport << "\t" << tcp_dport << "\t" << tcp_seq << "\t" << ttl_field_selected << "\t" << timestamp_field_selected << "\t" << balanced_field_selected << "\t" << mipv6 << "\t" << ttl << "\t" << send_time << "\t" << arrive_time << "\n";
                        std::string output = oss.str();
                        outfile << output;

                        if (file_size_exceeded(current_filename.c_str(), file_size)) {
                            outfile.close();
                            current_filename = *txt_path + generate_txt_filename(base_filename, file_index);
                            outfile = std::ofstream(current_filename);
                            if (!outfile.is_open()) {
                                std::cerr << "Fail to open a new log file" << std::endl;
                                exit(1);
                            }
                        }
                    }
                }
                else {
                    ipv6_pre_probe_map_lock3.unlock();
                }

            }
        }
        delete[] current_packet->packet;
        delete current_packet;
    }

    std::unique_lock<std::mutex> check_queue_lock1(*check_queue_mutex);
    while (!check_queue->empty()) {
        check_queue->pop();
    }
    check_queue_lock1.unlock();
}

