#include <map>
#include "start.h"

std::unordered_set<in_addr, V4AddrHash, V4AddrEqual> start_ipv4(const int *band_speed_limit, char *dev, std::string *sipv4, in_addr *in_ipv4, std::vector<in_addr> *dipv4_list, bool *probe_pcap_store, const int *nthread, int *max_ttl, int *pre_round, const int *begin_lower_bound, const int *begin_upper_bound, const bool *field_default, const bool *blk, const int *pool_size) {

    std::string pcap_path = "./pcaps_ipv4/";
    struct stat pcap_st = {0};
    if (stat("pcaps_ipv4", &pcap_st) == -1) {
        if (mkdir("pcaps_ipv4", 0777) == -1) {
            perror("Fail to create pcaps_ipv4");
            exit(1);
        }
    }
    std::string txt_path = "./txts_ipv4/";

    struct stat txt_st = {0};
    if (stat("txts_ipv4", &txt_st) == -1) {
        if (mkdir("txts_ipv4", 0777) == -1) {
            perror("Fail to create txts_ipv4");
            exit(1);
        }
    }

    std::cout << "The number of target IP is: " << dipv4_list->size() << ".\n";

    std::unordered_map<in_addr, IPv4_Pre_Probe, V4AddrHash, V4AddrEqual> preprobe_map;
    std::mutex preprobe_map_mutex;

    for (auto &ipv4: *dipv4_list) {
        preprobe_map[ipv4] = IPv4_Pre_Probe{};
    }

    if (!(*field_default)) {
        std::atomic<bool> proto_preprobe_isCaptureDone(false);
        std::queue<Packet_Information *> proto_preprobe_check_queue;
        std::mutex proto_preprobe_check_queue_mutex;

        std::vector<std::thread> proto_preprobe_thread_list;
        std::vector<int *> proto_preprobe_nt_list;

        for (int i = 0; i < *nthread; ++i) {
            int *nt = new int;
            *nt = i;
            proto_preprobe_nt_list.emplace_back(nt);
            proto_preprobe_thread_list.emplace_back(packet_process_proto_preprobe_ipv4, &proto_preprobe_isCaptureDone, &proto_preprobe_check_queue, &proto_preprobe_check_queue_mutex, in_ipv4, &preprobe_map, &preprobe_map_mutex);
        }
        bool proto_pcap_store = false;
        std::thread proto_capture_thread(capture_packets, &proto_preprobe_isCaptureDone, dev, sipv4, &proto_preprobe_check_queue, &proto_preprobe_check_queue_mutex, &pcap_path, &proto_pcap_store);
        std::thread run_proto_preprobe_ipv4_thread(run_proto_preprobe_ipv4, &proto_preprobe_isCaptureDone, pre_round, in_ipv4, dipv4_list, max_ttl, band_speed_limit, blk);

        for (int i = 0; i < *nthread; ++i) {
            proto_preprobe_thread_list[i].join();
        }
        proto_capture_thread.join();
        run_proto_preprobe_ipv4_thread.join();
        for (int i = 0; i < *nthread; ++i) {
            delete proto_preprobe_nt_list[i];
        }
        
    }


    std::unordered_map<in_addr, IPv4_Field_Adapt, V4AddrHash, V4AddrEqual> ipv4_adapt_map;
    for (auto &dipv4: *dipv4_list) {
        if (*field_default) {
            ipv4_adapt_map[dipv4].target_proto = "tcp";
        }
        else {
            if (preprobe_map[dipv4].proto_response["tcp"].size() > preprobe_map[dipv4].proto_response["udp"].size()) {
                ipv4_adapt_map[dipv4].target_proto = "tcp";
            }
            else {
                ipv4_adapt_map[dipv4].target_proto = "udp";
            }
        }

    }

    std::vector<in_addr> final_dipv4_list;
    for (auto &dipv4: *dipv4_list) {
        if ((*field_default) || !preprobe_map[dipv4].proto_response[ipv4_adapt_map[dipv4].target_proto].empty()) {
            final_dipv4_list.emplace_back(dipv4);
        }
    }

    if (!(*field_default)) {

        std::atomic<bool> field_preprobe_isCaptureDone(false);
        std::queue<Packet_Information *> field_preprobe_check_queue;
        std::mutex field_preprobe_check_queue_mutex;

        std::vector<std::thread> field_preprobe_thread_list;
        std::vector<int *> field_preprobe_nt_list;

        for (int i = 0; i < *nthread; ++i) {
            int *nt = new int;
            *nt = i;
            field_preprobe_nt_list.emplace_back(nt);
            field_preprobe_thread_list.emplace_back(packet_process_field_preprobe_ipv4, &field_preprobe_isCaptureDone, &field_preprobe_check_queue, &field_preprobe_check_queue_mutex, in_ipv4, &preprobe_map, &preprobe_map_mutex);
        }
        bool field_pcap_store = false;
        std::thread field_capture_thread(capture_packets, &field_preprobe_isCaptureDone, dev, sipv4, &field_preprobe_check_queue, &field_preprobe_check_queue_mutex, &pcap_path, &field_pcap_store);
        std::thread run_field_preprobe_ipv4_thread(run_field_preprobe_ipv4, &ipv4_adapt_map, &field_preprobe_isCaptureDone, pre_round, in_ipv4, dipv4_list, max_ttl, band_speed_limit, blk);

        for (int i = 0; i < *nthread; ++i) {
            field_preprobe_thread_list[i].join();
        }
        field_capture_thread.join();
        run_field_preprobe_ipv4_thread.join();
        for (int i = 0; i < *nthread; ++i) {
            delete field_preprobe_nt_list[i];
        }


        for (auto &dipv4: final_dipv4_list) {
            if (ipv4_adapt_map[dipv4].target_proto == "udp") {
                std::unordered_set<in_addr, V4AddrHash, V4AddrEqual> origin_set;
                for (auto &in_ip: preprobe_map[dipv4].flow_response["origin"]) {
                    origin_set.insert(in_ip);
                }
                if (preprobe_map[dipv4].flow_response["origin"].empty()) {
                    ipv4_adapt_map[dipv4].target_proto = "tcp";
                    continue;
                }

                bool ip_ident_balanced_bul = false;
                for (auto &in_ip: preprobe_map[dipv4].flow_response["ipv4_ident"]) {
                    if (origin_set.find(in_ip) == origin_set.end()) {
                        ip_ident_balanced_bul = true;
                        break;
                    }
                }
                if (ip_ident_balanced_bul || preprobe_map[dipv4].flow_response["ipv4_ident"].empty()) {
                    ipv4_adapt_map[dipv4].balanced_field.insert("ipv4_ident");
                }
                else {
                    ipv4_adapt_map[dipv4].information_field.insert("ipv4_ident");
                }

                bool udp_sport_balanced_bul = false;
                for (auto &in_ip: preprobe_map[dipv4].flow_response["udp_sport"]) {
                    if (origin_set.find(in_ip) == origin_set.end()) {
                        udp_sport_balanced_bul = true;
                        break;
                    }
                }
                if (udp_sport_balanced_bul || preprobe_map[dipv4].flow_response["udp_sport"].empty()) {
                    ipv4_adapt_map[dipv4].balanced_field.insert("udp_sport");
                }
                else {
                    ipv4_adapt_map[dipv4].information_field.insert("udp_sport");
                }

                bool udp_dport_balanced_bul = false;
                for (auto &in_ip: preprobe_map[dipv4].flow_response["udp_dport"]) {
                    if (origin_set.find(in_ip) == origin_set.end()) {
                        udp_dport_balanced_bul = true;
                        break;
                    }
                }
                if (udp_dport_balanced_bul || preprobe_map[dipv4].flow_response["udp_dport"].empty()) {
                    ipv4_adapt_map[dipv4].balanced_field.insert("udp_dport");
                }
                else {
                    ipv4_adapt_map[dipv4].information_field.insert("udp_dport");
                }

                bool udp_crc_balanced_bul = false;
                for (auto &in_ip: preprobe_map[dipv4].flow_response["udp_crc"]) {
                    if (origin_set.find(in_ip) == origin_set.end()) {
                        udp_crc_balanced_bul = true;
                        break;
                    }
                }
                if (udp_crc_balanced_bul || preprobe_map[dipv4].flow_response["udp_crc"].empty()) {
                    ipv4_adapt_map[dipv4].balanced_field.insert("udp_crc");
                }
                else {
                    ipv4_adapt_map[dipv4].information_field.insert("udp_crc");
                }
            }
            else {
                std::unordered_set<in_addr, V4AddrHash, V4AddrEqual> origin_set;
                for (auto &in_ip: preprobe_map[dipv4].flow_response["origin"]) {
                    origin_set.insert(in_ip);
                }

                bool ip_ident_balanced_bul = false;
                for (auto &in_ip: preprobe_map[dipv4].flow_response["ipv4_ident"]) {
                    if (origin_set.find(in_ip) == origin_set.end()) {
                        ip_ident_balanced_bul = true;
                        break;
                    }
                }
                if (ip_ident_balanced_bul || preprobe_map[dipv4].flow_response["ipv4_ident"].empty()) {
                    ipv4_adapt_map[dipv4].balanced_field.insert("ipv4_ident");
                }
                else {
                    ipv4_adapt_map[dipv4].information_field.insert("ipv4_ident");
                }

                bool tcp_sport_balanced_bul = false;
                for (auto &in_ip: preprobe_map[dipv4].flow_response["tcp_sport"]) {
                    if (origin_set.find(in_ip) == origin_set.end()) {
                        tcp_sport_balanced_bul = true;
                        break;
                    }
                }
                if (tcp_sport_balanced_bul || preprobe_map[dipv4].flow_response["tcp_sport"].empty()) {
                    ipv4_adapt_map[dipv4].balanced_field.insert("tcp_sport");
                }
                else {
                    ipv4_adapt_map[dipv4].information_field.insert("tcp_sport");
                }

                bool tcp_dport_balanced_bul = false;
                for (auto &in_ip: preprobe_map[dipv4].flow_response["tcp_dport"]) {
                    if (origin_set.find(in_ip) == origin_set.end()) {
                        tcp_dport_balanced_bul = true;
                        break;
                    }
                }
                if (tcp_dport_balanced_bul || preprobe_map[dipv4].flow_response["tcp_dport"].empty()) {
                    ipv4_adapt_map[dipv4].balanced_field.insert("tcp_dport");
                }
                else {
                    ipv4_adapt_map[dipv4].information_field.insert("tcp_dport");
                }

                bool tcp_seq_balanced_bul = false;
                for (auto &in_ip: preprobe_map[dipv4].flow_response["tcp_seq"]) {
                    if (origin_set.find(in_ip) == origin_set.end()) {
                        tcp_seq_balanced_bul = true;
                        break;
                    }
                }
                if (tcp_seq_balanced_bul || preprobe_map[dipv4].flow_response["tcp_seq"].empty()) {
                    ipv4_adapt_map[dipv4].balanced_field.insert("tcp_seq");
                }
                else {
                    ipv4_adapt_map[dipv4].information_field.insert("tcp_seq");
                }
            }
        }
    }



    for (auto &dipv4: final_dipv4_list) {
        if (ipv4_adapt_map[dipv4].target_proto == "udp") {
            if (*field_default) {
                ipv4_adapt_map[dipv4].ttl_field_selected = "udp_crc";
                ipv4_adapt_map[dipv4].timestamp_field_selected = "ipv4_ident";
                ipv4_adapt_map[dipv4].balanced_field_selected = "udp_sport";
            }
            else {
                if (ipv4_adapt_map[dipv4].information_field.empty()) {
                    ipv4_adapt_map[dipv4].target_proto = "tcp";
                    ipv4_adapt_map[dipv4].ttl_field_selected = "tcp_seq";
                    ipv4_adapt_map[dipv4].timestamp_field_selected = "tcp_seq";
                    ipv4_adapt_map[dipv4].balanced_field_selected = "tcp_sport";
                }
                else {
                    if (ipv4_adapt_map[dipv4].information_field.find("udp_crc") != ipv4_adapt_map[dipv4].information_field.end()) {
                        ipv4_adapt_map[dipv4].ttl_field_selected = "udp_crc";
                        if (ipv4_adapt_map[dipv4].information_field.find("ipv4_ident") != ipv4_adapt_map[dipv4].information_field.end()) {
                            ipv4_adapt_map[dipv4].timestamp_field_selected = "ipv4_ident";
                        }
                        else {
                            ipv4_adapt_map[dipv4].timestamp_field_selected = "none";
                        }
                    }
                    else {
                        ipv4_adapt_map[dipv4].ttl_field_selected = "ipv4_ident";
                        ipv4_adapt_map[dipv4].timestamp_field_selected = "none";
                    }
                    if (ipv4_adapt_map[dipv4].balanced_field_selected.empty()) {
                        if (ipv4_adapt_map[dipv4].balanced_field.find("udp_sport") != ipv4_adapt_map[dipv4].balanced_field.end()) {
                            ipv4_adapt_map[dipv4].balanced_field_selected = "udp_sport";
                        }
                        else {
                            ipv4_adapt_map[dipv4].balanced_field_selected = "udp_dport";
                        }
                    }
                }
            }
        }
        else {
            if (*field_default) {
                ipv4_adapt_map[dipv4].ttl_field_selected = "tcp_seq";
                ipv4_adapt_map[dipv4].timestamp_field_selected = "tcp_seq";
                ipv4_adapt_map[dipv4].balanced_field_selected = "tcp_sport";
            }
            else {
                ipv4_adapt_map[dipv4].ttl_field_selected = "tcp_seq";
                ipv4_adapt_map[dipv4].timestamp_field_selected = "tcp_seq";
                if (ipv4_adapt_map[dipv4].balanced_field.find("tcp_sport") != ipv4_adapt_map[dipv4].balanced_field.end()) {
                    ipv4_adapt_map[dipv4].balanced_field_selected = "tcp_sport";
                }
                else {
                    ipv4_adapt_map[dipv4].balanced_field_selected = "tcp_dport";
                }
            }

        }
    }

    std::unordered_map<in_addr, IPv4_Probe, V4AddrHash, V4AddrEqual> ipv4_probe_map;
    for (auto &dipv4: final_dipv4_list) {
        ipv4_probe_map[dipv4] = IPv4_Probe{};
        if (!(*field_default) && preprobe_map[dipv4].proto_response[ipv4_adapt_map[dipv4].target_proto].size() == 0) {
            ipv4_probe_map[dipv4].finished = true;
        }
        else {
            ipv4_probe_map[dipv4].finished = false;
        }
        ipv4_probe_map[dipv4].current_ttl = 1;
        ipv4_probe_map[dipv4].ipv4_pool_cur = 0;
        for (int i = 0; i < *pool_size; ++i) {
            ipv4_probe_map[dipv4].ipv4_pool_cnt.emplace_back(0);
        }

        ipv4_probe_map[dipv4].flow_upper_bound = *begin_lower_bound;
        ipv4_probe_map[dipv4].begin_lower_bound = *begin_lower_bound;
        ipv4_probe_map[dipv4].begin_upper_bound = *begin_upper_bound;

        if (ipv4_adapt_map[dipv4].balanced_field_selected == "tcp_sport" || ipv4_adapt_map[dipv4].balanced_field_selected == "udp_sport") {
            ipv4_probe_map[dipv4].balanced_value = 35265;
        }
        else if (ipv4_adapt_map[dipv4].balanced_field_selected == "tcp_dport" || ipv4_adapt_map[dipv4].balanced_field_selected == "udp_dport") {
            ipv4_probe_map[dipv4].balanced_value = 33434;
        }
        else {
            ipv4_probe_map[dipv4].balanced_value = 114;
        }
        ipv4_probe_map[dipv4].sended_flow_num = 0;

        ipv4_probe_map[dipv4].connect_pool_cur = 0;
        ipv4_probe_map[dipv4].pool_size = *pool_size;

        for (int i = 0; i < *pool_size; ++i) {
            ipv4_probe_map[dipv4].connect_pool_cnt.emplace_back(0);
        }

    }



    std::atomic<bool> probe_isCaptureDone(false);
    std::queue<Packet_Information *> probe_check_queue;
    std::mutex probe_check_queue_mutex;

    std::mutex ipv4_probe_map_mutex;
    std::mutex ipv4_adapt_map_mutex;

    std::vector<std::thread> probe_thread_list;
    std::vector<int *> probe_nt_list;

    std::unordered_set<in_addr, V4AddrHash, V4AddrEqual> reponse_ip_set;
    std::mutex reponse_ip_set_mutex;

    for (int i = 0; i < *nthread; ++i) {
        int *nt = new int;
        *nt = i;
        probe_nt_list.emplace_back(nt);
        probe_thread_list.emplace_back(packet_process_ipv4, &probe_isCaptureDone, &probe_check_queue, &probe_check_queue_mutex, &ipv4_probe_map, &ipv4_probe_map_mutex, &ipv4_adapt_map, &ipv4_adapt_map_mutex, &reponse_ip_set, &reponse_ip_set_mutex, in_ipv4, &preprobe_map, &preprobe_map_mutex, &txt_path, nt);
    }
    std::thread probe_capture_thread(capture_packets, &probe_isCaptureDone, dev, sipv4, &probe_check_queue, &probe_check_queue_mutex, &pcap_path, probe_pcap_store);
    std::thread run_probe_ipv4_thread(run_send_ipv4, &ipv4_probe_map, &ipv4_probe_map_mutex, &ipv4_adapt_map, &ipv4_adapt_map_mutex, &probe_isCaptureDone, in_ipv4, &final_dipv4_list, max_ttl, band_speed_limit, blk);

    for (int i = 0; i < *nthread; ++i) {
        probe_thread_list[i].join();
    }
    probe_capture_thread.join();
    run_probe_ipv4_thread.join();
    for (int i = 0; i < *nthread; ++i) {
        delete probe_nt_list[i];
    }

    return reponse_ip_set;

}

std::unordered_set<in6_addr, V6AddrHash, V6AddrEqual> start_ipv6(const int *band_speed_limit, char *dev, std::string *sipv6, in6_addr *in_ipv6, std::vector<in6_addr> *dipv6_list, bool *probe_pcap_store, const int *nthread, int *max_ttl, int *pre_round, const int *begin_lower_bound, const int *begin_upper_bound, const bool *field_default, const bool *blk, const int *pool_size) {
    std::string pcap_path = "./pcaps_ipv6/";
    struct stat pcap_st = {0};
    if (stat("pcaps_ipv6", &pcap_st) == -1) {
        if (mkdir("pcaps_ipv6", 0777) == -1) {
            perror("Fail to create pcaps_ipv6");
            exit(1);
        }
    }
    std::string txt_path = "./txts_ipv6/";

    struct stat txt_st = {0};
    if (stat("txts_ipv6", &txt_st) == -1) {
        if (mkdir("txts_ipv6", 0777) == -1) {
            perror("Fail to create txts_ipv6");
            exit(1);
        }
    }

    std::cout << "The number of target IP is: " << dipv6_list->size() << ".\n";

    std::unordered_map<in6_addr, IPv6_Pre_Probe, V6AddrHash, V6AddrEqual> preprobe_map;
    std::mutex preprobe_map_mutex;

    for (auto &ipv6: *dipv6_list) {
        preprobe_map[ipv6] = IPv6_Pre_Probe{};
    }

    if (!(*field_default)) {
        std::atomic<bool> proto_preprobe_isCaptureDone(false);
        std::queue<Packet_Information *> proto_preprobe_check_queue;
        std::mutex proto_preprobe_check_queue_mutex;

        std::vector<std::thread> proto_preprobe_thread_list;
        std::vector<int *> proto_preprobe_nt_list;

        for (int i = 0; i < *nthread; ++i) {
            int *nt = new int;
            *nt = i;
            proto_preprobe_nt_list.emplace_back(nt);
            proto_preprobe_thread_list.emplace_back(packet_process_proto_preprobe_ipv6, &proto_preprobe_isCaptureDone, &proto_preprobe_check_queue, &proto_preprobe_check_queue_mutex, in_ipv6, &preprobe_map, &preprobe_map_mutex);
        }
        bool proto_pcap_store = false;
        std::thread proto_capture_thread(capture_packets, &proto_preprobe_isCaptureDone, dev, sipv6, &proto_preprobe_check_queue, &proto_preprobe_check_queue_mutex, &pcap_path, &proto_pcap_store);
        std::thread run_proto_preprobe_ipv6_thread(run_proto_preprobe_ipv6, &proto_preprobe_isCaptureDone, pre_round, in_ipv6, dipv6_list, max_ttl, band_speed_limit, blk);

        for (int i = 0; i < *nthread; ++i) {
            proto_preprobe_thread_list[i].join();
        }
        proto_capture_thread.join();
        run_proto_preprobe_ipv6_thread.join();
        for (int i = 0; i < *nthread; ++i) {
            delete proto_preprobe_nt_list[i];
        }
    }

    std::unordered_map<in6_addr, IPv6_Field_Adapt, V6AddrHash, V6AddrEqual> ipv6_adapt_map;
    for (auto &dipv6: *dipv6_list) {
        int icmpv6_size = preprobe_map[dipv6].proto_response["icmpv6"].size(), tcp_size = preprobe_map[dipv6].proto_response["tcp"].size(), udp_size = preprobe_map[dipv6].proto_response["udp"].size();
        if (*field_default) {
            ipv6_adapt_map[dipv6].target_proto = "tcp";
        }
        else {
            if (icmpv6_size > tcp_size && icmpv6_size > udp_size) {
                ipv6_adapt_map[dipv6].target_proto = "icmpv6";
            }
            else if (tcp_size > udp_size) {
                ipv6_adapt_map[dipv6].target_proto = "tcp";
            }
            else {
                ipv6_adapt_map[dipv6].target_proto = "udp";
            }
        }
    }

    std::vector<in6_addr> final_dipv6_list;
    for (auto &dipv6: *dipv6_list) {
        if ((*field_default) || !preprobe_map[dipv6].proto_response[ipv6_adapt_map[dipv6].target_proto].empty()) {
            final_dipv6_list.emplace_back(dipv6);
        }
    }



    if (!(*field_default)) {
        std::atomic<bool> field_preprobe_isCaptureDone(false);
        std::queue<Packet_Information *> field_preprobe_check_queue;
        std::mutex field_preprobe_check_queue_mutex;

        std::vector<std::thread> field_preprobe_thread_list;
        std::vector<int *> field_preprobe_nt_list;

        for (int i = 0; i < *nthread; ++i) {
            int *nt = new int;
            *nt = i;
            field_preprobe_nt_list.emplace_back(nt);
            field_preprobe_thread_list.emplace_back(packet_process_field_preprobe_ipv6, &field_preprobe_isCaptureDone, &field_preprobe_check_queue, &field_preprobe_check_queue_mutex, in_ipv6, &preprobe_map, &preprobe_map_mutex);
        }
        bool field_pcap_store = false;
        std::thread field_capture_thread(capture_packets, &field_preprobe_isCaptureDone, dev, sipv6, &field_preprobe_check_queue, &field_preprobe_check_queue_mutex, &pcap_path, &field_pcap_store);
        std::thread run_field_preprobe_ipv6_thread(run_field_preprobe_ipv6, &ipv6_adapt_map, &field_preprobe_isCaptureDone, pre_round, in_ipv6, dipv6_list, max_ttl, band_speed_limit, blk);

        for (int i = 0; i < *nthread; ++i) {
            field_preprobe_thread_list[i].join();
        }
        field_capture_thread.join();
        run_field_preprobe_ipv6_thread.join();
        for (int i = 0; i < *nthread; ++i) {
            delete field_preprobe_nt_list[i];
        }



        for (auto &dipv6: final_dipv6_list) {
            if (ipv6_adapt_map[dipv6].target_proto == "udp") {
                std::unordered_set<in6_addr, V6AddrHash, V6AddrEqual> origin_set;
                for (auto &in_ip: preprobe_map[dipv6].flow_response["origin"]) {
                    origin_set.insert(in_ip);
                }
                if (preprobe_map[dipv6].flow_response["origin"].empty()) {
                    ipv6_adapt_map[dipv6].target_proto = "tcp";
                    continue;
                }

                bool ipv6_flow_label_balanced_bul = false;
                for (auto &in_ip: preprobe_map[dipv6].flow_response["ipv6_flow_label"]) {
                    if (origin_set.find(in_ip) == origin_set.end()) {
                        ipv6_flow_label_balanced_bul = true;
                        break;
                    }
                }
                if (ipv6_flow_label_balanced_bul || preprobe_map[dipv6].flow_response["ipv6_flow_label"].empty()) {
                    ipv6_adapt_map[dipv6].balanced_field.insert("ipv6_flow_label");
                }
                else {
                    ipv6_adapt_map[dipv6].information_field.insert("ipv6_flow_label");
                }

                bool udp_sport_balanced_bul = false;
                for (auto &in_ip: preprobe_map[dipv6].flow_response["udp_sport"]) {
                    if (origin_set.find(in_ip) == origin_set.end()) {
                        udp_sport_balanced_bul = true;
                        break;
                    }
                }
                if (udp_sport_balanced_bul || preprobe_map[dipv6].flow_response["udp_sport"].empty()) {
                    ipv6_adapt_map[dipv6].balanced_field.insert("udp_sport");
                }
                else {
                    ipv6_adapt_map[dipv6].information_field.insert("udp_sport");
                }

                bool udp_dport_balanced_bul = false;
                for (auto &in_ip: preprobe_map[dipv6].flow_response["udp_dport"]) {
                    if (origin_set.find(in_ip) == origin_set.end()) {
                        udp_dport_balanced_bul = true;
                        break;
                    }
                }
                if (udp_dport_balanced_bul || preprobe_map[dipv6].flow_response["udp_dport"].empty()) {
                    ipv6_adapt_map[dipv6].balanced_field.insert("udp_dport");
                }
                else {
                    ipv6_adapt_map[dipv6].information_field.insert("udp_dport");
                }

                bool udp_crc_balanced_bul = false;
                for (auto &in_ip: preprobe_map[dipv6].flow_response["udp_crc"]) {
                    if (origin_set.find(in_ip) == origin_set.end()) {
                        udp_crc_balanced_bul = true;
                        break;
                    }
                }
                if (udp_crc_balanced_bul || preprobe_map[dipv6].flow_response["udp_crc"].empty()) {
                    ipv6_adapt_map[dipv6].balanced_field.insert("udp_crc");
                }
                else {
                    ipv6_adapt_map[dipv6].information_field.insert("udp_crc");
                }
            }
            else if (ipv6_adapt_map[dipv6].target_proto == "tcp") {
                std::unordered_set<in6_addr, V6AddrHash, V6AddrEqual> origin_set;
                for (auto &in_ip: preprobe_map[dipv6].flow_response["origin"]) {
                    origin_set.insert(in_ip);
                }

                bool ipv6_flow_label_balanced_bul = false;
                for (auto &in_ip: preprobe_map[dipv6].flow_response["ipv6_flow_label"]) {
                    if (origin_set.find(in_ip) == origin_set.end()) {
                        ipv6_flow_label_balanced_bul = true;
                        break;
                    }
                }
                if (ipv6_flow_label_balanced_bul) {
                    ipv6_adapt_map[dipv6].balanced_field.insert("ipv6_flow_label");
                }
                else {
                    ipv6_adapt_map[dipv6].information_field.insert("ipv6_flow_label");
                }

                bool tcp_sport_balanced_bul = false;
                for (auto &in_ip: preprobe_map[dipv6].flow_response["tcp_sport"]) {
                    if (origin_set.find(in_ip) == origin_set.end()) {
                        tcp_sport_balanced_bul = true;
                        break;
                    }
                }
                if (tcp_sport_balanced_bul) {
                    ipv6_adapt_map[dipv6].balanced_field.insert("tcp_sport");
                }
                else {
                    ipv6_adapt_map[dipv6].information_field.insert("tcp_sport");
                }

                bool tcp_dport_balanced_bul = false;
                for (auto &in_ip: preprobe_map[dipv6].flow_response["tcp_dport"]) {
                    if (origin_set.find(in_ip) == origin_set.end()) {
                        tcp_dport_balanced_bul = true;
                        break;
                    }
                }
                if (tcp_dport_balanced_bul) {
                    ipv6_adapt_map[dipv6].balanced_field.insert("tcp_dport");
                }
                else {
                    ipv6_adapt_map[dipv6].information_field.insert("tcp_dport");
                }

                bool tcp_seq_balanced_bul = false;
                for (auto &in_ip: preprobe_map[dipv6].flow_response["tcp_seq"]) {
                    if (origin_set.find(in_ip) == origin_set.end()) {
                        tcp_seq_balanced_bul = true;
                        break;
                    }
                }
                if (tcp_seq_balanced_bul) {
                    ipv6_adapt_map[dipv6].balanced_field.insert("tcp_seq");
                }
                else {
                    ipv6_adapt_map[dipv6].information_field.insert("tcp_seq");
                }
            }
            else {
                std::unordered_set<in6_addr, V6AddrHash, V6AddrEqual> origin_set;
                for (auto &in_ip: preprobe_map[dipv6].flow_response["origin"]) {
                    origin_set.insert(in_ip);
                }
                if (preprobe_map[dipv6].flow_response["origin"].empty()) {
                    ipv6_adapt_map[dipv6].target_proto = "tcp";
                    continue;
                }

                bool ipv6_flow_label_balanced_bul = false;
                for (auto &in_ip: preprobe_map[dipv6].flow_response["ipv6_flow_label"]) {
                    if (origin_set.find(in_ip) == origin_set.end()) {
                        ipv6_flow_label_balanced_bul = true;
                        break;
                    }
                }
                if (ipv6_flow_label_balanced_bul || preprobe_map[dipv6].flow_response["ipv6_flow_label"].empty()) {
                    ipv6_adapt_map[dipv6].balanced_field.insert("ipv6_flow_label");
                }
                else {
                    ipv6_adapt_map[dipv6].information_field.insert("ipv6_flow_label");
                }

                bool icmpv6_ident_balanced_bul = false;
                for (auto &in_ip: preprobe_map[dipv6].flow_response["icmpv6_ident"]) {
                    if (origin_set.find(in_ip) == origin_set.end()) {
                        icmpv6_ident_balanced_bul = true;
                        break;
                    }
                }
                if (icmpv6_ident_balanced_bul || preprobe_map[dipv6].flow_response["icmpv6_ident"].empty()) {
                    ipv6_adapt_map[dipv6].balanced_field.insert("icmpv6_ident");
                }
                else {
                    ipv6_adapt_map[dipv6].information_field.insert("icmpv6_ident");
                }

                bool icmpv6_seq_balanced_bul = false;
                for (auto &in_ip: preprobe_map[dipv6].flow_response["icmpv6_seq"]) {
                    if (origin_set.find(in_ip) == origin_set.end()) {
                        icmpv6_seq_balanced_bul = true;
                        break;
                    }
                }
                if (icmpv6_seq_balanced_bul || preprobe_map[dipv6].flow_response["icmpv6_seq"].empty()) {
                    ipv6_adapt_map[dipv6].balanced_field.insert("icmpv6_seq");
                }
                else {
                    ipv6_adapt_map[dipv6].information_field.insert("icmpv6_seq");
                }

                bool icmpv6_content_balanced_bul = false;
                for (auto &in_ip: preprobe_map[dipv6].flow_response["icmpv6_content"]) {
                    if (origin_set.find(in_ip) == origin_set.end()) {
                        icmpv6_content_balanced_bul = true;
                        break;
                    }
                }
                if (icmpv6_content_balanced_bul || preprobe_map[dipv6].flow_response["icmpv6_content"].empty()) {
                    ipv6_adapt_map[dipv6].balanced_field.insert("icmpv6_content");
                }
                else {
                    ipv6_adapt_map[dipv6].information_field.insert("icmpv6_content");
                }
            }
        }
    }

    for (auto &dipv6: final_dipv6_list) {
        if (ipv6_adapt_map[dipv6].target_proto == "udp") {
            if (*field_default) {
                ipv6_adapt_map[dipv6].ttl_field_selected = "udp_crc";
                ipv6_adapt_map[dipv6].timestamp_field_selected = "udp_content";
                ipv6_adapt_map[dipv6].balanced_field_selected = "udp_sport";
            }
            else {
                if (ipv6_adapt_map[dipv6].information_field.find("udp_crc") != ipv6_adapt_map[dipv6].information_field.end()) {
                    ipv6_adapt_map[dipv6].ttl_field_selected = "udp_crc";
                    ipv6_adapt_map[dipv6].timestamp_field_selected = "udp_content";
                    ipv6_adapt_map[dipv6].balanced_field_selected = "udp_sport";
                }
                else {
                    ipv6_adapt_map[dipv6].target_proto = "tcp";
                    ipv6_adapt_map[dipv6].ttl_field_selected = "tcp_seq";
                    ipv6_adapt_map[dipv6].timestamp_field_selected = "tcp_seq";
                    ipv6_adapt_map[dipv6].balanced_field_selected = "tcp_sport";
                }
                if (ipv6_adapt_map[dipv6].balanced_field_selected.empty()) {
                    if (ipv6_adapt_map[dipv6].balanced_field.find("udp_sport") != ipv6_adapt_map[dipv6].balanced_field.end()) {
                        ipv6_adapt_map[dipv6].balanced_field_selected = "udp_sport";
                    }
                    else if (ipv6_adapt_map[dipv6].balanced_field.find("ipv6_flow_label") != ipv6_adapt_map[dipv6].balanced_field.end()) {
                        ipv6_adapt_map[dipv6].balanced_field_selected = "ipv6_flow_label";
                    }
                    else {
                        ipv6_adapt_map[dipv6].balanced_field_selected = "udp_dport";
                    }
                }
            }
        }
        else if (ipv6_adapt_map[dipv6].target_proto == "tcp") {
            if (*field_default) {
                ipv6_adapt_map[dipv6].ttl_field_selected = "tcp_seq";
                ipv6_adapt_map[dipv6].timestamp_field_selected = "tcp_seq";
                ipv6_adapt_map[dipv6].balanced_field_selected = "tcp_sport";
            }
            else {
                ipv6_adapt_map[dipv6].ttl_field_selected = "tcp_seq";
                ipv6_adapt_map[dipv6].timestamp_field_selected = "tcp_seq";
                if (ipv6_adapt_map[dipv6].balanced_field.find("tcp_sport") != ipv6_adapt_map[dipv6].balanced_field.end()) {
                    ipv6_adapt_map[dipv6].balanced_field_selected = "tcp_sport";
                }
                else {
                    ipv6_adapt_map[dipv6].balanced_field_selected = "tcp_dport";
                }
            }

        }
        else {
            ipv6_adapt_map[dipv6].ttl_field_selected = "icmpv6_ident";
            ipv6_adapt_map[dipv6].timestamp_field_selected = "icmpv6_content";
            ipv6_adapt_map[dipv6].balanced_field_selected = "ipv6_flow_label";
        }
    }

    std::unordered_map<in6_addr, IPv6_Probe, V6AddrHash, V6AddrEqual> ipv6_probe_map;
    for (auto &dipv6: final_dipv6_list) {
        ipv6_probe_map[dipv6] = IPv6_Probe{};
        if (!(*field_default) && preprobe_map[dipv6].proto_response[ipv6_adapt_map[dipv6].target_proto].size() == 0) {
            ipv6_probe_map[dipv6].finished = true;
        }
        else {
            ipv6_probe_map[dipv6].finished = false;
        }
        ipv6_probe_map[dipv6].current_ttl = 1;
        ipv6_probe_map[dipv6].ipv6_pool_cur = 0;
        for (int i = 0; i < *pool_size; ++i) {
            ipv6_probe_map[dipv6].ipv6_pool_cnt.emplace_back(0);
        }

        ipv6_probe_map[dipv6].flow_upper_bound = *begin_lower_bound;
        ipv6_probe_map[dipv6].begin_lower_bound = *begin_lower_bound;
        ipv6_probe_map[dipv6].begin_upper_bound = *begin_upper_bound;

        if (ipv6_adapt_map[dipv6].balanced_field_selected == "udp_sport" || ipv6_adapt_map[dipv6].balanced_field_selected == "tcp_sport") {
            ipv6_probe_map[dipv6].balanced_value = 35265;
        }
        else if (ipv6_adapt_map[dipv6].balanced_field_selected == "udp_dport" || ipv6_adapt_map[dipv6].balanced_field_selected == "tcp_dport") {
            ipv6_probe_map[dipv6].balanced_value = 33434;
        }
        else {
            ipv6_probe_map[dipv6].balanced_value = 114;
        }
        ipv6_probe_map[dipv6].sended_flow_num = 0;

        ipv6_probe_map[dipv6].connect_pool_cur = 0;
        ipv6_probe_map[dipv6].pool_size = *pool_size;

        for (int i = 0; i < *pool_size; ++i) {
            ipv6_probe_map[dipv6].connect_pool_cnt.emplace_back(0);
        }

    }


    std::atomic<bool> probe_isCaptureDone(false);
    std::queue<Packet_Information *> probe_check_queue;
    std::mutex probe_check_queue_mutex;

    std::mutex ipv6_probe_map_mutex;
    std::mutex ipv6_adapt_map_mutex;

    std::vector<std::thread> probe_thread_list;
    std::vector<int *> probe_nt_list;

    std::unordered_set<in6_addr, V6AddrHash, V6AddrEqual> reponse_ip_set;
    std::mutex reponse_ip_set_mutex;

    for (int i = 0; i < *nthread; ++i) {
        int *nt = new int;
        *nt = i;
        probe_nt_list.emplace_back(nt);
        probe_thread_list.emplace_back(packet_process_ipv6, &probe_isCaptureDone, &probe_check_queue, &probe_check_queue_mutex, &ipv6_probe_map, &ipv6_probe_map_mutex, &ipv6_adapt_map, &ipv6_adapt_map_mutex, &reponse_ip_set, &reponse_ip_set_mutex, in_ipv6, &preprobe_map, &preprobe_map_mutex, &txt_path, nt);
    }
    std::thread probe_capture_thread(capture_packets, &probe_isCaptureDone, dev, sipv6, &probe_check_queue, &probe_check_queue_mutex, &pcap_path, probe_pcap_store);
    std::thread run_probe_ipv6_thread(run_send_ipv6, &ipv6_probe_map, &ipv6_probe_map_mutex, &ipv6_adapt_map, &ipv6_adapt_map_mutex, &probe_isCaptureDone, in_ipv6, &final_dipv6_list, max_ttl, band_speed_limit, blk);

    for (int i = 0; i < *nthread; ++i) {
        probe_thread_list[i].join();
    }
    probe_capture_thread.join();
    run_probe_ipv6_thread.join();
    for (int i = 0; i < *nthread; ++i) {
        delete probe_nt_list[i];
    }

    return reponse_ip_set;

}
