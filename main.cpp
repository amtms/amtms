#include "start.h"
#include "cmath"

int main(int argc, char* argv[]) {
    if (argc == 2 && std::string(argv[1]) == "--help") {
        std::cout << "    --version          ipv4 or ipv6, default is ipv4" << '\n';
        std::cout << "    --default          use default method, true or false, default is false" << '\n';
        std::cout << "    --ip-file          input file path" << '\n';
        std::cout << "    --prefix-file      input prefix file path" << '\n';
        std::cout << "    --upper-path       path upperbound, default is 100" << '\n';
        std::cout << "    --lower-path       path lowerbound, default is 20" << '\n';
        std::cout << "    --pre-round        preprobe round, default is 3" << '\n';
        std::cout << "    --pcap-store       store pcap, ture or false, default is true" << '\n';
        std::cout << "    --band-limit       band limit, a limit for max speed of sending, default is 1500" << '\n';
        std::cout << "    --process-thread   the number of packet process thread, default is 1" << '\n';
        std::cout << "    --max-ttl          the number of ttl or hop limit, default is 32" << '\n';
        std::cout << "    --interface        the name of interface, default is eth0" << '\n';
        std::cout << "    --block-send       use block model, true or false, default is false" << '\n';
        std::cout << "    --group-size       group size, default is 2500" << '\n';
        std::cout << "    --pool-size        pool size for pruning, default is 10" << '\n';
        return 0;
    }

    bool pcap_store = true;
    int ip_version = 4;
    int num_thread = 1;
    int band_speed_limit = 1500;
    int max_ttl = 32;
    int pre_round = 3;
    int lower_bound = 20, upper_bound = 100;
    bool block_send = false;
    bool field_default = false;
    int group_size = 2500;
    int pool_size = 10;
    std::string interface = "eth0";
    std::string ip_file_name;
    std::string prefix_file_name ;

    for (int i = 1; i < argc; ++i) {
        if (std::string(argv[i]) == "--version") {
            if (std::string(argv[i+1]) == "ipv4") {
                ip_version = 4;
            }
            else if (std::string(argv[i+1]) == "ipv6") {
                ip_version = 6;
            }
            else {
                std::cout << "ip version error" << '\n';
                exit(1);
            }
            ++i;
        }
        else if (std::string(argv[i]) == "--ip-file") {
            ip_file_name = std::string(argv[i+1]);
            ++i;
        }
        else if (std::string(argv[i]) == "--prefix-file") {
            prefix_file_name = std::string(argv[i+1]);
            ++i;
        }
        else if (std::string(argv[i]) == "--pcap-store") {
            if (std::string(argv[i+1]) == "true") {
                pcap_store = true;
            }
            else if (std::string(argv[i+1]) == "false") {
                pcap_store = false;
            }
            else {
                std::cout << "pcap store error" << '\n';
                exit(1);
            }
            ++i;
        }
        else if (std::string(argv[i]) == "--band-limit") {
            band_speed_limit = std::stoi(std::string(argv[i+1]));
            ++i;
        }
        else if (std::string(argv[i]) == "--group-size") {
            group_size = std::stoi(std::string(argv[i+1]));
            ++i;
        }
        else if (std::string(argv[i]) == "--pool-size") {
            pool_size = std::stoi(std::string(argv[i+1]));
            ++i;
        }
        else if (std::string(argv[i]) == "--process-thread") {
            num_thread = std::stoi(std::string(argv[i+1]));
            ++i;
        }
        else if (std::string(argv[i]) == "--max-ttl") {
            max_ttl = std::stoi(std::string(argv[i+1]));
            ++i;
        }
        else if (std::string(argv[i]) == "--interface") {
            interface = std::string(argv[i+1]);
            ++i;
        }
        else if (std::string(argv[i]) == "--default") {
            if (std::string(argv[i+1]) == "true") {
                field_default = true;
            }
            else if (std::string(argv[i+1]) == "false") {
                field_default = false;
            }
            ++i;
        }
        else if (std::string(argv[i]) == "--upper-path") {
            upper_bound = std::stoi(std::string(argv[i+1]));
            ++i;
        }
        else if (std::string(argv[i]) == "--lower-path") {
            lower_bound = std::stoi(std::string(argv[i+1]));
            ++i;
        }
        else if (std::string(argv[i]) == "--pre-round") {
            pre_round = std::stoi(std::string(argv[i+1]));
            ++i;
        }
        else if (std::string(argv[i]) == "--block-send") {
            if (std::string(argv[i+1]) == "true") {
                block_send = true;
            }
            else if (std::string(argv[i+1]) == "false") {
                block_send = false;
            }
            ++i;
        }
    }

    std::string sipv4, sipv6;
    getNetworkInfo(interface, sipv4, sipv6);
    char *dev = const_cast<char *>(interface.c_str());

    std::cout << "Current interface is: " << interface << ", current ipv4 address is:" << sipv4 << ", current ipv6 address is: " << sipv6 << ".\n";

    in_addr sipv4_i{};
    sipv4_i.s_addr = ipv4_string_to_inaddr(sipv4);
    in6_addr sipv6_i{};
    ipv6_string_to_inaddr6(sipv6, sipv6_i);

    std::vector<in_addr> dipv4_list;
    Trie* dprev4_trie;
    std::vector<in6_addr> dipv6_list;
    Trie* dprev6_trie;
    if (ip_version == 4) {
        if (ip_file_name.empty()) {
            dprev4_trie = nullptr;
            contructIPv4Addresses(dipv4_list, prefix_file_name);
        }
        else {
            dprev4_trie = v4Prefix_tire_construct(prefix_file_name);
            readIPv4Addresses(dipv4_list, dprev4_trie, ip_file_name);
        }
        std::cout << "Total number of target address is: " << dipv4_list.size() << ".\n";
        shutffleIPv4Addresses(dipv4_list);
    }
    else {
        if (ip_file_name.empty()) {
            dprev6_trie = nullptr;
            constructIPv6Addresses(dipv6_list, prefix_file_name);
        }
        else {
            dprev6_trie = v6Prefix_tire_construct(prefix_file_name);
            readIPv6Addresses(dipv6_list, dprev6_trie, ip_file_name);
        }

        for (auto &v: dipv6_list) {
            char sipv6_str[INET6_ADDRSTRLEN];
            if (inet_ntop(AF_INET6, &v, sipv6_str, INET6_ADDRSTRLEN) == nullptr) {
                perror("inet_ntop");
                exit(1);
            }
            std::string sipv6(sipv6_str);
            if (sipv6.size() < 5) {
                std::cout << 111 << ' ' << sipv6 << '\n';
            }
        }

        std::cout << "Total number of target address is: " << dipv6_list.size() << ".\n";
        shutffleIPv6Addresses(dipv6_list);
    }

    long long interval = group_size;
    long long cnt_dipv4 = dipv4_list.size(), cnt_dipv6 = dipv6_list.size();

    if (ip_version == 4) {
        std::vector<in_addr> tmp_dipv4_list;
        int num_tmp = 0;
        for (long long i = 0; i < cnt_dipv4; ++i) {
            if (dprev4_trie) {
                long long ipv4_int = ipv4_inaddr_to_int(dipv4_list[i].s_addr);
                int pre = 32;
                Trie* current = v4Prefix_trie_find(dprev4_trie, ipv4_int, pre);
                if (current) {
                    if (current->probe_done == 0) {
                        tmp_dipv4_list.emplace_back(dipv4_list[i]);
                        num_tmp += 1;
                    }
                }
            }
            else {
                tmp_dipv4_list.emplace_back(dipv4_list[i]);
                num_tmp += 1;
            }
            if (num_tmp == interval || i == cnt_dipv4-1) {
                std::cout << "Current progress: " << i+1 << '/' << cnt_dipv4 << '\n';
                int speed_max = tmp_dipv4_list.size()*16;
                int cur_band_speed_limit = std::min(band_speed_limit, speed_max);
                std::unordered_set<in_addr, V4AddrHash, V4AddrEqual> response_ip_set = start_ipv4(&cur_band_speed_limit, dev, &sipv4, &sipv4_i, &tmp_dipv4_list, &pcap_store, &num_thread, &max_ttl, &pre_round, &lower_bound, &upper_bound, &field_default, &block_send, &pool_size);
                tmp_dipv4_list.clear();
                num_tmp = 0;
                if (dprev4_trie) {
                    for (auto res_ipv4: response_ip_set) {
                        char ipv4_str[INET_ADDRSTRLEN];
                        if (inet_ntop(AF_INET, &res_ipv4.s_addr, ipv4_str, INET_ADDRSTRLEN) == nullptr) {
                            perror("inet_ntop");
                            exit(1);
                        }
                        std::string s_ipv4(ipv4_str);
                        long long res_ipv4_int = ipv4_string_to_int(s_ipv4);
                        int pre = 32;
                        Trie *current = v4Prefix_trie_find(dprev4_trie, res_ipv4_int, pre);
                        if (current) {
                            current->probe_done = 1;
                        }
                    }
                }
                std::cout << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" << '\n' << std::endl;
            }
        }
    }
    else {
        std::vector<in6_addr> tmp_dipv6_list;
        int num_tmp = 0;
        for (long long i = 0; i < cnt_dipv6; ++i) {
            if (dprev6_trie) {
                int pre = 128;
                Trie* current = v6Prefix_trie_find(dprev6_trie, dipv6_list[i], pre);
                if (current) {
                    if (current->probe_done == 0) {
                        tmp_dipv6_list.emplace_back(dipv6_list[i]);
                        num_tmp += 1;
                    }
                }
            }
            else {
                tmp_dipv6_list.emplace_back(dipv6_list[i]);
                num_tmp += 1;
            }
            if (num_tmp == interval || i == cnt_dipv6-1) {
                std::cout << "Current progress: " << i+1 << '/' << cnt_dipv6 << '\n';
                int speed_max = tmp_dipv6_list.size()*16;
                int cur_band_speed_limit = std::min(band_speed_limit, speed_max);
                std::unordered_set<in6_addr, V6AddrHash, V6AddrEqual> response_ip_set = start_ipv6(&cur_band_speed_limit, dev, &sipv6, &sipv6_i, &tmp_dipv6_list, &pcap_store, &num_thread, &max_ttl, &pre_round, &lower_bound, &upper_bound, &field_default, &block_send, &pool_size);
                tmp_dipv6_list.clear();
                num_tmp = 0;
                if (dprev6_trie) {
                    for (auto res_ipv6: response_ip_set) {
                        int pre = 128;
                        Trie *current = v6Prefix_trie_find(dprev6_trie, res_ipv6, pre);
                        if (current) {
                            current->probe_done = 1;
                        }
                    }
                }
                std::cout << "~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~" << '\n' << std::endl;
            }
        }
    }
    return 0;
}

