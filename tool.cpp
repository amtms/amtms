#include "tool.h"

long long get_nanoseconds() {
    struct timespec ts{};
    clock_gettime(CLOCK_MONOTONIC, &ts);
    return ts.tv_sec * 1000000000LL + ts.tv_nsec;
}

void getNetworkInfo(std::string& interfaceName, std::string& ipv4Address, std::string& ipv6Address) {
    struct ifaddrs *ifaddr, *ifa;
    char addrStr[INET6_ADDRSTRLEN];

    if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

    for (ifa = ifaddr; ifa != nullptr; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == nullptr) continue;

        if ((ifa->ifa_flags & IFF_LOOPBACK)) {
            continue;
        }
        if (!(ifa->ifa_flags & IFF_UP)) {
            continue;
        }

        void* tmpAddrPtr = nullptr;
        if (std::string(ifa->ifa_name) != interfaceName) {
            continue;
        }
        else {
            if (ifa->ifa_addr->sa_family == AF_INET) {
                tmpAddrPtr = &((struct sockaddr_in *) ifa->ifa_addr)->sin_addr;
                inet_ntop(AF_INET, tmpAddrPtr, addrStr, INET_ADDRSTRLEN);
                ipv4Address = std::string(addrStr);
            }
            else if (ifa->ifa_addr->sa_family == AF_INET6) {
                tmpAddrPtr = &((struct sockaddr_in6 *) ifa->ifa_addr)->sin6_addr;
                inet_ntop(AF_INET6, tmpAddrPtr, addrStr, INET6_ADDRSTRLEN);
                if (std::string(addrStr).find("fe80:") == -1) {
                    ipv6Address = std::string(addrStr);
                }
            }
        }
    }

    freeifaddrs(ifaddr);
}

void readIPv4Addresses(std::vector<in_addr> &ipv4Addresses, Trie* v4preTrie, const std::string &filename) {
    std::ifstream file(filename);
    std::string line;

    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return ;
    }

    while (getline(file, line)) {
        if (!line.empty() && line.size() > 5) {
            int ln = line.size();
            std::string sipv4_s;
            int cut = 0;
            if (line.find('\r') != -1) {
                ++cut;
            }
            if (line.find('\n') != -1) {
                ++cut;
            }
            sipv4_s = line.substr(0, ln-cut);

            in_addr sipv4_i_tmp{};
            sipv4_i_tmp.s_addr = ipv4_string_to_inaddr(sipv4_s);
            long long ip_bin = ipv4_inaddr_to_int(sipv4_i_tmp.s_addr);
            if ((ip_bin&0xff) == 0 || (ip_bin&0xff) == 255) {
                continue;
            }
            if (v4preTrie == nullptr) {
                ipv4Addresses.emplace_back(sipv4_i_tmp);
            }
            else {

                int pre = 32;
                Trie* current = v4Prefix_trie_find(v4preTrie, ip_bin, pre);
                if (current) {
                    ipv4Addresses.emplace_back(sipv4_i_tmp);
                }
            }
        }
    }

    file.close();
}

void contructIPv4Addresses(std::vector<in_addr> &ipv4Addresses, const std::string &filename) {
    std::ifstream file(filename);
    std::string line;

    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return ;
    }

    while (getline(file, line)) {
        if (!line.empty() && line.size() > 5) {
            int ln = line.size();
            std::string v4pre;
            int cut = 0;
            if (line.find('\r') != -1) {
                ++cut;
            }
            if (line.find('\n') != -1) {
                ++cut;
            }
            v4pre = line.substr(0, ln-cut);

            int pos = v4pre.find("/");
            std::string ip = v4pre.substr(0, pos-1)+"1";

            in_addr sipv4_i_tmp{};
            sipv4_i_tmp.s_addr = ipv4_string_to_inaddr(ip);
            ipv4Addresses.emplace_back(sipv4_i_tmp);
        }
    }

    file.close();
}

Trie* v4Prefix_tire_construct(const std::string &filename) {

    if (filename.empty()) {
        return nullptr;
    }

    std::ifstream file(filename);
    std::string line;

    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return nullptr;
    }

    Trie* v4preTrie = new Trie;

    while (getline(file, line)) {
        if (!line.empty() && line.size() > 5) {
            int ln = line.size();
            std::string v4pre;
            int cut = 0;
            if (line.find('\r') != -1) {
                ++cut;
            }
            if (line.find('\n') != -1) {
                ++cut;
            }
            v4pre = line.substr(0, ln-cut);

            int pos = v4pre.find("/");
            ln = v4pre.length();
            std::string ip = v4pre.substr(0, pos);
            int pre = std::stoi(v4pre.substr(pos+1, ln-pos));

            long long ip_bin = ipv4_string_to_int(ip);

            Trie* current = v4preTrie;
            for (int i = 0; i < pre; ++i) {
                long long val = ip_bin&(1ll<<(32-i-1));
                if (val == 0) {
                    if (current->child_0 == nullptr) {
                        current->child_0 = new Trie;
                        current = current->child_0;
                        current->current_layer = i+1;
                    }
                    else {
                        current = current->child_0;
                    }
                }
                else {
                    if (current->child_1 == nullptr) {
                        current->child_1 = new Trie;
                        current = current->child_1;
                        current->current_layer = i+1;
                    }
                    else {
                        current = current->child_1;
                    }
                }
                if (i == pre-1) {
                    current->prefix_mark = 1;
                    current->probe_done = 0;

                }
            }
        }
    }

    file.close();

    return v4preTrie;

}

Trie* v4Prefix_trie_find(Trie* v4preTrie, long long& ipv4_int, int& pre) {
    Trie* current = v4preTrie;
    for (int i = 0; i < pre; ++i) {
        long long val = ipv4_int&(1ll<<(32-i-1));
        if (val == 0) {
            if (current->child_0 == nullptr) {
                return nullptr;
            }
            else {
                current = current->child_0;
                if (current->prefix_mark) {
                    return current;
                }
            }
        }
        else {
            if (current->child_1 == nullptr) {
                return nullptr;
            }
            else {
                current = current->child_1;
                if (current->prefix_mark) {
                    return current;
                }
            }
        }
    }
    return nullptr;
}

void readIPv6Addresses(std::vector<in6_addr> &ipv6Addresses, Trie* v6preTrie, const std::string &filename) {
    std::ifstream file(filename);
    std::string line;

    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return ;
    }

    while (getline(file, line)) {
        if (!line.empty() && line.size() > 5) {
            int ln = line.size();
            std::string sipv6_s;
            int cut = 0;
            if (line.find('\r') != -1) {
                ++cut;
            }
            if (line.find('\n') != -1) {
                ++cut;
            }
            sipv6_s = line.substr(0, ln-cut);


            in6_addr sipv6_i_tmp{};
            ipv6_string_to_inaddr6(sipv6_s, sipv6_i_tmp);
            ln = sizeof(sipv6_i_tmp.s6_addr)/sizeof(sipv6_i_tmp.s6_addr[0]);
            bool bul1 = true, bul2 = true;
            for (int i = ln/2; i < ln; ++i) {
                if (sipv6_i_tmp.s6_addr[i] != 0) {
                    bul1 = false;
                    break;
                }
            }
            if (bul1) {
                continue;
            }
            long long tv = (1<<(128/ln))-1;
            for (int i = ln/2; i < ln; ++i) {
                if (sipv6_i_tmp.s6_addr[i] != tv) {
                    bul2 = false;
                    break;
                }
            }
            if (bul2) {
                continue;
            }
            if (v6preTrie == nullptr) {
                ipv6Addresses.emplace_back(sipv6_i_tmp);
            }
            else {
                int pre = 128;
                Trie* current = v6Prefix_trie_find(v6preTrie, sipv6_i_tmp, pre);
                if (current) {
                    ipv6Addresses.emplace_back(sipv6_i_tmp);
                }
            }
        }
    }

    file.close();
}

void constructIPv6Addresses(std::vector<in6_addr> &ipv6Addresses, const std::string &filename) {
    std::ifstream file(filename);
    std::string line;

    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return ;
    }

    while (getline(file, line)) {
        if (!line.empty() && line.size() > 5) {
            int ln = line.size();
            std::string v6pre;
            int cut = 0;
            if (line.find('\r') != -1) {
                ++cut;
            }
            if (line.find('\n') != -1) {
                ++cut;
            }
            v6pre = line.substr(0, ln-cut);


            int pos = v6pre.find("/");
            std::string ip = v6pre.substr(0, pos);

            in6_addr pre_tmp{};
            ipv6_string_to_inaddr6(ip, pre_tmp);

            int group_num = sizeof(pre_tmp.s6_addr)/sizeof(pre_tmp.s6_addr[0]);
            pre_tmp.s6_addr[group_num-1] += 1;

            ipv6Addresses.emplace_back(pre_tmp);

        }
    }

    file.close();
}

Trie* v6Prefix_tire_construct(const std::string &filename) {

    if (filename.empty()) {
        return nullptr;
    }

    std::ifstream file(filename);
    std::string line;

    if (!file.is_open()) {
        std::cerr << "Failed to open file: " << filename << std::endl;
        return nullptr;
    }

    Trie* v6preTrie = new Trie;

    while (getline(file, line)) {
        if (!line.empty() && line.size() > 5) {
            int ln = line.size();
            std::string v6pre;
            int cut = 0;
            if (line.find('\r') != -1) {
                ++cut;
            }
            if (line.find('\n') != -1) {
                ++cut;
            }
            v6pre = line.substr(0, ln-cut);


            int pos = v6pre.find("/");
            ln = v6pre.length();
            std::string ip = v6pre.substr(0, pos);
            int pre = std::stoi(v6pre.substr(pos+1, ln-pos));

            in6_addr pre_tmp{};
            ipv6_string_to_inaddr6(ip, pre_tmp);

            int group_num = sizeof(pre_tmp.s6_addr)/sizeof(pre_tmp.s6_addr[0]);
            int group_size = 128/group_num;
            Trie* current = v6preTrie;
            for (int i = 0; i < pre; ++i) {
                int cur_group = i/group_size;
                int cur_pos = i%group_size;
                int group_val = pre_tmp.s6_addr[cur_group];
                int val = group_val&(1<<(group_size-cur_pos-1));
                if (val == 0) {
                    if (current->child_0 == nullptr) {
                        current->child_0 = new Trie;
                        current = current->child_0;
                        current->current_layer = i+1;
                    }
                    else {
                        current = current->child_0;
                    }
                }
                else {
                    if (current->child_1 == nullptr) {
                        current->child_1 = new Trie;
                        current = current->child_1;
                        current->current_layer = i+1;
                    }
                    else {
                        current = current->child_1;
                    }
                }
                if (i == pre-1) {
                    current->prefix_mark = 1;
                    current->probe_done = 0;
                }
            }
        }
    }
    return v6preTrie;
}

Trie* v6Prefix_trie_find(Trie* v6preTrie, in6_addr& ipv6, int& pre) {
    Trie* current = v6preTrie;
    int group_num = sizeof(ipv6.s6_addr)/sizeof(ipv6.s6_addr[0]);
    int group_size = 128/group_num;
    for (int i = 0; i < pre; ++i) {
        int cur_group = i/group_size;
        int cur_pos = i%group_size;
        int group_val = ipv6.s6_addr[cur_group];
        int val = group_val&(1<<(group_size-cur_pos-1));
        if (val == 0) {
            if (current->child_0 == nullptr) {
                return nullptr;
            }
            else {
                current = current->child_0;
                if (current->prefix_mark) {
                    return current;
                }
            }
        }
        else {
            if (current->child_1 == nullptr) {
                return nullptr;
            }
            else {
                current = current->child_1;
                if (current->prefix_mark) {
                    return current;
                }
            }
        }
    }
    return nullptr;
}


void shutffleIPv4Addresses(std::vector<in_addr> &addressesVector) {
    std::random_device rd;
    std::mt19937 g(rd());

    std::shuffle(addressesVector.begin(), addressesVector.end(), g);
}

void shutffleIPv6Addresses(std::vector<in6_addr> &addressesVector) {
    std::random_device rd;
    std::mt19937 g(rd());

    std::shuffle(addressesVector.begin(), addressesVector.end(), g);
}

in_addr_t ipv4_string_to_inaddr(std::string &sipv4_s) {
    return inet_addr(sipv4_s.c_str());
}

long long ipv4_inaddr_to_int(in_addr_t &ipv4) {
    char ipv4_str[INET_ADDRSTRLEN];
    if (inet_ntop(AF_INET, &ipv4, ipv4_str, INET_ADDRSTRLEN) == nullptr) {
        perror("inet_ntop");
        exit(1);
    }
    std::string ipv4_string(ipv4_str);
    return ipv4_string_to_int(ipv4_string);
}

long long ipv4_string_to_int(std::string &sipv4_s) {
    long long ip_bin = 0;
    int bgn = 0, nd = 0, ln = sipv4_s.size();
    for (int i = 0; i < 4; ++i) {
        nd = sipv4_s.find('.', bgn);
        if (nd == -1) {
            nd = ln;
        }
        ip_bin *= 256;
        ip_bin += std::stoi(sipv4_s.substr(bgn, nd-bgn));
        bgn = nd+1;
    }
    return ip_bin;
}

bool ipv4_address_equal(in_addr &ipv4_v1, in_addr &ipv4_v2) {
    return ipv4_v1.s_addr == ipv4_v2.s_addr;
}

void ipv6_string_to_inaddr6(std::string &sipv6_s, in6_addr &sipv6_i) {
    inet_pton(AF_INET6, sipv6_s.c_str(), &sipv6_i);
}

bool ipv6_address_equal(in6_addr &ipv6_v1, in6_addr &ipv6_v2) {
    int ln = sizeof(ipv6_v1.s6_addr)/sizeof(ipv6_v1.s6_addr[0]);
    for (int i = 0; i < ln; ++i) {
        if (ipv6_v1.s6_addr[i] != ipv6_v2.s6_addr[i]) {
            return false;
        }
    }
    return true;
}

std::string generate_pcap_filename(std::string &base_filename, int &file_index) {
    std::ostringstream str_index;
    str_index.width(5);
    str_index.fill('0');
    str_index.setf(std::ios::right | std::ios::adjustfield);
    str_index << std::to_string(file_index);

    std::string filename = base_filename + "_" + str_index.str() + ".pcap";

    file_index++;
    return filename;
}

std::string generate_txt_filename(std::string &base_filename, int &file_index) {
    std::ostringstream str_index;
    str_index.width(5);
    str_index.fill('0');
    str_index.setf(std::ios::right | std::ios::adjustfield);
    str_index << std::to_string(file_index);

    std::string filename = base_filename + "_" + str_index.str() + ".txt";

    file_index++;
    return filename;
}

bool file_size_exceeded(const char* filename, long long &max_file_size) {
    struct stat stat_buf{};
    int rc = stat(filename, &stat_buf);
    return rc == 0 && stat_buf.st_size >= (max_file_size);
}

std::vector<int> string_split(std::string s_str, const std::string& p_str) {

    s_str = p_str + s_str + p_str;
    std::vector<int> ans;
    std::string str;

    size_t begin_pos = 0;
    size_t find_index = p_str.find(p_str, begin_pos);

    if(find_index == 0) {
        begin_pos = 1;
        find_index = s_str.find(p_str, begin_pos);
    }

    while(find_index != std::string::npos) {
        str = s_str.substr(begin_pos, find_index-begin_pos);
        ans.push_back(std::stoi(str));

        begin_pos = find_index + 1;
        find_index = s_str.find(p_str, begin_pos);
    }

    return ans;
}

void printProgress(int percentage, int total, const std::string& other) {
    int length = 50;
    int pos = (percentage * length) / total;

    std::cout << "[";
    for (int i = 0; i < length; ++i) {
        if (i < pos) std::cout << "=";
        else if (i == pos) std::cout << ">";
        else std::cout << " ";
    }
    std::cout << "] " << percentage << "/" << total << ", " << other << "\r";
    std::cout.flush();
}
