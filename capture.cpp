#include "capture.h"

void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet) {
    auto timestamp = std::chrono::seconds(pkthdr->ts.tv_sec) + std::chrono::microseconds(pkthdr->ts.tv_usec);
    auto milliseconds = std::chrono::duration_cast<std::chrono::milliseconds>(timestamp).count();

    uint16_t arrive_time = milliseconds&((1<<16)-1);

    auto *args = (CallbackArgs *)user;

    std::queue<Packet_Information *> *check_queue = args->check_queue;
    std::mutex *check_queue_mutex = args->check_queue_mutex;

    auto *packet_information = new Packet_Information;
    packet_information->arrive_time = arrive_time;

    packet_information->packet = new u_char[pkthdr->caplen];
    memcpy(packet_information->packet, packet, pkthdr->caplen);

    std::unique_lock<std::mutex> lock(*check_queue_mutex);
    check_queue->push(packet_information);

    lock.unlock();

    if (*args->pcap_store) {
        pcap_dumper_t *dumper = args->dumper;
        pcap_dump((u_char *)dumper, pkthdr, packet);
    }
}


void capture_packets(std::atomic<bool> *isCaptureDone, const char *dev, std::string *sip, std::queue<Packet_Information *> *check_queue, std::mutex *check_queue_mutex, std::string *pcap_path, bool *pcap_store) {
    long long file_size = 2ll*1024*1024*1024;
    char errbuf[PCAP_ERRBUF_SIZE];
    pcap_t *capture_handle = pcap_open_live(dev, BUFSIZ, 1, 1000, errbuf);

    if (capture_handle == nullptr) {
        std::cerr << "Couldn't open device " << dev << ": " << errbuf << std::endl;
        return;
    }

    std::string s_filter_exp = "dst host " + *sip;

    const char *filter_exp = s_filter_exp.c_str();

    struct bpf_program fp{};
    if (pcap_compile(capture_handle, &fp, filter_exp, 0, PCAP_NETMASK_UNKNOWN) == -1) {
        std::cerr << "Couldn't parse filter " << filter_exp << ": " << pcap_geterr(capture_handle) << std::endl;
        return;
    }
    if (pcap_setfilter(capture_handle, &fp) == -1) {
        std::cerr << "Couldn't install filter " << filter_exp << ": " << pcap_geterr(capture_handle) << std::endl;
        return;
    }

    int nonblock = 1;
    if (pcap_setnonblock(capture_handle, nonblock, errbuf) == -1) {
        std::cerr << "Couldn't set non-blocking mode: " << errbuf << std::endl;
        return;
    }


    CallbackArgs args{};
    if (*pcap_store) {
        std::time_t now = std::time(nullptr);
        struct std::tm *timeinfo;
        timeinfo = localtime(&now);
        char buffer[80];
        strftime(buffer, sizeof(buffer), "%Y-%m-%d-%H-%M-%S", timeinfo);
        std::string base_filename = std::string(buffer);

        int file_index = 0;
        std::string current_filename = *pcap_path + generate_pcap_filename(base_filename, file_index);

        pcap_dumper_t *dumper = pcap_dump_open(capture_handle, current_filename.c_str());
        if (dumper == nullptr) {
            std::cerr << "Couldn't open dump file " << current_filename << ": " << pcap_geterr(capture_handle) << std::endl;
            return;
        }

        args.dumper = dumper;
        args.check_queue = check_queue;
        args.check_queue_mutex = check_queue_mutex;
        args.pcap_store = pcap_store;


        while (!isCaptureDone->load(std::memory_order_acquire)) {
            pcap_dispatch(capture_handle, 1, packet_handler, (u_char *)&args);
            if (file_size_exceeded(current_filename.c_str(), file_size)) {
                pcap_dump_close(dumper);
                current_filename = *pcap_path + generate_pcap_filename(base_filename, file_index);
                dumper = pcap_dump_open(capture_handle, current_filename.c_str());
                if (dumper == nullptr) {
                    std::cerr << "Couldn't open dump file " << current_filename << ": " << pcap_geterr(capture_handle) << std::endl;
                    break;
                }
            }
        }

        pcap_dump_close(dumper);
    }
    else {
        args.check_queue = check_queue;
        args.check_queue_mutex = check_queue_mutex;
        args.pcap_store = pcap_store;

        while (!isCaptureDone->load(std::memory_order_acquire)) {
            pcap_dispatch(capture_handle, 1, packet_handler, (u_char *)&args);
        }
    }

    pcap_freecode(&fp);
    pcap_close(capture_handle);

    std::cout << "Packet capture ended and file saved." << std::endl;
}