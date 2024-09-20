#ifndef AMTMS_CAPTURE_H
#define AMTMS_CAPTURE_H

#include <pcap.h>
#include <atomic>
#include <thread>
#include <iostream>
#include <cstring>
#include <chrono>
#include <ctime>
#include <queue>

#include "send.h"
#include "data_structure.h"
#include "tool.h"




void packet_handler(u_char *user, const struct pcap_pkthdr *pkthdr, const u_char *packet);

void capture_packets(std::atomic<bool> *isCaptureDone, const char *dev, std::string *sip, std::queue<Packet_Information *> *check_queue, std::mutex *check_queue_mutex, std::string *pcap_path, bool *pcap_store);

#endif //AMTMS_CAPTURE_H
