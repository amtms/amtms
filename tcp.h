#ifndef AMTMS_TCP_H
#define AMTMS_TCP_H

#include <cstdlib>
#include <netinet/ip.h>
#include "data_structure.h"

uint16_t tcp_checksum(unsigned short *buf, int nwords);

#endif //AMTMS_TCP_H
