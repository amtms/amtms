#ifndef AMTMS_UDP_H
#define AMTMS_UDP_H

#include <cstdlib>
#include <netinet/ip.h>
#include "data_structure.h"


uint16_t udp_checksum(uint16_t *buf, int nwords);

#endif //AMTMS_UDP_H
