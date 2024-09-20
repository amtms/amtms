#ifndef AMTMS_IPV4_H
#define AMTMS_IPV4_H

#include <netinet/ip.h>
#include "data_structure.h"



uint16_t ipv4_checksum(uint16_t *buf, int nwords);




#endif //AMTMS_IPV4_H
