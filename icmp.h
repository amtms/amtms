#ifndef AMTMS_ICMP_H
#define AMTMS_ICMP_H

#include "data_structure.h"

uint16_t icmpv4_checksum(uint16_t *buf, int nwords);

uint16_t icmpv6_checksum(uint16_t *buf, int nwords);

#endif //AMTMS_ICMP_H
