#include "udp.h"

uint16_t udp_checksum(uint16_t *buf, int nwords) {
    uint32_t sum;
    for(sum = 0; nwords > 0; --nwords) {
        sum += *buf;
        buf++;
    }
    while ((sum >> 16) > 0) {
        sum = (sum >> 16) + (sum&0xffff);
    }
    return (uint16_t)(~sum);
}

