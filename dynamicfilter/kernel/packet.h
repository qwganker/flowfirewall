#ifndef __PACKET_H__
#define __PACKET_H__

typedef struct packet
{
    unsigned int sip;
    unsigned int dip;
    unsigned short sport;
    unsigned short dport;
} packet_t;

#endif
