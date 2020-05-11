#ifndef __UTILS_H__
#define __UTILS_H__


#define IPSTR(addr)                     \
    ((unsigned char *)&addr)[0],     \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]


unsigned int ipstr_to_uint(const char *ipstr);

#endif