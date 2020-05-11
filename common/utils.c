#include "utils.h"

#include <linux/kernel.h>

unsigned int ipstr_to_uint(const char *ipstr)
{
    unsigned int tmp[4] = {0};
    unsigned int ui = 0;

    sscanf(ipstr, "%d.%d.%d.%d", &tmp[0], &tmp[1], &tmp[2], &tmp[3]);

    ui = (tmp[3] << 24) | (tmp[2] << 16) | (tmp[1] << 8) | (tmp[0]);

    return ui;
}