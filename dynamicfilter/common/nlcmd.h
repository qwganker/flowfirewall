#ifndef __NLCMD_H__
#define __NLCMD_H__

#include "config.h"

typedef enum nlcmd_action
{
    ADD_RULE = 1,
    DEL_RULE = 2,
    LIST_RULES = 3,
    START = 4,
    STOP = 5,
} nlcmd_action_e;

typedef struct nlcmd
{
    nlcmd_action_e action;
    config_t config;
} nlcmd_t;

#endif
