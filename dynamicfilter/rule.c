#include "rule.h"

#include "utils.h"
#include <linux/slab.h>


rule_t *rule_malloc(void)
{
    rule_t *p = kmalloc(sizeof(rule_t), GFP_ATOMIC);
    if (!p)
    {
        return NULL;
    }
    return p;
}

void rule_free(rule_t *p)
{
    if (!p)
    {
        return;
    }
    kfree(p);
}

void rule_init(rule_t *prule, const char *sip, unsigned short sport, unsigned short trojanport)
{
    prule->sip = ipstr_to_uint(sip);
    prule->sport = sport;
    prule->trojanport = trojanport;
    prule->next = NULL;
}
