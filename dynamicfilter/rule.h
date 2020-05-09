#ifndef __RULE_H__
#define __RULE_H__

typedef struct rule
{
    unsigned int sip;
    unsigned short sport;
    unsigned short trojanport; // 木马端口
    struct rule *next;
} rule_t;

rule_t *rule_malloc(void);
void rule_free(rule_t *p);
void rule_init(rule_t *prule, const char *sip, unsigned short sport, unsigned short trojanport);

#endif