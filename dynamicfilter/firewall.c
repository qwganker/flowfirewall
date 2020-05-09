/**
 * Linux 4.18.0-15-generic
*/
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/kernel.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/icmp.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include "config.h"

#define LOG_ERROR(fmt, ...) printk("[%s:%d]Error: " fmt "", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LOG_WARN(fmt, ...) printk("[%s:%d]Warn: " fmt "", __FUNCTION__, __LINE__, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) printk("[%s:%d]: " fmt "", __FUNCTION__, __LINE__, ##__VA_ARGS__)

#define IP(addr)                     \
    ((unsigned char *)&addr)[0],     \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]

typedef struct packet
{
    unsigned int sip;
    unsigned int dip;
    unsigned short sport;
    unsigned short dport;
} packet_t;

typedef struct rule
{
    unsigned int sip;
    unsigned short sport;
    unsigned short trojanport; // 木马端口
    struct rule *next;
} rule_t;

static rule_t rule_list_head;

unsigned int ipstr_to_uint(const char *ipstr)
{
    unsigned int tmp[4] = {0};
    unsigned int ui = 0;

    sscanf(ipstr, "%d.%d.%d.%d", &tmp[0], &tmp[1], &tmp[2], &tmp[3]);

    ui = (tmp[3] << 24) | (tmp[2] << 16) | (tmp[1] << 8) | (tmp[0]);

    return ui;
}


rule_t *kmalloc_rule(void)
{
    rule_t *p = kmalloc(sizeof(rule_t), GFP_ATOMIC);
    if (!p)
    {
        return NULL;
    }
    return p;
}

void free_rule(rule_t *p)
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


void skb_to_packet(struct sk_buff *skb, packet_t *packet)
{
    // struct ethhdr *eth = eth_hdr(skb);
    struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *tcph = (struct tcphdr *)(skb->data + (iph->ihl * 4));

    packet->sip = iph->saddr;
    packet->dip = iph->daddr;
    packet->sport = ntohs(tcph->source);
    packet->dport = ntohs(tcph->dest);
}

void init_rule_list(void)
{
    int len  = sizeof(configs)/sizeof(config_t);

    rule_t *p = &rule_list_head;
    
    int i = 0;
    for (; i < len; i++) {
        rule_t *r = kmalloc_rule();
        rule_init(r, configs[i].sip, configs[i].sport, configs[i].trojanport);
        p->next = r;
        p = r;
    }
}

bool rule_match(const rule_t *rule, const packet_t *in)
{
    LOG_DEBUG("rule---> source [%u.%u.%u.%u:%u] trojanport: [%u]\n", IP(rule->sip), rule->sport, rule->trojanport);

    // 匹配源ip/port 或者 木马端口
    if ((rule->sip == in->sip && rule->sport == in->sport) || rule->trojanport == in->dport)
    {
        LOG_WARN("to drop packet !!!\n\n");
        return true;
    }

    return false;
}

/**
 *  return: true: NF_DROP 
 *          false: NF_ACCEPT
 */
bool rule_chain_filter_packet(const packet_t *in) {
    
    rule_t *r = rule_list_head.next;
    while (r != NULL)
    {
        if (rule_match(r, in))
        {
            return true;
        }

        r = r->next;
    }
    
    LOG_DEBUG("to accept packet ...\n\n");
    return false;
}

unsigned int watch_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct ethhdr *eth = eth_hdr(skb);
    struct iphdr *iph = ip_hdr(skb);
    packet_t packet = {0, 0, 0, 0};

    if (!skb || !iph)
    {
        return NF_ACCEPT;
    }

    if (eth->h_proto != htons(ETH_P_IP) || iph->version != 4)
    {
        return NF_ACCEPT;
    }

    if (iph->protocol != IPPROTO_TCP)
    {
        return NF_ACCEPT;
    }


    skb_to_packet(skb, &packet);

    LOG_DEBUG("Hook TCP packet: [%u.%u.%u.%u:%u] -->  [%u.%u.%u.%u:%u]\n", IP(packet.sip), packet.sport, IP(packet.dip), packet.dport);

    if (rule_chain_filter_packet(&packet))
    {
        return NF_DROP;
    }

    return NF_ACCEPT;
}

static struct nf_hook_ops firewall_hook_ops = {
    .hook = watch_in,
    .pf = PF_INET,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

static int __init firewall_module_init(void)
{
    if (0 > nf_register_net_hook(&init_net, &firewall_hook_ops))
    {
        LOG_ERROR("register nf module failed !!!\n");
    }

    init_rule_list();

    LOG_DEBUG("firewall startup ...\n");
    return 0;
}

static void __exit firewall_module_exit(void)
{
    nf_unregister_net_hook(&init_net, &firewall_hook_ops);
    LOG_DEBUG("firewall shutdown ...\n");
}

MODULE_LICENSE("GPL");

module_init(firewall_module_init);
module_exit(firewall_module_exit);