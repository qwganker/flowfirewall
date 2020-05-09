/**
 * Linux 4.18.0-15-generic
*/
#include <linux/module.h>
#include <linux/fs.h>
#include <linux/kernel.h>
// #include <linux/skbuff.h>
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
#include <linux/slab.h>

#define LOG_ERROR(fmt, ...) printk("[%d][%s]Error: " fmt "", __LINE__, __FUNCTION__, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) printk("[%d][%s]: " fmt "", __LINE__, __FUNCTION__, ##__VA_ARGS__)

#define IP(addr)                     \
    ((unsigned char *)&addr)[0],     \
        ((unsigned char *)&addr)[1], \
        ((unsigned char *)&addr)[2], \
        ((unsigned char *)&addr)[3]

typedef struct rule
{
    unsigned int sip;
    unsigned int dip;
    unsigned short sport;
    unsigned short dport;
    bool isPermit;
    struct rule *next;
} rule_t;

static rule_t *ruleListHead = NULL;

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

void init_rule_list() {

}


unsigned int watch_in(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
    struct ethhdr *eth = eth_hdr(skb);
    struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *tcph = (struct tcphdr *)(skb->data + (iph->ihl * 4));

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

    rule_t rule = {0, 0, 0, 0, 0, false};
    rule.sip = iph->saddr;
    rule.dip = iph->daddr;
    rule.sport = ntohs(tcph->source);
    rule.dport = ntohs(tcph->dest);

    LOG_DEBUG("Hook TCP: source [%u.%u.%u.%u]:[%u] --> destination [%u.%u.%u.%u]:[%u]\n", IP(rule.sip), rule.sport, IP(rule.dip), rule.dport);

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