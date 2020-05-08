/**
 * Linux 4.18.0-15-generic
*/

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/netdevice.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/timer.h>
#include <linux/rtc.h>
#include <linux/if_ether.h>

#define LOG_ERROR(fmt, ...) printk("[%d][%s]Error: " fmt "", __LINE__, __FUNCTION__, ##__VA_ARGS__)
#define LOG_DEBUG(fmt, ...) printk("[%d][%s]: " fmt "", __LINE__, __FUNCTION__, ##__VA_ARGS__)

#define NIPQUAD(addr) \
((unsigned char *)&addr)[0], \
((unsigned char *)&addr)[1], \
((unsigned char *)&addr)[2], \
((unsigned char *)&addr)[3]

typedef struct Rule
{
    unsigned int sip;
    unsigned int dip;
    unsigned short sport;
    unsigned short dport;
    unsigned short protocol;
    bool isPermit;
    bool isLog;
    struct Rule *next;
} Rule;

unsigned int
watch_in(void *priv,
         struct sk_buff *skb,
         const struct nf_hook_state *state)
{
    struct ethhdr *eth = eth_hdr(skb);
    struct iphdr *iph = ip_hdr(skb);

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

    LOG_DEBUG("Hook tcp -> sip: [%u.%u.%u.%u],  dst: [%u.%u.%u.%u]\n", NIPQUAD(iph->saddr), NIPQUAD(iph->daddr));

    Rule rule = {0, 0, 0, 0, 0, false, false, NULL};
    rule.sip = iph->saddr;
    rule.dip = iph->daddr;
    rule.protocol = IPPROTO_TCP;

    struct tcphdr *tcph;
    tcph = (struct tcphdr *)(skb->data + (iph->ihl * 4));
    rule.sport = ntohs(tcph->source);
    rule.dport = ntohs(tcph->dest);


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
        LOG_ERROR("Regist nf module failed !!!\n");
    }

    LOG_DEBUG("firewall startup ...\n");
    return 0;
}

static void __exit firewall_module_exit(void)
{
    nf_unregister_net_hook(&init_net, &firewall_hook_ops);
    LOG_DEBUG("firewall shutdown ...\n");
}

module_init(firewall_module_init);
module_exit(firewall_module_exit);