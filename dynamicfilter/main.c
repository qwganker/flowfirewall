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
#include <linux/netlink.h>
#include <linux/if_arp.h>
#include <linux/if_ether.h>
#include <linux/if_packet.h>

#include <stddef.h> // NULL
#include <stdbool.h> // bool

#include "../common/utils.h"
#include "../common/log.h"

#include "config.h"
#include "packet.h"
#include "rule.h"

static rule_t rule_list_head;
static struct sock *nl_sock_fd = NULL;

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
    int len = sizeof(configs) / sizeof(config_t);

    rule_t *p = &rule_list_head;

    int i = 0;
    for (; i < len; i++)
    {
        rule_t *r = rule_malloc();
        rule_init(r, configs[i].sip, configs[i].sport, configs[i].trojanport);
        p->next = r;
        p = r;
    }
}

bool match_rule(const rule_t *rule, const packet_t *in)
{
    LOG_DEBUG("match rule --> source [%u.%u.%u.%u:%u] trojanport: [%u]\n", IPSTR(rule->sip), rule->sport, rule->trojanport);

    // 匹配源ip/port 或者 木马端口
    if ((rule->sip == in->sip && rule->sport == in->sport) || rule->trojanport == in->dport)
    {
        return true;
    }

    return false;
}

/**
 *  return: true: NF_DROP 
 *          false: NF_ACCEPT
 */
bool filter_packet(const packet_t *in)
{
    rule_t *r = rule_list_head.next;
    while (r != NULL)
    {
        if (match_rule(r, in))
        {
            LOG_WARN("to drop packet !!!\n\n");
            return true;
        }

        r = r->next;
    }

    LOG_DEBUG("to accept packet ...\n\n");
    return false;
}

unsigned int nf_watch(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
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

    LOG_DEBUG("Hook TCP packet: [%u.%u.%u.%u:%u] -->  [%u.%u.%u.%u:%u]\n", IPSTR(packet.sip), packet.sport, IPSTR(packet.dip), packet.dport);

    if (filter_packet(&packet))
    {
        return NF_DROP;
    }

    return NF_ACCEPT;
}

static struct nf_hook_ops firewall_hook_ops = {
    .hook = nf_watch,
    .pf = PF_INET,
    .hooknum = NF_INET_PRE_ROUTING,
    .priority = NF_IP_PRI_FIRST,
};

static void nl_watch(struct sk_buff *skb)
{

}

static int init_netlink(void)
{
    struct netlink_kernel_cfg nl_cfg = {
        .input = nl_watch,
    };

    nl_sock_fd = netlink_kernel_create(&init_net, 20, &nl_cfg);
    if (nl_sock_fd == NULL)
    {
        return -1;
    }

    return 1;
}

static int __init firewall_module_init(void)
{
    if (0 > nf_register_net_hook(&init_net, &firewall_hook_ops))
    {
        LOG_ERROR("register nf module failed !!!\n");
        return -1;
    }

    if (0 > init_netlink())
    {
        LOG_ERROR("init netlink failed !!!");
        return -1;
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
