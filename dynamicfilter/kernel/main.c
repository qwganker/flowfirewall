/**
 * ubunt18.04 Linux 4.18.0-15-generic
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
// #include <linux/list.h>
// #include <linux/spinlock.h>

#include <stddef.h>  // NULL
#include <stdbool.h> // bool

#include "../../common/utils.h"
#include "../../common/log.h"

#include "../common/config.h"
#include "../common/nlcmd.h"
#include "packet.h"
#include "rule.h"

#define DF_NETLINK 30

static spinlock_t rule_list_lock;
static bool flowswitch = true;
static rule_t rule_list_head;
static struct sock *nl_sockfd = NULL;
static long total = 0;

#define INIT_LOCK_BH spin_lock_init(&rule_list_lock);
#define LOCK_BH spin_lock_bh(&rule_list_lock);
#define UNLOCK_BH spin_unlock_bh(&rule_list_lock);

void __skb_to_packet(struct sk_buff *skb, packet_t *packet)
{
    struct iphdr *iph = ip_hdr(skb);
    struct tcphdr *tcph = (struct tcphdr *)(skb->data + (iph->ihl * 4));

    packet->sip = iph->saddr;
    packet->dip = iph->daddr;
    packet->sport = ntohs(tcph->source);
    packet->dport = ntohs(tcph->dest);
}

static int __nl_sendto_userspace(char *pbuf, uint16_t len)
{
    struct sk_buff *nl_skb;
    struct nlmsghdr *nlh;

    int ret;

    /* 创建sk_buff 空间 */
    nl_skb = nlmsg_new(len, GFP_ATOMIC);
    if (!nl_skb)
    {
        KLOG_ERROR("netlink alloc failure\n");
        return -1;
    }

    /* 设置netlink消息头部 */
    nlh = nlmsg_put(nl_skb, 0, 0, DF_NETLINK, len, 0);
    if (nlh == NULL)
    {
        KLOG_ERROR("nlmsg_put failaure \n");
        nlmsg_free(nl_skb);
        return -1;
    }

    memcpy(nlmsg_data(nlh), pbuf, len);
    ret = netlink_unicast(nl_sockfd, nl_skb, 100, MSG_DONTWAIT);

    return ret;
}

static void __handle_recv_nlcmd(const nlcmd_t *cmd)
{
    KLOG_DEBUG("Recv nlcmd action:[%d] sip:[%s] sport:[%u] trojanport:[%u]", cmd->action, cmd->config.sip, cmd->config.sport, cmd->config.trojanport);

    LOCK_BH
    switch (cmd->action)
    {
    case ADD_RULE:
    {
        rule_t *rule = rule_malloc();
        rule_init(rule, cmd->config.sip, cmd->config.sport, cmd->config.trojanport);
        rule_list_add(rule, &rule_list_head);
    }
    break;
    case DEL_RULE:
    {
        rule_t rule;
        rule_init(&rule, cmd->config.sip, cmd->config.sport, cmd->config.trojanport);
        rule_list_remove(&rule, &rule_list_head);
    }
    break;
    case STOP:
        flowswitch = false;
        break;
    case START:
        flowswitch = true;
        break;
    case LIST_RULES:
    {
        char *p = rule_list_serialize(&rule_list_head);
        unsigned int total = rule_list_total(&rule_list_head);
        KLOG_DEBUG("total ===== %d", total);
        __nl_sendto_userspace(p, sizeof(rule_t) * total);
    }
    break;
    default:
        KLOG_WARN("Unknow nlcmd action !!!\n");
        break;
    }
    UNLOCK_BH
}

bool __match_rule(const rule_t *rule, const packet_t *in)
{
    KLOG_DEBUG("match rule --> source [%u.%u.%u.%u:%u] trojanport: [%u]", IPSTR(rule->sip), rule->sport, rule->trojanport);

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
bool __filter_packet(const packet_t *in)
{
    rule_t *pos, *n;

    LOCK_BH
    list_for_each_entry_safe(pos, n, &rule_list_head.node, node)
    {
        if (__match_rule(pos, in))
        {
            KLOG_WARN("to drop packet !!!\n");
            UNLOCK_BH
            return true;
        }
    }
    UNLOCK_BH

    KLOG_DEBUG("to accept packet ...\n");
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

    __skb_to_packet(skb, &packet);

    total++;
    KLOG_DEBUG("Hook TCP packet: [%u.%u.%u.%u:%u] -->  [%u.%u.%u.%u:%u]  total: [%ld]", IPSTR(packet.sip), packet.sport, IPSTR(packet.dip), packet.dport, total);

    if (!flowswitch)
    {
        KLOG_DEBUG("flowswitch is close, to drop packet ...\n");
        return NF_DROP;
    }

    if (__filter_packet(&packet))
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

static void __nl_recv(struct sk_buff *skb)
{
    struct nlmsghdr *nlh = NULL;
    nlcmd_t *cmd = NULL;

    if (skb->len >= nlmsg_total_size(0))
    {
        nlh = nlmsg_hdr(skb);
        cmd = (nlcmd_t *)NLMSG_DATA(nlh);
        __handle_recv_nlcmd(cmd);
    }
}

static int __init_netlink(void)
{
    struct netlink_kernel_cfg nl_cfg = {
        .input = __nl_recv,
    };

    nl_sockfd = netlink_kernel_create(&init_net, DF_NETLINK, &nl_cfg);
    if (nl_sockfd == NULL)
    {
        return -1;
    }

    return 1;
}

static int __init firewall_module_init(void)
{
    INIT_LOCK_BH

    rule_list_init(&rule_list_head);

    if (0 > nf_register_net_hook(&init_net, &firewall_hook_ops))
    {
        KLOG_ERROR("register nf module failed !!!\n");
        return -1;
    }

    if (0 > __init_netlink())
    {
        KLOG_ERROR("init netlink failed !!!");
        return -1;
    }

    KLOG_DEBUG("firewall startup ...\n");
    return 0;
}

static void __exit firewall_module_exit(void)
{
    nf_unregister_net_hook(&init_net, &firewall_hook_ops);

    rule_list_free(&rule_list_head);

    netlink_kernel_release(nl_sockfd);

    KLOG_DEBUG("firewall shutdown ...\n");
}

MODULE_LICENSE("GPL");

module_init(firewall_module_init);
module_exit(firewall_module_exit);
