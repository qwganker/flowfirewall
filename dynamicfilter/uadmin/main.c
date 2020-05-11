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

#define DF_NETLINK 30

static int __init_netlink(void)
{
    int sockfd = socket(AF_NETLINK, SOCK_RAW, DF_NETLINK);
    if (sockfd == -1)
    {
        LOG_ERROR("create socket error\n");
        return -1;
    }

    struct sockaddr_nl saddr;
    memset(&saddr, 0, sizeof(saddr));
    saddr.nl_family = AF_NETLINK;
    saddr.nl_pid = getpid();
    saddr.nl_groups = 0;
    if (bind(sockfd, (struct sockaddr *)&saddr, sizeof(saddr)) != 0)
    {
        LOG_ERROR("bind() error\n");
        close(sockfd);
        return -1;
    }

    return sockfd;
}

static int __sendtokernel(int sockfd, nlcmd_t *cmd)
{
    struct sockaddr_nl daddr;

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
    if (0 == strcasecmp("add", action)) return ADD_RULE;
    if (0 == strcasecmp("del", action)) return DEL_RULE;
    if (0 == strcasecmp("list", action)) return LIST_RULES;
    if (0 == strcasecmp("start", action)) return START;
    if (0 == strcasecmp("stop", action)) return STOP;

    return -1;
}

int main(int argc, char **argv)
{
    int opt, index;
    // nlcmd_t cmd = {
    //     .action = ADD_RULE,
    //     .config = {"122.119.4.127", 80, 0}, // aggsky.travelsky.com
    // };
    nlcmd_t cmd;

    struct option opts[] = {
        {"action", required_argument, NULL, 'a'},
        {"sip", required_argument, NULL, 'i'},
        {"sport", required_argument, NULL, 'p'},
        {"tport", required_argument, NULL, 't'},
        {0, 0, 0, 0}};

    while ((opt = getopt_long(argc, argv, "a:i::s::t::", opts, &index)) != -1)
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
        default:
            usage();
            return -1;
        }
    }

    int sockfd = __init_netlink();
    if (0 > __sendtokernel(sockfd, &cmd))
    {
        return -1;
    }
    close(sockfd);

    return 0;
}
