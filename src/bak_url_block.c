#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/skbuff.h> 
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/string.h>
#include <linux/list.h>
#include <linux/netlink.h>
#include <linux/netfilter.h>
#include <linux/netfilter_ipv4.h>
#include <linux/timer.h>
#include <linux/rtc.h>

MODULE_AUTHOR("Xcloud");
MODULE_DESCRIPTION("url_block");
MODULE_LICENSE("GPL");

//#define _DEBUG_ 1

#ifdef  _DEBUG_
#define DEBUG(fmt,...)	printk("[%d][%s]: "fmt"", __LINE__, __FUNCTION__, ##__VA_ARGS__)
//#define ERROR(fmt,...)  printk("[%d][%s]Error: "fmt"", __LINE__, __FUNCTION__, ##__VA_ARGS__)
#else
#define DEBUG(fmt,...)  do { } while (0);
//#define ERROR(fmt,...)  do { } while (0);
#endif

#define ERROR(fmt,...)  printk("[%d][%s]Error: "fmt"", __LINE__, __FUNCTION__, ##__VA_ARGS__)


#define MAX_PAYLOAD_LEN    2048
#define MAX_HASH_TABLE     100
#define MAX_MSGSIZE        32

#define FULL_MATCH_MODE	    1
#define SCOPE_MATCH_MODE    0

#define NL_STATUS_FAIL 	    1
#define NL_STATUS_SUCESS    0

#define MY_NETLINK  26

#define MODULE_STOP    0
#define MODULE_START   1

#define MIN(m, n)   ((m) > (n)? (n) : (m)) 

struct PlugControl {
	spinlock_t	lock;
	unsigned int flag; //0: set the module close; 1: set the module effect
};

typedef struct url_list_head {
	struct hlist_head head;
	spinlock_t	lock;
}URL_LIST_HEAD;

typedef enum status {
    ENTRY_NO_BLOCK   = 0,
    ENTRY_NEED_BLOCK = 1, 
}NODE_STATUS;

typedef enum node_action {
    ADD   = 1,
    DEL   = 2,
    SET   = 3,
    GET_ALL_DATA  = 4, //get all data
    START = 5, //OPEN module
    STOP  = 6,  //stop module
    GET_MODULE_STATUS = 7,//get plug module is open or close
}ACTION;

#pragma pack(4)
typedef struct url_list_node {
    ACTION   action;
    unsigned char  hour_start;
    unsigned char  min_start;
    unsigned char  hour_end;
    unsigned char  min_end;
    NODE_STATUS  effect;       // set by the user
    NODE_STATUS  entry_switch; // set by the timer
    struct hlist_node list;  //8byte
    unsigned int entry_len;
    char entry[0];
}URL_LIST_NODE;
#pragma pack()

typedef struct nl_msg {
	ACTION action;
	unsigned int data;
}NL_MSG;

static struct sock *nl_sock = NULL; 
URL_LIST_HEAD  hash_bucket[MAX_HASH_TABLE];
struct timer_list timer;
static struct PlugControl plug_control;

static void set_switch(URL_LIST_NODE *node)
{
	struct timex  txc;
	struct rtc_time tm;	
	unsigned int now_hour, now_min;

	do_gettimeofday(&(txc.time));
	rtc_time_to_tm(txc.time.tv_sec, &tm);

	DEBUG("Local time :%d-%d-%d %d:%d:%d \n",tm.tm_year+1900, tm.tm_mon,
					 tm.tm_mday, tm.tm_hour + 8, tm.tm_min, tm.tm_sec);

	now_hour = tm.tm_hour + 8;
	now_min  = tm.tm_min;

	if ((now_hour < node->hour_start) || (now_hour > node->hour_end)) {
		node->entry_switch = ENTRY_NO_BLOCK;	
		return;
	}

	if ((now_hour == node->hour_start) && (now_min < node->min_start)) {
		node->entry_switch = ENTRY_NO_BLOCK;			
		return;
	}

	if ((now_hour ==  node->hour_end) && (now_min >= node->min_end)) {
		node->entry_switch = ENTRY_NO_BLOCK;	
		return;
	}

	node->entry_switch = ENTRY_NEED_BLOCK;
	return;
}

static URL_LIST_NODE *node_kmalloc(unsigned int entry_len)
{

	URL_LIST_NODE *p = kmalloc(sizeof(URL_LIST_NODE) + entry_len, GFP_ATOMIC);
	if (!p)
		return NULL;

	memset(p, 0, sizeof(URL_LIST_NODE) + entry_len);
	return p;
}


static unsigned int calculate_hash_key(char *str, int str_length)
{
    int hash, i;

    for(hash = 0, i = 0; i < str_length; ++i)
	        hash = 33*hash + (int)(*str++);
    
    return ((hash & 0x7FFFFFFF) % MAX_HASH_TABLE);
}

static const char *findend(const char *data, const char *tail, int min)
{
	int n = tail - data;
	if (n >= min) {
		while (data < tail) {
			if (*data == '\r')
				 return data;
			++data;
		}
	}
	return NULL;
}

/*
	return  0 : match sucess
		   -1 : match failed
*/
static unsigned int scope_match(char *entry, unsigned int entry_len,
						char *host, unsigned int host_len)
{
	int m, n = 0;
	m = host_len;

	if ((!entry) || (entry_len > host_len))
		return -1;

	while (n <= host_len)
	{
		if (m < entry_len) {
			DEBUG("m < entry_len scope_match() failed !!!\n");
			return -1;
		}

		if (*entry == *host) {
			if (0 == memcmp(entry, host, entry_len)) {
				DEBUG("sucess!!! scope_match()\n");
				return 0;
			}
		}

		++host;
		++n;
		--m;
	}

	return -1;
}

static int __match_rule(unsigned int mode, unsigned int hash_val,
				 char *host, unsigned int host_len)
{
	int num = 0;
	URL_LIST_NODE *pos;
	struct hlist_node *n;

	if(mode == FULL_MATCH_MODE) {
		spin_lock_bh(&hash_bucket[hash_val].lock);
		hlist_for_each_entry_safe(pos, n, &hash_bucket[hash_val].head, list)
		{
			DEBUG("FULL_MATCH_MODE -> [%s] pos->entry_len:%d  host:[%s] host_len:%d\n",
										 pos->entry, pos->entry_len, host, host_len);
			if (0 == memcmp(pos->entry, host, host_len)) {
				DEBUG("FULL_MATCH_MODE effect:(%d) switch:(%d) ......\n", pos->effect, pos->entry_switch);
				if (pos->effect == ENTRY_NO_BLOCK) {
					spin_unlock_bh(&hash_bucket[hash_val].lock);
					return ENTRY_NO_BLOCK;
				}

				if (pos->entry_switch == ENTRY_NEED_BLOCK) {
					spin_unlock_bh(&hash_bucket[hash_val].lock);
					return ENTRY_NEED_BLOCK;
				}
			}
		}
		DEBUG("FULL_MATCH_MODE not match!!!\n");
		spin_unlock_bh(&hash_bucket[hash_val].lock);
		return ENTRY_NO_BLOCK;
	}

	if (mode == SCOPE_MATCH_MODE) {
		while(num < MAX_HASH_TABLE)
		{
			spin_lock_bh(&hash_bucket[num].lock);
			hlist_for_each_entry_safe(pos, n, &hash_bucket[num].head, list)
			{
				DEBUG("SCOPE_MATCH_MODE -> [%s] pos->entry_len:%d  host:[%s] host_len:%d\n",
										 pos->entry, pos->entry_len , host,host_len);
				if (0 == scope_match(pos->entry, pos->entry_len, host, host_len)) {
					DEBUG("SCOPE_MATCH_MODE effect:(%d) switch:(%d) ......\n", pos->effect, pos->entry_switch);
					if (pos->effect == ENTRY_NO_BLOCK) {
						spin_unlock_bh(&hash_bucket[num].lock);
						return ENTRY_NO_BLOCK;
					}

					if (pos->entry_switch == ENTRY_NEED_BLOCK) {
						spin_unlock_bh(&hash_bucket[num].lock);
						return ENTRY_NEED_BLOCK;
					}

					spin_unlock_bh(&hash_bucket[num].lock);
					return ENTRY_NO_BLOCK;
				}
			}
			spin_unlock_bh(&hash_bucket[num].lock);
			++num;
		}
	}

	DEBUG("SCOPE_MATCH_MODE not match!!!\n");
	return ENTRY_NO_BLOCK;
}

static int match_rule(const char *data, const char *tail)
{
	const char *p_tail;
	char *host;
	unsigned int host_len, hash_val;

	p_tail = findend(data, tail, 6);
	if (p_tail == NULL)
		return ENTRY_NO_BLOCK;

	if (memcmp(data, "Host: ", 6) != 0) {
		//ERROR("no Host entry in HTTP request !!!\n");
		return ENTRY_NO_BLOCK;
	}

	data += 6;//skip 'Host: ', pointer to host string

	/*while(): skip ' ' between host_string's start and end*/
	while ((data < p_tail) && (*data == ' ')) ++data;
	while ((p_tail > data) && (*(p_tail - 1) == ' ')) --p_tail;

	host_len = p_tail - data;

	host = (char *)kmalloc(host_len + 1, GFP_ATOMIC);
	if (!host)
		return ENTRY_NO_BLOCK;
	memcpy(host, data, host_len);
	host[host_len] = '\0';

	hash_val = calculate_hash_key(host, host_len);
	
	//full match entry 
	if (ENTRY_NEED_BLOCK == __match_rule(FULL_MATCH_MODE, hash_val, host, host_len))
		goto block;

	//socpe match entry 
	if(ENTRY_NEED_BLOCK == __match_rule(SCOPE_MATCH_MODE, hash_val, host, host_len))
		goto block;

	kfree(host);
	return ENTRY_NO_BLOCK;

block:
	kfree(host);
	return ENTRY_NEED_BLOCK;
}	

static int is_block_url(const char *payload, int payload_len)
{
	const char *tail;
	const char *p;

	// POST / HTTP/1.x$$ '/r/n'
	// GET / HTTP/1.x$$
	// 1234567890123456789
	if (payload_len < 18){
		DEBUG("HTTP payload is too small !!!\n");
		return ENTRY_NO_BLOCK;
	}

	//max match payload length -> 2048 btye
	tail = payload + min(payload_len, MAX_PAYLOAD_LEN);	

	p = findend(payload, tail, 18);
	if (p == NULL) {
		DEBUG("not find line end -> '/r'!!!\n");
		return ENTRY_NO_BLOCK;
	}

	//pointer 'GET -9 , POST -8'
	if ((memcmp(p - 9, " HTTP/", 6) != 0) && (memcmp(p - 8, " HTTP/", 6) != 0)) {
		DEBUG("HTTP request format error !!!\n");
		return ENTRY_NO_BLOCK;
	}

	p += 2; //skip '/r/n' pointer to 'Host: '
	if (ENTRY_NO_BLOCK == match_rule(p, tail))
			return ENTRY_NO_BLOCK;

	return ENTRY_NEED_BLOCK;
}

static unsigned int url_block_hook(unsigned int hooknum, struct sk_buff *skb,
			                         const struct net_device *in,
			                         const struct net_device *out,
			                         int (*okfn)(struct sk_buff *))
{
	const struct iphdr  *iph  = NULL;
	const struct tcphdr *tcph = NULL;
	const char *payload = NULL;
	int  payload_len;

	if (!skb)
		return NF_ACCEPT;

	spin_lock_bh(&plug_control.lock);
	if (plug_control.flag == MODULE_STOP) {
		DEBUG(" MODULE_STOP-> return NF_ACCEPT\n");
		spin_unlock_bh(&plug_control.lock);		
		return NF_ACCEPT;
	}
	spin_unlock_bh(&plug_control.lock);

	iph  = ip_hdr(skb);
	tcph = tcp_hdr(skb);

	if ((iph == NULL) || (tcph == NULL))
			return NF_ACCEPT;

	if ((iph->protocol != IPPROTO_TCP) || (ntohs(tcph->dest) != 80))
			return NF_ACCEPT;

	payload = (char *)tcph + (tcph->doff * 4); //tcp_hdrlen(skb);
	payload_len = ntohs(iph->tot_len) - (payload - (char *)iph);

	if ((0 != memcmp(payload, "GET", 3)) && (0 != memcmp(payload, "POST", 4)))
			return NF_ACCEPT;

#if 0
	if (skb_is_nonlinear(skb)) {
		if (unlikely(skb_linearize(skb)))
			return NF_ACCEPT; // failed to linearize packet, bailing
	}
#endif

	if (ENTRY_NEED_BLOCK == is_block_url(payload, payload_len))
			return NF_DROP;

	return NF_ACCEPT;
}

/*
return value:
1->normal;
2->when add entry, match same entry
-1-> error action;
*/
static int deal_node(URL_LIST_NODE *node, unsigned int hash_val, unsigned int action)
{
	URL_LIST_NODE *pos;
	struct hlist_node *n;

	switch (action) {
		case ADD:
			DEBUG("add entry .....\n");
			spin_lock_bh(&hash_bucket[hash_val].lock);
			hlist_for_each_entry_safe(pos, n, &hash_bucket[hash_val].head, list)
			{
				if (0 == memcmp(pos->entry, node->entry, node->entry_len)) {
					DEBUG("ADD: had been added same entry !!!\n");
					spin_unlock_bh(&hash_bucket[hash_val].lock);
					return -1;//have same entry
				}
			}
			hlist_add_head(&node->list, &hash_bucket[hash_val].head);
			spin_unlock_bh(&hash_bucket[hash_val].lock);
			return 1;

		case DEL:
			DEBUG("delete entry ......\n");
			spin_lock_bh(&hash_bucket[hash_val].lock);
			hlist_for_each_entry_safe(pos, n, &hash_bucket[hash_val].head, list)
			{
				if (0 == memcmp(pos->entry, node->entry, node->entry_len)) {
					hlist_del(&pos->list);
					kfree(pos);
					spin_unlock_bh(&hash_bucket[hash_val].lock);
					return 1;
				}
			}
			spin_unlock_bh(&hash_bucket[hash_val].lock);
			DEBUG("DEL_ENTRY: not find entry !!!\n");
			return -1;

		case SET:
			DEBUG("set entry ....\n");
			spin_lock_bh(&hash_bucket[hash_val].lock);
			hlist_for_each_entry_safe(pos, n, &hash_bucket[hash_val].head, list)
			{
				if (0 == memcmp(pos->entry, node->entry, node->entry_len)) {
					DEBUG("SET: had been added same entry !!!\n");
					pos->hour_start = node->hour_start;
					pos->min_start  = node->min_start;
					pos->hour_end   = node->hour_end;
					pos->min_end    = node->min_end;
					pos->effect     = node->effect;
					kfree(node); //find same entry ,so need free node after set
					spin_unlock_bh(&hash_bucket[hash_val].lock);
					return 1;
				}
			}
			hlist_add_head(&node->list, &hash_bucket[hash_val].head);
			spin_unlock_bh(&hash_bucket[hash_val].lock);
			return 1;

		default:
			ERROR("mode(%d) error !!!\n", action);
			return -1;
	}

	return 1;
}

static void node_cpy(URL_LIST_NODE *new_node, URL_LIST_NODE *node)
{

	new_node->action      =	node->action;        
    new_node->hour_start  = node->hour_start;
    new_node->min_start   = node->min_start;
    new_node->hour_end    = node->hour_end;
    new_node->min_end     = node->min_end;
    new_node->effect      = node->effect;
    new_node->entry_switch = node->entry_switch; 
    new_node->entry_len   = node->entry_len;

    memcpy(new_node->entry, node->entry, node->entry_len);

#if 1
 	DEBUG("new_node: action(%d) hourStart(%d) minStart(%d) hourEnd(%d) minEnd(%d) effect(%d)  domain(%s) domain_len(%d) entry_switch(%d)\n",
                                new_node->action, new_node->hour_start, new_node->min_start, new_node->hour_end,
                                 new_node->min_end, new_node->effect, new_node->entry, new_node->entry_len, new_node->entry_switch);
#endif

}

static void nl_send_msg(unsigned int action, unsigned int data, struct nlmsghdr *nlh_in)
{
	unsigned int dest_pid, err;
	struct sk_buff *skb;
	struct nlmsghdr *nlh;
	NL_MSG msg_data;

	msg_data.action = action;
	msg_data.data = data;

	dest_pid = nlh_in->nlmsg_pid;

	skb = alloc_skb(NLMSG_SPACE(MAX_MSGSIZE), GFP_ATOMIC);
	if (!skb) {
        ERROR("alloc_skb() failed !!!\n");
        return;
    }

    nlh = nlmsg_put(skb, 0, 0, 0, NLMSG_SPACE(MAX_MSGSIZE) - sizeof(struct nlmsghdr), 0);
	if (!nlh) {
		ERROR("nlmsg_put() failed !!!\n");
		kfree_skb(skb);
		return;
	}

	memcpy(NLMSG_DATA(nlh), &msg_data, sizeof(msg_data));
	
	nlh->nlmsg_len = NLMSG_SPACE(MAX_MSGSIZE);

    DEBUG("skb->data: action: [%d] data:[%d]\n", ((NL_MSG *)NLMSG_DATA((struct nlmsghdr *)skb->data))->action,
    					 ((NL_MSG *)NLMSG_DATA((struct nlmsghdr *)skb->data))->data);

    NETLINK_CB(skb).portid = 0;    // 0  from kernel to user space
    NETLINK_CB(skb).dst_group = 0; //0  someonw porcess

 	err = netlink_unicast(nl_sock, skb, dest_pid, MSG_DONTWAIT);
 	if (err < 0) {
 		ERROR("netlink_unicast() failed !!!\n");
 		return;
 	}

    return;
}

static void nl_func(struct sk_buff *skb_in)
{
	struct nlmsghdr *nlh  = NULL; 
	struct sk_buff  *skb  = NULL;
	URL_LIST_NODE *node, *new_node;
	unsigned int hash_val;

	skb = skb_get(skb_in);
	if (!skb) {
		ERROR("skb is (NULL) !!!\n");
		return;
	}

	nlh = nlmsg_hdr(skb);
	if (!nlh) {
		ERROR("nlh is (NULL) !!!\n");
		goto out;
	}

	node = (URL_LIST_NODE *)NLMSG_DATA(nlh);

	if ((node->action != ADD) && (node->action != SET)
		 && (node->action != DEL) && (node->action != STOP)
		 && (node->action != START) && (node->action != GET_MODULE_STATUS)) {
		
		ERROR("mode(%d) undefine !!!\n", node->action);
		nl_send_msg(node->action, NL_STATUS_FAIL, nlh);
		goto out;
	}

#if 0
 	DEBUG("action(%d) hourStart(%d) minStart(%d) hourEnd(%d) minEnd(%d) effect(%d)  domain(%s) domain_len(%d) entry_switch(%d)\n",
                              node->action, node->hour_start, node->min_start, node->hour_end,
                             node->min_end, node->effect, node->entry, node->entry_len, node->entry_switch);
 #endif

	if ((node->action == START) || (node->action == STOP) || (node->action == GET_MODULE_STATUS)) {
		spin_lock_bh(&plug_control.lock);
		switch (node->action) {
			case START:
				plug_control.flag = MODULE_START;
				spin_unlock_bh(&plug_control.lock);
				nl_send_msg(node->action, NL_STATUS_SUCESS, nlh);
				goto out;

			case STOP:
				plug_control.flag = MODULE_STOP;
				spin_unlock_bh(&plug_control.lock);
				nl_send_msg(node->action, NL_STATUS_SUCESS, nlh);
				goto out;

			case GET_MODULE_STATUS:
				if (plug_control.flag == MODULE_START)
					nl_send_msg(node->action, MODULE_START, nlh);
				else 
					nl_send_msg(node->action, MODULE_STOP, nlh);
				spin_unlock_bh(&plug_control.lock);
				goto out;

			default:
				spin_unlock_bh(&plug_control.lock);
				goto out;
		}
	}
	
	hash_val = calculate_hash_key(node->entry, node->entry_len);
	
	if (node->action == DEL) {
		if (-1 == deal_node(node, hash_val, node->action))
			nl_send_msg(node->action, NL_STATUS_FAIL, nlh);
		else
			nl_send_msg(node->action, NL_STATUS_SUCESS, nlh);
			goto out;
	}

	new_node = node_kmalloc(node->entry_len);
	if (!new_node) {
		nl_send_msg(node->action, NL_STATUS_FAIL, nlh);
		goto out;
	}

	node_cpy(new_node, node);
	set_switch(new_node);

/*node->action : ADD or SET*/
	if (-1 == deal_node(new_node, hash_val, node->action)) {
		nl_send_msg(node->action, NL_STATUS_FAIL, nlh);
		goto out;
	}
	
	nl_send_msg(node->action, NL_STATUS_SUCESS, nlh);

out:
	kfree_skb(skb);
	return;
}

static int init_netlink(void)
{
	struct netlink_kernel_cfg cfg = {
		.input = nl_func,
	};

	nl_sock = netlink_kernel_create(&init_net, MY_NETLINK, &cfg);
	if (nl_sock == NULL) {
		ERROR("create netlink failed() !!!\n");
		return -1;
	}
	
	return 1;
}

static struct nf_hook_ops url_block_ops = {
    .hook           = url_block_hook,
	.owner          = THIS_MODULE,
	.pf             = PF_INET,
	.hooknum        =  NF_INET_PRE_ROUTING, //NF_INET_LOCAL_OUT, 
	.priority       = NF_IP_PRI_FIRST,
};

static void init_hash_list(void)
{
	int num = 0;

	while (num < MAX_HASH_TABLE) {
		spin_lock_init(&hash_bucket[num].lock);
		INIT_HLIST_HEAD(&hash_bucket[num].head);	
		++num;
	}

}

static void release_hash_list(void)
{
	int num = 0;
	URL_LIST_NODE *pos;
	struct hlist_node *n;

	while (num < MAX_HASH_TABLE) {		
		spin_lock_bh(&hash_bucket[num].lock);
		hlist_for_each_entry_safe(pos, n, &hash_bucket[num].head, list) {
			hlist_del(&pos->list);
			kfree(pos);
		}
		spin_unlock_bh(&hash_bucket[num].lock);
		
		++num;
	}
	DEBUG("release_hash_list() done\n");
}


static void timeout(unsigned long data)
{
	int num = 0;
	URL_LIST_NODE *pos;
	struct hlist_node *n;

	spin_lock_bh(&plug_control.lock);
	if (plug_control.flag == MODULE_STOP) {
		timer.expires  = jiffies + 10 * HZ; // 10/sec
		add_timer(&timer);	
		spin_unlock_bh(&plug_control.lock);
		return;
	}
	spin_unlock_bh(&plug_control.lock);


	while (num < MAX_HASH_TABLE) {
		spin_lock_bh(&hash_bucket[num].lock);
		hlist_for_each_entry_safe(pos, n, &hash_bucket[num].head, list) {
			//if (pos->effect == ENTRY_NEED_BLOCK)
			set_switch(pos);
		}
		spin_unlock_bh(&hash_bucket[num].lock);	
		++num;
	}

	timer.expires  = jiffies + 10 * HZ; //10/sec  ENTRY_NO_BLOCK timer
	add_timer(&timer);
}

static int __init url_block_init(void)
{
	int ret;

	init_hash_list();
	
	spin_lock_init(&plug_control.lock);
	plug_control.flag = MODULE_START;

	init_timer(&timer);

	timer.data = (unsigned long)jiffies;
	timer.function = timeout;
	timer.expires  = jiffies + 10 * HZ; //10/sec  ENTRY_NO_BLOCK timer
	add_timer(&timer);

	init_netlink();

	ret = nf_register_hook(&url_block_ops);
	if (ret < 0)
		ERROR("nf_register_hook() failed !!!\n");
	else
		DEBUG("nf_register_hook() sucess !!!\n");

	return ret;
}

static void __exit url_block_exit(void)
{
	del_timer_sync(&timer);
	nf_unregister_hook(&url_block_ops);
	netlink_kernel_release(nl_sock);
	release_hash_list();

	DEBUG("nf_unregister_hook() done !!!\n");
}

module_init(url_block_init);
module_exit(url_block_exit);