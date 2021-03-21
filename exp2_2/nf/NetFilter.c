#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/skbuff.h>
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
#include <linux/init.h>
#include <linux/string.h>

/*
struct nf_hook_ops {
	nf_hookfn		   *hook;    //钩子处理函数
	struct net_device	*dev;     //钩子处理设备
	void			      *priv;    //上一个钩子处理
	u_int8_t		      pf;       //钩子协议族
	unsigned int		hooknum;  //钩子的位置值（PREROUTING、POSTOUTING、INPUT、FORWARD、OUTPUT五个位置）
	int			      priority; //钩子的的优先级
};
 */
struct nf_hook_ops  post_hook;              

static unsigned int watch_out(void *priv, struct sk_buff *skb, const struct nf_hook_state *state)
{
  /* 让传入的缓冲skb存到sock_buff中 */ 
    struct sk_buff *sock_buff = skb;
	struct iphdr *iph; // ip头部
	struct tcphdr *tcph; // tcp头部
	char *tcpdata; // tcp数据部分
	char *index; // 当前数据指针
	char *end; // ip包尾部
	int n = 0; // username或password 的长度

	/**
	 * sk_buff结构中有一个end指针, 作用是指向packet data 的末尾, 同样也是skb_shared_info的开头,
	 * sk_buff的部分数据被分片后存储在skb_shared_info中
	 * 这导致data的非线程内存分布
	 * 可以通过将sk_buff中的end指针转换为skb_shared_info指针获得分片信息
	 * 
	 * 也可以通过skb_linearize函数将分片整合变的线性化,这样才能获取数据
	 */
	skb_linearize(sock_buff);

 	if(!sock_buff){
		printk("buffer error!\n");
		return NF_ACCEPT;
	}
	// //丢弃tcp报文
	// if(ip_hdr(sock_buff)->protocol == 6){
	// 	return NF_DROP;
	// }
	iph = ip_hdr(sock_buff);
	// 不是TCP
	if (iph->protocol != 6) {
		//printk("protocol: %d\n",(int)(iph->protocol) );
		return NF_ACCEPT;
	}
	// printk(KERN_INFO "A TCP\n");
	// 通过ip包的总长度获得ip包的末尾指针,应该是最后一个字节的下一个指针
	// 得到tcp头
	tcph = (struct tcphdr *)(sock_buff->data + (ip_hdr(sock_buff)->ihl*4));
	if (tcph->dest != htons(8080)) {
		return NF_ACCEPT;
	}
	// printk("ip->tot_len: %d\n",ntohs(iph->tot_len)); // 查看ip包长度
	// 偏移一个tcp头部长度
	// printk("%d",tcph->doff); // 查看tcp头长度
	tcpdata = (char *)((unsigned long)tcph + (unsigned long)(tcph->doff * 4)); // doff为tcp头部长度 单位4字节
	//printk("content: %02x %02x %02x %02x\n",*((char*)tcph + 32),*((char*)tcph + 33),*((char*)tcph + 34),*((char*)tcph + 35));
	if (strstr(tcpdata,".exe") != NULL) {
		return NF_DROP;
	}

	end = (char*)iph + ntohs(iph->tot_len); // 获取数据最末尾指针

	if ((index = strstr(tcpdata,"username")) != NULL) {
		index += 9; // 跳过username=
		n = 0;
		while (*index != '&' && index != end) {
			n++;
			index++;
		}

		//printk("n: %d\n",n);
		char t[n+1];
		memset(t,0,n+1);
		memcpy(t,index - n,n);
		printk("username: %s\n",t);
		
	}
	if ((index = strstr(tcpdata,"password")) != NULL) {
		index += 9;
		n = 0;
		while (*index != '&' && index != end) {
			n++;
			index++;
		}
		//printk("password n: %d\n",n);
		char t[n+1];
		memset(t,0,n+1);
		memcpy(t,index - n,n);
		printk("password: %s\n",t); // 不加\n 会导致只能输出一次
	}
	

	return NF_ACCEPT;
}

/*
内核模块中的两个函数 init_my_module() ：表示起始 和 exit_my_module() ：表示结束 
*/ 
static int __init init_my_module(void)
{
	/*hook函数指针指向watc_out*/ 
   post_hook.hook     = watch_out;
   /*协议簇为ipv4*/  
   post_hook.pf       = PF_INET;
   /*优先级最高*/
   post_hook.priority = NF_IP_PRI_FIRST;
   // 出站规则
   post_hook.hooknum  = NF_INET_POST_ROUTING;

   /*将post_hook注册，注册实际上就是在一个nf_hook_ops链表中再插入一个nf_hook_ops结构*/ 
   nf_register_net_hook(&init_net ,&post_hook);
   return 0;
}

static void __exit exit_my_module(void)
{
	/*将post_hook取消注册，取消注册实际上就是在一个nf_hook_ops链表中删除一个nf_hook_ops结构*/ 
   nf_unregister_net_hook(&init_net ,&post_hook);

}

module_init(init_my_module);
module_exit(exit_my_module);

MODULE_LICENSE("GPL");