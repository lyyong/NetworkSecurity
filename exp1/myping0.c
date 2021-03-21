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

#define icmp_id         icmp_hun.ih_idseq.icd_id
#define icmp_seq        icmp_hun.ih_idseq.icd_seq

char buff[28] = {0};
int sockfd;
struct sockaddr_in target;
struct sockaddr_in source;

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

    int send, recv, i;
    send = 0;
    recv = 0;
    i = 0;

    if (argc != 2)
    {
        printf("usage: %s targetip\n", argv[0]);
        exit(1);
    }

    if (inet_aton(argv[1], &target.sin_addr) == 0)
    {
        printf("bad ip address %s\n", argv[1]);
        exit(1);
    }

    int recvfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP);

    struct icmp *icmp = (struct icmp *)(buff);

    if ((sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_ICMP)) < 0)
    {
        perror("socket error!");
        exit(1);
    }

    icmp->icmp_type = ICMP_ECHO;
    icmp->icmp_code = 0;
    icmp->icmp_cksum = 0;
    icmp->icmp_id = 2;
    icmp->icmp_seq = 3;

    while (send < 4)
    {
        send++;
        icmp->icmp_seq = icmp->icmp_seq + 1;
        icmp->icmp_cksum = 0;
        icmp->icmp_cksum = in_cksum((unsigned short *)icmp, 8);
        sendto(sockfd, buff, 28, 0, (struct sockaddr *)&target, sizeof(target));
        sleep(1);
    }

    struct sockaddr_in from;
    int lenfrom = sizeof(from);
    char recvbuff[1024];
    int n;
    while (1)
    {
        memset(recvbuff, 0, 1024);
        if ((n = recvfrom(recvfd, recvbuff, sizeof(recvbuff), 0, NULL, NULL)) < 0)
        {
            perror("receive error!\n");
            exit(1);
        };
        struct ip *ip = (struct ip *)recvbuff;
        struct icmp *icmp = (struct icmp *)(ip + 1);
        printf("n is %d,ip header length is %d\n ", n, ip->ip_hl);
        if ((n - ip->ip_hl * 4) < 8)
        {
            printf("Not ICMP Reply!\n");
            break;
        }
        printf("ttl is %d\n", ip->ip_ttl);
        printf("protocol is %d\n", ip->ip_p);
        if ((icmp->icmp_type == ICMP_ECHOREPLY) && (icmp->icmp_id == 2))
        {
            printf("%d reply coming back from %s: icmp sequence=%u ttl=%d\n", recv + 1, inet_ntoa(from.sin_addr), icmp->icmp_seq, ip->ip_ttl);
            printf("src is %s\n", inet_ntoa(ip->ip_src));
            printf("dst is %s\n", inet_ntoa(ip->ip_dst));
            recv++;
        }
    }

    return 0;
}