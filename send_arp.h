#include <sys/types.h>
#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/sysctl.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/stat.h>

#define ETHER_ADDR_LEN 6
#define ETHERNET 1
#define ETH_ARP 0x0806
#define ETHERTYPE_IP 0x0800

u_char* GetSvrMacAddress(char* dev_name)
{
    int         mib[6], len;
    char            *buf;
    unsigned char       *ptr;
    struct if_msghdr    *ifm;
    struct sockaddr_dl  *sdl;
    char *dev;

    dev = dev_name;

    mib[0] = CTL_NET;
    mib[1] = AF_ROUTE;
    mib[2] = 0;
    mib[3] = AF_LINK;
    mib[4] = NET_RT_IFLIST;
    if ((mib[5] = if_nametoindex(dev)) == 0) {
        perror("if_nametoindex error");
        exit(2);
    }

    if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0) {
        perror("sysctl 1 error");
        exit(3);
    }

    if ((buf = malloc(len)) == NULL) {
        perror("malloc error");
        exit(4);
    }

    if (sysctl(mib, 6, buf, &len, NULL, 0) < 0) {
        perror("sysctl 2 error");
        exit(5);
    }

    ifm = (struct if_msghdr *)buf;
    sdl = (struct sockaddr_dl *)(ifm + 1);
    ptr = (unsigned char *)LLADDR(sdl);
    return ptr;
}

int s_get_IPAddress(const char *ifr,u_char *out){
	int sockfd;
	struct ifreq ifrq;
	struct sockaddr_in *sin;

	sockfd = socket(AF_INET,SOCK_DGRAM,0);
	strcpy(ifrq.ifr_name,ifr);
	if (ioctl(sockfd, SIOCGIFADDR, &ifrq) < 0) {
        	perror( "ioctl() SIOCGIFADDR error");
		return -1;
	}

	sin = (struct sockaddr_in *)&ifrq.ifr_addr;
	memcpy(out,(void*)&sin->sin_addr,sizeof(sin->sin_addr));

	close(sockfd);

	return 4;
}
