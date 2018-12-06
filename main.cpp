#include <sys/socket.h>
#include <sys/ioctl.h>
#include <sys/time.h>
#include <sys/types.h>
#include <ifaddrs.h>

#include <arpa/inet.h>

#include <asm/types.h>

#include <math.h>
#include <string.h>
#include <stdio.h>
#include <stdlib.h>
#include <unistd.h>
#include <signal.h>

#include <linux/if_packet.h>
#include <linux/if_ether.h>
#include <linux/if_arp.h>

#include <vector>
#include <string>
#include <map>

#define HW_ADDR_LENGTH 6

void usage() {
    fprintf(stdout, "arpreply version 1.0, release date: 2018-12-06\n\n"
                    "Usage: arpreply -h | -list | [-i interfacename] -rti ipaddr -rqi ipaddr [-rqm macaddr]\n"
                    "-list           list all interfaces\n"
                    "-i              specify outgoing interface\n"
                    "-h              display help\n"
                    "-rti            reply to ip address\n"
                    "-rqi            ip address that using to reply\n"
                    "-rqm            mac address that using to reply\n"
                    "\n"
                    "example: arpreply -rti 192.168.1.123 -rqi 192.168.1.1 -rqm 00:00:00:00:00:00\n"
                    "just work in ipv4 networking\n"
                    "");
}

std::vector<std::string> getCmdOutput(const char *__command, const char *__modes = "r") {

    std::vector<std::string> result;
    FILE *fp;
    char path[1024];
    /* Open the command for reading. */
    fp = popen(__command, __modes);
    if (fp == NULL) {
        printf("Failed to run command\n" );
        return result;
    }


    /* Read the output a line at a time - output it. */
    while (fgets(path, sizeof(path)-1, fp) != NULL) {
        result.push_back(std::string(path));
    }

    pclose(fp);
    return result;
}

std::string getARPReplyMAC(int fd, const unsigned char* ipaddr) {
    //send arp request

    //receive arp response

    return std::string();
}

bool isInterfaceOnline(int fd, const char* interface) {
    struct ifreq ifr;
    memset(&ifr, 0, sizeof(ifr));
    strcpy(ifr.ifr_name, interface);
    if (ioctl(fd, SIOCGIFFLAGS, &ifr) < 0) {
        perror("SIOCGIFFLAGS");
    }
    return !!(ifr.ifr_flags | IFF_RUNNING);
}

void getIpAddr(int fd)
{
    std::map<std::string, std::string> ipMapMac;
    struct ifaddrs * ifAddrStruct=NULL;
    struct ifaddrs * ifa=NULL;
    void * tmpAddrPtr=NULL;

    getifaddrs(&ifAddrStruct);

    for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) {
            continue;
        }
        if (ifa->ifa_addr->sa_family == AF_INET) { // check it is IP4
            // is a valid IP4 Address
            tmpAddrPtr=&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
            char addressBuffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
            printf("%s IP Address %s\n", ifa->ifa_name, addressBuffer);
            printf("status: %d\n", isInterfaceOnline(fd, ifa->ifa_name));
        } else if (ifa->ifa_addr->sa_family == AF_INET6) {
#ifdef IPV6
            // check it is IP6
            // is a valid IP6 Address
            tmpAddrPtr=&((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
            char addressBuffer[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, tmpAddrPtr, addressBuffer, INET6_ADDRSTRLEN);
#endif
        }
    }
    if (ifAddrStruct!=NULL) freeifaddrs(ifAddrStruct);
}
int main(int argc, char* argv[]) {
    getIpAddr(0);
    return 0;
    if (argc == 1) {
        usage();
        return 0;
    }

    if (argc == 2) {
        if (!memcmp("-h", argv[1], 2)) {
            usage();
        } else {
            fprintf(stdout, "Invalid parameter\n");
            usage();
            exit(1);
        }

        return 0;
    }

    unsigned char rti[4]{0};
    unsigned char rqi[4]{0};
    unsigned char rqm[6]{0};

    for (int i = 1; i < argc; i++) {
        if (!memcmp("-rti", argv[i], 4) && i + 1 < argc && memcmp("-", argv[i+1], 1)) {
            in_addr_t addr = inet_addr(argv[++i]);
            memcpy(rti, (void*)(&addr), 4);
        } else if (!memcmp("-rqi", argv[i], 4) && i + 1 < argc && memcmp("-", argv[i+1], 1)) {
            in_addr_t addr = inet_addr(argv[++i]);
            memcpy(rqi, (void*)(&addr), 4);
        } else if (!memcmp("-rqm", argv[i], 4) && i + 1 < argc && memcmp("-", argv[i+1], 1)) {
            if (6 != sscanf(argv[++i], "%02x-%02x-%02x-%02x-%02x-%02x", &rqm[0], &rqm[1], &rqm[2], &rqm[3], &rqm[4], &rqm[5])) {
                if (6 != sscanf(argv[++i], "%02x-%02x-%02x-%02x-%02x-%02x", &rqm[0], &rqm[1], &rqm[2], &rqm[3], &rqm[4], &rqm[5])) {
                    fprintf(stdout, "Invalid mac address, must be like this 00:00:00:00:00:00 or 00-00-00-00-00-00");
                    exit(1);
                }
            }
        } else {
            usage();
            exit(1);
        }
    }

    struct ifaddrs *addrs,*tmp;

    getifaddrs(&addrs);
    tmp = addrs;

    while (tmp)
    {
        if (tmp->ifa_addr && tmp->ifa_addr->sa_family == AF_PACKET)
            printf("%s\n", tmp->ifa_name);

        tmp = tmp->ifa_next;
    }

    freeifaddrs(addrs);
    exit(0);


    struct ARPHeader
    {
        unsigned short HWType{0};
        unsigned short ProcType{0};
        unsigned char HWSize{0};
        unsigned char ProcSize{0};
        unsigned short Opcode{0};
        unsigned char SenderMAC[6]{0};
        unsigned char SenderIP[4]{0};
        unsigned char TargetMAC[6]{0};
        unsigned char TargetIP[4]{0};
    };

    struct MACHeader {
        unsigned char destMACAddr[6]{0};
        unsigned char srcMACAddr[6]{0};
        unsigned short upperType{0};
        ARPHeader arpHeader;
        //alignment
        unsigned char padding[18]{0};
    };

    struct IPSock {
        int fdSock{0};
        explicit IPSock () {
        }

        ~IPSock () {
            if (0 != fdSock) {
                close(fdSock);
            }
        }

        IPSock& operator = (int iFdSock) {
            if (0 != fdSock) {
                close(fdSock);
            }

            fdSock = iFdSock;
            return *this;
        }

        bool operator == (int iVal) const {
            return (iVal == fdSock);
        }

    } ipSock;

    struct ifreq ifreq;
    strcpy(ifreq.ifr_name, "eth0");
    ipSock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (ipSock == -1) {
        perror("socket():");
        exit(1);
    }

    struct sockaddr_ll sockAddr;
    sockAddr.sll_family = AF_PACKET;
    sockAddr.sll_protocol = htons(ETH_P_ARP);

    if (-1 == ioctl(ipSock.fdSock, SIOCGIFINDEX, &ifreq)) {
        perror("SIOCGIFINDEX");
        exit(1);
    }
    sockAddr.sll_ifindex = ifreq.ifr_ifindex;

    sockAddr.sll_hatype = htons(ARPHRD_ETHER);
    sockAddr.sll_pkttype = PACKET_BROADCAST;
    sockAddr.sll_halen = HW_ADDR_LENGTH;
    memset(sockAddr.sll_addr + HW_ADDR_LENGTH, '\0', 2);

    if (-1 == ioctl(ipSock.fdSock, SIOCGIFHWADDR, &ifreq)) {
        perror("SIOCGIFHWADDR");
        exit(1);
    }

    for (int idx = 0; idx < HW_ADDR_LENGTH; idx++) {
        *(sockAddr.sll_addr + idx) = *(ifreq.ifr_hwaddr.sa_data + idx);
    }

    unsigned char buf[sizeof(MACHeader)]{0};
    //    {
    //        //construct arp request
    //        MACHeader &pMAC = (MACHeader&)buf;
    //        memset(pMAC.destMACAddr, 0xff, sizeof(pMAC.destMACAddr));
    //        for (int idx = 0; idx < HW_ADDR_LENGTH; idx++) {
    //            *(pMAC.srcMACAddr + idx) = *(ifreq.ifr_hwaddr.sa_data + idx);
    //            *(pMAC.arpHeader.SenderMAC + idx) = *(ifreq.ifr_hwaddr.sa_data + idx);
    //        }

    //        pMAC.upperType = htons(0x0806);
    //        pMAC.arpHeader.HWType = htons(0x0001);
    //        pMAC.arpHeader.ProcType = htons(0x0800);
    //        pMAC.arpHeader.HWSize = 6;
    //        pMAC.arpHeader.ProcSize = 4;
    //        pMAC.arpHeader.Opcode = htons(0x0001);
    //        unsigned char sendrIP[4] = {192, 168, 254, 254};
    //        unsigned char targetIP[4] = {192, 168, 123, 123};
    //        memcpy(pMAC.arpHeader.SenderIP, sendrIP, 4);
    //        memcpy(pMAC.arpHeader.TargetIP, targetIP, 4);
    //    }

    {
        //construct arp response
        MACHeader &pMAC = (MACHeader&)buf;
        unsigned char destMACAddr[6] = {0x9c, 0xe8, 0x2b, 0xe4, 0x18, 0xd7};
        memcpy(pMAC.destMACAddr, destMACAddr, sizeof(pMAC.destMACAddr));
        //        for (int idx = 0; idx < HW_ADDR_LENGTH; idx++) {
        //            *(pMAC.srcMACAddr + idx) = *(ifreq.ifr_hwaddr.sa_data + idx);
        //            *(pMAC.arpHeader.SenderMAC + idx) = *(ifreq.ifr_hwaddr.sa_data + idx);
        //        }
        unsigned char fakeSenderMACAddr[6] = {0x00, 0x23, 0x24, 0xe0, 0x95, 0x80};
        memcpy(pMAC.srcMACAddr, fakeSenderMACAddr, sizeof(pMAC.srcMACAddr));
        memcpy(pMAC.arpHeader.SenderMAC, fakeSenderMACAddr, sizeof(pMAC.arpHeader.SenderMAC));

        pMAC.upperType = htons(0x0806);
        pMAC.arpHeader.HWType = htons(0x0001);
        pMAC.arpHeader.ProcType = htons(0x0800);
        pMAC.arpHeader.HWSize = 6;
        pMAC.arpHeader.ProcSize = 4;
        pMAC.arpHeader.Opcode = htons(0x0002);
        unsigned char sendrIP[4] = {192, 168, 2, 1};
        unsigned char targetIP[4] = {192, 168, 2, 113};
        memcpy(pMAC.arpHeader.SenderIP, sendrIP, 4);
        memcpy(pMAC.arpHeader.TargetIP, targetIP, 4);
    }

    for (;;){
        if (-1 == sendto(ipSock.fdSock, buf, sizeof(buf), 0, (struct sockaddr *)&sockAddr, sizeof(sockAddr))) {
            perror("Sending failure");
        }
        sleep(1);
        fprintf(stdout, "Send\n");
    }

    return 0;
    return 0;
}
