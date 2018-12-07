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
#include <regex>

#define HW_ADDR_LENGTH 6

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

void usage() {
    fprintf(stdout, "arpreply version 1.0, release date: 2018-12-06\n\n"
                    "Usage: arpreply --help | -list | [-i interfacename] [-itval n] -rti ipaddr -rqi ipaddr [-rqm macaddr] [-q]\n"
                    "-list           list all interfaces\n"
                    "-i              specify outgoing interface\n"
                    "-itval          specify the interval seconds between two sending (default: 1)\n"
                    "--help          display help\n"
                    "-rti            reply to ip address\n"
                    "-rqi            ip address that using to reply\n"
                    "-rqm            mac address that using to reply\n"
                    "-q              quite model\n"
                    "\n"
                    "example: arpreply -rti 192.168.1.123 -rqi 192.168.1.1 -rqm 00:00:00:00:00:00\n"
                    "just work in ipv4 networking, ipv6 is still considering\n"
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


//to do
std::string getARPReplyMAC(int fd, const unsigned char* ipaddr) {
    //send arp request
    unsigned char buf[sizeof(MACHeader)]{'\0'};
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
    //        unsigned char sendrIP[4] = {0, 0, 0, 0};
    //        unsigned char targetIP[4] = {0, 0, 0, 0};
    //        memcpy(pMAC.arpHeader.SenderIP, sendrIP, 4);
    //        memcpy(pMAC.arpHeader.TargetIP, targetIP, 4);
    //    }

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

template <typename T>
bool isEmpty(const T p, int c) {
    for (int i = 0; i < c; i++) {
        if ('\0' != p[i]) return false;
    }

    return true;
}

void listInterfaces() {
    struct ifaddrs * ifAddrStruct{NULL};
    struct ifaddrs * ifa{NULL};
    void * tmpAddrPtr{NULL};

    getifaddrs(&ifAddrStruct);

    IPSock ipSock;
    ipSock = socket(AF_PACKET, SOCK_RAW, htons(ETH_P_ALL));
    if (ipSock == -1) {
        perror("Fail to open socket");
        return;
    }

    for (ifa = ifAddrStruct; ifa != NULL; ifa = ifa->ifa_next) {
        if (!ifa->ifa_addr) {
            continue;
        }
        if (ifa->ifa_addr->sa_family == AF_INET) { // check it is IP4
            // is a valid IP4 Address
            tmpAddrPtr=&((struct sockaddr_in *)ifa->ifa_addr)->sin_addr;
            char addressBuffer[INET_ADDRSTRLEN];
            inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
            struct ifreq ifreq;
            strcpy(ifreq.ifr_name, ifa->ifa_name);
            if (-1 == ioctl(ipSock.fdSock, SIOCGIFHWADDR, &ifreq)) {
                perror("SIOCGIFHWADDR");
                exit(1);
            }

            if (!isInterfaceOnline(ipSock.fdSock, ifa->ifa_name)) {
                continue;
            }

            fprintf(stdout, "%s\t%s\t%02x-%02x-%02x-%02x-%02x-%02x\n", ifa->ifa_name, addressBuffer,
                    (unsigned char)(ifreq.ifr_hwaddr.sa_data[0]),
                    (unsigned char)(ifreq.ifr_hwaddr.sa_data[1]),
                    (unsigned char)(ifreq.ifr_hwaddr.sa_data[2]),
                    (unsigned char)(ifreq.ifr_hwaddr.sa_data[3]),
                    (unsigned char)(ifreq.ifr_hwaddr.sa_data[4]),
                    (unsigned char)(ifreq.ifr_hwaddr.sa_data[5]));
        } else if (ifa->ifa_addr->sa_family == AF_INET6) { // check it is IP6
#ifdef IPV6
            // is a valid IP6 Address
            tmpAddrPtr=&((struct sockaddr_in6 *)ifa->ifa_addr)->sin6_addr;
            char addressBuffer[INET6_ADDRSTRLEN];
            inet_ntop(AF_INET6, tmpAddrPtr, addressBuffer, INET6_ADDRSTRLEN);
            printf("%s IP Address %s\n", ifa->ifa_name, addressBuffer);
#endif
        }
    }

    if (ifAddrStruct != NULL)
        freeifaddrs(ifAddrStruct);
}

int main(int argc, char* argv[]) {
    if (argc == 1) {
        usage();
        return 0;
    }

    if (argc == 2) {
        if (!memcmp("--help", argv[1], 6)) {
            usage();
            exit(0);
        } else if (!memcmp("-list", argv[1], 5)) {
            listInterfaces();
            exit(0);
        } else {
            fprintf(stdout, "Invalid parameter\n");
            usage();
            exit(1);
        }
    }

    char rti[16]{'\0'};
    unsigned char rtm[32]{'\0'};
    char rqi[16]{'\0'};
    unsigned char rqm[32]{'\0'};
    char iInterfaceName[96]{'\0'};
    int iInterval = 1;
    bool quite = false;

    for (int i = 1; i < argc; i++) {
        if (!memcmp("-rti", argv[i], 4) && i + 1 < argc && memcmp("-", argv[i+1], 1)) {
            if (strlen(argv[i + 1]) > 15) {
                fprintf(stdout, "Invalid reply to ip address, must be like 10.0.0.1\n");
                exit(1);
            }
            memccpy(rti, argv[++i], '\0', sizeof(rti));
        } else if (!memcmp("-rqi", argv[i], 4) && i + 1 < argc && memcmp("-", argv[i+1], 1)) {
            if (strlen(argv[i + 1]) > 15) {
                fprintf(stdout, "Invalid request ip address, must be like 10.0.0.1\n");
                exit(1);
            }
            memccpy(rqi, argv[++i], '\0', sizeof(rqi));
        } else if (!memcmp("-rqm", argv[i], 4) && i + 1 < argc && memcmp("-", argv[i+1], 1)) {
            if (strlen(argv[i + 1]) != 17) {
                fprintf(stdout, "Invalid mac address, must be like this 00:00:00:00:00:00 or 00-00-00-00-00-00\n");
                exit(1);
            }
            if (6 != sscanf(argv[i + 1], "%02x-%02x-%02x-%02x-%02x-%02x", &rqm[0], &rqm[1],
                            &rqm[2], &rqm[3], &rqm[4], &rqm[5])) {
                if (6 != sscanf(argv[i + 1], "%02x:%02x:%02x:%02x:%02x:%02x", &rqm[0],
                                &rqm[1], &rqm[2], &rqm[3], &rqm[4], &rqm[5])) {
                    fprintf(stdout, "Invalid mac address, must be like this 00:00:00:00:00:00 or 00-00-00-00-00-00\n");
                    exit(1);
                }
            }
            i++;
        } else if (!memcmp("-itval", argv[i], 6) && i + 1 < argc && memcmp("-", argv[i+1], 1)) {
            char * pEnd;
            iInterval = (int) strtol(argv[++i], &pEnd, 10);
        } else if (!memcmp("-i", argv[i], 2) && i + 1 < argc && memcmp("-", argv[i+1], 1)) {
            if (strlen(argv[i + 1]) > 95) {
                fprintf(stdout, "Interface name is too long, Valid large length is 95\n");
                exit(1);
            }
            memccpy(iInterfaceName, argv[++i], '\0', 100);
        } else if (!memcmp("-list", argv[i], 5)) {
            listInterfaces();
            exit(0);
        } else if (!memcmp("-q", argv[i], 2)) {
            quite = true;
        } else {
            usage();
            exit(1);
        }
    }

    if (isEmpty(rti, sizeof(rti)) || isEmpty(rqi, sizeof(rqi))) {
        fprintf(stdout, "-rti and -rqi both must not be empty\n");
        exit(-1);
    }


    //if unspecified interface, so find out the first available interface name
    if (isEmpty(iInterfaceName, sizeof(iInterfaceName))) {
        struct ifaddrs *addrs{NULL}, *tmp{NULL};
        getifaddrs(&addrs);
        tmp = addrs;
        while (tmp)
        {
            if (!tmp->ifa_addr || tmp->ifa_addr->sa_family != AF_INET) {
                tmp = tmp->ifa_next;
                continue;
            }
            void *tmpAddrPtr = &((struct sockaddr_in *)tmp->ifa_addr)->sin_addr;
            char addressBuffer[INET_ADDRSTRLEN]{'\0'};
            inet_ntop(AF_INET, tmpAddrPtr, addressBuffer, INET_ADDRSTRLEN);
            if (!memcmp(addressBuffer, "127.0.0.1", 9)) {
                tmp = tmp->ifa_next;
                continue;
            }

            memccpy(iInterfaceName, tmp->ifa_name, '\0', 100);
            tmp = tmp->ifa_next;
        }
        if (NULL != addrs) {
            freeifaddrs(addrs);
        }

        if (isEmpty(iInterfaceName, sizeof(iInterfaceName))) {
            fprintf(stdout, "No available interface\n");
            exit(1);
        }
    }

    struct ifreq ifreq;
    strcpy(ifreq.ifr_name, iInterfaceName);
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

    if (isEmpty(rqm, sizeof(rqm))) {
        for (int idx = 0; idx < HW_ADDR_LENGTH; idx++) {
            *(rqm + idx) = *(ifreq.ifr_hwaddr.sa_data + idx);
        }
    }

    char cmd[48]{'\0'};
    sprintf(cmd, "cat /proc/net/arp | grep '^%s\\s'", &rti);
    std::vector<std::string> outputLst = getCmdOutput(cmd);
    std::regex rgx("\\s+(\\w{2}\\:\\w{2}\\:\\w{2}\\:\\w{2}\\:\\w{2}\\:\\w{2})");
    std::smatch matches;
    for (int i = 0; i < outputLst.size(); i++) {
        std::string oneRow =  outputLst.at(i);
        if (!std::regex_search(oneRow, matches, rgx)) {
            continue;
        }

        if (2 == matches.size()) {
            sscanf(matches[1].str().c_str(), "%02x:%02x:%02x:%02x:%02x:%02x", &rtm[0], &rtm[1], &rtm[2], &rtm[3], &rtm[4], &rtm[5]);
        }
        break;
    }

    if (isEmpty(rtm, sizeof(rtm))) {
        //to do: get mac address through to send arp request and receive the response

        if (isEmpty(rtm, sizeof(rtm))) {
            fprintf(stdout, "Can not found %s mac address from arp cache, Please try to ping %s firstly\n", rti, rti);
            exit(1);
        }
    }

    unsigned char buf[sizeof(MACHeader)]{'\0'};
    {
        //construct arp response
        MACHeader &pMAC = (MACHeader&)buf;
        memcpy(pMAC.destMACAddr, rtm, sizeof(pMAC.destMACAddr));
        memcpy(pMAC.arpHeader.TargetMAC, rtm, sizeof(pMAC.arpHeader.TargetMAC));
        memcpy(pMAC.srcMACAddr, rqm, sizeof(pMAC.srcMACAddr));
        memcpy(pMAC.arpHeader.SenderMAC, rqm, sizeof(pMAC.arpHeader.SenderMAC));

        pMAC.upperType = htons(0x0806);
        pMAC.arpHeader.HWType = htons(0x0001);
        pMAC.arpHeader.ProcType = htons(0x0800);
        pMAC.arpHeader.HWSize = 6;
        pMAC.arpHeader.ProcSize = 4;
        pMAC.arpHeader.Opcode = htons(0x0002);
        in_addr_t tmp = inet_addr(rqi);
        memcpy(pMAC.arpHeader.SenderIP, (void*)(&tmp), sizeof(in_addr_t));
        tmp = inet_addr(rti);
        memcpy(pMAC.arpHeader.TargetIP, (void*)(&tmp), sizeof(in_addr_t));
    }

    for (;;){
        if (-1 == sendto(ipSock.fdSock, buf, sizeof(buf), 0, (struct sockaddr *)&sockAddr, sizeof(sockAddr))) {
            perror("Sending failure");
        }
        if (!quite) {
            fprintf(stdout, "%02x:%02x:%02x:%02x:%02x:%02x "
                            "%02x:%02x:%02x:%02x:%02x:%02x 0806 42: arp reply %s is-at "
                            "%02x:%02x:%02x:%02x:%02x:%02x\n", rqm[0], rqm[1], rqm[2], rqm[3], rqm[4], rqm[5],
                    rtm[0], rtm[1], rtm[2], rtm[3], rtm[4], rtm[5], rqi,
                    rqm[0], rqm[1], rqm[2], rqm[3], rqm[4], rqm[5]);
        }
        sleep(iInterval);
    }

    return 0;
}
