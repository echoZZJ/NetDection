//
//  traceroute_query.c
//  sdt
//
//  Created by didi on 2020/2/18.
//

#include "traceroute_query.h"
#include <stdio.h>
#include <math.h>
#include <stdlib.h>
#include <errno.h>
#include <unistd.h>
#include <limits.h>
#include <fcntl.h>
#include <string.h>

#include "mars/comm/xlogger/xlogger.h"
#include "mars/comm/network/getgateway.h"
#include "mars/comm/socket/socketselect.h"
#include "mars/comm/socket/socket_address.h"
#include "mars/sdt/constants.h"
using namespace mars::sdt;
#define TRAFFIC_LIMIT_RET_CODE (INT_MIN)


#ifdef ANDROID
#include <linux/types.h>
#include <linux/errqueue.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <stdarg.h>
#define MAXLINE (512) /* max text line length
*/
#ifndef IP_PMTUDISC_PROBE
#define IP_PMTUDISC_PROBE    3

#endif

#define MAX_HOPS_LIMIT        255
#define MAX_HOPS_DEFAULT    30

struct hhistory
{
    int    hops;
    struct timeval sendtime;
};

struct hhistory his[64];
int hisptr;

struct sockaddr_in target;
__u16 base_port;
int max_hops = MAX_HOPS_DEFAULT;

const int overhead = 28;
int mtu = 65535;
void *pktbuf;
int hops_to = -1;
int hops_from = -1;
int no_resolve = 0;
int show_both = 0;

#define HOST_COLUMN_SIZE    24

struct probehdr
{
    __u32 ttl;
    struct timeval tv;
};

int TraceRouteQuery::t_printf(const char *fmt, ...){
    va_list argptr;
    int cnt;
    va_start(argptr, fmt);
    char tempbuff[1024] = {0};
    snprintf(tempbuff, 1024, fmt, argptr);
    tracerouteresult_.append(tempbuff);
    return 1;
}

/**
 * 给套接口设置timeout市场，等待返回；
 */
void data_wait(int fd)
{
    fd_set fds;
    struct timeval tv;
    FD_ZERO(&fds);
    FD_SET(fd, &fds);
    tv.tv_sec = 1;
    tv.tv_usec = 0;
    select(fd+1, &fds, NULL, NULL, &tv);
}


/**
 * 打印host地址
 */
void TraceRouteQuery::print_host(const char *a, const char *b, int both)
{
    int plen;
    plen = t_printf("%s", a);
    if (both)
        plen += printf(" (%s)", b);
    if (plen >= HOST_COLUMN_SIZE)
        plen = HOST_COLUMN_SIZE - 1;
    t_printf("%*s", HOST_COLUMN_SIZE - plen, "");
}

/**
 * 处理错误信息，当发生错误，时间片还未用完的时候，继续ping；
 */
int TraceRouteQuery::recverr(int fd, int ttl)
{
    int res;
    struct probehdr rcvbuf;
    char cbuf[512];
    struct iovec  iov;
    struct msghdr msg;
    struct cmsghdr *cmsg;
    struct sock_extended_err *e;
    struct sockaddr_in addr;
    struct timeval tv;
    struct timeval *rettv;
    int slot;
    int rethops;
    int sndhops;
    int progress = -1;
    int broken_router;

restart:
    memset(&rcvbuf, -1, sizeof(rcvbuf));
    iov.iov_base = &rcvbuf;
    iov.iov_len = sizeof(rcvbuf);
    msg.msg_name = (__u8*)&addr;
    msg.msg_namelen = sizeof(addr);
    msg.msg_iov = &iov;
    msg.msg_iovlen = 1;
    msg.msg_flags = 0;
    msg.msg_control = cbuf;
    msg.msg_controllen = sizeof(cbuf);

    gettimeofday(&tv, NULL);
    res = recvmsg(fd, &msg, MSG_ERRQUEUE);
    if (res < 0) {
        if (errno == EAGAIN)
            return progress;
        goto restart;
    }

    progress = mtu;

    rethops = -1;
    sndhops = -1;
    e = NULL;
    rettv = NULL;
    slot = ntohs(addr.sin_port) - base_port;
    if (slot>=0 && slot < 63 && his[slot].hops) {
        sndhops = his[slot].hops;
        rettv = &his[slot].sendtime;
        his[slot].hops = 0;
    }
    broken_router = 0;
    if (res == sizeof(rcvbuf)) {
        if (rcvbuf.ttl == 0 || rcvbuf.tv.tv_sec == 0) {
            broken_router = 1;
        } else {
            sndhops = rcvbuf.ttl;
            rettv = &rcvbuf.tv;
        }
    }

    for (cmsg = CMSG_FIRSTHDR(&msg); cmsg; cmsg = CMSG_NXTHDR(&msg, cmsg)) {
        if (cmsg->cmsg_level == SOL_IP) {
            if (cmsg->cmsg_type == IP_RECVERR) {
                e = (struct sock_extended_err *) CMSG_DATA(cmsg);
            } else if (cmsg->cmsg_type == IP_TTL) {
                memcpy(&rethops, CMSG_DATA(cmsg), sizeof(rethops));
            } else {
                t_printf("cmsg:%d\n ", cmsg->cmsg_type);
            }
        }
    }
    if (e == NULL) {
        t_printf("no info\n");
        return 0;
    }
    if (e->ee_origin == SO_EE_ORIGIN_LOCAL) {
        t_printf("%2d?: %*s ", ttl, -(HOST_COLUMN_SIZE - 1), "[LOCALHOST]");
    } else if (e->ee_origin == SO_EE_ORIGIN_ICMP) {
        char abuf[128];
        struct sockaddr_in *sin = (struct sockaddr_in*)(e+1);
        struct hostent *h = NULL;
        char *idn = NULL;

        inet_ntop(AF_INET, &sin->sin_addr, abuf, sizeof(abuf));

        if (sndhops>0)
            t_printf("%2d:  ", sndhops);
        else
            t_printf("%2d?: ", ttl);

        if (!no_resolve || show_both) {
            fflush(stdout);
            h = gethostbyaddr((char *) &sin->sin_addr, sizeof(sin->sin_addr), AF_INET);
        }

#ifdef USE_IDN
        if (h && idna_to_unicode_lzlz(h->h_name, &idn, 0) != IDNA_SUCCESS)
            idn = NULL;
#endif
        if (no_resolve)
            print_host(abuf, h ? (idn ? idn : h->h_name) : abuf, show_both);
        else
            print_host(h ? (idn ? idn : h->h_name) : abuf, abuf, show_both);

#ifdef USE_IDN
        free(idn);
#endif
    }

    if (rettv) {
        int diff = (tv.tv_sec-rettv->tv_sec)*1000000+(tv.tv_usec-rettv->tv_usec);
        t_printf("%3d.%03dms ", diff/1000, diff%1000);
        if (broken_router)
            t_printf("(This broken router returned corrupted payload) ");
    }

    switch (e->ee_errno) {
    case ETIMEDOUT:
        
        t_printf("\n");
        break;
    case EMSGSIZE:
        t_printf("pmtu %d\n", e->ee_info);
        mtu = e->ee_info;
        progress = mtu;
        break;
    case ECONNREFUSED:
        t_printf("reached\n");
        hops_to = sndhops<0 ? ttl : sndhops;
        hops_from = rethops;
        return 0;
    case EPROTO:
        t_printf("!P\n");
        return 0;
    case EHOSTUNREACH:
        if (e->ee_origin == SO_EE_ORIGIN_ICMP &&
            e->ee_type == 11 &&
            e->ee_code == 0) {
            if (rethops>=0) {
                if (rethops<=64)
                    rethops = 65-rethops;
                else if (rethops<=128)
                    rethops = 129-rethops;
                else
                    rethops = 256-rethops;
                /*
                if (sndhops>=0 && rethops != sndhops)
                    printf("asymm %2d ", rethops);
                else if (sndhops<0 && rethops != ttl)
                    printf("asymm %2d ", rethops);
                    */
            }
            t_printf("\n");
            break;
        }
        t_printf("!H\n");
        return 0;
    case ENETUNREACH:
        t_printf("!N\n");
        return 0;
    case EACCES:
        t_printf("!A\n");
        return 0;
    default:
        t_printf("\n");
        errno = e->ee_errno;
        perror("NET ERROR");
        return 0;
    }
    goto restart;
}

/**
 * 发送ICMP报文经历指定跳数
 */
int TraceRouteQuery::probe_ttl(int fd, int ttl)
{
    xinfo2(TSF"probe_ttl begin");
    int i;
    struct probehdr *hdr;
    struct probehdr t_hdr = {0};
    memset(&t_hdr, 0, mtu);
    hdr = (struct probehdr *)&t_hdr;
//    memset(hdr, 0, mtu);
restart:
    //尝试在发送不成功的情况下连续发送10次
    xinfo2(TSF"probe_ttl restart begin");
    for (i=0; i<2; i++) {
        xinfo2(TSF"probe_ttl loop begin");
        int res;
        hdr->ttl = ttl;
        target.sin_port = htons(base_port + hisptr);
        gettimeofday(&hdr->tv, NULL);
        his[hisptr].hops = ttl;
        his[hisptr].sendtime = hdr->tv;
        if (sendto(fd, pktbuf, mtu-overhead, 0, (struct sockaddr*)&target, sizeof(target)) > 0){
            xinfo2(TSF"sendto fd:%_,target:%_",fd,target.sin_port);
            break;
        }
        res = recverr(fd, ttl);
        his[hisptr].hops = 0;
        if (res==0){
            xinfo2(TSF"recverr ret is 0");
            return 0;
        }
        if (res > 0)
            goto restart;
    }
    hisptr = (hisptr + 1)&63;

    if (i<2) {
        data_wait(fd);
        if (recv(fd, pktbuf, mtu, MSG_DONTWAIT) > 0) {
            t_printf("%2d?: reply received 8)\n", ttl);
            return 0;
        }
        return recverr(fd, ttl);
    }

    t_printf("%2d:  send failed\n", ttl);
    return 0;
}


int TraceRouteQuery::doATracePath(int argc, char **argv)
{
    struct hostent *he;
    int fd;
    int on;
    int ttl;
    char *p;
    int ch;
#ifdef USE_IDN
    int rc;
    setlocale(LC_ALL, "");
#endif
    //解析命令参数
    xinfo2(TSF"doATracePath begin");
    while ((ch = getopt(argc, argv, "nbh?l:m:p:")) != EOF) {
        switch(ch) {
        case 'n':
            no_resolve = 1;
            break;
        case 'b':
            show_both = 1;
            break;
        case 'l':
            if ((mtu = atoi(optarg)) <= overhead) {
                xerror2(TSF"Error: pktlen must be > %0 and <= %0.\n",overhead, INT_MAX);
                t_printf("Error: pktlen must be > %d and <= %d.\n",overhead, INT_MAX);
                return -1;
            }
            break;
        case 'm':
            max_hops = atoi(optarg);
            if (max_hops < 0 || max_hops > MAX_HOPS_LIMIT) {
                xerror2(TSF"Error: max hops must be 0 .. %0 (inclusive).\n",
                        MAX_HOPS_LIMIT);
                t_printf(
                "Error: max hops must be 0 .. %d (inclusive).\n",
                MAX_HOPS_LIMIT);
            }
            break;
        case 'p':
            base_port = atoi(optarg);
            break;
        default:
            xinfo2(TSF"Usage: tracepath [-n] [-b] [-l <len>] [-p port] <destination>\n");
            t_printf("Usage: tracepath [-n] [-b] [-l <len>] [-p port] <destination>\n");
            return -1;
            break;
        }
    }

    //去掉所有的约束参数
    argc -= optind;
    argv += optind;
    if (argc != 1){
        xinfo2(TSF"argc != 1");
        t_printf("Usage: tracepath [-n] [-b] [-l <len>] [-p port] <destination>\n");
        return -1;
    }

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        xerror2(TSF"\n socket: cant create socket detail:%_.\n",strerror(errno));
        t_printf("\n socket: cant create socket detail:%s.\n",strerror(errno));
        return -1;
    }
    target.sin_family = AF_INET;
    //获取制定的端口号
    /* Backward compatiblity */
    if (!base_port) {
        p = strchr(argv[0], '/');
        if (p) {
            *p = 0;
            base_port = atoi(p+1);
        } else
            base_port = 44444;
    }

    p = argv[0];
#ifdef USE_IDN
    rc = idna_to_ascii_lz(argv[0], &p, 0);
    if (rc != IDNA_SUCCESS) {
        xerror2(TSF"\nIDNA encoding failed: %_\n", idna_strerror(rc));
        t_printf("\nIDNA encoding failed: %s\n", idna_strerror(rc));
        return -2;
    }
#endif

    he = gethostbyname(p);
    if (he == NULL) {
        xerror2(TSF"\ngethostbyname: cant get host from hostname");
        t_printf("\ngethostbyname: cant get host from hostname");
        return -1;
    }
    xinfo2(TSF"host is %_",he->h_addr);
#ifdef USE_IDN
    free(p);
#endif

    memcpy(&target.sin_addr, he->h_addr, 4);

    on = IP_PMTUDISC_PROBE;
    if (setsockopt(fd, SOL_IP, IP_MTU_DISCOVER, &on, sizeof(on)) &&
        (on = IP_PMTUDISC_DO,
         setsockopt(fd, SOL_IP, IP_MTU_DISCOVER, &on, sizeof(on)))) {
        xerror2(TSF"\nIP_MTU_DISCOVER error detail:%_",strerror(errno));
        t_printf("\nIP_MTU_DISCOVER error detail:%s",strerror(errno));
        return -1;
    }
    on = 1;
    if (setsockopt(fd, SOL_IP, IP_RECVERR, &on, sizeof(on))) {
        xerror2(TSF"\nIP_RECVERR error detail:%_",strerror(errno));
        t_printf("\nIP_RECVERR error detail:%s",strerror(errno));
        return -1;
    }
    if (setsockopt(fd, SOL_IP, IP_RECVTTL, &on, sizeof(on))) {
        xerror2(TSF"\nIP_RECVERR IP_RECVTTL error  detail:%_",strerror(errno));
        t_printf("\nIP_RECVERR IP_RECVTTL error  detail:%s",strerror(errno));
        return -1;
    }

    pktbuf = malloc(mtu);
    if (!pktbuf) {
        xerror2(TSF"\nmalloc pktbuf error");
        t_printf("\nmalloc pktbuf error");
        return -1;
    }

    //连续发送max_hops去traceroute
    int timeoutTTL = 0;
    xinfo2(TSF"ttl loop begin");
    for (ttl = 1; ttl <= max_hops; ttl++) {
        int res;
        int i;

        on = ttl;
        if (setsockopt(fd, SOL_IP, IP_TTL, &on, sizeof(on))) {
            xerror2(TSF"\nIP_TTL error  detail:%_",strerror(errno));
            t_printf("\nIP_TTL error  detail:%s",strerror(errno));
            return -1;
        }

restart:
        //每一条尝试三次发送
        xinfo2(TSF"restart begin");
        for (i=0; i<1; i++) {
            int old_mtu;

            old_mtu = mtu;
            res = probe_ttl(fd, ttl);
            if (mtu != old_mtu)
                goto restart;
            if (res == 0)
                goto done;
            if (res > 0){
                timeoutTTL = 0;
                break;
            }
        }

        if (res < 0){
            if(timeoutTTL >= 3){
                return 0;
            }else {
                timeoutTTL++;
                printf("%2d:  **********", ttl);
            }
        }
    }
    printf("     Too many hops: pmtu %d\n", mtu);
done:
    xinfo2(TSF"Resume: pmtu %_ \n",mtu);
    printf("     Resume: pmtu %d \n", mtu);
    if (hops_to>=0)
        printf("hops %d ", hops_to);
    if (hops_from>=0)
        printf("back %d ", hops_from);
    return 0;
}


int TraceRouteQuery::t_RunTraceRouteQuery(int _querycount, int _interval/*S*/, int _timeout/*S*/, const char* _dest, unsigned int _packet_size){
    std::string action = "tracepath";
    char* argv[]={(char *)action.c_str(), (char *)_dest};
    return  doATracePath(2, argv);
}
std::string TraceRouteQuery::GetTraceRoute() {
    return tracerouteresult_;
}


#elif defined __APPLE__

// APPLE
#include    <netinet/ip.h>
#include    <sys/time.h>
#include    <sys/un.h>
#include    <arpa/inet.h>
#include    <signal.h>
#include    <netinet/in_systm.h>
#include    <netinet/ip.h>
#include    <sys/types.h>
#include    <time.h>
#include    <sys/socket.h>
#include    <netdb.h>


#include <TargetConditionals.h>
#if TARGET_OS_IPHONE
#include    "mars/comm/objc/ip_icmp.h"
#else
#include    <netinet/ip_icmp.h>
#endif

#include "mars/comm/time_utils.h"  // comm/utils.h
#define MAXBUFSIZE      4096
#define UDPPORT         30001
#define MAXATTEMP       3
#define MAXTRTTL        20
int TraceRouteQuery::t_RunTraceRouteQuery(int _querycount, int _interval/*S*/, int _timeout/*S*/, const char* _dest, unsigned int _packet_size) {
    std::string destination = std::string(_dest);
    bool isIPV6 = false;
    struct sockaddr *target;
    if (destination.find(":") == std::string::npos) {
        struct sockaddr_in nativeAddr4;
        memset(&nativeAddr4, 0, sizeof(nativeAddr4));
        nativeAddr4.sin_len = sizeof(nativeAddr4);
        nativeAddr4.sin_family = AF_INET;
        nativeAddr4.sin_port = htons(UDPPORT);
        nativeAddr4.sin_addr.s_addr = htonl(INADDR_ANY);
        inet_pton(AF_INET, destination.c_str(), &nativeAddr4.sin_addr.s_addr);
        target = (struct sockaddr*)&nativeAddr4;
    }else {
        isIPV6 = true;
        struct sockaddr_in6 nativeAddr6;
        memset(&nativeAddr6, 0, sizeof(nativeAddr6));
        nativeAddr6.sin6_len = sizeof(nativeAddr6);
        nativeAddr6.sin6_family = AF_INET6;
        nativeAddr6.sin6_port = htons(UDPPORT);
        inet_pton(AF_INET6, destination.c_str(), &nativeAddr6.sin6_addr);
        target = (struct sockaddr*)&nativeAddr6;
    }
    //初始化套接口
       struct sockaddr fromAddr;
       int recv_sock;
       int send_sock;
       int ret = 0;
       //创建一个支持ICMP协议的UDP网络套接口（用于接收）
       if ((recv_sock = socket(target->sa_family, SOCK_DGRAM, isIPV6?IPPROTO_ICMPV6:IPPROTO_ICMP)) < 0) {
           char temp[1024] = {0};
           xerror2(TSF"\nerror: recv_sock socket create failed with :%_.\n",strerror(errno));
           snprintf(temp, 1024, "\nerror: recv_sock socket create failed with :%s.\n",strerror(errno));
           tracerouteresult_.append(std::string(temp));
           return -1;
       }
       //创建一个UDP套接口（用于发送）
       if ((send_sock = socket(target->sa_family, SOCK_DGRAM, 0)) < 0) {
           char temp[1024] = {0};
           xerror2(TSF"\nerror: send_sock socket create failed with :%_.\n",strerror(errno));
           snprintf(temp, 1024, "\nerror: send_sock socket create failed with :%s.\n",strerror(errno));
           tracerouteresult_.append(std::string(temp));
           return -1;
       }
    
        const char *cmsg = std::string("GET / HTTP/1.1\r\n\r\n").c_str();
        socklen_t n = sizeof(fromAddr);
        char buf[100];

        int ttl = 1;  // index sur le TTL en cours de traitement.
        int timeoutTTL = 0;
        bool icmp = false;  // Positionné à true lorsqu'on reçoit la trame ICMP en retour.
        long startTime;     // Timestamp lors de l'émission du GET HTTP
    
        while (ttl <= MAXTRTTL) {
            xinfo2(TSF"TraceRoute Check with ttl:%_",ttl);
            startTime = gettickcount();
            memset(&fromAddr, 0, sizeof(fromAddr));
            //设置sender 套接字的ttl
            if ((isIPV6? setsockopt(send_sock,IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl)):setsockopt(send_sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl))) < 0) {
                char temp[1024] = {0};
                snprintf(temp, 1024, "\nerror: sender socket setsockopt failed with :%s.\n",strerror(errno));
                xerror2(TSF"\nerror: sender socket setsockopt failed with :%_.\n",strerror(errno));
                tracerouteresult_.append(std::string(temp));
                ret = -1;
            }
            //每一步连续发送maxAttenpts报文
            icmp = false;
            std::string traceLog = "";
            std::string hostaddress = "***";
            
            for (int t_try = 0; t_try < MAXATTEMP; t_try ++) {
                xinfo2(TSF"TraceRoute Check with ttl :%_ with attemp :%_",ttl,t_try);
                long t_starttime = gettickcount();
                //发送成功返回值等于发送消息的长度
                ssize_t sentLen = sendto(send_sock, cmsg, sizeof(cmsg), 0, target, isIPV6?sizeof(struct sockaddr_in6):sizeof(struct sockaddr_in));
                if (sentLen == -1) {
                    xerror2(TSF"send sock is faild with detail:%_, isIPV6 %_",strerror(errno),isIPV6);
                    break;
                }
                if (sentLen != sizeof(cmsg)) {
                    ret = -1;
                    xerror2(TSF"sentLen != sizeof(cmsg)!! sentLen is:%_; cmsg size is:%_",sentLen,sizeof(cmsg));
                    break;
                }

                long res = 0;
                //从（已连接）套接口上接收数据，并捕获数据发送源的地址。
                if (-1 == fcntl(recv_sock, F_SETFL, O_NONBLOCK)) {
                    char temp[1024] = {0};
                    xerror2(TSF"\nerror: fcntl recv_sock failed with :%_.\n",strerror(errno));
                    snprintf(temp, 1024, "\nerror: fcntl recv_sock failed with :%s.\n",strerror(errno));
                    traceLog.append(std::string(temp));
                    return -1;
                }
                /* set recvfrom from server timeout */
                struct timeval tv;
                fd_set readfds;
                tv.tv_sec = 1;
                tv.tv_usec = 0;  //设置了1s的延迟
                FD_ZERO(&readfds);
                FD_SET(recv_sock, &readfds);
                select(recv_sock + 1, &readfds, NULL, NULL, &tv);
                if (FD_ISSET(recv_sock, &readfds) > 0) {
                    timeoutTTL = 0;
                    if ((res = recvfrom(recv_sock, buf, 100, 0, (struct sockaddr *)&fromAddr, &n)) <
                        0) {
                        ret = -1;
                         char temp[1024] = {0};
                        xerror2(TSF"\nerror: recv from error detail:%_.\n",strerror(errno));
                        snprintf(temp, 1024, "\nerror: recv from error detail:%s.\n",strerror(errno));
                        traceLog.append(std::string(temp));
                    } else {
                        icmp = true;
                        uint64_t cost_time = (uint64_t)(gettickcount() - t_starttime);
                        //将“二进制整数” －> “点分十进制，获取hostAddress和hostName
                        if (fromAddr.sa_family == AF_INET) {
                            char display[INET_ADDRSTRLEN] = {0};
                            inet_ntop(AF_INET, &((struct sockaddr_in *)&fromAddr)->sin_addr.s_addr, display, sizeof(display));
                            hostaddress = std::string(display);
                            xinfo2(TSF"TraceRoute Check with v4: hostaddress is :%_ ", hostaddress);
                        }
                        
                        else if (fromAddr.sa_family == AF_INET6) {
                            char ip[INET6_ADDRSTRLEN];
                            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&fromAddr)->sin6_addr, ip, INET6_ADDRSTRLEN);
                            hostaddress = std::string(ip);
                            xinfo2(TSF"TraceRoute Check with v6: hostaddress is :%_ ", hostaddress);
                        }
                        
                        if (t_try == 0) {
                            char temp[1024] = {0};
                            snprintf(temp, 1024, "\n host:%s.\t\t",hostaddress.c_str());
                            traceLog.append(std::string(temp));
                        }
                        char temp[1024] = {0};
                        snprintf(temp, 1024, "%llums.\t",cost_time);
                        traceLog.append(std::string(temp));
                    }
                } else {
                    timeoutTTL++;
                    char temp[1024] = {0};
                    snprintf(temp, 1024, "\nerror: ttl timeout ;FD_Set < 0 with:%s.\n",strerror(errno));
                    xerror2(TSF"TraceRoute Check with detail:%_",strerror(errno));
                    traceLog.append(std::string(temp));
                    break;
            }
            
        }
        //输出报文,如果三次都无法监控接收到报文，跳转结束
        if (icmp) {
            tracerouteresult_.append(traceLog);
        } else {
            //如果连续三次接收不到icmp回显报文
            if (timeoutTTL >= 4) {
                break;
            } else {
                char temp[1024] = {0};
                snprintf(temp, 1024, "\n %d\t********\t.\n",ttl);
                tracerouteresult_.append(std::string(temp));
            }
        }
        if (hostaddress == destination) {
            char temp[1024] = {0};
            uint64_t total_cost = (uint64_t)(gettickcount() - startTime);
            snprintf(temp, 1024, "\n\t tracefinished with total cost:%llu.\t",total_cost);
            tracerouteresult_.append(std::string(temp));
            break;
        }
        ttl++;
    }
    xinfo2(TSF"TraceRoute end");
    char temp[1024] = {0};
    snprintf(temp, 1024, "\n traceEnded .\n");
    tracerouteresult_.append(std::string(temp));
    return ret;
    
}
//int TraceRouteQuery::RunTraceRouteQuery(int _querycount, int _interval/*S*/, int _timeout/*S*/, const char* _dest, unsigned int _packet_size) {}
std::string TraceRouteQuery::GetTraceRoute() {
    return tracerouteresult_;
}
#endif
