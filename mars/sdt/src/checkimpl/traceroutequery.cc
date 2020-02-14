//
//  traceroutequery.c
//  sdt
//
//  Created by didi on 2020/2/13.
//

#include "traceroutequery.h"

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

#ifdef ANDROID

#include <linux/types.h>
#include <linux/errqueue.h>
#include <sys/socket.h>
#include <sys/time.h>
#include <sys/uio.h>
#include <stdarg.h>
#endif

using namespace mars::sdt;
#define TRAFFIC_LIMIT_RET_CODE (INT_MIN)


#ifdef ANDROID
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
void print_host(const char *a, const char *b, int both)
{
    int plen;
    plen = printf("%s", a);
    if (both)
        plen += printf(" (%s)", b);
    if (plen >= HOST_COLUMN_SIZE)
        plen = HOST_COLUMN_SIZE - 1;
    printf("%*s", HOST_COLUMN_SIZE - plen, "");
}

/**
 * 处理错误信息，当发生错误，时间片还未用完的时候，继续ping；
 */
int recverr(int fd, int ttl)
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
                printf("cmsg:%d\n ", cmsg->cmsg_type);
            }
        }
    }
    if (e == NULL) {
        printf("no info\n");
        return 0;
    }
    if (e->ee_origin == SO_EE_ORIGIN_LOCAL) {
        printf("%2d?: %*s ", ttl, -(HOST_COLUMN_SIZE - 1), "[LOCALHOST]");
    } else if (e->ee_origin == SO_EE_ORIGIN_ICMP) {
        char abuf[128];
        struct sockaddr_in *sin = (struct sockaddr_in*)(e+1);
        struct hostent *h = NULL;
        char *idn = NULL;

        inet_ntop(AF_INET, &sin->sin_addr, abuf, sizeof(abuf));

        if (sndhops>0)
            printf("%2d:  ", sndhops);
        else
            printf("%2d?: ", ttl);

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
        printf("%3d.%03dms ", diff/1000, diff%1000);
        if (broken_router)
            printf("(This broken router returned corrupted payload) ");
    }

    switch (e->ee_errno) {
    case ETIMEDOUT:
        printf("\n");
        break;
    case EMSGSIZE:
        printf("pmtu %d\n", e->ee_info);
        mtu = e->ee_info;
        progress = mtu;
        break;
    case ECONNREFUSED:
        printf("reached\n");
        hops_to = sndhops<0 ? ttl : sndhops;
        hops_from = rethops;
        return 0;
    case EPROTO:
        printf("!P\n");
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
            printf("\n");
            break;
        }
        printf("!H\n");
        return 0;
    case ENETUNREACH:
        printf("!N\n");
        return 0;
    case EACCES:
        printf("!A\n");
        return 0;
    default:
        printf("\n");
        errno = e->ee_errno;
        perror("NET ERROR");
        return 0;
    }
    goto restart;
}

/**
 * 发送ICMP报文经历指定跳数
 */
int probe_ttl(int fd, int ttl)
{
    int i;
    struct probehdr t_hdr;
    memset(&t_hdr, 0, mtu);
    struct probehdr *hdr = &t_hdr;
restart:
    //尝试在发送不成功的情况下连续发送10次
    for (i=0; i<2; i++) {
        int res;

        hdr->ttl = ttl;
        target.sin_port = htons(base_port + hisptr);
        gettimeofday(&hdr->tv, NULL);
        his[hisptr].hops = ttl;
        his[hisptr].sendtime = hdr->tv;
        if (sendto(fd, pktbuf, mtu-overhead, 0, (struct sockaddr*)&target, sizeof(target)) > 0)
            break;
        res = recverr(fd, ttl);
        his[hisptr].hops = 0;
        if (res==0)
            return 0;
        if (res > 0)
            goto restart;
    }
    hisptr = (hisptr + 1)&63;

    if (i<2) {
        data_wait(fd);
        if (recv(fd, pktbuf, mtu, MSG_DONTWAIT) > 0) {
            printf("%2d?: reply received 8)\n", ttl);
            return 0;
        }
        return recverr(fd, ttl);
    }

    printf("%2d:  send failed\n", ttl);
    return 0;
}

static int usage(void);

static int usage(void)
{
    printf("Usage: tracepath [-n] [-b] [-l <len>] [-p port] <destination>\n");
    return -1;
}


int doATracePath(int argc, char **argv)
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
                printf("Error: pktlen must be > %d and <= %d.\n",
                    overhead, INT_MAX);
                return -1;
            }
            break;
        case 'm':
            max_hops = atoi(optarg);
            if (max_hops < 0 || max_hops > MAX_HOPS_LIMIT) {
                printf(
                    "Error: max hops must be 0 .. %d (inclusive).\n",
                    MAX_HOPS_LIMIT);
            }
            break;
        case 'p':
            base_port = atoi(optarg);
            break;
        default:
            return usage();
            break;
        }
    }

    //去掉所有的约束参数
    argc -= optind;
    argv += optind;


    if (argc != 1)
        return usage();

    fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd < 0) {
        printf("socket: cant create socket");
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
        printf("IDNA encoding failed: %s\n", idna_strerror(rc));
        return -2;
    }
#endif

    he = gethostbyname(p);
    if (he == NULL) {
        printf("gethostbyname: cant get host from hostname");
        return -1;
    }

#ifdef USE_IDN
    free(p);
#endif

    memcpy(&target.sin_addr, he->h_addr, 4);

    on = IP_PMTUDISC_PROBE;
    if (setsockopt(fd, SOL_IP, IP_MTU_DISCOVER, &on, sizeof(on)) &&
        (on = IP_PMTUDISC_DO,
         setsockopt(fd, SOL_IP, IP_MTU_DISCOVER, &on, sizeof(on)))) {
        printf("IP_MTU_DISCOVER error");
        return -1;
    }
    on = 1;
    if (setsockopt(fd, SOL_IP, IP_RECVERR, &on, sizeof(on))) {
        printf("IP_RECVERR error");
        return -1;
    }
    if (setsockopt(fd, SOL_IP, IP_RECVTTL, &on, sizeof(on))) {
        printf("IP_RECVTTL error");
        return -1;
    }

    pktbuf = malloc(mtu);
    if (!pktbuf) {
        printf("malloc pktbuf error");
        return -1;
    }

    //连续发送max_hops去traceroute
    int timeoutTTL = 0;
    for (ttl = 1; ttl <= max_hops; ttl++) {
        int res;
        int i;

        on = ttl;
        if (setsockopt(fd, SOL_IP, IP_TTL, &on, sizeof(on))) {
            printf("IP_TTL error");
            return -1;
        }

restart:
        //每一条尝试三次发送
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
    printf("     Resume: pmtu %d ", mtu);
    if (hops_to>=0)
        printf("hops %d ", hops_to);
    if (hops_from>=0)
        printf("back %d ", hops_from);
    printf("\n");

    return 0;
}

int TraceRouteQuery::t_RunTraceRouteQuery(int _querycount, int _interval/*S*/, int _timeout/*S*/, const char* _dest, unsigned int _packet_size){
    std::string action = "tracepath";
    char* argv[]={(char *)action.c_str(), (char *)_dest};
    doATracePath(2, argv);
    return 1;
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
#define MAXATTEMP       4

//static int DATALEN = 56;        /* data that goes with ICMP echo request */
//static const int IP_HEADER_LEN = 20;
//static const int ICMP_HEADER_LEN = 8;
//
//static char* sock_ntop_host(const struct sockaddr* sa, socklen_t salen) {
//    static char str[128];   /* Unix domain is largest */
//
//    switch (sa->sa_family) {
//    case AF_INET: {
//        struct sockaddr_in* sin = (struct sockaddr_in*)sa;
//
//        if (socket_inet_ntop(AF_INET, &sin->sin_addr, str, sizeof(str))
//                == NULL)
//            return (NULL);
//
//        return (str);
//    }
//
//#ifdef  IPV6
//
//    case AF_INET6: {
//        struct sockaddr_in6* sin6 = (struct sockaddr_in6*)sa;
//
//        if (inet_ntop
//                (AF_INET6, &sin6->sin6_addr, str,
//                 sizeof(str)) == NULL)
//            return (NULL);
//
//        return (str);
//    }
//
//#endif
//
//
//
//#ifdef  AF_UNIX
//
//    case AF_UNIX: {
//        struct sockaddr_un* unp = (struct sockaddr_un*)sa;
//
//        /* OK to have no pathname bound to the socket: happens on
//           every connect() unless client calls bind() first. */
//        if (unp->sun_path[0] == 0)
//            strcpy(str, "(no pathname bound)");
//        else
//            snprintf(str, sizeof(str), "%s", unp->sun_path);
//
//        return (str);
//    }
//
//#endif
//
//
//
//#ifdef  HAVE_SOCKADDR_DL_STRUCT
//
//    case AF_LINK: {
//        struct sockaddr_dl* sdl = (struct sockaddr_dl*)sa;
//
//        if (sdl->sdl_nlen > 0)
//            snprintf(str, sizeof(str), "%*s",
//                     sdl->sdl_nlen, &sdl->sdl_data[0]);
//        else
//            snprintf(str, sizeof(str), "AF_LINK, index=%d",
//                     sdl->sdl_index);
//
//        return (str);
//    }
//
//#endif
//
//    default:
//        snprintf(str, sizeof(str),
//                 "sock_ntop_host: unknown AF_xxx: %d, len %d",
//                 sa->sa_family, salen);
//        return (str);
//    }
//
//    return (NULL);
//}
//
//static char* Sock_ntop_host(const struct sockaddr* sa, socklen_t salen) {
//    char* ptr;
//
//    if ((ptr = sock_ntop_host(sa, salen)) == NULL) {
//        xerror2(TSF"sock_ntop_host error,errno=%0", errno); /* inet_ntop() sets errno */
//    }
//
//    return (ptr);
//}
//
//static void Gettimeofday(struct timeval* tv, void* foo) {
//    if (gettimeofday(tv, (struct timezone*)foo) == -1) {
//        xerror2(TSF"gettimeofday error");
//    }
//
//    return;
//}
//static int Sendto(int fd, const void* ptr, size_t nbytes, int flags, const struct sockaddr* sa, socklen_t salen) {
//    xdebug_function();
//    int len = 0;
//
//    if ((len = (int)sendto(fd, ptr, nbytes, flags, sa, salen)) != (ssize_t) nbytes) {
//        xerror2(TSF"sendto: uncomplete packet, len:%_, nbytes:%_, errno:%_(%_)", len, nbytes, socket_errno, strerror(socket_errno));
//    }
//
//    return len;
//}
//static struct addrinfo* Host_serv(const char* host, const char* serv, int family, int socktype) {
//    int n;
//    struct addrinfo hints, *res;
//    bzero(&hints, sizeof(struct addrinfo));
//    hints.ai_flags = AI_CANONNAME;  /* always return canonical name */
//    hints.ai_family = family;   /* 0, AF_INET, AF_INET6, etc. */
//    hints.ai_socktype = socktype;   /* 0, SOCK_STREAM, SOCK_DGRAM, etc. */
//
//    if ((n = getaddrinfo(host, serv, &hints, &res)) != 0) {
//        xerror2(TSF"host_serv error for %0, %1: %2",
//                ((host == NULL) ? "(no hostname)" : host),
//                ((serv == NULL) ? "(no service name)" : serv),
//                gai_strerror(n));
//        return NULL;
//    }
//
//    return (res);       /* return pointer to first on linked list */
//}
//
//static int Socket(int family, int type, int protocol) {
//    int n;
//
//    if ((n = socket(family, type, protocol)) < 0) {
//        xerror2(TSF"socket error");
//    }
//
//    return (n);
//}
//static uint16_t in_cksum(uint16_t* _addr, int _len) {
//    int             nleft = _len;
//    uint32_t        sum = 0;
//    uint16_t*        w = _addr;
//    uint16_t        answer = 0;
//
//    while (nleft > 1)  {
//        sum += *w++;
//        nleft -= 2;
//    }
//
//    /* 4mop up an odd byte, if necessary */
//    if (nleft == 1) {
//        *(unsigned char*)(&answer) = *(unsigned char*)w;
//        sum += answer;
//    }
//
//    /* 4add back carry outs from top 16 bits to low 16 bits */
//    sum = (sum >> 16) + (sum & 0xffff); /* add hi 16 to low 16 */
//    sum += (sum >> 16);         /* add carry */
//    answer = ~sum;              /* truncate to 16 bits */
//    return (answer);
//}
//
//static void tv_sub(struct timeval* _out, struct timeval* _in) {
//    if ((_out->tv_usec -= _in->tv_usec) < 0) {     /* out -= in */
//        --_out->tv_sec;
//        _out->tv_usec += 1000000;
//    }
//
//    _out->tv_sec -= _in->tv_sec;
//}

//void TraceRouteQuery::proc_v4(char* _ptr, ssize_t _len, struct msghdr* _msg, struct timeval* _tvrecv) {
//    int     icmplen;
//    double      rtt;
//    struct icmp* icmp;
//    struct timeval*  tvsend;
//    icmp = (struct icmp*) _ptr;
//
//    if ((icmplen = (int)_len - IP_HEADER_LEN) < ICMP_HEADER_LEN) {
//        xerror2(TSF"receive malformed icmp packet");
//        return;             /* malformed packet */
//    }
//
//    // if (icmp->icmp_type == ICMP_ECHOREPLY)
//    //  {
//    xdebug2(TSF"icmp->icmp_type=%0,is equal with ICMP_ECHOREPLY:%1", icmp->icmp_type, icmp->icmp_type == ICMP_ECHOREPLY);
//
//    if (icmplen < ICMP_HEADER_LEN + sizeof(struct timeval)) {
//        xerror2(TSF"not enough data to compute RTT");
//        return;         /* not enough data to use */
//    }
//
//    tvsend = (struct timeval*)(&_ptr[ICMP_MINLEN]);
//    xdebug2(TSF"before ntohl tvsend sec=%_, nsec=%_; tvrecv sec=%_, usec=%_", tvsend->tv_sec
//            , tvsend->tv_usec, _tvrecv->tv_sec, _tvrecv->tv_usec);
//
//    tvsend->tv_sec = ntohl(tvsend->tv_sec);
//    tvsend->tv_usec = ntohl(tvsend->tv_usec);
//
//    xdebug2(TSF"tvsend sec=%_, nsec=%_; tvrecv sec=%_, usec=%_", tvsend->tv_sec
//            , tvsend->tv_usec, _tvrecv->tv_sec, _tvrecv->tv_usec);
//
//    tv_sub(_tvrecv, tvsend);
//    rtt = _tvrecv->tv_sec * 1000.0 + _tvrecv->tv_usec / 1000.0;
//
//    if (rtt < 10000.0 && rtt > 0.0) {
//        vecrtts_.push_back(rtt);
//    } else {
//        xerror2(TSF"rtt = %0 is illegal.receive %1 bytes from %2", rtt, icmplen, Sock_ntop_host(&recvaddr_, sizeof(recvaddr_)));
//    }
//
//    char tempbuff[1024] = {0};
//    snprintf(tempbuff, 1024, "%d bytes from %s: seq=%d,  rtt=%f ms\n",
//             icmplen, Sock_ntop_host(&recvaddr_, sizeof(recvaddr_)),
//             ntohs(icmp->icmp_seq), rtt);
//    xinfo2(TSF"%_", (char*)tempbuff);
//    tracerouteresult_.append(tempbuff);
//    //   }
//}
//
//int TraceRouteQuery::__prepareSendAddr(const char* _dest) {
//    struct addrinfo* ai;
//    char* h;
//    const char* host = _dest;
//    ai = Host_serv(host, NULL, 0, 0);
//
//    if (NULL == ai) return -1;
//
//    h = Sock_ntop_host(ai->ai_addr, ai->ai_addrlen);
//    xinfo2(TSF"PING %0 (%1): %2 data bytes\n", (ai->ai_canonname ? ai->ai_canonname : h), h, DATALEN);
//
//    if (ai->ai_family != AF_INET && ai->ai_family != AF_INET6) {
//        xinfo2(TSF"unknown address family %0\n", ai->ai_family);
//        freeaddrinfo(ai);
//        return -1;
//    }
//
//    memcpy(&sendaddr_, ai->ai_addr, sizeof(struct sockaddr));
//    xdebug2(TSF"m_sendAddr=%0", socket_address(&sendaddr_).ip());
//    freeaddrinfo(ai);  // 閲婃斁addrinfo鍐呴儴瀛楁malloc鐨勫唴瀛橈紙鐢眊etaddrinfo鍑芥暟鍐呴儴浜х敓锛�
//    return 0;
//}
//
//int TraceRouteQuery::__initttl(int ttl){
//    int ret = setsockopt(socksd_, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl));
//    return ret;
//}

//int TraceRouteQuery::__initialize(const char* _dest) {
//    if (-1 == __prepareSendAddr(_dest)) return -1;;
//
////    sockfd_ = Socket(sendaddr_.sa_family, SOCK_DGRAM/*SOCK_RAW*/, IPPROTO_ICMP);
//    socksd_ = Socket(sendaddr_.sa_family, SOCK_DGRAM/*SOCK_RAW*/, IPPROTO_UDP);
//    sockrc_ = Socket(sendaddr_.sa_family, SOCK_DGRAM/*SOCK_RAW*/, IPPROTO_ICMP);
////    if (sockfd_ < 0) return -1;
//    if (socksd_< 0 || sockrc_< 0) {
//        return -1;
//    }
//
////    int size = 60 * 1024;       /* OK if setsockopt fails */
////    setsockopt(sockfd_, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
//
////    setsockopt(socksd_, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
////    setsockopt(sockrc_, SOL_SOCKET, SO_RCVBUF, &size, sizeof(size));
//
//    // make nonblock socket
////    if (0 != socket_ipv6only(sockfd_, 0)){
////        xwarn2(TSF"set ipv6only failed. error %_",strerror(socket_errno));
////    }
//    if (0 != socket_ipv6only(socksd_, 0)){
//        xwarn2(TSF"set ipv6only failed. error %_",strerror(socket_errno));
//    }
//
//    int sdret = ::socket_set_nobio(socksd_);
////    int rcret = ::socket_set_nobio(sockrc_);
////
//    if (sdret != 0) {
//        xerror2(TSF"__initialize():set nonblock socket error:%0", socket_strerror(socket_errno));
//        return -1;
//    }
//
//    return 0;
//}
//void TraceRouteQuery::__deinitialize() {
////    if (sockfd_ >= 0) {
////        ::socket_close(sockfd_);
////    }
//    if (sockrc_ >=0) {
//        socket_close(sockrc_);
//    }
//    if (socksd_ >=0) {
//        socket_close(socksd_);
//    }
//}
//int TraceRouteQuery::__recv() {
//    char            recvbuf[MAXBUFSIZE];
//    char            controlbuf[MAXBUFSIZE];
//    memset(recvbuf, 0, MAXBUFSIZE);
//    memset(controlbuf, 0, MAXBUFSIZE);
//
//    struct msghdr   msg = {0};
//    struct iovec    iov = {0};
//
//
//    iov.iov_base = recvbuf;
//    iov.iov_len = sizeof(recvbuf);
//    msg.msg_name = &recvaddr_;
//    msg.msg_iov = &iov;
//    msg.msg_iovlen = 1;
//    msg.msg_control = controlbuf;
//
//    msg.msg_namelen = sizeof(recvaddr_);
//    msg.msg_controllen = sizeof(controlbuf);
//
//    int n = (int)recvmsg(sockrc_, &msg, 0);
//
//    xinfo2(TSF"after recvmsg() n =%0\n", (int)n);
//
//    if (n < 0) {
//        return -1;
//    }
//
//    struct timeval  tval;
//
//    Gettimeofday(&tval, NULL);
//
//    xdebug2(TSF"gettimeofday sec=%0,usec=%1", tval.tv_sec, tval.tv_usec);
//
//    proc_v4(recvbuf + IP_HEADER_LEN, n, &msg, &tval);  // 杩欎釜闀垮害n锛屽寘鍚�20涓瓧鑺傜殑ip澶�
//
//    return n;
//}
//int TraceRouteQuery::__send() {
////    char sendbuffer[MAXBUFSIZE];
////    memset(sendbuffer, 0, MAXBUFSIZE);
////    int len = 0;
////    __preparePacket(sendbuffer, len);
//    char *tmsg = "GET / HTTP/1.1\r\n\r\n";
//
//    int sendLen = Sendto(socksd_, tmsg, sizeof(tmsg), 0, &sendaddr_, sizeof(sendaddr_));
////    sendtimes_++;
//
//    return sendLen;
//}
//void TraceRouteQuery::__preparePacket(char* _sendbuffer, int& _len) {
//    char *cmsg = "GET / HTTP/1.1\r\n\r\n";
////    char    sendbuf[MAXBUFSIZE];
////    memset(sendbuf, 0, MAXBUFSIZE);
////    struct icmp* icmp;
////    icmp = (struct icmp*) sendbuf;
////    icmp->icmp_type = ICMP_ECHO;
////    icmp->icmp_code = 0;
////    icmp->icmp_id = getpid() & 0xffff;/* ICMP ID field is 16 bits */
////    icmp->icmp_seq = htons(nsent_++);
////    memset(&sendbuf[ICMP_MINLEN], 0xa5, DATALEN);   /* fill with pattern */
////
////    struct timeval now;
////    (void)gettimeofday(&now, NULL);
////    xdebug2(TSF"gettimeofday now sec=%0, nsec=%1", now.tv_sec, now.tv_usec);
////    now.tv_usec = htonl(now.tv_usec);
////    now.tv_sec = htonl(now.tv_sec);
////    bcopy((void*)&now, (void*)&sendbuf[ICMP_MINLEN], sizeof(now));
////    _len = ICMP_MINLEN + DATALEN;        /* checksum ICMP header and data */
////    icmp->icmp_cksum = 0;
////    icmp->icmp_cksum = in_cksum((u_short*) icmp, _len);
//    memcpy(_sendbuffer, cmsg, sizeof(cmsg));
//}
//void TraceRouteQuery::__onAlarm() {
//    readwrite_breaker_.Break();
//}
//int TraceRouteQuery::__runReadWrite(int& _errcode) {
//    xinfo_function();
//    std::string tempLog = "";
//    unsigned long timeout_point = timeout_ * 1000 + gettickcount();
//    unsigned long send_next = 0;
//    unsigned long sendts = 0;
//
//    int sel_timeout_cnt = 0;
//
//    int maxttl = 30;
//    int ttl = 1;  // index sur le TTL en cours de traitement.
//    int timeoutTTL = 0;
//    int maxAttempts = 3;
//
//    while (ttl < maxttl) {
//        std::string t_dest = "";
//        if (__initttl(ttl) < 0) {
//            return -1;
//        }
//
//        for (int i=0; i<maxAttempts; i++) {
//
//            bool should_send = false;
//
//            if (send_next <= gettickcount()) {
//                send_next = gettickcount() + interval_ * 1000;
//                should_send = true;
//            }
//
//            SocketSelect sel(readwrite_breaker_, true);
//            sel.PreSelect();
//            sel.Read_FD_SET(socksd_);
//            sel.Read_FD_SET(sockrc_);
//            sel.Exception_FD_SET(socksd_);
//            sel.Exception_FD_SET(sockrc_);
//
//            if (should_send) {
//                sel.Write_FD_SET(socksd_);
//                sel.Write_FD_SET(sockrc_);
//            }
//
//            long timeoutMs = timeout_point - gettickcount();
//
//            if (timeoutMs < 0) {
//                return -1;  //设置的超时时间内没有收完所有的包
//            }
//
//            int retsel = sel.Select((int)timeoutMs);
//
//            if (retsel < 0) {
//                xerror2(TSF"retSel<0");
//                _errcode = sel.Errno();
//                return -1;
//            }
//
//            if (sel.IsBreak()){
//                xinfo2(TSF"user breaked");
//                _errcode = EINTR;
//                return -1;
//            }
//
//            if (sel.IsException()) {
//                xerror2(TSF"socketselect exception");
//                _errcode = socket_error(socksd_);
//                return -1;
//            }
//
//            if (sel.Exception_FD_ISSET(socksd_)) {
//                _errcode = socket_error(socksd_);
//                return -1;
//            }
//
//            if (0 == retsel){
//                _errcode = ETIMEDOUT;
//                ++sel_timeout_cnt;
//            }
//            if (sel.Write_FD_ISSET(socksd_) && should_send) {
//                int sendLen = __send();
//
//                if (TRAFFIC_LIMIT_RET_CODE == sendLen) {
//                    return TRAFFIC_LIMIT_RET_CODE;
//                }
//
//                if (sendLen < 0) {
//                    _errcode = socket_error(socksd_);
//                    continue;
//                }
//                sendts = gettickcount();
//            }
////            if (::socket_set_nobio(socksd_) == -1) {
////                xerror2(TSF"set nonblock socket error:%0", socket_strerror(socket_errno));
////            }
//            if (-1 == __recv()) {
//                return -1;
//            }
//            if (TRAFFIC_LIMIT_RET_CODE == __recv()) {
//                return TRAFFIC_LIMIT_RET_CODE;
//            }
//            //将“二进制整数” －> “点分十进制，获取hostAddress和hostName
//
//            if (recvaddr_.sa_family == AF_INET) {
//                char display[INET_ADDRSTRLEN] = {0};
//                inet_ntop(AF_INET, &((struct sockaddr_in *)&recvaddr_)->sin_addr.s_addr, display, sizeof(display));
//                t_dest = std::string(display);
//
//                char temp[1024] = {0};
//                uint64_t t_cost_time = gettickcount() - sendts;
//                snprintf(temp, 1024, "\n recvpackets with timediff%d and ip %s.\n ", t_cost_time, display);
//                tempLog.append(std::string(temp));
//            }
//            else if (recvaddr_.sa_family == AF_INET6) {
//               char ip[INET6_ADDRSTRLEN];
//               inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&recvaddr_)->sin6_addr, ip, INET6_ADDRSTRLEN);
//                t_dest = std::string(ip);
//                char temp[1024] = {0};
//                uint64_t t_cost_time = gettickcount() - sendts;
//                snprintf(temp, 1024, "\n recvpackets with timediff%d and ip %s.\n ", t_cost_time, ip);
//                tempLog.append(std::string(temp));
//            }
//
//            if (i == maxAttempts - 1) {
//                //超过最大尝试次数后就不再发送了
//                break;
//            }
//        }
//        if (t_dest == destIP) {
//            char temp[1024] = {0};
//            uint64_t t_cost_time = gettickcount() - sendts;
//            snprintf(temp, 1024, "\n finish traceroute with timediff%d and ip %s.\n ", t_cost_time, t_dest.c_str());
//            tempLog.append(std::string(temp));
//            break;
//        }
//        ttl++;
//    }
//    return 0;
//}
int TraceRouteQuery::t_RunTraceRouteQuery(int _querycount, int _interval/*S*/, int _timeout/*S*/, const char* _dest, unsigned int _packet_size) {
    std::string destination = std::string(_dest);
    char* addrbytes;
    bool isIPV6 = false;
    if (destination.find(":") == std::string::npos) {
        struct sockaddr_in nativeAddr4;
        memset(&nativeAddr4, 0, sizeof(nativeAddr4));
        nativeAddr4.sin_len = sizeof(nativeAddr4);
        nativeAddr4.sin_family = AF_INET;
        nativeAddr4.sin_port = htons(UDPPORT);
        
        inet_pton(AF_INET, destination.c_str(), &nativeAddr4.sin_addr.s_addr);
        addrbytes = reinterpret_cast<char*>(&nativeAddr4);
    }else {
        isIPV6 = true;
        struct sockaddr_in6 nativeAddr6;
        memset(&nativeAddr6, 0, sizeof(nativeAddr6));
        nativeAddr6.sin6_len = sizeof(nativeAddr6);
        nativeAddr6.sin6_family = AF_INET6;
        nativeAddr6.sin6_port = htons(UDPPORT);
        inet_pton(AF_INET6, destination.c_str(), &nativeAddr6.sin6_addr);
        addrbytes = reinterpret_cast<char*>(&nativeAddr6);
    }
    
    struct sockaddr *destinationadrs;
    destinationadrs = (struct sockaddr *)addrbytes;
    
    //初始化套接口
       struct sockaddr fromAddr;
       int recv_sock;
       int send_sock;
       int ret = 0;
       //创建一个支持ICMP协议的UDP网络套接口（用于接收）
       if ((recv_sock = socket(destinationadrs->sa_family, SOCK_DGRAM, isIPV6?IPPROTO_ICMPV6:IPPROTO_ICMP)) < 0) {
           char temp[1024] = {0};
           snprintf(temp, 1024, "\nerror: recv_sock socket create failed with :%s.\n",strerror(errno));
           tracerouteresult_.append(std::string(temp));
           return -1;
       }
       //创建一个UDP套接口（用于发送）
       if ((send_sock = socket(destinationadrs->sa_family, SOCK_DGRAM, 0)) < 0) {
           char temp[1024] = {0};
           snprintf(temp, 1024, "\nerror: send_sock socket create failed with :%s.\n",strerror(errno));
           tracerouteresult_.append(std::string(temp));
           return -1;
       }
    
        char *cmsg = "GET / HTTP/1.1\r\n\r\n";
        socklen_t n = sizeof(fromAddr);
        char buf[100];

        int ttl = 1;  // index sur le TTL en cours de traitement.
        int timeoutTTL = 0;
        bool icmp = false;  // Positionné à true lorsqu'on reçoit la trame ICMP en retour.
        long startTime;     // Timestamp lors de l'émission du GET HTTP
        long delta;         // Durée de l'aller-retour jusqu'au hop.
    
        while (ttl <= MAXTTL) {
            startTime = gettickcount();
            memset(&fromAddr, 0, sizeof(fromAddr));
            //设置sender 套接字的ttl
            if ((isIPV6? setsockopt(send_sock,IPPROTO_IPV6, IPV6_UNICAST_HOPS, &ttl, sizeof(ttl)):setsockopt(send_sock, IPPROTO_IP, IP_TTL, &ttl, sizeof(ttl))) < 0) {
                char temp[1024] = {0};
                snprintf(temp, 1024, "\nerror: sender socket setsockopt failed with :%s.\n",strerror(errno));
                tracerouteresult_.append(std::string(temp));
                ret = -1;
            }
            //每一步连续发送maxAttenpts报文
            icmp = false;
            std::string traceLog = "";
            std::string hostaddress = "***";
            
            for (int t_try = 0; t_try < MAXATTEMP; t_try ++) {
                long t_starttime = gettickcount();
                //发送成功返回值等于发送消息的长度
                ssize_t sentLen = sendto(send_sock, cmsg, sizeof(cmsg), 0, (struct sockaddr *)destinationadrs, isIPV6?sizeof(struct sockaddr_in6):sizeof(struct sockaddr_in));
                if (sentLen != sizeof(cmsg)) {
                    ret = -1;
                }

                long res = 0;
                //从（已连接）套接口上接收数据，并捕获数据发送源的地址。
                if (-1 == fcntl(recv_sock, F_SETFL, O_NONBLOCK)) {
                    char temp[1024] = {0};
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
                        }
                        
                        else if (fromAddr.sa_family == AF_INET6) {
                            char ip[INET6_ADDRSTRLEN];
                            inet_ntop(AF_INET6, &((struct sockaddr_in6 *)&fromAddr)->sin6_addr, ip, INET6_ADDRSTRLEN);
                            hostaddress = std::string(ip);
                        }
                        
                        if (t_try == 0) {
                            char temp[1024] = {0};
                            snprintf(temp, 1024, "\n host:%s.\t\t",hostaddress.c_str());
                            traceLog.append(std::string(temp));
                        }
                        char temp[1024] = {0};
                        snprintf(temp, 1024, "%dms.\t",cost_time);
                        traceLog.append(std::string(temp));
                    }
                } else {
                    timeoutTTL++;
                    char temp[1024] = {0};
                    snprintf(temp, 1024, "\nerror: ttl timeout ;FD_Set < 0 with:%s.\n",strerror(errno));
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
            snprintf(temp, 1024, "\n\t tracefinished with total cost:%d.\t",total_cost);
            tracerouteresult_.append(std::string(temp));
            break;
        }
        ttl++;
    }
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
