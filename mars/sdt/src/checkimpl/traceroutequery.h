//
//  traceroutequery.h
//  sdt
//
//  Created by didi on 2020/2/13.
//

#ifndef traceroutequery_h
#define traceroutequery_h

#include <string>
#include <vector>

#include "boost/bind.hpp"

#include "mars/comm/socket/unix_socket.h"

#ifdef __APPLE__
#include "mars/comm/alarm.h"
#include "mars/comm/socket/socketselect.h"
#endif

#define DISALLOW_COPY_AND_ASSIGN(cls)    \
private:\
cls(const cls&);    \
cls& operator=(const cls&);

namespace mars {
namespace sdt {

class TraceRouteQuery {
public:
    TraceRouteQuery():
            tracerouteresult_("")
    #ifdef __APPLE__
            , destIP("")
            , nsent_(0),
            sockfd_(-1),
            socksd_(-1),
            sockrc_(-1),
            sendtimes_(0),
            sendcount_(0),
            readcount_(0),
            interval_(0),
            timeout_(0),
            readwrite_breaker_()
    #endif
        {}
        ~TraceRouteQuery() {
        }
public:
    std::string GetTraceRoute();
    /**
     * return value:
     * 0---->success
     * -1--->error
     */
    int t_RunTraceRouteQuery(int queryCount, int interval/*S*/, int timeout/*S*/,const char* dest, unsigned int packetSize = 0);
    
    #ifdef __APPLE__
      private:
        void proc_v4(char* ptr, ssize_t len, struct msghdr* msg, struct timeval* tvrecv);
        int  __prepareSendAddr(const char* dest);
        int  __runReadWrite(int& errCode);
        void __onAlarm();
        void __preparePacket(char* sendbuffer, int& len);
        int  __send();
        int  __recv();
        int  __initttl(int ttl);
        int  __initialize(const char* dest);
        void  __deinitialize();
    #endif

        DISALLOW_COPY_AND_ASSIGN(TraceRouteQuery);
    
    private:
        std::string                tracerouteresult_;
    #ifdef __APPLE__
        int                     nsent_;                /* add 1 for each sendto() */
        std::string             destIP;
        int                     sockfd_;
        int                     socksd_;
        int                     sockrc_;
        std::vector<double>     vecrtts_;
        int                     sendtimes_;
        int                     sendcount_;
        int                     readcount_;
        int                     interval_;
        int                     timeout_;
        struct sockaddr          sendaddr_;
        struct sockaddr            recvaddr_;
        SocketBreaker     readwrite_breaker_;
    #endif
    
};

}
}

#endif /* traceroutequery_h */
