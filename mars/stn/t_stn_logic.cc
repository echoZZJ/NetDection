//
//  t_stn_logic.c
//  stn
//
//  Created by didi on 2020/2/8.
//

#include "t_stn_logic.h"

#include <stdlib.h>
#include <string>
#include <map>

#include "mars/log/appender.h"

#include "mars/baseevent/baseprjevent.h"
#include "mars/baseevent/active_logic.h"
#include "mars/baseevent/baseevent.h"
#include "mars/comm/xlogger/xlogger.h"
#include "mars/comm/messagequeue/message_queue.h"
#include "mars/comm/singleton.h"
#include "mars/comm/bootrun.h"
#include "mars/comm/platform_comm.h"
#include "mars/comm/alarm.h"
#include "mars/boost/signals2.hpp"
#include "stn/src/t_net_core.h"//一定要放这里，Mac os 编译
#include "stn/src/t_net_check_logic.h"

#define PINGCheck (1 << 3)
#define BasicCheck 1
#define TCPCheck (1 << 1)
#define HTTPCheck (1 << 2)

namespace mars {
namespace stn {
static Callback* sg_callback = NULL;
static const std::string kLibName = "stn";

enum NetWorkCheckOperationType {
    PingType = (1 << 3),
    BasicType = 1,  //ping,dns,traceroute
//    TraceRouteType = 2,
    TcpType = (1 << 1),
    HttpType = (1 << 2),
    DefaultType = ((1 << 2) | (1 << 1) | 1),
};

static std::map<std::string, NetWorkCheckOperationType> const netCheckTable = {
    {
        "PING",NetWorkCheckOperationType::PingType
    },
    {
        "BASIC",NetWorkCheckOperationType::BasicType
    },
    {
        "DEFAULT",NetWorkCheckOperationType::DefaultType
    },
//    {
//        "TraceRoute",NetWorkCheckOperationType::TraceRouteType
//    },
    {
        "TCP",NetWorkCheckOperationType::TcpType
    },
    {
        "HTTP",NetWorkCheckOperationType::HttpType
    }
};
boost::signals2::signal<void (ErrCmdType _err_type, int _err_code, const std::string& _ip, uint16_t _port)> SignalOnLongLinkNetworkError;
boost::signals2::signal<void (ErrCmdType _err_type, int _err_code, const std::string& _ip, const std::string& _host, uint16_t _port)> SignalOnShortLinkNetworkError;


static void __initbind_baseprjevent() {
#ifdef ANDROID
    mars::baseevent::addLoadModule(kLibName);
#endif
}
BOOT_RUN_STARTUP(__initbind_baseprjevent);
    
void SetCallback(Callback* const callback) {
    sg_callback = callback;
}

void (*StartNetWorkSniffering)()
=[](){
    NetCheckLogic().__StartNetCheck();
};

void (*StartPingCheck)()
=[](){
    StartNetWorkCheck("PING");
//    NetCheckLogic().__StartNetCheckOption(PINGCheck);
    
};

void (*StartNetWorkCheck)(const std::string& type)
=[](const std::string& type){
//    std::string checkType = type;
//    std::find_if(netCheckTable.begin(), netCheckTable.end(), [&type](const NetWorkCheckOperationType _enum){
//        return _enum;
//    });
    auto findtype = netCheckTable.find(type);
    if(findtype != netCheckTable.end()) {
        NetCheckLogic().__StartNetCheckOption(findtype->second);
    }
//    netCheckTable.find(_operationType);
    /**
     auto find_it = std::find_if(content.lst_runloop_info.begin(), content.lst_runloop_info.end(),
                                 [&_message](const RunLoopInfo& _v){ return _message == _v.runing_message_id; });
     
     if (find_it != content.lst_runloop_info.end())  { return true; }
     */
};

void (*SetLonglinkSvrAddr)(const std::string& host, const std::vector<uint16_t> ports, const std::string& debugip)
= [](const std::string& host, const std::vector<uint16_t> ports, const std::string& debugip) {
    std::vector<std::string> hosts;
    if (!host.empty()) {
        hosts.push_back(host);
    }
    NetSource::SetLongLink(hosts, ports, debugip);
};
    
void (*SetShortlinkSvrAddr)(const uint16_t port, const std::string& debugip)
= [](const uint16_t port, const std::string& debugip) {
    NetSource::SetShortlink(port, debugip);
};

void (*SetShortlinkSvrAddrs)(const std::vector<std::string>& hosts, const std::vector<uint16_t> ports, const std::string& debugip)
= [](const std::vector<std::string>& hosts, const std::vector<uint16_t> ports, const std::string& debugip){
//    std::vector<std::string> hosts;
//    if (!host.empty()) {
//        hosts.push_back(host);
//    }
    if(!hosts.empty()){
        NetSource::SetShortLinks(hosts, ports, debugip);
    }
    
};
#ifndef ANDROID
//底层询问上层该host对应的ip列表
std::vector<std::string> (*OnNewDns)(const std::string& host)
= [](const std::string& host) {
    xassert2(sg_callback != NULL);
    return sg_callback->OnNewDns(host);
};
#endif

}
}
