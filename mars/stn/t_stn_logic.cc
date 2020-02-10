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
//#include "stn/src/net_source.h"
//#include "stn/src/signalling_keeper.h"
//#include "stn/src/proxy_test.h"
#include "stn/src/t_net_check_logic.h"

namespace mars {
namespace stn {
static Callback* sg_callback = NULL;
    
void SetCallback(Callback* const callback) {
    sg_callback = callback;
}

void (*StartNetWorkSniffering)()
=[](){
    NetCheckLogic().__StartNetCheck();
};


void (*SetLonglinkSvrAddr)(const std::string& host, const std::vector<uint16_t> ports, const std::string& debugip)
= [](const std::string& host, const std::vector<uint16_t> ports, const std::string& debugip) {
    std::vector<std::string> hosts;
    if (!host.empty()) {
        hosts.push_back(host);
    }
    NetSource::SetLongLink(hosts, ports, debugip);
};

//void SetShortlinkSvrAddr(const uint16_t port)
//{
//    NetSource::SetShortlink(port, "");
//};
    
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

//底层询问上层该host对应的ip列表
std::vector<std::string> (*OnNewDns)(const std::string& host)
= [](const std::string& host) {
    xassert2(sg_callback != NULL);
    return sg_callback->OnNewDns(host);
};

}
}
