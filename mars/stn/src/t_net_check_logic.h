//
//  t_net_check_logic.hpp
//  stn
//
//  Created by didi on 2020/2/8.
//

#ifndef t_net_check_logic_hpp
#define t_net_check_logic_hpp


#include <list>
#include <string>

#include "t_net_source.h"

class CommFrequencyLimit;

namespace mars {
    namespace stn {
    
class NetSource;

class NetCheckLogic {
    public:
    NetCheckLogic();
    ~NetCheckLogic();
    void __StartNetCheck();
    
    private:
    struct NetTaskStatusItem{
        uint32_t records;
        uint64_t last_failedtime;
        NetTaskStatusItem(): records(0xFFFFFFFF), last_failedtime(0) {}
    };
    
    private:

    CommFrequencyLimit* frequency_limit_;
    NetSource::DnsUtil dns_util_;

//    unsigned long long last_netcheck_time_;

    NetTaskStatusItem longlink_taskstatus_item_;;
    NetTaskStatusItem shortlink_taskstatus_item_;
};
}
}
#endif /* t_net_check_logic_hpp */


