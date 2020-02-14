//
//  traceroutechecker.c
//  sdt
//
//  Created by didi on 2020/2/13.
//

#include "traceroutechecker.h"

#include "mars/comm/xlogger/xlogger.h"
#include "mars/comm/singleton.h"
#include "mars/comm/time_utils.h"
#include "mars/sdt/constants.h"

#include "sdt/src/checkimpl/traceroutequery.h"

using namespace mars::sdt;

TraceRouteChecker::TraceRouteChecker() {
    xverbose_function();
}
TraceRouteChecker::~TraceRouteChecker() {
    xverbose_function();
}

int TraceRouteChecker::StartDoCheck(CheckRequestProfile &_check_request){
    #if defined(ANDROID) || defined(__APPLE__)
    xinfo_function();
    return BaseChecker::StartDoCheck(_check_request);
    #else
        xinfo2(TSF"neither android nor ios");
        return -1;
    #endif
}

void TraceRouteChecker::__DoCheck(CheckRequestProfile &_check_request) {
    #if defined(ANDROID) || defined(__APPLE__)
    xinfo_function();
    //短连接通道
    for (CheckIPPorts_Iterator iter = _check_request.shortlink_items.begin(); iter != _check_request.shortlink_items.end(); ++iter) {
        for (std::vector<CheckIPPort>::iterator ipport = iter->second.begin(); ipport != iter->second.end(); ++ipport) {
            if (is_canceled_) {
                xinfo2(TSF"traceRouteChecker is canceled.");
                return;
            }
            CheckResultProfile profile;
            std::string host = (*ipport).ip.empty() ? DEFAULT_PING_HOST : (*ipport).ip;
            profile.ip = host;
            profile.netcheck_type = kPingCheck;

            TraceRouteQuery traceQuery;
            int ret = traceQuery.t_RunTraceRouteQuery(0, 0, 0, host.c_str());
            profile.error_code = ret;
            profile.traceRoute = traceQuery.GetTraceRoute();
            _check_request.checkresult_profiles.push_back(profile);
            _check_request.check_status = (profile.error_code == 0) ? kCheckContinue : kCheckFinish;
        }
        
    }
        
    #endif
    
}
