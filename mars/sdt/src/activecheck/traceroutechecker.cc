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

#include "sdt/src/checkimpl/traceroute_query.h"

#define MAX_TRACEROUT (1)
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
    int counter = 0;
    for (CheckIPPorts_Iterator iter = _check_request.shortlink_items.begin(); iter != _check_request.shortlink_items.end(); ++iter) {
        if (counter >= 1) {
            break;
        }
        for (std::vector<CheckIPPort>::iterator ipport = iter->second.begin(); ipport != iter->second.end(); ++ipport) {
            if (is_canceled_) {
                xinfo2(TSF"traceRouteChecker is canceled.");
                return;
            }
            CheckResultProfile profile;
            std::string host = (*ipport).ip.empty() ? DEFAULT_PING_HOST : (*ipport).ip;
            profile.ip = host;
            profile.netcheck_type = kTracerouteCheck;
            profile.domain_name = iter->first;
            TraceRouteQuery traceQuery;
            xinfo2(TSF"t_RunTraceRouteQuery with host%_",host);
            int ret = traceQuery.t_RunTraceRouteQuery(0, 0, 0, host.c_str());
            profile.error_code = ret;
            profile.traceRoute = traceQuery.GetTraceRoute();
            _check_request.checkresult_profiles.push_back(profile);
            _check_request.check_status = (profile.error_code == 0) ? kCheckContinue : kCheckFinish;
            if (ret != 0) {
                xinfo2(TSF"checkfinished error with ret:%_",ret);
            }
        }
        counter++;
    }
        
    #endif
    
}
