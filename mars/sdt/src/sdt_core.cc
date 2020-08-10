// Tencent is pleased to support the open source community by making Mars available.
// Copyright (C) 2016 THL A29 Limited, a Tencent company. All rights reserved.

// Licensed under the MIT License (the "License"); you may not use this file except in 
// compliance with the License. You may obtain a copy of the License at
// http://opensource.org/licenses/MIT

// Unless required by applicable law or agreed to in writing, software distributed under the License is
// distributed on an "AS IS" basis, WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND,
// either express or implied. See the License for the specific language governing permissions and
// limitations under the License.


/*
 * netchecker_service.cc
 *
 *  Created on: 2014-6-17
 *      Author: renlibin caoshaokun
 */

#include <algorithm>

#include "boost/bind.hpp"

#include "mars/comm/thread/lock.h"
#include "mars/comm/xlogger/xlogger.h"
#include "mars/comm/singleton.h"
#include "mars/comm/messagequeue/message_queue.h"
#include "mars/sdt/constants.h"

#include "activecheck/dnschecker.h"
#include "activecheck/httpchecker.h"
#include "activecheck/pingchecker.h"
#include "activecheck/tcpchecker.h"
#include "activecheck/traceroutechecker.h"
#include "sdt_core.h"

using namespace mars::sdt;

#define RETURN_NETCHECKER_SYNC2ASYNC_FUNC(func) RETURN_SYNC2ASYNC_FUNC(func, async_reg_.Get(), )

#define TYPE_PING "PING"
#define TYPE_DNS "DNS"
#define TYPE_HTPP "HTTP"
#define TYPE_TCP "TCP"
#define TYPE_TRACEROUTE "TraceRoute"

SdtCore::SdtCore()
    : thread_(boost::bind(&SdtCore::__RunOn, this))
    , check_list_(std::list<BaseChecker*>())
    , cancel_(false)
    , checking_(false) {
    xinfo_function();
}

SdtCore::~SdtCore() {
    xinfo_function();

    cancel_ = true;

    if (!thread_.isruning()) {
    	__Reset();
    } else {
        CancelAndWait();
    }
}

void SdtCore::StartCheck(CheckIPPorts& _longlink_items, CheckIPPorts& _shortlink_items, int _mode, int _timeout) {
    xinfo_function();
    ScopedLock lock(checking_mutex_);

    if (checking_) return;

    __InitCheckReq(_longlink_items, _shortlink_items, _mode, _timeout);

	if (thread_.isruning() || thread_.start() != 0)
		return;
}

void SdtCore::__InitCheckReq(CheckIPPorts& _longlink_items, CheckIPPorts& _shortlink_items, int _mode, int _timeout) {
	xinfo_function();
	checking_ = true;

	check_request_.Reset();
	check_request_.longlink_items.insert(_longlink_items.begin(), _longlink_items.end());
    check_request_.shortlink_items.insert(_shortlink_items.begin(), _shortlink_items.end());
	check_request_.mode = _mode;
	check_request_.total_timeout = _timeout;
    
    if (check_request_.shortlink_items.empty()) {
        xinfo2(TSF"shortlink_items is empty");
    }
        
    if (check_request_.longlink_items.empty()) {
        xinfo2(TSF"longlink_items is empty");
    }
    
    if (MODE_PING(_mode)) {
        xinfo2(TSF"__InitCheckReq MODE_PING");
        PingChecker* ping_checker = new PingChecker();
        check_list_.push_back(ping_checker);
        xinfo2(TSF"MODE_BASIC  checkList is %_",check_list_.size());
    }
    
    if (MODE_BASIC(_mode)) {
        xinfo2(TSF"__InitCheckReq MODE_BASIC");
        PingChecker* ping_checker = new PingChecker();
        check_list_.push_back(ping_checker);
        DnsChecker* dns_checker = new DnsChecker();
        check_list_.push_back(dns_checker);
        TraceRouteChecker * trace_checker = new TraceRouteChecker();
        check_list_.push_back(trace_checker);
        xinfo2(TSF"MODE_BASIC  checkList is %_",check_list_.size());
        
    }
    if (MODE_TRACEROUTE(_mode)) {
        xinfo2(TSF"__InitCheckReq MODE_TRACEROUTE");
        TraceRouteChecker * trace_checker = new TraceRouteChecker();
        check_list_.push_back(trace_checker);
        xinfo2(TSF"MODE_BASIC  checkList is %_",check_list_.size());
    }
    if (MODE_DNS(_mode)) {
        xinfo2(TSF"__InitCheckReq MODE_DNS");
        DnsChecker* dns_checker = new DnsChecker();
        check_list_.push_back(dns_checker);
        xinfo2(TSF"MODE_BASIC  checkList is %_",check_list_.size());
    }
    
    if (MODE_LONG(_mode)) {
           xinfo2(TSF"__InitCheckReq MODE_LONG");
           TcpChecker* tcp_checker = new TcpChecker();
           check_list_.push_back(tcp_checker);
           xinfo2(TSF"MODE_LONG  checkList is %_",check_list_.size());
    }
    
    if (MODE_SHORT(_mode)) {
        xinfo2(TSF"__InitCheckReq MODE_SHORT");
//    	check_request_.shortlink_items.insert(_shortlink_items.begin(), _shortlink_items.end());
        HttpChecker* http_checker = new HttpChecker();
        check_list_.push_back(http_checker);
        xinfo2(TSF"MODE_SHORT  checkList is %_",check_list_.size());
    }
   
    
}

void SdtCore::__Reset() {
    xinfo_function();

    //check_request_.report

    std::list<BaseChecker*>::iterator iter = check_list_.begin();

    for (; iter != check_list_.end();) {
        if (NULL != (*iter)) {
            delete(*iter);
            (*iter) = NULL;
        }

        iter = check_list_.erase(iter);
    }

    checking_ = false;
}

void SdtCore::__RunOn() {
    xinfo_function();
    for (std::list<BaseChecker*>::iterator iter = check_list_.begin(); iter != check_list_.end(); ++iter) {
        if (cancel_) {
            xinfo2(TSF"check_request cancel");
            break;
        }
        if (check_request_.check_status == kCheckFinish){
            xinfo2(TSF"check_request finish");
            break;
        }
        if (check_request_.check_status == kCheckTimeOut) {
            xinfo2(TSF"check_request timeout");
            break;
        }
        if (check_request_.check_status == kCheckDNSNoBlock) {
            xinfo2(TSF"check_request faild at DNS");
        }
        if (check_request_.check_status == kCheckHTTPNoBlock) {
            xinfo2(TSF"check_request faild at HTTP");
        }
        (*iter)->StartDoCheck(check_request_);
    }

    xinfo2(TSF"all checkers end! cancel_=%_, check_request_.check_status_=%_, check_list__size=%_", cancel_, check_request_.check_status, check_list_.size());

    __DumpCheckResult();
    __Reset();
}
bool t_updateMapValue(std::string &key,std::map<const std::string, std::vector<CheckResultProfile>> &resMap){
    if (resMap.find(key) == resMap.end()){
       return true;
    }
    return false;
}
void SdtCore::__DumpCheckResult() {
    std::vector<CheckResultProfile>::iterator iter = check_request_.checkresult_profiles.begin();
    std::vector<std::string> resJsonVec;
    std::vector<std::string> displayVec;
    std::vector<std::string> pingVec;
    std::vector<std::string> httpVec;
    std::vector<std::string> dnsVec;
    std::vector<std::string> tcpVec;
    std::vector<std::string> traceRouteVec;
    std::map<const std::string, std::vector<std::string>> dump_res;
    for (; iter != check_request_.checkresult_profiles.end(); ++iter) {
        XMessage res_str;
        switch(iter->netcheck_type) {
        case kTcpCheck:
            res_str(TSF"tcp check result, error_code:%_, ip:%_, port:%_, network_type:%_, rtt:%_", iter->error_code, iter->ip, iter->port, iter->network_type, iter->rtt);
            tcpVec.push_back(iter->toJson());
            break;
        case kHttpCheck:
            res_str(TSF"http check result, status_code:%_, url:%_, ip:%_, port:%_, network_type:%_, rtt:%_", iter->status_code, iter->url, iter->ip, iter->port, iter->network_type, iter->rtt);
            httpVec.push_back(iter->toJson());
            break;
        case kPingCheck:
            res_str(TSF"ping check result, error_code:%_, ip:%_, network_type:%_, loss_rate:%_, rtt:%_", iter->error_code, iter->ip, iter->network_type, iter->loss_rate, iter->rtt_str);
            pingVec.push_back(iter->toJson());
            break;
        case kDnsCheck:
            res_str(TSF"dns check result, error_code:%_, domain_name:%_, network_type:%_, ip1:%_, rtt:%_", iter->error_code, iter->domain_name, iter->network_type, iter->ip1, iter->rtt);
            dnsVec.push_back(iter->toJson());
            break;
        case kTracerouteCheck:
            res_str(TSF"traceroute check result, error_code:%_, network_type:%_, traceroute_str:%_",iter->error_code, iter->network_type, iter->traceRoute);
            break;
        }
        resJsonVec.push_back(iter->toJson());
    }
    if (!pingVec.empty()) {
        dump_res.insert(std::pair<const std::string, std::vector<std::string>>(TYPE_PING,pingVec));
    }
    if (!tcpVec.empty()) {
        dump_res.insert(std::pair<const std::string, std::vector<std::string>>(TYPE_TCP,tcpVec));
    }
    if (!httpVec.empty()) {
        dump_res.insert(std::pair<const std::string, std::vector<std::string>>(TYPE_HTPP,httpVec));
    }
    if (!dnsVec.empty()) {
        dump_res.insert(std::pair<const std::string, std::vector<std::string>>(TYPE_DNS,dnsVec));
    }
    if (!traceRouteVec.empty()) {
        dump_res.insert(std::pair<const std::string, std::vector<std::string>>(TYPE_TRACEROUTE,traceRouteVec));
    }
    dump_res.insert(std::pair<const std::string, std::vector<std::string>>("report",resJsonVec));
    xinfo2(TSF"dump finished");
    //generate network report for developers
    dumpNetReportRes(dump_res);
    //display  user's network check UI in app
    dumpNetSniffRes(dump_res,false);
}

void SdtCore::CancelCheck() {
    xinfo_function();
    cancel_ = true;
    for (std::list<BaseChecker*>::iterator iter = check_list_.begin(); iter != check_list_.end(); ++iter) {
        (*iter)->CancelDoCheck();
    }
    std::map<const std::string, std::vector<std::string>> dump_res;
    dumpNetSniffRes(dump_res,true);
}

void SdtCore::CancelAndWait() {
    xinfo_function();
    CancelCheck();
    thread_.join();
}
