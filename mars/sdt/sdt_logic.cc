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
 * sdt_logic.cc
 *
 *  Created on: 2016年3月18日
 *      Author: caoshaokun
 */

#include "mars/sdt/sdt_logic.h"

#include "mars/baseevent/baseevent.h"
#include "mars/baseevent/baseprjevent.h"
#include "mars/comm/xlogger/xlogger.h"
#include "mars/comm/bootrun.h"
#include "mars/sdt/constants.h"

#include "sdt/src/sdt_core.h"

namespace mars {
namespace sdt {

static Callback* sg_callback = NULL;

void SetCallBack(Callback* const callback) {
    sg_callback = callback;
}

static const std::string kLibName = "sdt";

#define SDT_WEAK_CALL(func) \
    boost::shared_ptr<SdtCore> sdt_ptr = SdtCore::Singleton::Instance_Weak().lock();\
    if (!sdt_ptr) {\
        xwarn2(TSF"sdt uncreate");\
        return;\
    }\
	sdt_ptr->func

static void onCreate() {
    xinfo2(TSF"sdt oncreate");
    SdtCore::Singleton::Instance();
}

static void onDestroy() {
    xinfo2(TSF"sdt onDestroy");
    SdtCore::Singleton::AsyncRelease();
}

static void __initbind_baseprjevent() {

#ifdef ANDROID
	mars::baseevent::addLoadModule(kLibName);
#endif
	GetSignalOnCreate().connect(&onCreate);
	GetSignalOnDestroy().connect(5, &onDestroy);
}

BOOT_RUN_STARTUP(__initbind_baseprjevent);

//active netcheck interface
void StartActiveCheck(CheckIPPorts& _longlink_check_items, CheckIPPorts& _shortlink_check_items, int _mode, int _timeout) {
    xinfo2("StartActiveCheck");
	SDT_WEAK_CALL(StartCheck(_longlink_check_items, _shortlink_check_items, _mode, _timeout));
}

void CancelActiveCheck() {
	SDT_WEAK_CALL(CancelCheck());
}


#ifndef ANDROID

void (*dumpNetSniffRes)(const std::map<const std::string, std::vector<std::string>>& checkResDic,bool isCancle)
= [](const std::map<const std::string, std::vector<std::string>>& checkResDic,bool isCancle) {
    xassert2(sg_callback != NULL);
    return sg_callback->dumpNetSniffRes(checkResDic,isCancle);
};
void (*dumpNetReportRes)(const std::map<const std::string, std::vector<std::string>>& checkResDic)
= [](const std::map<const std::string, std::vector<std::string>>& checkResDic) {
    xassert2(sg_callback != NULL);
    return sg_callback->dumpNetReportRes(checkResDic);
};

#endif

//#ifndef ANDROID

std::map<const std::string, std::vector<CheckResultProfile>> (*ReformatNetCheckResult)(const std::vector<CheckResultProfile>& _check_results)
= [](const std::vector<CheckResultProfile>& _check_results) {
    std::map<const std::string, std::vector<CheckResultProfile>> resDic;
        std::vector<CheckResultProfile> pingVec;
        std::vector<CheckResultProfile> DNSVec;
        std::vector<CheckResultProfile> TCPVec;
        std::vector<CheckResultProfile> HTTPVec;
        std::vector<CheckResultProfile> TraceRouteVec;
        size_t resLength = _check_results.size();
        for(size_t i = 0; i < resLength; i++){
            CheckResultProfile resItem = _check_results[i];
            if(resItem.netcheck_type == kPingCheck){
                pingVec.push_back(resItem);
            }
            if(resItem.netcheck_type == kDnsCheck){
                DNSVec.push_back(resItem);
            }
            if(resItem.netcheck_type == kTcpCheck){
                TCPVec.push_back(resItem);
            }
            if(resItem.netcheck_type == kHttpCheck){
                HTTPVec.push_back(resItem);
            }
            if(resItem.netcheck_type == kTracerouteCheck){
                TraceRouteVec.push_back(resItem);
            }
        }
        if(!pingVec.empty()){
            resDic.insert(std::pair<std::string, std::vector<CheckResultProfile>>("PING",pingVec));
        }
        if(!DNSVec.empty()){
            resDic.insert(std::pair<std::string, std::vector<CheckResultProfile>>("DNS",DNSVec));
        }
        if(!TCPVec.empty()){
            resDic.insert(std::pair<std::string, std::vector<CheckResultProfile>>("TCP",TCPVec));
        }
        if(!HTTPVec.empty()){
            resDic.insert(std::pair<std::string, std::vector<CheckResultProfile>>("HTTP",HTTPVec));
        }
        if(!TraceRouteVec.empty()) {
            resDic.insert(std::pair<std::string, std::vector<CheckResultProfile>>("TraceRoute",TraceRouteVec));
        }
        return resDic;
};



void (*ReportNetCheckResult)(const std::vector<CheckResultProfile>& _check_results)
= [](const std::vector<CheckResultProfile>& _check_results) {
    std::map<const std::string, std::vector<CheckResultProfile>> resDic;
    std::vector<CheckResultProfile> pingVec;
    std::vector<CheckResultProfile> DNSVec;
    std::vector<CheckResultProfile> TCPVec;
    std::vector<CheckResultProfile> HTTPVec;
    size_t resLength = _check_results.size();
    for(size_t i = 0; i < resLength; i++){
        CheckResultProfile resItem = _check_results[i];
        if(resItem.netcheck_type == kPingCheck){
            pingVec.push_back(resItem);
        }
        if(resItem.netcheck_type == kDnsCheck){
            DNSVec.push_back(resItem);
        }
        if(resItem.netcheck_type == kTcpCheck){
            TCPVec.push_back(resItem);
        }
        if(resItem.netcheck_type == kHttpCheck){
            HTTPVec.push_back(resItem);
        }
    }
    if(!pingVec.empty()){
        resDic.insert(std::pair<std::string, std::vector<CheckResultProfile>>("PING",pingVec));
    }
    if(!DNSVec.empty()){
        resDic.insert(std::pair<std::string, std::vector<CheckResultProfile>>("DNS",DNSVec));
    }
    if(!TCPVec.empty()){
        resDic.insert(std::pair<std::string, std::vector<CheckResultProfile>>("TCP",TCPVec));
    }
    if(!HTTPVec.empty()){
        resDic.insert(std::pair<std::string, std::vector<CheckResultProfile>>("HTTP",HTTPVec));
    }
};


}}
