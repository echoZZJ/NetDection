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
 * com_tencent_mars_sdt_SdtLogic_C2Java.cc
 *
 *  Created on: 2016年8月9日
 *      Author: caoshaokun
 */

#include <jni.h>
#include <vector>

#include "mars/comm/autobuffer.h"
#include "mars/comm/xlogger/xlogger.h"
#include "mars/comm/jni/util/var_cache.h"
#include "mars/comm/jni/util/scope_jenv.h"
#include "mars/comm/jni/util/comm_function.h"
#include "mars/comm/jni/util/scoped_jstring.h"
#include "mars/comm/compiler_util.h"
#include "mars/sdt/sdt.h"
#include "mars/sdt/netchecker_profile.h"

DEFINE_FIND_CLASS(KC2Java, "com/tencent/mars/sdt/SdtLogic")

#define TYPE_PING "PING"
#define TYPE_DNS "DNS"
#define TYPE_HTPP "HTTP"
#define TYPE_TCP "TCP"

namespace mars {
namespace sdt {

DEFINE_FIND_STATIC_METHOD(KC2Java_dumpNetSniffRes,KC2Java,"dumpNetSniffRes","(Ljava/lang/String;)V")
void(*dumpNetSniffRes)(const std::map<const std::string, std::vector<std::string>>& checkResDic,bool isCancle)
=[](const std::map<const std::string, std::vector<std::string>>& checkResDic,bool isCancle){
	xverbose_function();

	VarCache* cache_instance = VarCache::Singleton();
	ScopeJEnv scope_jenv(cache_instance->GetJvm());
	JNIEnv *env = scope_jenv.GetEnv();

	XMessage check_results_str;
	check_results_str << "{";
    std::string jsonRes =   "\"SniffResult\":{";
    if (isCancle)
    {
        check_results_str << jsonRes << "}}";
        JNU_CallStaticMethodByMethodInfo(env, KC2Java_dumpNetSniffRes, ScopedJstring(env, check_results_str.String().c_str()).GetJstr());
        return;
    }
    
    
    std::string pingRes =  "\"PING\":[";
    std::string dnsRes =  "\"DNS\":[";
    std::string httpRes =  "\"HTTP\":[";
    std::string tcpRes =  "\"TCP\":[";
    for (const auto &m : checkResDic) {
        if (m.first == TYPE_PING)
        {
            std::vector<std::string>::const_iterator t_iter = m.second.begin();
             for (const auto &piece : m.second) {
                 pingRes +=  piece;
                 if (++t_iter != m.second.end()) {
                     pingRes += ",\n";
                 }
             }
        }
        if (m.first == TYPE_DNS)
        {
            /* code */
            std::vector<std::string>::const_iterator t_iter = m.second.begin();
             for (const auto &piece : m.second) {
                 dnsRes +=  piece;
                 if (++t_iter != m.second.end()) {
                     dnsRes += ",\n";
                 }
             }
        }
        if (m.first == TYPE_HTPP)
        {
            /* code */
            std::vector<std::string>::const_iterator t_iter = m.second.begin();
             for (const auto &piece : m.second) {
                 httpRes +=  piece;
                 if (++t_iter != m.second.end()) {
                     httpRes += ",\n";
                 }
             }
        }
        if (m.first == TYPE_TCP)
        {
            /* code */
            std::vector<std::string>::const_iterator t_iter = m.second.begin();
             for (const auto &piece : m.second) {
                 tcpRes +=  piece;
                 if (++t_iter != m.second.end()) {
                     tcpRes += ",\n";
                 }
             }
        }
     }
    pingRes += "],";
    dnsRes += "],";
    httpRes += "],";
    tcpRes += "]";
    check_results_str << jsonRes << pingRes << dnsRes << httpRes << tcpRes ;
    check_results_str << "}}";
	JNU_CallStaticMethodByMethodInfo(env, KC2Java_dumpNetSniffRes, ScopedJstring(env, check_results_str.String().c_str()).GetJstr());
    
};

DEFINE_FIND_STATIC_METHOD(KC2Java_dumpNetReportRes,KC2Java,"dumpNetReportRes","(Ljava/lang/String;)V")
void(*dumpNetReportRes)(const std::map<const std::string, std::vector<std::string>>& checkResDic)
=[](const std::map<const std::string, std::vector<std::string>>& checkResDic){
	xverbose_function();

	VarCache* cache_instance = VarCache::Singleton();
	ScopeJEnv scope_jenv(cache_instance->GetJvm());
	JNIEnv *env = scope_jenv.GetEnv();

	XMessage check_results_str;
	check_results_str << "{";
    std::string reportRes = "\"ReportResult\":[";
    for (const auto &m : checkResDic) {
         if (m.first == "report") {
             std::vector<std::string>::const_iterator t_iter = m.second.begin();
             for (const auto &piece : m.second) {
                 reportRes +=  piece;
                 if (++t_iter != m.second.end()) {
                     reportRes += ",\n";
                 }
             }
         } 
     }
    reportRes += "]";
    check_results_str << reportRes << "}" ;
	JNU_CallStaticMethodByMethodInfo(env, KC2Java_dumpNetReportRes, ScopedJstring(env, check_results_str.String().c_str()).GetJstr());
    
};

// DEFINE_FIND_STATIC_METHOD(KC2Java_reportSignalDetectResults, KC2Java, "reportSignalDetectResults", "(Ljava/lang/String;)V")
// void (*ReportNetCheckResult)(const std::vector<CheckResultProfile>& _check_results)
// = [](const std::vector<CheckResultProfile>& _check_results) {
// 	xverbose_function();

// 	VarCache* cache_instance = VarCache::Singleton();
// 	ScopeJEnv scope_jenv(cache_instance->GetJvm());
// 	JNIEnv *env = scope_jenv.GetEnv();

// 	XMessage check_results_str;
// 	check_results_str << "{";
// 	check_results_str << "\"details\":[";
// 	std::vector<CheckResultProfile>::const_iterator iter = _check_results.begin();
// 	for (; iter != _check_results.end();) {
// 		check_results_str << "{";
// 		check_results_str << "\"detectType\":" << iter->netcheck_type;
// 		check_results_str << ",\"errorCode\":" << iter->error_code;
// 		check_results_str << ",\"networkType\":" << iter->network_type;
// 		check_results_str << ",\"detectIP\":\"" << iter->ip << "\"";
// 		check_results_str << ",\"port\":" << iter->port;
// 		check_results_str << ",\"conntime\":" << iter->conntime;
// 		check_results_str << ",\"rtt\":" << iter->rtt;
// 		check_results_str << ",\"rttStr\":\"" << iter->rtt_str << "\"";
// 		check_results_str << ",\"httpStatusCode\":" << iter->status_code;
// 		check_results_str << ",\"pingCheckCount\":" << iter->checkcount;
// 		check_results_str << ",\"pingLossRate\":\"" << iter->loss_rate << "\"";
// 		check_results_str << ",\"dnsDomain\":\"" << iter->domain_name << "\"";
// 		check_results_str << ",\"localDns\":\"" << iter->local_dns << "\"";
// 		check_results_str << ",\"dnsIP1\":\"" << iter->ip1 << "\"";
// 		check_results_str << ",\"dnsIP2\":\"" << iter->ip2 << "\"";
// 		check_results_str << "}";
// 		if (++iter != _check_results.end()) {
// 			check_results_str << ",";
// 		}
// 		else {
// 			break;
// 		}
// 	}
// 	check_results_str << "]}";

// 	JNU_CallStaticMethodByMethodInfo(env, KC2Java_reportSignalDetectResults, ScopedJstring(env, check_results_str.String().c_str()).GetJstr());
// };

}}
