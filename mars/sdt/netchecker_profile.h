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
 * netchecker_profile.h
 *
 *  Created on: 2016年4月11日
 *      Author: caoshaokun
 */

#ifndef SDT_SRC_NETCHECKER_PROFILE_H_
#define SDT_SRC_NETCHECKER_PROFILE_H_

#include <string>
#include <vector>
#include <map>
#include <stdint.h>

#include "mars/sdt/sdt.h"
#include "mars/sdt/constants.h"
#include "comm/platform_comm.h"


namespace mars {
namespace sdt  {

struct CheckResultProfile {

	CheckResultProfile() {
		Reset();
	}

	void Reset() {
		netcheck_type = -1;

		error_code = 0;
		network_type = 0;

		ip.clear();
		port = 0;
		conntime = 0;
		rtt = 0;

		url.clear();
		status_code = 0;

		checkcount = 0;
		loss_rate.clear();

		domain_name.clear();
		local_dns.clear();
		ip1.clear();
		ip2.clear();
        traceRoute.clear();
	}
    std::string netWorkContent() {
        std::string netType = "";
         switch (::getNetInfo()) {
            case kNoNet: {
                netType = "No Net";
            }
                break;
            case kWifi: {
                netType = "WIFI";
            }
                break;
            case kMobile: {
                netType = "Mobile";
            }
                break;
                
            case kOtherNet: {
                netType = "Other";
            }
                break;
                
             default:{
                netType = "UnKnow";
             }
                break;
         }
        return netType;
    }
    std::string toJson() {
        std::string errorStr = (error_code == 0) ? "success" : "fail";
       
        if(netcheck_type == kPingCheck){
            return std::string("{") + "\"netcheck_type\":"+ "\""+"PING"+"\""+ "," +"\"error_code\":"+"\""+errorStr+"\""+","+"\"network_type\":"+"\""+netWorkContent()+"\""+","+"\"rtt_str\":"+"\""+rtt_str.substr(0,rtt_str.find(".")+3)+"\""+","+"\"domain_name\":"+"\""+domain_name+"\""+","+"\"ip\":"+"\""+ip+"\""+","+"\"url\":"+"\""+url+"\""+std::string("}");
        }
        if(netcheck_type == kDnsCheck){
            return std::string("{") + "\"netcheck_type\":"+ "\""+ "DNS"+ "\""+"," +"\"error_code\":"+"\""+errorStr+"\""+","+"\"network_type\":"+"\""+netWorkContent()+"\""+","+"\"domain_name\":"+"\""+domain_name+"\""+","+"\"ip\":"+"\""+ip+"\""+","+"\"ip1\":"+"\""+ip1+"\""+","+"\"ip2\":"+"\""+ip2+"\""+","+"\"url\":"+"\""+url+"\""+std::string("}");
        }
        if(netcheck_type == kTcpCheck){
            return std::string("{") + "\"netcheck_type\":"+ "\""+"TCP"+"\""+ "," +"\"error_code\":"+"\""+errorStr+"\""+","+"\"network_type\":"+"\""+netWorkContent()+"\""+","+"\"rtt_str\":"+"\""+rtt_str.substr(0,rtt_str.find(".")+3)+"\""+","+"\"domain_name\":"+"\""+domain_name+"\""+","+"\"rtt\":"+"\""+std::to_string(rtt)+"\""+","+"\"url\":"+"\""+url+"\""+std::string("}");
        }
        if(netcheck_type == kHttpCheck){
            return std::string("{") + "\"netcheck_type\":"+ "\""+"HTTP"+"\""+ "," +"\"error_code\":"+"\""+errorStr+"\""+","+"\"network_type\":"+"\""+netWorkContent()+"\""+","+"\"domain_name\":"+"\""+domain_name+"\""+","+"\"httpRequestStatusCode\":"+"\""+std::to_string(status_code)+"\""+","+"\"url\":"+"\""+url+"\""+std::string("}");
        }
        if(netcheck_type == kTracerouteCheck){
             return std::string("{") + "\"netcheck_type\":"+ "\""+"HTTP"+"\""+ "," +"\"error_code\":"+"\""+errorStr+"\""+","+"\"network_type\":"+"\""+netWorkContent()+"\""+","+"\"domain_name\":"+"\""+domain_name+"\""+","+"\n"+"\"traceRoute\":"+"\""+traceRoute+"\""+"\n"+","+"\"url\":"+"\""+url+"\""+std::string("}");
        }
        return "";
    }

	int netcheck_type;	//ping dns tcp http

    int error_code;
    int network_type;

    std::string ip;		//ping tcp http
	unsigned int port;	//tcp http
    uint64_t conntime;
    uint64_t rtt;		//tcp http rtt, dns resolve time
    std::string rtt_str;	//ping

    std::string url;
    int status_code;	//http

    unsigned int checkcount;	//ping
    std::string loss_rate;		//ping

    std::string domain_name;	//dns host
    std::string local_dns;		//dns
    std::string ip1;			//dns
    std::string ip2;			//dns
    
    std::string traceRoute;  //traceRoute

};

struct CheckRequestProfile {

	CheckRequestProfile() {
		Reset();
	}

	void Reset() {
		longlink_items.clear();
		shortlink_items.clear();

		checkresult_profiles.clear();
		mode = NET_CHECK_BASIC;
		check_status = kCheckContinue;

		total_timeout = 0;
	}

	CheckIPPorts longlink_items;
	CheckIPPorts shortlink_items;

	int	mode;
	CheckStatus check_status;

	int32_t total_timeout;

	std::vector<CheckResultProfile> checkresult_profiles;

};

}}

#endif /* SDT_SRC_NETCHECKER_PROFILE_H_ */
