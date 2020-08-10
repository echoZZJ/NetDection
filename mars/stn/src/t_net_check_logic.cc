//
//  t_net_check_logic.cpp
//  stn
//
//  Created by didi on 2020/2/8.
//

#include "t_net_check_logic.h"

#include <map>
#include <vector>

#include "boost/bind.hpp"

#include "mars/comm/xlogger/xlogger.h"
#include "mars/comm/thread/lock.h"
#include "mars/comm/comm_frequency_limit.h"
#include "mars/comm/time_utils.h"
#include "mars/sdt/sdt_logic.h"
#include "mars/sdt/constants.h"

#include "t_net_source.h"

using namespace mars::stn;
using namespace mars::sdt;

static const unsigned long kLimitTimeSpan = 60 * 60 * 1000;  // 60 min
static const size_t kLimitCount = 1;

NetCheckLogic::NetCheckLogic()
    : frequency_limit_(new CommFrequencyLimit(kLimitCount, kLimitTimeSpan))
    {
    xinfo_function();
}

NetCheckLogic::~NetCheckLogic() {
    xinfo_function();
    delete frequency_limit_;
}
void NetCheckLogic::__StartNetCheckOption(uint16_t optionType) {
    //get longlink check map
    CheckIPPorts longlink_check_items;
    //shortlink check map
    CheckIPPorts shortlink_check_items;
    std::vector<std::string> shortlink_hostlist = NetSource::GetShortLinkHosts();
    std::vector<uint16_t> shortlink_ports = NetSource::GetShortlinkPorts();
    for (std::vector<std::string>::iterator iter = shortlink_hostlist.begin(); iter != shortlink_hostlist.end(); ++iter) {
        std::vector<std::string> shortlink_iplist;
//        dns_util_.GetNewDNS().GetHostByName(*iter, shortlink_iplist);
        if (shortlink_iplist.empty()) dns_util_.GetDNS().GetHostByName(*iter, shortlink_iplist);
        if (shortlink_iplist.empty()) {
            xerror2(TSF"no dns ip for shortlink host: %_", *iter);
            continue;
        }
        shortlink_iplist.erase(unique(shortlink_iplist.begin(), shortlink_iplist.end()), shortlink_iplist.end());
        std::vector<CheckIPPort> check_ipport_list;
        for (std::vector<std::string>::iterator ip_iter = shortlink_iplist.begin(); ip_iter != shortlink_iplist.end(); ++ip_iter) {
            for (std::vector<uint16_t>::iterator port_iter = shortlink_ports.begin(); port_iter != shortlink_ports.end(); ++port_iter) {
                CheckIPPort ipport_item(*ip_iter, *port_iter);
                check_ipport_list.push_back(ipport_item);
            }
        }
        if (!check_ipport_list.empty()) shortlink_check_items.insert(std::pair< std::string, std::vector<CheckIPPort> >(*iter, check_ipport_list));
    }
    
    int mode = optionType;
    xinfo2(TSF"net check mode is %_",mode);
    if (!shortlink_check_items.empty()) StartActiveCheck(longlink_check_items, shortlink_check_items, mode, NETSNIFF_TIMEOUT);
    else
        CancelActiveCheck();
}
void NetCheckLogic::__StartNetCheck() {
    //get longlink check map
    CheckIPPorts longlink_check_items;
    std::vector<std::string> longlink_hosts = NetSource::GetLongLinkHosts();
    if (longlink_hosts.empty()) {
        xerror2(TSF"longlink host is empty.");
        return;
    }

    std::vector<uint16_t> longlink_portlist;
    NetSource::GetLonglinkPorts(longlink_portlist);
    if (longlink_portlist.empty()) {
        xerror2(TSF"longlink no port");
        return;
    }

    for (std::vector<std::string>::iterator host_iter = longlink_hosts.begin(); host_iter != longlink_hosts.end(); ++host_iter) {
        std::vector<std::string> longlink_iplist;
//        dns_util_.GetNewDNS().GetHostByName(*host_iter, longlink_iplist);
        if (longlink_iplist.empty()) dns_util_.GetDNS().GetHostByName(*host_iter, longlink_iplist);
        if (longlink_iplist.empty()) {
            xerror2(TSF"no dns ip for longlink host: %_", *host_iter);
            continue;
        }
        std::sort( longlink_iplist.begin(), longlink_iplist.end() );
        longlink_iplist.erase(unique(longlink_iplist.begin(), longlink_iplist.end()), longlink_iplist.end());
        std::vector<CheckIPPort> check_ipport_list;
        for (std::vector<uint16_t>::iterator port_iter = longlink_portlist.begin(); port_iter != longlink_portlist.end(); ++port_iter) {
            for (std::vector<std::string>::iterator ip_iter = longlink_iplist.begin(); ip_iter != longlink_iplist.end(); ++ip_iter) {
                CheckIPPort ipport_item(*ip_iter, *port_iter);
                check_ipport_list.push_back(ipport_item);
            }
        }

        if (!check_ipport_list.empty()) longlink_check_items.insert(std::pair< std::string, std::vector<CheckIPPort> >(*host_iter, check_ipport_list));
    }

    //shortlink check map
    CheckIPPorts shortlink_check_items;
    std::vector<std::string> shortlink_hostlist = NetSource::GetShortLinkHosts();
    std::vector<uint16_t> shortlink_ports = NetSource::GetShortlinkPorts();
    for (std::vector<std::string>::iterator iter = shortlink_hostlist.begin(); iter != shortlink_hostlist.end(); ++iter) {
        std::vector<std::string> shortlink_iplist;
//        dns_util_.GetNewDNS().GetHostByName(*iter, shortlink_iplist);
        if (shortlink_iplist.empty()) dns_util_.GetDNS().GetHostByName(*iter, shortlink_iplist);
        if (shortlink_iplist.empty()) {
            xerror2(TSF"no dns ip for shortlink host: %_", *iter);
            continue;
        }
        shortlink_iplist.erase(unique(shortlink_iplist.begin(), shortlink_iplist.end()), shortlink_iplist.end());
        std::vector<CheckIPPort> check_ipport_list;
        for (std::vector<std::string>::iterator ip_iter = shortlink_iplist.begin(); ip_iter != shortlink_iplist.end(); ++ip_iter) {
            for (std::vector<uint16_t>::iterator port_iter = shortlink_ports.begin(); port_iter != shortlink_ports.end(); ++port_iter) {
                CheckIPPort ipport_item(*ip_iter, *port_iter);
                check_ipport_list.push_back(ipport_item);
            }
        }
        if (!check_ipport_list.empty()) shortlink_check_items.insert(std::pair< std::string, std::vector<CheckIPPort> >(*iter, check_ipport_list));
    }
    
    int mode = (NET_CHECK_BASIC | NET_CHECK_LONG | NET_CHECK_SHORT);
    xinfo2(TSF"net check mode is %_",mode);
    if (!longlink_check_items.empty() || !shortlink_check_items.empty()) StartActiveCheck(longlink_check_items, shortlink_check_items, mode, NETSNIFF_TIMEOUT);
    else
        CancelActiveCheck();
}
