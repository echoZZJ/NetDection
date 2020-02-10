//
//  t_net_source.h
//  stn
//
//  Created by didi on 2020/2/8.
//

#ifndef t_net_source_h
#define t_net_source_h

#include <vector>
#include <string>
#include <map>

#include "boost/function.hpp"

#include "mars/baseevent/active_logic.h"
#include "mars/comm/thread/mutex.h"
#include "mars/comm/dns/dns.h"
#include "mars/stn/config.h"

//#include "simple_ipport_sort.h"

class ActiveLogic;

namespace mars {
    namespace stn {

struct IPPortItem;

class NetSource {
  public:
    class DnsUtil {
    public:
        DnsUtil();
        ~DnsUtil();
        
    public:
        DNS& GetNewDNS() {    return new_dns_;}
        DNS& GetDNS() {    return dns_;}

        void Cancel(const std::string& host = "");
        
    private:
        DnsUtil(const DnsUtil&);
        DnsUtil& operator=(const DnsUtil&);
        
    private:
        DNS new_dns_;
        DNS dns_;
    };

  public:
    boost::function<bool ()> fun_need_use_IPv6_;

  public:
    //set longlink host and ports
    static void SetLongLink(const std::vector<std::string>& _hosts, const std::vector<uint16_t>& _ports, const std::string& _debugip);
    //set shortlink port
    
    static void SetShortLinks(const std::vector<std::string>& _hosts, const std::vector<uint16_t>& _ports, const std::string& _debugip);
    
    static void SetShortlink(const uint16_t _port, const std::string& _debugip);
    //set backup ips for host, these ips would be used when host dns failed
    static void SetBackupIPs(const std::string& _host, const std::vector<std::string>& _ips);
    //set debug ip
    static void SetDebugIP(const std::string& _host, const std::string& _ip);
    static const std::string& GetLongLinkDebugIP();
    static const std::string& GetShortLinkDebugIP();
    
//    static void SetLowPriorityLonglinkPorts(const std::vector<uint16_t>& _lowpriority_longlink_ports);

    static void GetLonglinkPorts(std::vector<uint16_t>& _ports);
    static const std::vector<std::string>& GetLongLinkHosts();
    
    static uint16_t GetShortLinkPort();
    
    static const std::vector<std::string>& GetShortLinkHosts();
    static std::vector<uint16_t> GetShortlinkPorts();
    
    static void GetBackupIPs(std::string _host, std::vector<std::string>& _iplist);

//    static std::string DumpTable(const std::vector<IPPortItem>& _ipport_items);
    
  public:
    NetSource(ActiveLogic& _active_logic);
    ~NetSource();

  public:
    // for long link
    bool GetLongLinkItems(std::vector<IPPortItem>& _ipport_items, DnsUtil& _dns_util);

    // for short link
    bool GetShortLinkItems(const std::vector<std::string>& _hostlist, std::vector<IPPortItem>& _ipport_items, DnsUtil& _dns_util);

//    void AddServerBan(const std::string& _ip);
    
//    void ClearCache();

//    void ReportLongIP(bool _is_success, const std::string& _ip, uint16_t _port);
//    void ReportShortIP(bool _is_success, const std::string& _ip, const std::string& _host, uint16_t _port);
//
//    void RemoveLongBanIP(const std::string& _ip);
//
//    bool GetLongLinkSpeedTestIPs(std::vector<IPPortItem>& _ip_vec);
//    void ReportLongLinkSpeedTestResult(std::vector<IPPortItem>& _ip_vec);

  private:
    
    bool __HasShortLinkDebugIP(const std::vector<std::string>& _hostlist);
    
    bool __GetLonglinkDebugIPPort(std::vector<IPPortItem>& _ipport_items);
    bool __GetShortlinkDebugIPPort(const std::vector<std::string>& _hostlist, std::vector<IPPortItem>& _ipport_items);

    void __GetIPPortItems(std::vector<IPPortItem>& _ipport_items, const std::vector<std::string>& _hostlist, DnsUtil& _dns_util, bool _islonglink);
    size_t __MakeIPPorts(std::vector<IPPortItem>& _ip_items, const std::string& _host, size_t _count, DnsUtil& _dns_util, bool _isbackup, bool _islonglink);

  private:
    ActiveLogic&        active_logic_;
//    SimpleIPPortSort    ipportstrategy_;
};
        
    }
}

#endif /* t_net_source_h */
