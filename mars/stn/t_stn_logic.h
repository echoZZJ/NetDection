//
//  t_stn_logic.h
//  stn
//
//  Created by didi on 2020/2/8.
//

#ifndef t_stn_logic_h
#define t_stn_logic_h

#include <stdint.h>
#include <string>
#include <map>
#include <vector>

#include "mars/comm/autobuffer.h"
#include "mars/stn/stn.h"


namespace mars{

namespace comm {
class ProxyInfo;
}

namespace stn{
//callback interface
class Callback
{
public:
    virtual ~Callback() {}
    //底层询问上层该host对应的ip列表
    virtual std::vector<std::string> OnNewDns(const std::string& host) = 0;
    
};
void SetCallback(Callback* const callback);

  extern void (*StartNetWorkSniffering)();
  extern void (*StartNetWorkCheck)(const std::string& type);
// 'host' will be ignored when 'debugip' is not empty.
   extern void (*SetLonglinkSvrAddr)(const std::string& host, const std::vector<uint16_t> ports, const std::string& debugip);
   
   // 'task.host' will be ignored when 'debugip' is not empty.
   extern void (*SetShortlinkSvrAddr)(const uint16_t port, const std::string& debugip);

   extern void (*SetShortlinkSvrAddrs)(const std::vector<std::string>& host, const std::vector<uint16_t> ports, const std::string& debugip);
}
}
#endif /* t_stn_logic_h */
