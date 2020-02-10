//
//  t_net_core.h
//  stn
//
//  Created by didi on 2020/2/8.
//

#ifndef t_net_core_h
#define t_net_core_h

#include "mars/comm/singleton.h"
#include "mars/comm/messagequeue/message_queue.h"

#include "mars/stn/stn.h"
#include "mars/stn/config.h"

namespace mars {
    
    namespace stn {

class NetSource;
class NetCheckLogic;
    
class NetCore {
    public:
    SINGLETON_INTRUSIVE(NetCore, new NetCore, __Release);
    
    
    public:
       MessageQueue::MessageQueue_t GetMessageQueueId() { return messagequeue_creater_.GetMessageQueue(); }
       NetSource& GetNetSourceRef() {return *net_source_;}
    
    private:
    NetCore();
    virtual ~NetCore();
    static void __Release(NetCore* _instance);
    
    private:
      NetCore(const NetCore&);
      NetCore& operator=(const NetCore&);
      void    __OnSignalActive(bool _isactive);

    private:
      MessageQueue::MessageQueueCreater   messagequeue_creater_;
      MessageQueue::ScopeRegister         asyncreg_;
      NetSource*                          net_source_;
      NetCheckLogic*                      netcheck_logic_;
    
};
    }
}

#endif /* t_net_core_h */
