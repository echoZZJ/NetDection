//
//  t_net_core.c
//  stn
//
//  Created by didi on 2020/2/8.
//

#include "t_net_core.h"
#include <stdlib.h>

#include "boost/bind.hpp"
#include "boost/ref.hpp"


#include "mars/comm/messagequeue/message_queue.h"
#include "mars/comm/network/netinfo_util.h"
#include "mars/comm/socket/local_ipstack.h"
#include "mars/comm/xlogger/xlogger.h"
#include "mars/comm/singleton.h"
#include "mars/comm/platform_comm.h"

#include "mars/app/app.h"
#include "mars/baseevent/active_logic.h"
#include "mars/baseevent/baseprjevent.h"
#include "mars/stn/config.h"
#include "mars/stn/task_profile.h"
#include "mars/stn/proto/longlink_packer.h"

#include "t_net_source.h"
#include "t_net_check_logic.h"

using namespace mars::stn;
using namespace mars::app;

#define AYNC_HANDLER asyncreg_.Get()

NetCore::NetCore()
: messagequeue_creater_(true, XLOGGER_TAG)
,asyncreg_(MessageQueue::InstallAsyncHandler(messagequeue_creater_.CreateMessageQueue()))
, net_source_(new NetSource(*ActiveLogic::Singleton::Instance()))
, netcheck_logic_(new NetCheckLogic()){
    xwarn2(TSF"publiccomponent version: %0 %1", __DATE__, __TIME__);
       xassert2(messagequeue_creater_.GetMessageQueue() != MessageQueue::KInvalidQueueID, "CreateNewMessageQueue Error!!!");
       xinfo2(TSF"netcore messagequeue_id=%_, handler:(%_,%_)", messagequeue_creater_.GetMessageQueue(), asyncreg_.Get().queue, asyncreg_.Get().seq);

       std::string printinfo;

       SIMInfo info;
       getCurSIMInfo(info);
       printinfo = printinfo + "ISP_NAME : " + info.isp_name + "\n";
       printinfo = printinfo + "ISP_CODE : " + info.isp_code + "\n";

       AccountInfo account = ::GetAccountInfo();

       if (0 != account.uin) {
           char uinBuffer[64] = {0};
           snprintf(uinBuffer, sizeof(uinBuffer), "%u", (unsigned int)account.uin);
           printinfo = printinfo + "Uin :" + uinBuffer  + "\n";
       }

       if (!account.username.empty()) {
           printinfo = printinfo + "UserName :" + account.username + "\n";
       }

       char version[256] = {0};
       snprintf(version, sizeof(version), "0x%X", mars::app::GetClientVersion());
       printinfo = printinfo + "ClientVersion :" + version + "\n";

       xwarn2(TSF"\n%0", printinfo.c_str());

       {
           //note: iOS getwifiinfo may block for 10+ seconds sometimes
           ASYNC_BLOCK_START

           xinfo2(TSF"net info:%_", GetDetailNetInfo());
           
           ASYNC_BLOCK_END
       }
                      
       xinfo_function();

       ActiveLogic::Singleton::Instance()->SignalActive.connect(boost::bind(&NetCore::__OnSignalActive, this, _1));
}



NetCore::~NetCore() {
xinfo_function();

ActiveLogic::Singleton::Instance()->SignalActive.disconnect(boost::bind(&NetCore::__OnSignalActive, this, _1));
    asyncreg_.Cancel();
    
    delete netcheck_logic_;
    delete net_source_;
    MessageQueue::MessageQueueCreater::ReleaseNewMessageQueue(MessageQueue::Handler2Queue(asyncreg_.Get()));
}

void NetCore::__OnSignalActive(bool _isactive) {
    ASYNC_BLOCK_START
    
//    anti_avalanche_->OnSignalActive(_isactive);
    
    ASYNC_BLOCK_END
}

void NetCore::__Release(NetCore* _instance) {
    if (MessageQueue::CurrentThreadMessageQueue() != MessageQueue::Handler2Queue(_instance->asyncreg_.Get())) {
        WaitMessage(AsyncInvoke((MessageQueue::AsyncInvokeFunction)boost::bind(&NetCore::__Release, _instance), _instance->asyncreg_.Get(), "NetCore::__Release"));
        return;
    }
    
    delete _instance;
}
