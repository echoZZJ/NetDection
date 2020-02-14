//
//  traceroutechecker.h
//  sdt
//
//  Created by didi on 2020/2/13.
//

#ifndef traceroutechecker_h
#define traceroutechecker_h

#include "mars/sdt/sdt.h"

#include "basechecker.h"
namespace mars {
namespace sdt {

class TraceRouteChecker : public BaseChecker {
    public:
    TraceRouteChecker();
    virtual ~TraceRouteChecker();
    
    virtual int StartDoCheck(CheckRequestProfile& _check_request);
protected:
    virtual void __DoCheck(CheckRequestProfile &_check_request);
};

}
}

#endif /* traceroutechecker_h */
