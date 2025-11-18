//	test.h
//	测试用程序，用于一些功能的单元测试

#ifndef _CCS_UA_UNIT_TEST_H_
#define _CCS_UA_UNIT_TEST_H_
#include "commons.h"
namespace ccsua {

	class testclass {
	public:
		testclass();
		virtual ~testclass();

		//	密码算法使用相关的测试，验证协商过程和加解密过程是否正确
		int test_ciphers(int argc, const char *argv[]);
	};
}	//	namespace ccsua

#endif //	_CCS_UA_UNIT_TEST_H_
