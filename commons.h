//	commons.h
#ifndef _CCS_UA_COMMONS_H_
#define _CCS_UA_COMMONS_H_

#include <memory>
#include <mutex>
#include <string>
#include <map>
#include <set>
#include <list>
#include <vector>
#include <atomic>
#include <algorithm>
#include <functional>
#include <condition_variable>

#include "sb2bua.h"

static inline bool is_invite_request(pjsip_rx_data* rdata) {
	if (nullptr == rdata
		|| nullptr == rdata->msg_info.msg
		|| PJSIP_REQUEST_MSG != rdata->msg_info.msg->type
		|| PJSIP_INVITE_METHOD != rdata->msg_info.msg->line.req.method.id
		) {
		return false;
	}
	return true;
}
static inline bool is_invite_request(pjsip_tx_data* tdata) {
	if (nullptr == tdata
		|| nullptr == tdata->msg
		|| PJSIP_REQUEST_MSG != tdata->msg->type
		|| PJSIP_INVITE_METHOD != tdata->msg->line.req.method.id
		) {
		return false;
	}
	return true;
}
//	验证响应是否是 INVITE 200 成功响应
static inline bool is_invite_ok_response(pjsip_rx_data* rdata) {
	if (nullptr == rdata
		|| nullptr == rdata->msg_info.msg
		|| PJSIP_RESPONSE_MSG != rdata->msg_info.msg->type
		|| !(200 <= rdata->msg_info.msg->line.status.code && rdata->msg_info.msg->line.status.code < 300)
		) {
		return false;
	}
	pjsip_cseq_hdr* cseq_hdr = PJSIP_MSG_CSEQ_HDR(rdata->msg_info.msg);
	return cseq_hdr->method.id == PJSIP_INVITE_METHOD;
}

//	验证响应是否是 INVITE 200 成功响应
static inline bool is_invite_180_response(pjsip_rx_data* rdata) {
	if (nullptr == rdata
		|| nullptr == rdata->msg_info.msg
		|| PJSIP_RESPONSE_MSG != rdata->msg_info.msg->type
		|| !(180 == rdata->msg_info.msg->line.status.code)
		) {
		pj_assert(false);
		return false;
	}
	pjsip_cseq_hdr* cseq_hdr = PJSIP_MSG_CSEQ_HDR(rdata->msg_info.msg);
	return cseq_hdr->method.id == PJSIP_INVITE_METHOD;
}


//	c++1x中似乎没有信号量，使用mutex与条件变量模拟一只
class simple_semaphore {
public:
	simple_semaphore() : m_val(0) {}
	simple_semaphore(int val) : m_val(val) {
	}
	virtual ~simple_semaphore() {}

	//	定义信号量的操作，有值则返回，无值则等待
	void wait() {
		std::unique_lock<std::mutex> _lock(m_mtx);
		m_cv.wait<std::function<bool()>>(_lock, [this] { return m_val > 0; });
		m_val--;
	}
	//	触发语音播放的信号
	void post() {
		std::lock_guard<std::mutex> _lock(m_mtx);
		m_val++;
		m_cv.notify_one();
	}

protected:
	int m_val;
	std::mutex m_mtx;
	std::condition_variable m_cv;
};	//	class simple_semaphore

#endif //	_CCS_UA_COMMONS_H_
