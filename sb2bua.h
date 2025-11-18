// sb2bua.h: 标准系统包含文件的包含文件
// 或项目特定的包含文件。

#pragma once

#include <iostream>
#include <string>
#include <map>
#include <algorithm>
#include <thread>
#include <assert.h>
#include <pjsip.h>
#include <pjsip_ua.h>
#include <pjlib.h>
#include <pjlib-util.h>
#include <pjmedia.h>
#include <pjmedia-codec.h>
#include <pj/log.h>
#include <openssl/md5.h>
#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <time.h>
#include <string>
#include <sstream>
#include <memory>
#include <mutex>


// TODO: 在此处引用程序需要的其他标头。
#define THIS_FILE "b2bua_lowlevel"
#define SIP_PORT 5060

#define PJMEDIA_INVALID_PORT -1

/* ====== configuration ====== */
#define LOCAL_IP_UPSTREAM    "60.40.0.233"
#define LOCAL_IP_PHONE       "192.168.99.233"
#define SIP_SERVER           "60.40.0.205"
#define UPSTREAM_USER        "1005" //  向sip注册的用户名
#define UPSTREAM_PASS        "password555" //  向sip注册的密码
#define LOCAL_REG_USER       "111"  //  本地注册用户名
#define LOCAL_REG_PASS       "11111111" //  本地注册密码
#define REALM_DEFAULT        "b2bua"

#define CCS_USER_AGENT			"CCS Security VOIP Agent V 1.0.0.1" //	User-Agent用于简单的标识话机b2bua

extern pj_pool_t* g_pool;
extern pjmedia_endpt* g_med_endpt;

//  标识接收加密转发还是接收解密转发，由呼叫方是内端还是外端与UAC/UAS身份联合判断,满足以下规则:
/* 呼叫方是内端: UAS侧是接收后加密转发; UAC侧是接收后解密转发
* 呼叫方是外端: UAS侧是接收后解密转发; UAC侧是接收后加密转发
* 明通: 一方无法加密时使用明通
*/
typedef enum e_rtp_proc_type {
	E_PASSTHROU = 0, //	明通
	E_ENCRYPT_TRANS = 1, //	接收后加密转发
	E_DECRYPT_TRANS = 2 //	接收后解密转发
}E_RTP_PROC_TYPE;


std::string pjstr_to_string(const pj_str_t* pjs);
std::string pjstr_to_string(const pj_str_t& pjs);

//  根据路由信息，获取到相关的目标用于创建请求
typedef struct _st_route_info {
	std::string target;
	std::string from;
	std::string to;
	std::string contact;
	bool is_call_outer; //	标识是否呼叫外面，如果是则为true,如果是外端呼入的则为false

	//	这两个只有用户名信息，解析到后续用于证书验证,这两个用户名是指证书中匹配的用户名，不是b2bua本地用户
	std::string from_user, to_user;

	_st_route_info() {
		is_call_outer = false;
	}
} ST_ROUTE_INFO, * PST_ROUTE_INFO;

//	获取路由信息
PST_ROUTE_INFO get_route_info(pjsip_rx_data* rdata);


typedef struct media_sock_pair {
	int rtp_sock;           /* RTP socket (even port) */
	int rtcp_sock;          /* RTCP socket (odd port) */
	int rtp_port;          /* RTP port number */
	int rtcp_port;         /* RTCP port number */
	//	wg. 20251106, 再添加上 sock_addr 信息，用于后续创建媒体传输
	pj_sockaddr rtp_sockaddr;
	pj_sockaddr rtcp_sockaddr;
#ifdef __cplusplus
	media_sock_pair() {
		memset(this, 0, sizeof(struct media_sock_pair));
	}
#endif
} media_sock_pair_t;


//	B2BUA管理的用户,应该是只有一个,还是先做成映射
class b2buser {
public:
	b2buser() {
		m_contactport = 5060; //	这个先填默认值
		m_contact_uri = NULL;
	}
	virtual ~b2buser() {

	}
	static std::shared_ptr<b2buser> create_by_req(pjsip_rx_data* rdata) {
		std::shared_ptr<b2buser> _usr;
		assert(NULL != rdata);
		//	rdata 必须要验证是否 REGISTER REQUEST,这个函数只能处理这个协议
		pjsip_contact_hdr* contact_hdr = (pjsip_contact_hdr*)pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_CONTACT, NULL);
		if (NULL == contact_hdr) {
			//	log errs.
			assert(false); //	注册信息中必须要包含联系信息,后续将根据这个联系信息做路由转发
			return _usr;
		}

		pjsip_sip_uri* cont_uri = (pjsip_sip_uri*)pjsip_uri_get_uri(contact_hdr->uri);
		_usr.reset(new b2buser());
		_usr->reg_it();
		//	这个clone是否能完整的clone整个uri?待确认
		_usr->m_contact_uri = (pjsip_sip_uri *)pjsip_uri_clone(g_pool, cont_uri);
		_usr->set_username(pjstr_to_string(_usr->m_contact_uri->user));
		_usr->set_contactip(pjstr_to_string(_usr->m_contact_uri->host));
		_usr->set_contactport(_usr->m_contact_uri->port);
		
		return _usr;
	}
	static std::string get_un_by_req(const pjsip_rx_data* rdata) {
		if (NULL == rdata) { return ""; }
		pjsip_from_hdr* pfrom = PJSIP_MSG_FROM_HDR(rdata->msg_info.msg);
		if (NULL == pfrom) return "";
		pjsip_sip_uri* fromuri = (pjsip_sip_uri*)pjsip_uri_get_uri(pfrom->uri);
		return pjstr_to_string(fromuri->user);
	}
public:
	void set_username(const std::string& usrname) {
		m_usrname = usrname;
	}
	void set_dispname(const std::string& dispname) {
		m_dispname = dispname;
	}
	void set_contactip(const std::string& contactip) {
		m_contactip = contactip;
	}
	void set_contactport(unsigned short port) {
		if (0 == port) {
			port = 5060; //	使用默认的5060端口，如果没有提供的话(port==0)
		}
		m_contactport = port;
	}
	void set_otherparams(const std::string& params) {
		m_otherparams = params;
	}
	const std::string get_username() {
		assert(!m_usrname.empty());
		return m_usrname;
	}
	const std::string set_dispname() {
		return m_dispname;
	}
	const std::string get_contactip() {
		assert(!m_contactip.empty());
		return m_contactip;
	}

	const unsigned short get_contactport() {
		assert(m_contactport > 0);
		return m_contactport;
	}
	const std::string get_otherparams() {
		return m_otherparams;
	}
	//	获取到contact info完整的string表示
	const std::string get_contact_info() {
		pj_assert(NULL != m_contact_uri);
		char szoutbuf[128];
		memset(szoutbuf, 0, sizeof(szoutbuf));
		int retlen = pjsip_uri_print(PJSIP_URI_IN_CONTACT_HDR, m_contact_uri, szoutbuf, sizeof(szoutbuf));
		if (retlen < 1) {
			pj_assert(false);
			return "";
		}
		return std::string(szoutbuf);
	}
	//	设置过期时间
	void set_expired(unsigned int expired) {
		m_expired = expired;
	}
	unsigned int get_expired() {
		return m_expired;
	}
	//	注册它,自动填写必要的信息,这里面只有一个注册时间是需要填写的
	void reg_it() {
		m_regtime = (unsigned int)time(NULL);
	}
	bool is_timeout() {
		unsigned int tnow = time(NULL);
		return tnow < (m_regtime + m_expired);
	}
	

	pjsip_sip_uri* get_contact() {
		assert(NULL != m_contact_uri);
		return m_contact_uri;
	}
protected:
	std::string m_dispname; //	用户显示名
	std::string m_usrname;	//	用户名
	std::string m_contactip; //	联系地址
	unsigned short m_contactport; //	联系IP
	std::string m_otherparams; //	其它参数
	unsigned int m_expired; //	保留有效时间
	unsigned int m_regtime; //	保留注册的时间,

	//	保留它的联系信息
	pjsip_sip_uri* m_contact_uri;
};
//	保存b2b路由信息
class b2broute {
public:
	b2broute() {

	}
	virtual ~b2broute() {

	}
	//	根据请求信息获取到路由信息-- rdata 必须是REQUEST
	//	REQUEST由UAS接收,在一个通话中双方都有可能发起请求,现在验证方向时先通过用户路由的方式,
	//	可能会有更好的方式,待验证。如: 通过 pjsip_transport 判断是由哪个传输通道接收的,
	int get_route_info(pjsip_rx_data* rdata) {
		pj_assert(PJSIP_REQUEST_MSG == rdata->msg_info.msg->type); //	msg->type != PJSIP_REQUEST_MSG
		//	获取到target, from, to 三个参数，根据target, from确定路由方向，是对内还是对外
		pjsip_from_hdr* pfrom = PJSIP_MSG_FROM_HDR(rdata->msg_info.msg);		
		pjsip_sip_uri *ptargeturi = (pjsip_sip_uri*)pjsip_uri_get_uri(rdata->msg_info.msg->line.req.uri);
		pjsip_sip_uri* pfromuri = (pjsip_sip_uri*)pjsip_uri_get_uri(pfrom);
		
		std::string target_user(ptargeturi->user.ptr, ptargeturi->user.slen);
		std::string from_user(pfromuri->user.ptr, pfromuri->user.slen);

		//	目标地址是SIP服务器，这个请求是对外的
		if (ip_is_sip(std::string(ptargeturi->host.ptr, ptargeturi->host.slen))) {

		}
		else {
			//	目标地址不是SIP服务器，这个请求是对内的
			pj_assert(ip_is_b2bua(std::string(ptargeturi->host.ptr, ptargeturi->host.slen)));
		}
				
		//	没找到返回 NOT_FOUND
		//	return (int)PJSIP_SC_NOT_FOUND;
		return PJ_SUCCESS; //	找到返回0
	}
	//	当客户端注册时,添加客户端注册信息,需要保留客户端的联系地址及端口
	void save_clt_reg(pjsip_rx_data* rdata) {		
		pjsip_contact_hdr* contact_hdr = (pjsip_contact_hdr*)pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_CONTACT, NULL);
		if (NULL == contact_hdr) {
			//	log errs.
			return;
		}
		pjsip_sip_uri* cont_uri = (pjsip_sip_uri*)pjsip_uri_get_uri(contact_hdr->uri);
		std::string usrname(cont_uri->user.ptr, cont_uri->user.slen);
		std::string usrhost = std::string(cont_uri->host.ptr, cont_uri->host.slen);
		unsigned short _usrport = 5060;	//	默认5060端口,如果它没有发过来的话
		if (0 != cont_uri->port) {
			_usrport = cont_uri->port;
		}
		//cont_uri->method_param
		//	保存注册时必须要使用联系地址
		std::shared_ptr<b2buser> _usr = b2buser::create_by_req(rdata);
		if (!_usr) {
			assert(false);
			return;
		}
		pj_assert(_usr->get_username() == std::string(LOCAL_REG_USER)); //	
		std::lock_guard<std::mutex> _lock(m_usrmutex);
		m_usermap.insert(std::pair< std::string, std::shared_ptr<b2buser>>(_usr->get_username(), _usr));
	}
	//	当客户端注销时,清除客户端注册信息
	void remove_clt_reg(pjsip_rx_data* rdata) {
		std::lock_guard<std::mutex> _lock(m_usrmutex);
		std::string un = b2buser::get_un_by_req(rdata);
		pj_assert(un == std::string(LOCAL_REG_USER)); //	
		m_usermap.erase(un);
	}
	//	判断当前请求是否从内网侧发送,如果是,返回true,不是则返回false
	/* 是否是从内网侧发送的标识: 验证 From中的信息,获取到用户与IP地址*/
	bool is_inner(pjsip_rx_data* rdata) {
		return false;
	}
	//	当前当前的call请求是否是外呼，如果是外呼则返回true,不是外呼返回false
	bool is_call_out(pjsip_rx_data* rdata) {
		std::string un = b2buser::get_un_by_req(rdata);
		if (un == std::string(LOCAL_REG_USER)) {
			//	呼叫的用户是b2bua向sip服务注册的用户，是呼入
			return true;
		}
		return false;
	}
	//	验证一个IP是否是SIP地址,如果是则返回true,如果不是则返回false
	bool ip_is_sip(const std::string& ip) {
		return ip == std::string(SIP_SERVER);
	}
	//	验证一个IP是否是B2BUA内网地址,如果是则返回true,如果不是则返回false
	bool ip_is_b2bua(const std::string& ip) {
		return ip == std::string(LOCAL_IP_PHONE);
	}

	//	获取到一个注册的用户信息
	std::shared_ptr<b2buser> get_user(const std::string& uname) {
		std::map<std::string, std::shared_ptr<b2buser>>::iterator it = m_usermap.find(uname);
		if (it == m_usermap.end()) {
			return std::shared_ptr<b2buser>();
		}
		return it->second;
	}
protected:
	std::mutex m_usrmutex;
	std::map<std::string, std::shared_ptr<b2buser>> m_usermap;
}; //	class b2broute