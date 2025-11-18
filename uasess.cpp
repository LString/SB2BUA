//	uasess.cpp
//	uasess的实现
#include "uasess.h"

extern pj_pool_t* g_pool;
extern pjsip_endpoint* g_endpt;

namespace ccsua {

	//	获取到 rx 信息并打印到字符串
	std::string rx_info(pjsip_rx_data* rdata)
	{
		std::string msg;
		char* pmsg = new char[8192];
		memset(pmsg, 0, 8192);
		snprintf(pmsg, 8192, "RX %d bytes %s from %s %s:%d:\n"
			"%.*s\n"
			"--end msg--",
			rdata->msg_info.len,
			pjsip_rx_data_get_info(rdata),
			rdata->tp_info.transport->type_name,
			rdata->pkt_info.src_name,
			rdata->pkt_info.src_port,
			(int)rdata->msg_info.len,
			rdata->msg_info.msg_buf);
		msg = std::string(pmsg);
		delete pmsg;
		return msg;
	}

	//	获取到 tx 信息并打印到字符串
	std::string tx_info(pjsip_tx_data* tdata)
	{
		std::string msg;
		char* pmsg = new char[8192];
		memset(pmsg, 0, 8192);
		snprintf(pmsg, 8192, "TX %ld bytes %s to %s %s:%d:\n"
			"%.*s\n"
			"--end msg--",
			(tdata->buf.cur - tdata->buf.start),
			pjsip_tx_data_get_info(tdata),
			tdata->tp_info.transport->type_name,
			tdata->tp_info.dst_name,
			tdata->tp_info.dst_port,
			(int)(tdata->buf.cur - tdata->buf.start),
			tdata->buf.start);
		msg = std::string(pmsg);
		/* Always return success, otherwise message will not get sent! */
		delete pmsg;
		return msg;
	}
		

	uasess::uasess(): m_last_uas_request(nullptr), m_last_uac_request(nullptr), 
		m_last_uas_response(nullptr), m_last_uac_response(nullptr), m_calldirect(E_UNDEFINED), m_cseq(1),
	m_uas_rtp_port(0), m_uas_rtcp_port(0), m_uac_rtp_port(0), m_uac_rtcp_port(0), 
		m_caller_s_contact(nullptr), m_callee_r_contact(nullptr),
	m_caller_s_route(nullptr), m_callee_r_route(nullptr), m_session_running(false),
		m_uas_remote_rtp(0), m_uas_remote_rtcp(0), m_uac_remote_rtp(0), m_uac_remote_rtcp(0), m_remote_can_enc(false),
		m_invite_ok(false), uac_thread(nullptr), uas_thread(nullptr), 
		m_is_hungup(false)
	{}
	uasess::~uasess() {}

	//	创建UAC侧的呼叫请求--它使用最后一次的UAS请求创建，不传入其它参数,如果失败则返回false
	//	创建的呼叫请求需要将UAS接收到的请求中的media_session替换完成地址信息后附加上
	pjsip_tx_data* uasess::create_uac_invite() {
		
		pjsip_tx_data* uac_invite_req = nullptr;
		pj_assert(nullptr != m_last_uas_request);
		if (!is_invite_request(m_last_uas_request))
		{
			pj_assert(false);
			return nullptr;
		}
		//	INVITE 的请求根据配置的路由信息获取到目标--BYE/ACk请求似乎不能根据路由信息创建，至少它的目标要改成真机目标
		//	并且还可能要将路由信息添加进去
		PST_ROUTE_INFO prinfo = get_route_info(m_last_uas_request);
		if (nullptr == prinfo) {
			return nullptr;
		}
		//	开始创建通话时需要将加密参数创建出来并加载完成
		if (!m_ciphers) {
			m_ciphers = std::make_shared<sesscipher>();
			if (!sesscipher::self_can_enc()) {
				//	自身的参数加载失败，后续无法进行加密通信
				this->m_remote_can_enc = false;
				pj_assert(false);
			}
			else {
				m_ciphers->load_from_config();
				m_ciphers->generate_temp_para();	//	产生临时参数
			}
		}
		//	创建UAC侧的会话时需要立即将会话媒体对象创建出来，再根据呼叫的方向在合适的时候填上媒体网络信息和SDP信息
		if (!m_sessmedia) {
			m_sessmedia = std::make_shared<sessmedia>();
		}

		//	创建INVITE的时候就已经能获取到它的呼叫方向,现在需要解析对端的帐户，用于后续与证书匹配
		if (prinfo->is_call_outer) {
			this->m_calldirect = E_INNER_CALL;
			m_ciphers->set_role_is_sender();	//	需要设置协商的方向: 内端拔打，这端是发起方
			m_ciphers->set_remote_name(prinfo->to_user);
		}
		else {
			this->m_calldirect = E_OUTER_CALL;
			m_ciphers->set_role_is_receiver();	//	需要设置协商的方向: 外端拔打，这端是接收方
			m_ciphers->set_remote_name(prinfo->from_user);
			//	如果是外端呼入的，需要解析它的请求中是否有我们需要的证书和临时公钥
			if (!m_ciphers->parse_remote_by_rx_data(m_last_uas_request)) {
				this->m_remote_can_enc = false;
			}
		}

		pj_str_t ptarget, pfrom, pto, pcontact;
		ptarget = pj_strdup3(g_pool, prinfo->target.c_str());
		pfrom = pj_strdup3(g_pool, prinfo->from.c_str());
		pto = pj_strdup3(g_pool, prinfo->to.c_str());
		pcontact = pj_strdup3(g_pool, prinfo->contact.c_str());
		pjsip_cid_hdr* cidhdr = pjsip_cid_hdr_create(g_pool);
		pj_create_unique_string(g_pool, &cidhdr->id);

		m_cseq = sessman::next_cseq();
		pj_status_t status = pjsip_endpt_create_request(g_endpt,
			&pjsip_invite_method,
			&ptarget, //    target
			&pfrom, //    from
			&pto, //    to
			&pcontact, //    contact
			NULL, //&cidhdr->id, //    call_id, 尝试由pjsip自行生成
			m_cseq.load(), //   cseq,
			NULL,//   text
			&uac_invite_req
		);
		if (status != PJ_SUCCESS)
		{
			pj_assert(0);
			return NULL;
		}

		//	记录uas与uac侧的callid
		this->m_callid_uas = std::string(m_last_uas_request->msg_info.cid->id.ptr, m_last_uas_request->msg_info.cid->id.slen);
		pjsip_cid_hdr *puac_cid = PJSIP_MSG_CID_HDR(uac_invite_req->msg);
		pj_assert(nullptr != puac_cid);
		this->m_callid_uac = std::string(puac_cid->id.ptr, puac_cid->id.slen);
		
		pjsip_via_hdr* pviahdr = (pjsip_via_hdr*)pjsip_msg_find_hdr(uac_invite_req->msg, PJSIP_H_VIA, NULL);

		//  将VIA添加到第一个
		if (pviahdr->branch_param.slen == 0) {
			pj_str_t tmp;
			pviahdr->branch_param.ptr = (char*)
				pj_pool_alloc(g_pool, PJSIP_MAX_BRANCH_LEN);
			pviahdr->branch_param.slen = PJSIP_MAX_BRANCH_LEN;
			pj_memcpy(pviahdr->branch_param.ptr, PJSIP_RFC3261_BRANCH_ID,
				PJSIP_RFC3261_BRANCH_LEN);
			tmp.ptr = pviahdr->branch_param.ptr + PJSIP_RFC3261_BRANCH_LEN + 2;
			*(tmp.ptr - 2) = 80; *(tmp.ptr - 1) = 106;
			pj_generate_unique_string(&tmp);
		}
		//  VIA的其它参数
		pviahdr->transport = pj_str((char*)"UDP");
		if (!caller_s_isinner()) {	//	呼入的时候，UAS是外侧的
			pviahdr->sent_by.host = pj_str((char*)LOCAL_IP_PHONE);
			this->m_callid_inner = this->m_callid_uac;
			this->m_callid_outer = this->m_callid_uas;
		}
		else {	//	呼出的时候，UAS是内侧的
			pviahdr->sent_by.host = pj_str((char*)LOCAL_IP_UPSTREAM);
			this->m_callid_inner = this->m_callid_uas;
			this->m_callid_outer = this->m_callid_uac;
		}
		//	这个端口需要注意一下，应该是个活的,对内默认5060,对外可能随机。现在对外也是5060,先暂时填死
		pviahdr->sent_by.port = 5060;
		pviahdr->rport_param = 0;

		//	再添加 User-Agent 标识，用于简单识别呼叫方
		pj_str_t user_agent = pj_strdup3(g_pool, CCS_USER_AGENT);
		const pj_str_t _ua_name = { (char *)"User-Agent", 10 };
		pjsip_generic_string_hdr* user_agent_hdr = pjsip_generic_string_hdr_create(g_pool, &_ua_name, &user_agent);
		if (nullptr != user_agent_hdr) {
			pjsip_msg_add_hdr(uac_invite_req->msg, (pjsip_hdr*)user_agent_hdr);
		}		

		//	SDP则获取到媒体端口后更新
		if (m_last_uas_request->msg_info.msg->body && m_last_uas_request->msg_info.msg->body->len > 0) {
			//  复制sdp，更新在单独的 update uac invite sdp 函数中完成
			std::string _body((char *)m_last_uas_request->msg_info.msg->body->data, m_last_uas_request->msg_info.msg->body->len);
			//	wg. 20251110, 在创建UAC的INVITE时，_body是UAS INVITE,根据它的呼叫方向,将UAS INVITE中的SDP设置给会话媒体相应的sdp
			//	设置规则详见 mediaplayer.h 头中的注释
			if (caller_s_isinner()) {
				m_sessmedia->set_remote_sdp_session_inner(_body);
			}
			else {
				m_sessmedia->set_remote_sdp_session_outer(_body);
			}
			add_msg_body(uac_invite_req->msg, _body);
		}

		//	保存最后一次处理的request
		this->set_last_uac_request(uac_invite_req);

		//	记录拔打方的路由信息--如果有的话
		if (nullptr != this->m_last_uas_request->msg_info.record_route) {
			//	把响应中的 record_route改成route放到请求中
			m_caller_s_route = (pjsip_rr_hdr*)pjsip_hdr_clone(g_pool, this->m_last_uas_request->msg_info.record_route);
			pjsip_routing_hdr_set_route(m_caller_s_route);
		}

		return uac_invite_req;
	}

	// 将协商认证信息添加到sdp中
	pj_status_t uasess::append_key_exchanges(pjmedia_sdp_session* pmedia) {
		if (!m_ciphers || nullptr == pmedia) {
			return PJ_ERESOLVE;
		}
		pj_str_t _ucert = pj_strdup3(g_pool, m_ciphers->get_self_cert().c_str());
		pj_str_t _tmpkey = pj_strdup3(g_pool, m_ciphers->get_self_tmp_pubkey().c_str());
		pjmedia_sdp_attr* pcertattr = pjmedia_sdp_attr_create(g_pool, "ucert", &_ucert);
		pjmedia_sdp_attr* ptmpkeyattr = pjmedia_sdp_attr_create(g_pool, "tmpkey", &_tmpkey);
		pjmedia_sdp_session_add_attr(pmedia, pcertattr);
		pjmedia_sdp_session_add_attr(pmedia, ptmpkeyattr);

		return PJ_SUCCESS;
	}
	pj_status_t uasess::remove_key_exchange(pjmedia_sdp_session* pmedia) {
		
		//	TODO. pjmedia_sdp_session 似乎没有移除属性的API..
		return PJ_SUCCESS;
	}
	//	更新UAC侧invite的sdp信息--媒体信息
	//	更新，因此在创建uac请求的时候没有端口，所以更新放到了网络信息创建完成后进行
	pjsip_tx_data* uasess::update_uac_invite_sdp() {
		if (!is_invite_request(m_last_uac_request)
			|| !is_invite_request(m_last_uas_request)) {
			pj_assert(false);	//	更新时一定是创建完成后，媒体通道创建完成了就更新,此时最后一个uac_request一定是invite的
			return nullptr;
		}
		//	更新媒体信息时需要复制UAS侧的请求中的媒体信息，然后只更新网络参数
		pj_assert(0 != m_uas_rtp_port && 0 != m_uas_rtcp_port && 0 != m_uac_rtp_port && 0 != m_uas_rtcp_port);
		pjmedia_sdp_session* pmedia = nullptr;
		if (nullptr == m_last_uas_request->msg_info.msg->body->data || m_last_uas_request->msg_info.msg->body->len < 1) {
			pj_assert(false); //	请求包中无媒体信息，无法更新。这应该是一个不合理的请求，如果INVITE中无媒体信息，它的媒体信息
			//	似乎没法再获取到。
			return m_last_uac_request;
		}
		//	这个创建出来的sdp_session还不知道如何销毁...
		pj_status_t status = pjmedia_sdp_parse(g_pool, 
			(char *)m_last_uas_request->msg_info.msg->body->data, m_last_uas_request->msg_info.msg->body->len, &pmedia);
		pj_assert(PJ_SUCCESS == status);
		std::string _body((char*)m_last_uas_request->msg_info.msg->body->data, m_last_uas_request->msg_info.msg->body->len);
		if (this->caller_s_isinner()) {
			//	内端话机发起呼叫时，INVITE REQ中有它的媒体信息，此时可以获取到远端媒体信息, 本地媒体在响应 200 INVITE 时获得
			//	此时会话媒体的网络参数是UAS侧的，在更新 media信息前需要设置这个值，避免 remote 的信息被切换成外端地址
			m_sessmedia->set_netpara_inner(m_uas_media);
			m_sessmedia->set_netpara_outer(m_uac_media);
		}
		else {
			m_sessmedia->set_netpara_inner(m_uac_media);
			m_sessmedia->set_netpara_outer(m_uas_media);
		}
		
		//	更新它的联系地址和端口
		
		//	解析UAS与UAC侧 media 中的地址与端口信息，作为后续创建媒体桥使用
		this->m_uas_remote_ip = std::string(pmedia->conn->addr.ptr, pmedia->conn->addr.slen);
		this->m_uas_remote_rtp = pmedia->media[0]->desc.port;
		this->m_uas_remote_rtcp = pmedia->media[0]->desc.port + 1; //	默认rtcp是rtp+1,事实上可能不一定对，需要根据协议中解析。
				
		status = update_media_session(pmedia, pjsip_role_e::PJSIP_ROLE_UAC);

		//	如果是内端话机创建的呼叫，创建出的UAC请求中需要添加上自己的证书与公钥信息
		if (this->caller_s_isinner()) {
			append_key_exchanges(pmedia);
		}
		else {
			//	如果是外端话机创建的呼叫，它里面可能会有证书公钥信息，应该需要清除掉，避免传递到内网话机
			remove_key_exchange(pmedia);
		}
		
		//  如果有rtcp, 则修改它的rtcp port
		pjmedia_sdp_rtcp_attr rtcp;
		//pjmedia_sdp_attr_get_rtcp(pmedia->attr[0], &rtcp);
		//	然后将更新过的媒体信息更新到uac invite request中
		std::string body;
		body.resize(32768);
		int bodysize = pjmedia_sdp_print(pmedia, (char *)body.c_str(), 32768);
		pj_assert(bodysize > 0);
		body.resize(bodysize);
		status = add_msg_body(m_last_uac_request->msg, body);
		pj_assert(PJ_SUCCESS == status);

		//	UAC INVITE请求创建后，更新完成 SDP 时需要根据呼叫方向设置媒体端口的本地SDP,设置规则详见 mediaplayer.h 中的描述
		if (this->caller_s_isinner()) {
			m_sessmedia->set_local_sdp_session_outer(body);
		}
		else {
			m_sessmedia->set_local_sdp_session_inner(body);
		}
				
		return m_last_uac_request;
	}
	//	根据roletype决定待更新的pmedia中的信息应该是选择UAC侧的还是UAS侧的
	pj_status_t uasess::update_media_session(pjmedia_sdp_session* pmedia, pjsip_role_e roletype) {
		pj_status_t status = PJ_SUCCESS;
		/*	媒体信息应该是在呼叫建立阶段完成交互，此时UAC/UAS身份还没有转换，根据呼叫方向可以确定出UAC还是UAS
			媒体信息的更新是两个方向，只靠UAC/UAS无法区分出方向，完整的方向只有对内和对外两种。
			对内: 使用 LOCAL_IP_PHONE 地址， 创建请求/发送响应中更新，满足以下两个条件中任意一个:
				(外部呼入 && roletype==UAC) || (内部呼出 && roletype==UAS)
				方向是打进来并且创建UAC请求		方向是打出去，并且回复UAS的响应
			对外: 使用向SIP注册的地址, 创建请求/发送响应中更新，满足以下两个条件中任意一个:
				(外部呼入 && roletype==UAS) || (内部呼出 && roletype==UAC)
				方向是打进来并且回复UAS响应		方向是打出去，并且创建UAC请求
			*/
		char* pconnaddr = NULL, poriguser[64];
		memset(poriguser, 0, sizeof(poriguser));
		bool us_inner_ip = false;
		us_inner_ip = (this->caller_s_isouter() && pjsip_role_e::PJSIP_ROLE_UAC == roletype)
			|| (this->caller_s_isinner() && pjsip_role_e::PJSIP_ROLE_UAS == roletype);
		if (/*this->caller_r_isinner()*/us_inner_ip) {
			//	如果是外呼进来，UAC的联系地址是本地内网地址，但是注意用户信息是外部用户，而不是本地向SIP注册的用户
			//	也不是本地固定用户，避免话机端显示的信息不正确
			pconnaddr = (char*)LOCAL_IP_PHONE;
			pjsip_to_hdr* pto = PJSIP_MSG_TO_HDR(m_last_uas_request->msg_info.msg);
			pjsip_sip_uri* psuri = (pjsip_sip_uri*)pjsip_uri_get_uri(pto->uri);
			memcpy(poriguser, psuri->user.ptr, psuri->user.slen);
		}
		else {
			//	如果是内呼出去，UAC的联系地址是向SIP服务注册的地址
			pconnaddr = (char*)LOCAL_IP_UPSTREAM;
			memcpy(poriguser, UPSTREAM_USER, strlen(UPSTREAM_USER));
			
		}
		pmedia->conn->addr = pj_strdup3(g_pool, pconnaddr);
		pmedia->origin.user = pj_strdup3(g_pool, poriguser);
		pmedia->origin.addr = pj_strdup3(g_pool, pconnaddr);
		unsigned short media_port = 0;
		if (pjsip_role_e::PJSIP_UAC_ROLE == roletype) {
			media_port = this->m_uac_rtp_port;
		}
		else if (pjsip_role_e::PJSIP_UAS_ROLE == roletype) {
			media_port = this->m_uas_rtp_port;
		}
		else {
			pj_assert(false);
			return PJ_EINVALIDOP;
		}
		if (pmedia->media_count >= 1) {
			//	如果有多条媒体信息，是不是应该创建的是一个媒体信息组，一一对应。。。
			//	多条媒体信息的情况是不是应对着rtp与rtcp??应该不是
			pj_assert(1 == pmedia->media_count);
			for (int i = 0; i < pmedia->media_count; i++) {
				pmedia->media[i]->desc.port = media_port;
			}
		}
		else {
			//	无媒体信息
			pj_assert(false);
		}

		return status;	
	}

	pj_status_t uasess::add_msg_body(pjsip_msg* msg, const std::string& body, const std::string& content_type/* = "application"*/) {
		
		/* Create body instance */
		pjsip_msg_body* msg_body = (pjsip_msg_body*)PJ_POOL_ZALLOC_T(g_pool, pjsip_msg_body);
		if (!msg_body)
			return PJ_ENOMEM;

		/* Set content-type */
		char sz_type[32];
		memset(sz_type, 0, sizeof(sz_type));
		memcpy(sz_type, content_type.c_str(), content_type.size());
		msg_body->content_type.type = pj_strdup3(g_pool, sz_type);
		pj_str_t subtype = { (char*)"sdp", 3 }; /* default subtype */
		pj_strdup(g_pool, &msg_body->content_type.subtype, &subtype);

		/* Copy body content */
		msg_body->data = pj_pool_alloc(g_pool, body.size() + 1);
		if (!msg_body->data)
			return PJ_ENOMEM;
		memset(msg_body->data, 0, body.size() + 1);
		pj_memcpy(msg_body->data, body.c_str(), body.size());
		msg_body->len = body.size();
		msg_body->print_body = &pjsip_print_text_body;

		/* Set message body */
		msg->body = msg_body;

		return PJ_SUCCESS;
	}

	//	rdata: UAC侧接收到的响应信息
	pjsip_tx_data* uasess::create_uas_response(pjsip_rx_data* rdata) {
		//	这个rdata一定要是响应
		pj_assert(PJSIP_RESPONSE_MSG == rdata->msg_info.msg->type);

		int code = rdata->msg_info.msg->line.status.code;
		//	其它的响应原样转发
		pjsip_tx_data* tx = nullptr;
		//	响应需要根据最后一次接收到的请求创建
		if (pjsip_endpt_create_response(g_endpt, this->m_last_uas_request, code, NULL, &tx) != PJ_SUCCESS) {
			PJ_LOG(1, (THIS_FILE, "failed to create proxied response"));
			return nullptr;
		}

		//	记录下最后一次给UAS的响应
		this->set_last_uas_response(tx);
		//	收到 180 时就可以获取到路由信息了
		if (180 == code && nullptr != rdata->msg_info.record_route && nullptr == m_callee_r_route) {
			//	记录接听方的路由信息--如果有的话
			m_callee_r_route = (pjsip_rr_hdr*)pjsip_hdr_clone(g_pool, rdata->msg_info.record_route);
			pjsip_routing_hdr_set_route(m_callee_r_route);
		}

		//	200的回复需要更新联系地址、媒体消息联系地址端口等
		if (code >= 200 && code < 300 && rdata->msg_info.cseq->method.id == PJSIP_INVITE_METHOD) {
			return create_uas_response_invite_200(rdata, tx);
		}
		
		//	需要复制sdp,如果有的话--200的SDP会单独处理
		if (rdata->msg_info.msg->body && rdata->msg_info.msg->body->len > 0) {			
			std::string body((char *)rdata->msg_info.msg->body->data, rdata->msg_info.msg->body->len);
			add_msg_body(tx->msg, body);
		}
		return tx;
	}

	//	INVITE请求的200需要单独处理
	pjsip_tx_data* uasess::create_uas_response_invite_200(pjsip_rx_data* rdata, pjsip_tx_data* tx) {
		//	只处理200 code的，其它的不处理
		int code = rdata->msg_info.msg->line.status.code;
		pj_assert(code >= 200 && code < 300 && rdata->msg_info.cseq->method.id == PJSIP_INVITE_METHOD);
		//	tx中需要更新的是联系地址、媒体信息地址，这个与其它响应处理方式不同
		//	联系地址根据呼叫方向确定，是使用外网地址还是本地地址
		char* cont_addr = NULL, *pusers = NULL;		
		pjsip_sip_uri* call_to_uri = (pjsip_sip_uri*)pjsip_uri_get_uri(this->m_last_uas_request->msg_info.to->uri);
		
		if (this->caller_s_isinner()) {
			//	呼叫方是内网话机，响应中的联系地址使用的是内网地址
			cont_addr = (char *)LOCAL_IP_PHONE;
			//	响应中的用户是被叫用户--可以直接从UAS最后一个的请求中获取到用户信息,不论呼叫方是谁都是相同的获取方式

			//	内网话机作为主叫时，200是对端响应，它里面可能会有加密协商信息，需要解析
			this->m_remote_can_enc = this->m_ciphers->parse_remote_by_rx_data(rdata);
			if (!m_remote_can_enc) {
				//	对端无加密信息，需要提前接通呼叫方并且播放提示信息
				PJ_LOG(2, (THIS_FILE, "Remote Have No KeyExchange Parameters."));
			}
		}
		else {
			//	呼叫方是外网话机，响应中的联系地址使用的是外网地址
			cont_addr = (char*)LOCAL_IP_UPSTREAM;
			//	响应中的用户是被叫用户--也是本地配置的向SIP注册的固定用户
			pj_assert(0 == memcmp(call_to_uri->user.ptr, UPSTREAM_USER, call_to_uri->user.slen));
		}
		//	记录响应中的联系地址, 这个联系地址一定是接听方的:呼叫成功响应
		pjsip_contact_hdr* contact_hdr = (pjsip_contact_hdr*)pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_CONTACT, NULL);
		pj_assert(nullptr != contact_hdr);
		this->m_callee_r_contact = (pjsip_contact_hdr*)pjsip_hdr_clone(g_pool, contact_hdr);

		//	更新其中的contact,
		pj_str_t pcontact = pj_str((char*)"Contact");
		char* pcontactbuf = (char*)pj_pool_alloc(g_pool, 128);
		memset(pcontactbuf, 0, 128);
		char szusr[64];
		memset(szusr, 0, 64);
		memcpy(szusr, call_to_uri->user.ptr, call_to_uri->user.slen);
		snprintf(pcontactbuf, 128, "<sip:%s@%s>", szusr, cont_addr);
		pj_str_t pcontactvalue = pj_str(pcontactbuf);
		pjsip_generic_string_hdr* ch = pjsip_generic_string_hdr_create(g_pool, &pcontact, &pcontactvalue);
		pjsip_msg_add_hdr(tx->msg, (pjsip_hdr*)ch);

		//	获取媒体信息并更新媒体信息
		pjmedia_sdp_session* pmedia = nullptr;
		if (nullptr == rdata->msg_info.msg->body->data || rdata->msg_info.msg->body->len < 1) {
			pj_assert(false); //	请求包中无媒体信息，无法更新。这应该是一个不合理的请求，如果INVITE中无媒体信息，它的媒体信息
			//	似乎没法再获取到。
			return tx;
		}
		//	这个创建出来的sdp_session还不知道如何销毁...
		pj_status_t status = pjmedia_sdp_parse(g_pool,
			(char*)rdata->msg_info.msg->body->data, rdata->msg_info.msg->body->len, &pmedia);
		pj_assert(PJ_SUCCESS == status);

		//	如果是外端话机发起的拔打，内端话机接听，它在200 OK中携带媒体信息，此时会话媒体可获取到远端媒体信息		
		//	它需要在更新媒体端口前设置，避免更新后媒体端口变成外网地址

		//	UAC 200 INVITE 响应更新前设置会话媒体的SDP,设置规则详见mediaplayer.h头文件中的描述
		if (this->caller_s_isinner()) { //	设置上sdp后则可以创建会话媒体
			m_sessmedia->set_remote_sdp_session_outer(std::string((char*)rdata->msg_info.msg->body->data, rdata->msg_info.msg->body->len));
		}
		else {
			m_sessmedia->set_remote_sdp_session_inner(std::string((char*)rdata->msg_info.msg->body->data, rdata->msg_info.msg->body->len));
		}

		//	解析UAS与UAC侧 media 中的地址与端口信息，作为后续创建媒体桥使用-- pmedia中的地址已经更新
		this->m_uac_remote_ip = std::string(pmedia->conn->addr.ptr, pmedia->conn->addr.slen);
		this->m_uac_remote_rtp = pmedia->media[0]->desc.port;
		this->m_uac_remote_rtcp = pmedia->media[0]->desc.port + 1; //	默认rtcp是rtp+1,事实上可能不一定对，需要根据协议中解析。

		//	处理的是响应，角色是UAS
		status = this->update_media_session(pmedia, pjsip_role_e::PJSIP_ROLE_UAS);
		pj_assert(PJ_SUCCESS == status);
		//	media更新后，再添加到response tx中

		//	如果是外端话机创建的呼叫并且它传递过来的信息中包含有加密信息，创建出待转发的200 OK响应中需要添加上自己的证书与公钥信息
		//	用作协商
		if (this->caller_s_isouter() && this->m_remote_can_enc) {
			append_key_exchanges(pmedia);
		}		
		else {	//	对内的响应不传递证书和公钥过去.
			//	如果是外端话机创建的呼叫，它里面可能会有证书公钥信息，应该需要清除掉，避免传递到内网话机
			remove_key_exchange(pmedia);
		}
		std::shared_ptr<char> szTmpBuf(new char[32768]);
		memset(szTmpBuf.get(), 0, 32768);
		int mr = pjmedia_sdp_print(pmedia, szTmpBuf.get(), 32768);
		pj_assert(mr > 0);
		std::string _body(szTmpBuf.get(), mr);
		add_msg_body(tx->msg, _body);

		//	如果是外端话机发起的拔打，内端话机接听，它在200 OK中携带媒体信息，此时会话媒体可获取到远端媒体信息		
		//	UAC 200 INVITE 响应更新SDP后设置会话媒体的SDP,设置规则详见mediaplayer.h头文件中的描述
		if (this->caller_s_isinner()) { //	设置上sdp后则可以创建会话媒体
			m_sessmedia->set_local_sdp_session_inner(_body);
		}
		else {
			m_sessmedia->set_local_sdp_session_outer(_body);
		}
		if (!m_sessmedia->create_media_player()) {
			PJ_LOG(1, (THIS_FILE, "Session Media Create Failed."));
		}

		//	INVITE OK处理完毕
		this->set_invite_ok();
		return tx;
	}
	
	//	创建发给UAC端的ACK，需要合理的填充路由信息、地址信息
	pjsip_tx_data* uasess::create_uac_ack() {
		pjsip_tx_data* ack = nullptr;
		//	ACK先只考虑 INVITE_200 的， m_last_uac_response的类型需要是 INVITE 200,这个需要验证
		pj_assert(nullptr != this->m_last_uac_response);
		if (!is_invite_ok_response(this->m_last_uac_response)) {
			pj_assert(false); //	是否有其它的ACK需要请求，待验证。现在只看到 INVITE 200 响应有
			return nullptr;
		}
		pj_status_t status = PJ_SUCCESS;
		//	target从 uac response中的contact中获取到
		pjsip_contact_hdr* target_contact_hdr = (pjsip_contact_hdr*)pjsip_msg_find_hdr(m_last_uac_response->msg_info.msg, PJSIP_H_CONTACT, NULL);
		pjsip_from_hdr* from_hdr = PJSIP_MSG_FROM_HDR(m_last_uac_response->msg_info.msg);
		pjsip_to_hdr* to_hdr = PJSIP_MSG_TO_HDR(m_last_uac_response->msg_info.msg);
		//	本地联系地址是否可以不填?
		pjsip_cid_hdr* cid_hdr = PJSIP_MSG_CID_HDR(m_last_uac_response->msg_info.msg);
		pjsip_cseq_hdr* cseq_hdr = PJSIP_MSG_CSEQ_HDR(m_last_uac_response->msg_info.msg);
		pj_assert(nullptr != target_contact_hdr);
		status = pjsip_endpt_create_request_from_hdr(
			g_endpt, &pjsip_ack_method,
			target_contact_hdr->uri,
			from_hdr,
			to_hdr, //tohdr,
			NULL, //contacthdr, // ACK里面先不填contact
			cid_hdr,
			cseq_hdr->cseq,
			NULL,
			&ack);
		pj_assert(PJ_SUCCESS == status);
		//	UAC 里面需要填route,如果UAC最后一个响应中有的话，从它最后一个响应中获取到
		if (nullptr != this->m_last_uac_response->msg_info.record_route) {
			//	把响应中的 record_route改成route放到请求中
			pjsip_rr_hdr* routehdr = (pjsip_rr_hdr*)pjsip_hdr_clone(g_pool, this->m_last_uac_response->msg_info.record_route);
			pjsip_routing_hdr_set_route(routehdr);
			pjsip_msg_add_hdr(ack->msg, (pjsip_hdr *)routehdr);
		}
		this->set_last_uac_request(ack);
		return ack;
	}

	//	创建BYE请求，BYE可以由两方发送，需要根据请求方确定生成的BYE是针对caller_s还是calle_r
	pjsip_tx_data* uasess::create_uac_bye() {
		pjsip_tx_data* bye = nullptr;
		/*	如果BYE是caller_s发起的，BYE的目标是callee_s, 如果BYE是callee_s发起的，目标则是caller_r
			caller_s发起结束时，生成的bye目标使用 m_last_uac_response (接听方的响应中获取，以获得相应的路由信息)
			callee_r发起结束时，生成的bye目标发向的是之前创建请求的UAS，它的目标使用 m_last_uas_response 中的信息
			m_last_uac_request 中才有目标信息, 
			m_last_uas_response响应中无目标信息，它需要从 m_last_uas_request中获取到contact作为目标
		*/
		pj_assert(nullptr != this->m_last_uas_request &&
		this->m_last_uas_request->msg_info.msg->line.req.method.id == PJSIP_BYE_METHOD);
		pjsip_tx_data* px = nullptr;
		
		pjsip_uri* target_uri = nullptr;

		pjsip_rr_hdr* target_routeinfo = nullptr;
		pjsip_from_hdr* from_hdr = nullptr;
		pjsip_to_hdr* to_hdr = nullptr;

		pjsip_transaction* uac_trans = pjsip_rdata_get_tsx(m_last_uac_response);
		pjsip_transaction* uas_trans = pjsip_rdata_get_tsx(m_last_uas_request);

		if (is_bye_by_caller_s(this->m_last_uas_request)) {
			//	由拔打方发出的BYE请求, 创建的请求目标是和之前的UAC请求目标一致,而且应该是接听方的CONTAXT
			px = m_last_uac_request;
			target_uri = (pjsip_uri*)pjsip_uri_clone(g_pool, this->m_callee_r_contact->uri);

			//	如果BYE是由拔打方发起，转发BYE请求目标信息的路由需要填接听方的
			target_routeinfo = this->m_callee_r_route;

			//	拔打方发起的BYE请求，转发的BYE请求需要是接收方的from与to
			from_hdr = PJSIP_MSG_FROM_HDR(px->msg);
			to_hdr = PJSIP_MSG_TO_HDR(px->msg);
		}
		else {
			//	由接听方发出的BYE请求，创建的请求目标是拔打方的CONTACT
			px = m_last_uas_response;			
			target_uri = (pjsip_uri*)pjsip_uri_clone(g_pool, this->m_caller_s_contact->uri);
			//	如果BYE是由接听方发起，转发BYE请求目标信息的路由需要填拔打方的
			target_routeinfo = this->m_caller_s_route;	//	这个方向是反的，要注意
			to_hdr = PJSIP_MSG_FROM_HDR(px->msg);
			from_hdr = PJSIP_MSG_TO_HDR(px->msg);
		}
		
		pjsip_cid_hdr* cid_hdr = PJSIP_MSG_CID_HDR(px->msg);
		pjsip_contact_hdr* contact_hdr = (pjsip_contact_hdr*)pjsip_msg_find_hdr(px->msg, PJSIP_H_CONTACT, NULL);
		pjsip_cseq_hdr* cseq_hdr = PJSIP_MSG_CSEQ_HDR(px->msg);
		
		//	BYE 的FROM 和TO方向是反的..
		pj_status_t status = pjsip_endpt_create_request_from_hdr(g_endpt, &pjsip_bye_method, target_uri,
			from_hdr, to_hdr, contact_hdr, cid_hdr, cseq_hdr->cseq, NULL, &bye);
		if (PJ_SUCCESS != status) {
			pj_assert(false);
			return nullptr;
		}
		//	如果BYE是由内端话机发起，转发BYE里面也需要填ROUTE信息；如果BYE由外端发起，转发的BYE里面ROUTE信息可以省略
		if (nullptr != target_routeinfo) {
			pjsip_msg_add_hdr(bye->msg, (pjsip_hdr *)target_routeinfo);
		}
		this->set_last_uac_request(bye);
		return bye;
	}

	//	验证BYE请求是否是由拔打方发出，如果是则返回true，如果不是则返回false
	bool uasess::is_bye_by_caller_s(pjsip_rx_data* rdata) {
		pj_assert(nullptr != this->m_last_uas_request &&
			this->m_last_uas_request->msg_info.msg->line.req.method.id == PJSIP_BYE_METHOD);
		if (nullptr == rdata || this->m_last_uas_request->msg_info.msg->line.req.method.id != PJSIP_BYE_METHOD) {
			return false; //	
		}
		//	是否由拔打方发出根据请求中的From确定
		pjsip_from_hdr* from_hdr = PJSIP_MSG_FROM_HDR(rdata->msg_info.msg);
		if (nullptr == from_hdr) {
			return false;
		}
		char szTmp[256];
		memset(szTmp, 0, sizeof(szTmp));
		int slen = pjsip_hdr_print_on(from_hdr, szTmp, 256);
		if (m_caller_s_addr == std::string(szTmp)) {
			return true;	//	FROM 信息与接收到的INVITE中的FROM信息匹配，则一定是拔打方发出的
		}
		return false;
	}

	//	验证最后一个UAS REQUEST是对内还是对外?
		//	如果是对个，返回true,如果是对外，返回false
	bool uasess::last_uas_is_inner() const {
		if (nullptr == this->m_last_uas_request) {
			return false;
		}
		pj_assert(PJSIP_REQUEST_MSG == m_last_uas_request->msg_info.msg->type);
		//	验证请求的发送方是否是内网地址，如果是内网地址则是对内
		pjsip_from_hdr* from_hdr = PJSIP_MSG_FROM_HDR(m_last_uas_request->msg_info.msg);
		if (nullptr == from_hdr) {
			return false;
		}
		pjsip_to_hdr* to_hdr = PJSIP_MSG_TO_HDR(m_last_uas_request->msg_info.msg);
		if (nullptr == to_hdr) {
			return false;
		}

		pjsip_sip_uri* puri = (pjsip_sip_uri*)pjsip_uri_get_uri(from_hdr->uri);
		pjsip_sip_uri* ptouri = (pjsip_sip_uri*)pjsip_uri_get_uri(to_hdr->uri);

		if (std::string(puri->user.ptr, puri->user.slen) == LOCAL_REG_USER
			&& std::string(ptouri->host.ptr, ptouri->host.slen) == LOCAL_IP_PHONE) {
			return true;
		}		
		return false;
	}

	//	等待通话转接桥线程结束
	void uasess::wait_bridge_ok() {
		if (nullptr != this->uac_thread) {
			pj_thread_join(this->uac_thread);
			pj_thread_destroy(this->uac_thread);
			this->uac_thread = nullptr;
		}
		if (nullptr != this->uas_thread) {
			pj_thread_join(this->uas_thread);
			pj_thread_destroy(this->uas_thread);
			this->uas_thread = nullptr;
		}
	}

	/// <summary>
	/// sessman, 记录所有的会话信息，用于呼叫保持与恢复。中途接收到需要的请求和响应后也需要通过 sessman 获取到相应的会话
	/// </summary>	
	std::atomic<int> sessman::m_cseq(0);
	sessman::sessman() {
	}
	sessman::~sessman() {
	}

	//	根据提供的INVITE请求，获取到一个 uasess,如果没有则新创建一个返回，这儿要考虑一下占线问题: 先不考虑
	std::shared_ptr<uasess> sessman::get_sess_by_invite(pjsip_rx_data* rdata) {
		std::shared_ptr<uasess> _uasess;
		//	根据 rdata 中的信息，先验证出它是由哪一端发起的呼叫--目标的用户名区分，如果目标用户名是本地向SIP注册用户
		//	则是外部呼入，如果目标的用户名不是本地向SIP注册用户则是内部呼出
		if (nullptr == rdata || nullptr == rdata->msg_info.msg
			|| PJSIP_INVITE_METHOD != rdata->msg_info.msg->line.req.method.id
			|| nullptr == rdata->msg_info.msg->line.req.uri) {
			assert(false);
			return _uasess;
		}
		assert(nullptr != rdata);
		assert(PJSIP_INVITE_METHOD == rdata->msg_info.msg->line.req.method.id);

		std::unique_lock<std::mutex> _lock(m_sessmutex);
		_uasess = get_by_request_nolock(rdata);
		if (_uasess) {
			return _uasess;	//	如果找到则直接使用它
		}
		//	没有找到则实列化新的
		_uasess.reset(new uasess());
		pjsip_sip_uri* target_uri = (pjsip_sip_uri*)pjsip_uri_get_uri(rdata->msg_info.msg->line.req.uri);
		std::string target_user(target_uri->user.ptr, target_uri->user.slen);
		if (UPSTREAM_USER == target_user) {
			//	目标用户是b2bua向sip注册的用户，是外部呼入的
			_uasess->m_calldirect = uasess::E_OUTER_CALL;
		}
		else {	//	目标用户不是b2bua向sip注册的用户，是内部呼出去的
			_uasess->m_calldirect = uasess::E_INNER_CALL;
		}

		_uasess->set_last_uas_request(rdata);

		//	记录下它的FROM信息
		pjsip_from_hdr* from_hdr = PJSIP_MSG_FROM_HDR(rdata->msg_info.msg);
		if (nullptr == from_hdr) {
			assert(false); //	INVITE 中必须要有FROM信息，不然一定是协议错误
			return std::shared_ptr<uasess>();
		}
		char szTmp[256];
		memset(szTmp, 0, sizeof(szTmp));
		int slen = pjsip_hdr_print_on(from_hdr, szTmp, 256);
		if (slen < 4) {
			assert(false); //	INVITE 中必须要有FROM信息，不然一定是协议错误
			return std::shared_ptr<uasess>();
		}

		_uasess->m_caller_s_addr = std::string(szTmp);
		//	记录下拔打方的联系地址,这个在INVITE请求中需要获取到
		pjsip_contact_hdr* contact_hdr = (pjsip_contact_hdr*)pjsip_msg_find_hdr(rdata->msg_info.msg, PJSIP_H_CONTACT, NULL);
		pj_assert(nullptr != contact_hdr);
		_uasess->m_caller_s_contact = (pjsip_contact_hdr*)pjsip_hdr_clone(g_pool, contact_hdr);

		
		m_sess_set.push_back(_uasess);
		return _uasess;
	}
	std::shared_ptr<uasess> sessman::get_by_request(pjsip_rx_data* rdata) {
		std::unique_lock<std::mutex> _lock(m_sessmutex);
		return get_by_request_nolock(rdata);
	}
	std::shared_ptr<uasess> sessman::get_by_request_nolock(pjsip_rx_data* rdata) {
		pj_assert(rdata->msg_info.msg->type == PJSIP_REQUEST_MSG);
		std::string cid(rdata->msg_info.cid->id.ptr, rdata->msg_info.cid->id.slen);
		
		std::list<std::shared_ptr<uasess>>::iterator it = m_sess_set.begin();
		for (it; it != m_sess_set.end(); it++) {
			if (cid == (*it)->get_callid_inner() ||
				cid == (*it)->get_callid_outer()) {
				return *it;
			}
		}
		return std::shared_ptr<uasess>();
	}
	//	通过响应查找
	std::shared_ptr<uasess> sessman::get_by_response(pjsip_rx_data* rdata) {
		pj_assert(rdata->msg_info.msg->type == PJSIP_RESPONSE_MSG);
		std::string cid(rdata->msg_info.cid->id.ptr, rdata->msg_info.cid->id.slen);
		std::unique_lock<std::mutex> _lock(m_sessmutex);
		std::list<std::shared_ptr<uasess>>::iterator it = m_sess_set.begin();
		for (it; it != m_sess_set.end(); it++) {
			if (cid == (*it)->get_callid_inner() ||
				cid == (*it)->get_callid_outer()) {
				return *it;
			}
		}
		return std::shared_ptr<uasess>();
	}
	//	结束后要移除
	void sessman::removesess(std::shared_ptr<uasess> _uases) {
		//	先停再等线程结束，避免转发线程不停止
		_uases->stop_running();
		_uases->wait_bridge_ok();
		std::unique_lock<std::mutex> _lock(m_sessmutex);
		std::list<std::shared_ptr<uasess>>::iterator it = m_sess_set.begin();
		for (it; it != m_sess_set.end(); it++) {
			if (_uases->get_callid_inner() == (*it)->get_callid_inner() &&
				_uases->get_callid_outer() == (*it)->get_callid_outer()) {
				m_sess_set.erase(it);
				break;
			}
		}
	}

}	//	namespace ccsua


