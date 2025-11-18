//	uasess.h
/*	定义一个b2bua的通话信息，通话信息由接收到 INVITE 时创建，接收到相应的
* Cancel/Bye时释放，或者因为一些错误主动销毁
*/
#ifndef _CCS_UA_SESSION_H_
#define _CCS_UA_SESSION_H_

#include "ciphers.h"
#include "mediaplayer.h"

namespace ccsua {

	/* 描述一个通话，通话中有UAS和UAC的概念，UAS接收请求，返回响应。UAC发送请求，接收响应。
	* 还有一个拔打方(caller)和接听方(callee)的概念,这两单词长得像，为作区分，在程序中使用 caller_s, callee_r 来定义变量和信息,
	* 分别代表: caller is sender, callee is receiver。
	* 在一个通话中，uas面对的可能是caller_s, 也有可能是callee_r，如BYE, CANCEL等消息可能由接听方发起, INVITE肯定由caller_s发起
	* 在uasess类中先完成uac请求创建、uas侧转发响应创建功能。它先不负责发送，由 sb2bua.cpp的模块函数中完成发送。
	* 因此uasess的功能是在逻辑上将呼叫双方关联起来，并根据协议要求产生合适的请求/响应数据
	* 
	* 发送到内端话机的请求/响应不需要附带路由信息，它和b2bua直连，发送到外端的请求/响应需要有路由信息，它需要通过sip中转
	*/

	class sessman;

	class uasess : public std::enable_shared_from_this<uasess> {
	protected:
		//	定义呼叫方向
		typedef enum e_call_direct {
			E_INNER_CALL = 0,	//	内部呼出去的
			E_OUTER_CALL = 1,	//	外部呼进来的
			E_UNDEFINED = 3		//	未定义的，初始化时设备
		}E_CALL_DIRECT;
	public:
		uasess();
		virtual ~uasess();

		//	呼叫方是否是内部话机,如果是返回true,如果呼叫方是外部话机
		//	也可以说是内部呼出返回true, 如果是外部呼入返回false
		bool caller_s_isinner() const { 
			assert(E_UNDEFINED != this->m_calldirect);
			return E_INNER_CALL == this->m_calldirect;
		}
		//	呼叫方是否是外部话机,如果是返回true,如果呼叫方是内部话机, 则返回false
		//	也可以说是外部呼入返回true,如果是内部呼出返回false
		bool caller_s_isouter() const { 
			assert(E_UNDEFINED != this->m_calldirect);
			return E_OUTER_CALL == this->m_calldirect;
		}
		//	验证最后一个UAS REQUEST是对内还是对外?
		//	如果是对个，返回true,如果是对外，返回false
		bool last_uas_is_inner() const;
		
		//	设置最近一次接收到的请求-UAS侧
		void set_last_uas_request(pjsip_rx_data* rdata) {
			pj_status_t status = PJ_SUCCESS;
			if (nullptr != m_last_uas_request) {
				status = pjsip_rx_data_free_cloned(m_last_uas_request);
				pj_assert(PJ_SUCCESS == status);
				m_last_uas_request = nullptr;
			}
			pjsip_rx_data_clone(rdata, 0, &m_last_uas_request);
		}
		//	获取到最近一次接收到的请求-UAS侧
		pjsip_rx_data* get_last_uas_request() {
			return m_last_uas_request;
		}
		//	设置最近一次发送出去的响应-UAS侧
		void set_last_uas_response(pjsip_tx_data* tdata) {
			pj_status_t status = PJ_SUCCESS;
			if (nullptr != m_last_uas_response) {
				status = pjsip_tx_data_dec_ref(m_last_uas_response);
				pj_assert(PJ_SUCCESS == status || PJSIP_EBUFDESTROYED == status);
				m_last_uas_response = nullptr;
			}
			//pjsip_tx_data_clone(tdata, 0, &m_last_uas_response);
			pjsip_tx_data_add_ref(tdata);
			m_last_uas_response = tdata;
		}
		//	获取到最近一次发送出去的响应-UAS侧
		pjsip_tx_data* get_last_uas_response() { return m_last_uas_response; }

		//	设置最近一次处理(生成)到的请求-UAC侧
		void set_last_uac_request(pjsip_tx_data* rdata) {
			pj_status_t status = PJ_SUCCESS;
			if (nullptr != m_last_uac_request) {
				status = pjsip_tx_data_dec_ref(m_last_uac_request);				
				pj_assert(PJ_SUCCESS == status || PJSIP_EBUFDESTROYED == status);
				m_last_uac_request = nullptr;
			}
			/*pjsip_tx_data_clone(rdata, 0, &m_last_uac_request);
			*/
			pjsip_tx_data_add_ref(rdata);
			m_last_uac_request = rdata;
		}
		//	获取到最近一次发送出的请求-UAC侧
		pjsip_tx_data* get_last_uac_request() {
			return m_last_uac_request;
		}
		//	设置最近一次接收到的响应-UAC侧
		void set_last_uac_response(pjsip_rx_data* tdata) {
			pj_status_t status = PJ_SUCCESS;
			if (nullptr != m_last_uac_response) {
				status = pjsip_rx_data_free_cloned(m_last_uac_response);
				pj_assert(PJ_SUCCESS == status);
				m_last_uac_response = nullptr;
			}
			pjsip_rx_data_clone(tdata, 0, &m_last_uac_response);
		}
		//	获取到最近一次接收到的响应-UAC侧
		pjsip_rx_data* get_last_uac_response() { return m_last_uac_response; }

		//	获取内端的callid
		const std::string get_callid_inner() const { return m_callid_inner; }
		//	获取外端的callid
		const std::string get_callid_outer() const { return m_callid_outer; }

		//	获取UAS的callid
		const std::string get_callid_uas() const { return m_callid_uas; }
		//	获取UAC的callid
		const std::string get_callid_uac() const { return m_callid_uac; }

		//	设置UAS侧rtp/rtcp媒体端口
		void set_uas_rtp_port(unsigned short port) { 
			m_uas_rtp_port = port; 
			//	添加一个rtcp默认端口
			m_uas_rtcp_port = m_uas_rtp_port + 1;
		}
		//	设置UAS侧rtcp媒体端口
		void set_uas_rtcp_port(unsigned short port) { m_uas_rtcp_port = port; }
		//	设置UAC侧rtp/rtcp媒体端口
		void set_uac_rtp_port(unsigned short port) {
			m_uac_rtp_port = port;
			//	添加一个rtcp默认端口
			m_uac_rtcp_port = m_uac_rtp_port + 1;
		}
		//	设置UAC侧rtcp媒体端口
		void set_uac_rtcp_port(unsigned short port) { m_uas_rtcp_port = port; }
		unsigned short get_uas_rtp_port() const {
			pj_assert(0 != m_uas_rtp_port);
			return m_uas_rtp_port;
		}
		unsigned short get_uas_rtcp_port() const {
			pj_assert(0 != m_uas_rtcp_port);
			return m_uas_rtcp_port;
		}
		unsigned short get_uac_rtp_port() const {
			pj_assert(0 != m_uac_rtp_port);
			return m_uac_rtp_port;
		}
		unsigned short get_uac_rtcp_port() const {
			pj_assert(0 != m_uac_rtcp_port);
			return m_uac_rtcp_port;
		}

		//	创建UAC侧的呼叫请求--它使用最后一次的UAS请求创建，不传入其它参数,如果失败则返回false
		//	创建的呼叫请求需要将UAS接收到的请求中的media_session替换完成地址信息后附加上
		pjsip_tx_data* create_uac_invite();
		//	更新invite的sdp信息--媒体信息，获取到返回的request消息。这个需要b2bua侧的媒体端口创建完成后才能
		//	更新，因此在创建uac请求的时候没有端口，所以更新放到了网络信息创建完成后进行
		pjsip_tx_data* update_uac_invite_sdp();

		//	根据接收到的UAC响应，创建UAS的响应,
		//	rdata: UAC侧接收到的响应信息,现在除200外其它的似乎直接回复转发即可
		pjsip_tx_data* create_uas_response(pjsip_rx_data* rdata);

		//	创建发给UAC端的ACK，需要合理的填充路由信息、地址信息
		pjsip_tx_data* create_uac_ack();

		//	创建BYE请求，BYE可以由两方发送，需要根据请求方确定生成的BYE是针对caller_s还是calle_r
		pjsip_tx_data* create_uac_bye();

		void set_uac_media(const media_sock_pair_t &_media) {
			pj_assert(0 != _media.rtp_port);
			memcpy(&m_uac_media, &_media, sizeof(media_sock_pair_t));
		}
		void set_uas_media(const media_sock_pair_t& _media) {
			pj_assert(0 != _media.rtp_port);
			memcpy(&m_uas_media, &_media, sizeof(media_sock_pair_t));
		}
		media_sock_pair_t& get_uac_media() {
			return m_uac_media;
		}
		media_sock_pair_t& get_uas_media() {
			return m_uas_media;
		}

		//	递增cseq,据协议说每执行一次请求这个cseq都需要递增..
		void increase_cseq() {
			m_cseq++;
		}
		int cseq() const {
			return m_cseq.load();
		}
		const std::string get_uas_remote_ip() const { 
			pj_assert(!m_uas_remote_ip.empty());
			return m_uas_remote_ip; 
		}
		const std::string get_uac_remote_ip() const { 
			pj_assert(!m_uac_remote_ip.empty());
			return m_uac_remote_ip; 
		}
		unsigned short get_uac_remote_rtp() const { 
			pj_assert(m_uac_remote_rtp > 0);
			return m_uac_remote_rtp; 
		}
		unsigned short get_uac_remote_rtcp() const { 
			pj_assert(m_uac_remote_rtcp > 0);
			return m_uac_remote_rtcp; 
		}
		unsigned short get_uas_remote_rtp() const { 
			pj_assert(m_uas_remote_rtp > 0);
			return m_uas_remote_rtp; 
		}
		unsigned short get_uas_remote_rtcp() const { 
			pj_assert(m_uas_remote_rtcp > 0);
			return m_uas_remote_rtcp; 
		}

		//	设置挂机标记--播放媒体语音过程中也需要检测这个挂机标记
		void hung_up() { 
			m_is_hungup = true;  
			if (m_sessmedia) {
				m_sessmedia->hung_up();
			}
		}
		bool is_hung_up() {
			return m_is_hungup;
		}

		bool is_running() const { return m_session_running; }
		void set_running() { m_session_running = true; }
		void stop_running() { m_session_running = false; }
		pj_bool_t* active() { return &m_session_running; }

		pj_thread_t* uas_thread;
		pj_thread_t* uac_thread;

		//	获取对端是否有能力进行加密通话,如果是返回true,否则返回false
		bool is_remote_can_enc() const {
			return m_remote_can_enc;
		}

		//	播放对端为普通话机，并等待按键确认--向b2bua注册的话机播放
		void play_remote_is_normal() {
			m_sessmedia->play_remote_is_normal();
		}
		
		//	
		bool is_invite_ok() const { return m_invite_ok; }
		void set_invite_ok() { m_invite_ok = true; }

		//	等待通话转接桥线程结束
		void wait_bridge_ok();

		//	加密定义: blkind: 编号, 这是一个递增的序列，需要根据它变换IV
		//	pinbuf, inlen: 输入的数据地址及长度; 
		//	poutbuf, outlen: 输出的密文块数据地址及长度，调用时outlen是poutbuf的有效长，成功后outlen会返回真实的长度。
		bool encrypt(unsigned int blkind, const unsigned char* pinbuf, size_t inlen, unsigned char* poutbuf, size_t& outlen) {
			if (!m_ciphers) return false;
			return m_ciphers->encrypt(blkind, pinbuf, inlen, poutbuf, outlen);
		}
		//	解密定义: 编号从密文块中解析到，不需要输入。
		//	pinbuf, inlen: 输入的密文块数据地址及长度; 
		//	poutbuf, outlen: 输出的明文块数据地址及长度，调用时outlen是poutbuf的有效长，成功后outlen会返回真实的长度。
		bool decrypt(const unsigned char* pinbuf, size_t inlen, unsigned char* poutbuf, size_t& outlen) {
			if (!m_ciphers) return false;
			return m_ciphers->decrypt(pinbuf, inlen, poutbuf, outlen);
		}
	protected:
		//	将sdp添加到SIP消息中
		pj_status_t add_msg_body(pjsip_msg* msg, const std::string &body, const std::string& content_type = "application");

		//	INVITE请求的200响应需要单独处理,需要将200响应中添加UAS侧的联系地址、需要将媒体信息中的地址与端口更新成UAS侧的媒体地址端口
		pjsip_tx_data* create_uas_response_invite_200(pjsip_rx_data* rdata, pjsip_tx_data* tx);

		//	更新媒体信息: pmedia是需要更新的媒体信息
		//	roletype: PJSIP_ROLE_UAC 表示更新的是UAC侧的媒体信息
		//			  PJSIP_ROLE_UAS 表示更新的是UAS侧的媒体信息
		//	成功返回 PJ_SUCCESS,其它为错误码
		pj_status_t update_media_session(pjmedia_sdp_session* pmedia, pjsip_role_e roletype);

		//	验证BYE请求是否是由拔打方发出，如果是则返回true，如果不是则返回false
		bool is_bye_by_caller_s(pjsip_rx_data* rdata);

		// 将协商认证信息添加到sdp中
		pj_status_t append_key_exchanges(pjmedia_sdp_session* pmedia);
		pj_status_t remove_key_exchange(pjmedia_sdp_session* pmedia);

	protected:
		//	最近一次接收到的请求-UAS侧与UAC侧需要分别记录
		pjsip_rx_data* m_last_uas_request;	//	UAS侧的REQUEST是rx_data,接收到的
		pjsip_tx_data* m_last_uac_request;	//	UAC侧的REQUEST是tx_data，自行创建并且发送出去，
		//	最近一次发送出去的响应-UAS侧与UAC侧需要分别记录
		pjsip_tx_data* m_last_uas_response; //	UAS侧的response是 txdata,自行创建并且发送出去
		pjsip_rx_data* m_last_uac_response;	//	UAC侧的response是rx_data
		
		//	记录内端与外端的callid
		std::string m_callid_inner, m_callid_outer;
		//	记录UAS与UAC侧的callid，注意在BYE请求时UAS与UAC相对于呼叫与被叫可能存在互换，BYE作为最后一个协议
		//	似乎可以不用处理，中途的呼叫暂停、重启需要验证
		std::string m_callid_uas, m_callid_uac;
		std::string m_caller_s_addr; //	记录拔打方的From信息，用于后续验证BYE等请求发送方是否是拔打方
		//	分别记录拔打方和接听方的contact地址信息
		pjsip_contact_hdr * m_caller_s_contact, *m_callee_r_contact;
		//	分别记录拔打方和接听方的路由信息，内网的无路由信息，外网有路由信息
		pjsip_rr_hdr* m_caller_s_route, * m_callee_r_route;
		
		E_CALL_DIRECT m_calldirect;
		std::string m_sessid; //	这个通话的ID信息,用于标识唯一一个通话。为后续的呼叫保持和恢复做准备

		std::atomic<int> m_cseq; //	UAC呼叫序号，每新创建一个请求则增加1，请求有 ACK, BYE等

		//	记录uas与uac的媒体端口，默认的rtcp端口为rtp+1
		unsigned short m_uas_rtp_port, m_uas_rtcp_port, m_uac_rtp_port, m_uac_rtcp_port;

		//	记录UAS与UAC侧的媒体网络信息
		media_sock_pair_t m_uac_media, m_uas_media;
		std::string m_uas_remote_ip, m_uac_remote_ip;
		unsigned short m_uas_remote_rtp, m_uas_remote_rtcp, m_uac_remote_rtp, m_uac_remote_rtcp;
		pj_bool_t m_session_running; //	标识会话是否正在运行，建立后为TRUE，

		//	标识通话是否是加密通话，并且需要知识不进行加密通话的原因

		//	标识对端是否能进行加密通话，呼叫由内网发起，在检测INVITE响应的180和200是否加密话机；如果呼叫由外网发起
		//	则检测INVITE请求是否加密话机
		bool m_remote_can_enc;
		std::atomic<bool> m_invite_ok; //	标识INVITE是否接收到200 OK，如果是则为TRUE，用于后续的语音媒体播放确认
		std::atomic<bool> m_is_hungup; //	是否已经挂机??

		//	加密相关的处理
		std::shared_ptr<sesscipher> m_ciphers;
		//	这个会话相关联的自动语音播放
		std::shared_ptr<sessmedia> m_sessmedia;
		friend class sessman;

	};	//	class uasess

	//	为兼容多方通话、呼叫保持与恢复，需要定义一个会话集
	class sessman {
	public:
		sessman();
		virtual ~sessman();
		//	根据提供的INVITE请求，获取到一个 uasess,如果没有则新创建一个返回，这儿要考虑一下占线问题: 先不考虑
		std::shared_ptr<uasess> get_sess_by_invite(pjsip_rx_data* rdata);
		//	通过请求查找，请求不能是INVITE,需要是其它的请求，现在已知的有ACK, BYE
		//	呼叫应答的ACK由拔打方发起，BYE双方都可能发起，因此ACK不会切换UAS与UAC，BYE可能会涉及到UAS与UAC切换
		//	一般来说BYE发起后会话会销毁，似乎切换后并没有什么实质的影响
		std::shared_ptr<uasess> get_by_request(pjsip_rx_data *rdata);
		//	通过响应查找
		std::shared_ptr<uasess> get_by_response(pjsip_rx_data* rdata);
		//	结束后要移除
		void removesess(std::shared_ptr<uasess> _uases);

		static void init_cseq() {
			m_cseq = time(NULL) % 65536;
		}
		static int next_cseq() {
			return ++m_cseq;
		}
	protected:
		std::shared_ptr<uasess> get_by_request_nolock(pjsip_rx_data* rdata);
	protected:
		std::mutex m_sessmutex;
		std::list<std::shared_ptr<uasess>> m_sess_set;

		static std::atomic<int> m_cseq;
	};


	//	一些辅助的全局函数
	std::string rx_info(pjsip_rx_data* rdata);
	std::string tx_info(pjsip_tx_data* tdata);
}	//	namespace ccsua

#endif	//	_CCS_UA_SESSION_H_
