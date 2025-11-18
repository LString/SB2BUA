//	mediaplayer.cpp
/*
* 一个通话的会话媒体实现
*/
#include "mediaplayer.h"
#include "uasess.h"

std::atomic<bool> g_sharp_ok(false);
extern "C" {
	//	先做一个简易的digit检测
	void cb_dtmf_check(pjmedia_stream* pstream,
		void* user_data,
		int digit) {
		if ('#' == digit) {
			g_sharp_ok = true;
		}
		g_sharp_ok = true;
	}
	void cb_dtmf_events(pjmedia_stream* pstream,
		void* user_data,
		const pjmedia_stream_dtmf_event* dtevent) {
		if ('#' == dtevent->digit) {
			g_sharp_ok = true;
		}
	}
}
namespace ccsua {

	const std::string _wav_dir = "F:\\wg\\voip\\sb2bua20251023\\wav_files\\";
	//	对端为普通话机，无法加密通话
	const std::string _wav_rmt_normal("01.normal_phone.wav");
	//	资源下载失败，无法加密通话
	const std::string _wav_res_downfail("02.res_down_fail.wav");
	//	对端证书验证失败
	const std::string _wav_rmt_certfail("03.verify_cert_fail.wav");
	//	工作密钥协商错误
	const std::string _wav_key_exchangefail("04.key_exchange_fail.wav");
	//	输入PIN认证
	const std::string _wav_pin_auth("05.pin_auth.wav");
	//	等待工作密钥协商
	const std::string _wav_wait_key_exchange("06.wait_key_exchange.wav");
	//	主菜单提示音
	const std::string _wav_main_menu("07.main_menu.wav");
	//	等待对方确认
	const std::string _wav_wait_remote_confirm("08.wait_remote_confirm.wav");

	sessmedia::sessmedia() : m_transport_inner(nullptr), m_transport_outer(nullptr), 
		m_stream_inner(nullptr), m_stream_outer(nullptr), 
		m_media_port_inner(nullptr), m_media_port_outer(nullptr),
		m_local_sdp_inner(nullptr), m_local_sdp_outer(nullptr), 
		m_remote_sdp_inner(nullptr), m_remote_sdp_outer(nullptr),
		m_mediaok(false), m_playing(false), m_ishunup(false)
	{
		memset(&m_streaminfo_inner, 0, sizeof(pjmedia_stream_info));
		memset(&m_streaminfo_outer, 0, sizeof(pjmedia_stream_info));
	}
	sessmedia::~sessmedia() {
		pj_status_t status = PJ_SUCCESS;
		/*if (nullptr != m_stream_inner) {
			status = pjmedia_stream_destroy(m_stream_inner);
			pj_assert(PJ_SUCCESS == status);
		}*/
		if (nullptr != m_transport_inner) {
			status = pjmedia_transport_close(m_transport_inner);
			pj_assert(PJ_SUCCESS == status);
			m_transport_inner = nullptr;
		}
		if (nullptr != m_transport_outer) {
			status = pjmedia_transport_close(m_transport_outer);
			pj_assert(PJ_SUCCESS == status);
			m_transport_outer = nullptr;
		}
	}

	//	设置本要sdp session，后续用来创建媒体会话使用--这两个分开设置是因为它们创建出来的时机不同
	void sessmedia::set_local_sdp_session_inner(const std::string& _localsdp) {
		if (m_mediaok) return;
		if (!m_local_sdp_str_inner.empty() || _localsdp.empty()) {
			pj_assert(false);
			return;
		}
		m_local_sdp_str_inner = _localsdp;
		pj_status_t status = pjmedia_sdp_parse(g_pool,
			m_local_sdp_str_inner.data(), m_local_sdp_str_inner.size(), &m_local_sdp_inner);
		pj_assert(PJ_SUCCESS == status);
	}
	//	设置对端的sdp session后续用来创建媒体会话使用
	void sessmedia::set_remote_sdp_session_inner(const std::string& _remotesdp) {
		if (m_mediaok) return;
		if (!m_remote_sdp_str_inner.empty() || _remotesdp.empty()) {
			pj_assert(false);
			return;
		}
		m_remote_sdp_str_inner = _remotesdp;
		pj_status_t status = pjmedia_sdp_parse(g_pool,
			m_remote_sdp_str_inner.data(), m_remote_sdp_str_inner.size(), &m_remote_sdp_inner);
		pj_assert(PJ_SUCCESS == status);
	}

	//	外端话机的sdp
	void sessmedia::set_local_sdp_session_outer(const std::string& _localsdp) {
		if (m_mediaok) return;
		if (!m_local_sdp_str_outer.empty() || _localsdp.empty()) {
			pj_assert(false);
			return;
		}
		m_local_sdp_str_outer = _localsdp;
		pj_status_t status = pjmedia_sdp_parse(g_pool,
			m_local_sdp_str_outer.data(), m_local_sdp_str_outer.size(), &m_local_sdp_outer);
		pj_assert(PJ_SUCCESS == status);
	}
	//	设置对端的sdp session后续用来创建媒体会话使用
	void sessmedia::set_remote_sdp_session_outer(const std::string& _rmtsdp) {
		if (m_mediaok) return;
		if (!m_remote_sdp_str_outer.empty() || _rmtsdp.empty()) {
			pj_assert(false);
			return;
		}
		m_remote_sdp_str_outer = _rmtsdp;
		pj_status_t status = pjmedia_sdp_parse(g_pool,
			m_remote_sdp_str_outer.data(), m_remote_sdp_str_outer.size(), &m_remote_sdp_outer);
		pj_assert(PJ_SUCCESS == status);
	}

	//	
	bool sessmedia::create_media_player() {
		if (m_mediaok) return true;
		//	需要先验证传输本地端口以及对端的媒体端口
		pj_assert(nullptr != g_med_endpt);
		pj_assert(0 != m_sockpair_inner.rtcp_sock); //	网络参数需要设置
		pj_assert(nullptr != m_local_sdp_inner);		//	然后是本地sdp
		pj_assert(nullptr != m_remote_sdp_inner);		//	再然后是远端sdp

		pj_assert(0 != m_sockpair_outer.rtcp_sock); //	网络参数需要设置
		pj_assert(nullptr != m_local_sdp_outer);		//	然后是本地sdp
		pj_assert(nullptr != m_remote_sdp_outer);		//	再然后是远端sdp

		pj_assert(!m_mediaok); //	创建成功后不能再创建，一次通话只允许创建一次

		//	对内对外都需要创建
		bool _medok = false;
		do {
			_medok = this->create_media_player(true);
			if (!_medok) {
				break;
			}
			_medok = this->create_media_player(false);
			if (!_medok) {
				break;
			}
		} while (false);
		if (!_medok) {
			//	需要清理创建出来的媒体流相关信息，现在还没有做
			stop_media_player();
		}
		m_mediaok = _medok;
		return _medok;
	}

	//	根据参数类型创建媒体播放, is_inner=true创建对内的媒体播放; is_inner=false创建对外的媒体播放
	bool sessmedia::create_media_player(bool is_inner) {
		if (m_mediaok) return true;
		//	需要先验证传输本地端口以及对端的媒体端口
		pj_assert(nullptr != g_med_endpt);
		pj_assert(0 != m_sockpair_inner.rtcp_sock); //	网络参数需要设置
		pj_assert(nullptr != m_local_sdp_inner);		//	然后是本地sdp
		pj_assert(nullptr != m_remote_sdp_inner);		//	再然后是远端sdp
		pj_assert(!m_mediaok); //	创建成功后不能再创建，一次通话只允许创建一次

		//	首先根据方向确定需要使用的参数--默认对内
		media_sock_pair_t* psockpair = &m_sockpair_inner;
		pjmedia_sdp_session* _plocalsdp = m_local_sdp_inner, * _premotesdp = m_remote_sdp_inner;
		pjmedia_stream_info* _pstreaminfo = &m_streaminfo_inner;
		pjmedia_port** _pmediaport = &m_media_port_inner;
		pjmedia_stream** _pmediastream = &m_stream_inner;
		pjmedia_transport** _ptransport = &m_transport_inner;
		char szName[64];
		snprintf(szName, sizeof(szName), "inner_msg");
		if (!is_inner) {
			snprintf(szName, sizeof(szName), "outer_msg");

			psockpair = &m_sockpair_outer;
			_plocalsdp = m_local_sdp_outer;
			_premotesdp = m_remote_sdp_outer;
			_pstreaminfo = &m_streaminfo_outer;
			_pmediaport = &m_media_port_outer;
			_pmediastream = &m_stream_outer;
			_ptransport = &m_transport_outer;
		}
		bool _mediaok = false;
		pjmedia_sock_info si;
		//si.rtcp_sock
		pj_status_t status = PJ_SUCCESS;

		//	直接使用协商的方式尝试获取到合适的sdp--直接从呼叫请求中获取到的sdp可能不被支持，需要根据双端的sdp做协商
		pjmedia_sdp_neg* p_neg = nullptr;
		status = pjmedia_sdp_neg_create_w_remote_offer(g_pool, _plocalsdp, _premotesdp, &p_neg);
		pj_assert(PJ_SUCCESS == status);
		status = pjmedia_sdp_neg_set_prefer_remote_codec_order(p_neg, true);
		pj_assert(PJ_SUCCESS == status);
		//	调用协商..
		status = pjmedia_sdp_neg_negotiate(g_pool, p_neg, 0);
		pj_assert(PJ_SUCCESS == status);
		//	再获取到协商好的sdp
		const pjmedia_sdp_session* _local_sdp = nullptr, *_remote_sdp = nullptr;
		status = pjmedia_sdp_neg_get_active_local(p_neg, &_local_sdp);
		pj_assert(PJ_SUCCESS == status);
		status = pjmedia_sdp_neg_get_active_remote(p_neg, &_remote_sdp);
		pj_assert(PJ_SUCCESS == status);

		si.rtp_sock = psockpair->rtp_sock;
		si.rtcp_sock = psockpair->rtcp_sock;
		memcpy(&si.rtp_addr_name, &psockpair->rtp_sockaddr, sizeof(si.rtp_addr_name));;
		memcpy(&si.rtcp_addr_name, &psockpair->rtcp_sockaddr, sizeof(si.rtcp_addr_name));;
		do {
			status = pjmedia_transport_udp_attach(g_med_endpt, szName, &si, PJMEDIA_UDP_NO_SRC_ADDR_CHECKING, _ptransport);
			if (PJ_SUCCESS != status) {
				pj_assert(PJ_SUCCESS == status);
				break;
			}

			status = pjmedia_stream_info_from_sdp(_pstreaminfo, g_pool, g_med_endpt, _local_sdp/*_plocalsdp*/, _remote_sdp/*_premotesdp*/, 0);
			if (PJ_SUCCESS != status) {
				pj_assert(PJ_SUCCESS == status);
				break;
			}
			status = pjmedia_stream_create(g_med_endpt, g_pool, _pstreaminfo, *_ptransport, nullptr, _pmediastream);
			if (PJ_SUCCESS != status) {
				pj_assert(PJ_SUCCESS == status);
				break;
			}
			if (is_inner) {
				//	dtmf 现在只做内端的检测，外端的略过，外端只播放语音提示
				status = pjmedia_stream_set_dtmf_callback(*_pmediastream, cb_dtmf_check, this);
				pj_assert(PJ_SUCCESS == status);

				status = pjmedia_stream_set_dtmf_event_callback(*_pmediastream, cb_dtmf_events, this);
				pj_assert(PJ_SUCCESS == status);
			}

			status = pjmedia_stream_start(*_pmediastream);
			pj_assert(PJ_SUCCESS == status);

			*_pmediaport = nullptr;
			status = pjmedia_stream_get_port(*_pmediastream, _pmediaport);
			pj_assert(PJ_SUCCESS == status);

			status = pjmedia_transport_media_start(*_ptransport, g_pool, _local_sdp/*_plocalsdp*/, _remote_sdp/*_premotesdp*/, 0);
			pj_assert(PJ_SUCCESS == status);
			_mediaok = true;

		} while (false);
		if (_mediaok) {
			return true;
		}
		if (nullptr != *_pmediastream) {
			status = pjmedia_stream_destroy(*_pmediastream);
			pj_assert(PJ_SUCCESS == status);
		}
		if (nullptr != *_ptransport) {
			status = pjmedia_transport_close(*_ptransport);
			pj_assert(PJ_SUCCESS == status);
			*_ptransport = nullptr;
		}
		return false;
	}

	//	语音播放的停止，此时需要取消掉双端创建的媒体通话并释放相关资源，将通话交回到语音桥
	bool sessmedia::stop_media_player() {
		do {
			//	相应的释放函数:
			//	pjmedia_transport_media_start -> pjmedia_transport_media_stop
			//	pjmedia_stream_start -> 
			//	pjmedia_stream_set_dtmf_callback
			//	pjmedia_stream_set_dtmf_event_callback
			//	pjmedia_stream_create -> pjmedia_stream_destroy
			//	pjmedia_transport_udp_attach -> pjmedia_transport_close
			pjmedia_transport* ar_transport[] = { m_transport_inner , m_transport_outer };
			pjmedia_stream* ar_stream[] = { m_stream_inner , m_stream_outer };
			pj_status_t status = PJ_SUCCESS;
			for (int i = 0; i < sizeof(ar_transport) / sizeof(pjmedia_transport*); i++) {
				if (nullptr != ar_transport[i]) {
					status = pjmedia_transport_media_stop(ar_transport[i]);
					pj_assert(PJ_SUCCESS == status);
				}
				if (nullptr != ar_stream[i]) {
					status = pjmedia_stream_destroy(ar_stream[i]);
					pj_assert(PJ_SUCCESS == status);
				}
				//	wg. 20251110, 虽然这个transport是attach出来的，但是在实测时发现如果将它关闭掉就无法进行语音通信。
				//	所以这个地方先不关闭这个transport.
				/*status = pjmedia_transport_close(ar_transport[i]);
				pj_assert(PJ_SUCCESS == status);*/
			}
		} while (false);
		return true;
	}

	//	播放对端为普通话机，并等待按键确认--向b2bua注册的话机播放
	void sessmedia::play_remote_is_normal() {
		replay_wav_and_wait(_wav_rmt_normal, _wav_wait_remote_confirm);
	}
	
	void sessmedia::replay_wav_and_wait(const std::string& wavfile, const std::string& wavfile_outer/* = ""*/) {
		g_sharp_ok = false;
		if (m_playing) {
			return;
		}

		m_playing = true;

		pjmedia_port* wavplayer = nullptr, * resample = nullptr, *wavplayer_outer = nullptr, *resample_outer = nullptr;
		pj_status_t status = PJ_SUCCESS;
		status = pjmedia_wav_player_port_create(g_pool,
			(_wav_dir + wavfile).c_str(),          // file name
			20,                   // ptime.
			0, //	循环播放.一直等到按键确认，或者是预设的超时
			0,                    // buffer size
			&wavplayer);
		pj_assert(PJ_SUCCESS == status);
		
		//	resample采样率不是任意设置的，是需要根据创建的对端媒体编码中指定的采样设置
		status = pjmedia_resample_port_create(g_pool, wavplayer, m_streaminfo_inner.fmt.clock_rate,
			0, &resample);
		pj_assert(PJ_SUCCESS == status);

		if (!wavfile_outer.empty()) {
			status = pjmedia_wav_player_port_create(g_pool,
				(_wav_dir + wavfile_outer).c_str(),          // file name
				20,                   // ptime.
				0, //	循环播放.一直等到按键确认，或者是预设的超时
				0,                    // buffer size
				&wavplayer_outer);
			pj_assert(PJ_SUCCESS == status);

			status = pjmedia_resample_port_create(g_pool, wavplayer_outer, m_streaminfo_outer.fmt.clock_rate,
				0, &resample_outer);
			pj_assert(PJ_SUCCESS == status);
		}

		int bufcnt = 16384;
		std::unique_ptr< pj_int16_t> samplebuf(new pj_int16_t[bufcnt]), samplebuf_outer(new pj_int16_t[bufcnt]);
		//	按确定键或者挂机，任意一个满足就停止播放
		while (!(g_sharp_ok || m_ishunup)) {
			pjmedia_frame frame, frame_outer;

			frame.buf = samplebuf.get();
			frame.size = bufcnt;

			// Get the frame from resample port.
			status = pjmedia_port_get_frame(resample, &frame);
			if (status != PJ_SUCCESS || frame.type == PJMEDIA_FRAME_TYPE_NONE) {
				// End-of-file, end the conversion.
				break;
			}
			// Put the frame to write port.
			status = pjmedia_port_put_frame(m_media_port_inner, &frame);
			if (status != PJ_SUCCESS) {
				// Error in writing the file.
				pj_assert(PJ_SUCCESS == status);
				break;
			}

			//	同步播放另一端
			if (!wavfile_outer.empty()) {
				frame.buf = samplebuf_outer.get();
				frame.size = bufcnt;

				// Get the frame from resample port.
				status = pjmedia_port_get_frame(resample_outer, &frame);
				if (status != PJ_SUCCESS || frame.type == PJMEDIA_FRAME_TYPE_NONE) {
					// End-of-file, end the conversion.
					break;
				}
				// Put the frame to write port.
				status = pjmedia_port_put_frame(m_media_port_outer, &frame);
				if (status != PJ_SUCCESS) {
					// Error in writing the file.
					pj_assert(PJ_SUCCESS == status);
					break;
				}
			}
			pj_thread_sleep(20);	//	这个每帧延时应该根据wav文件的采样、通道等参数计算，现在还算不来
		}
		m_playing = false;
		//	播放完成后停止语音通道，将通话交给媒体桥
		stop_media_player();
	}

	///////////////////////////////////////////////////////////////
	//	播放线程
	///////////////////////////////////////////////////////////////

	mediathread::mediathread() {
	}
	mediathread::~mediathread() {
	}
	void mediathread::start() {
		this->m_workthread = std::thread(std::bind(&mediathread::run, this));
	}
	void mediathread::stop() {
		{
			std::lock_guard<std::mutex> _lock(this->m_taskmutex);
			m_tasklist.push_back(std::shared_ptr<media_task>());
		}
		m_simple_semphore.post();
		m_workthread.join();
	}
	void mediathread::add_task(std::shared_ptr<ccsua::uasess> _uasess, std::function<void(void)> _taskfunc,
		std::function<void(std::shared_ptr<ccsua::uasess>)> _completed) {
		std::shared_ptr<media_task> ptr(new media_task());
		ptr->_uasess = _uasess;
		ptr->_completedfun = _completed;
		ptr->_taskfunc = _taskfunc;
		{
			std::lock_guard<std::mutex> _lock(this->m_taskmutex);
			m_tasklist.push_back(ptr);
		}
		m_simple_semphore.post();
	}

	void mediathread::run() {
		pj_thread_t* pthread = nullptr;
		pj_thread_desc _desc;
		memset(&_desc, 0, sizeof(pj_thread_desc));
		pj_thread_register("med_player", (long *)&_desc, &pthread);
		std::shared_ptr<media_task> ptr;
		while (true) {
			m_simple_semphore.wait();
			{
				std::lock_guard<std::mutex> _lock(this->m_taskmutex);
				ptr = m_tasklist.front();
				m_tasklist.pop_front();
			}
			if (!ptr) {
				break; //	这个是停止消息
			}
			//	执行任务
			ptr->_taskfunc();
			//	任务执行完成后，执行完成后事件
			if (!ptr->_uasess->is_hung_up()) {
				ptr->_completedfun(ptr->_uasess);
			}
			
		}
	}
}	//	namespace ccsua
