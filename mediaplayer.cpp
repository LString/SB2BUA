//	mediaplayer.cpp
/*
* һͨĻỰýʵ
*/
#include "mediaplayer.h"
#include "uasess.h"
#include "config.h"

std::atomic<bool> g_sharp_ok(false);
extern "C" {
	//	һ׵digit
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

        const std::string _wav_dir = config::get().wav_dir();
	//	ԶΪͨ޷ͨ
	const std::string _wav_rmt_normal("01.normal_phone.wav");
	//	Դʧܣ޷ͨ
	const std::string _wav_res_downfail("02.res_down_fail.wav");
	//	Զ֤֤ʧ
	const std::string _wav_rmt_certfail("03.verify_cert_fail.wav");
	//	ԿЭ̴
	const std::string _wav_key_exchangefail("04.key_exchange_fail.wav");
	//	PIN֤
	const std::string _wav_pin_auth("05.pin_auth.wav");
	//	ȴԿЭ
	const std::string _wav_wait_key_exchange("06.wait_key_exchange.wav");
	//	˵ʾ
	const std::string _wav_main_menu("07.main_menu.wav");
	//	ȴԷȷ
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

	//	ñҪsdp sessionýỰʹ--ֿΪǴʱͬ
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
	//	öԶ˵sdp sessionýỰʹ
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

	//	˻sdp
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
	//	öԶ˵sdp sessionýỰʹ
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
		//	Ҫ֤䱾ض˿ԼԶ˵ý˿
		pj_assert(nullptr != g_med_endpt);
		pj_assert(0 != m_sockpair_inner.rtcp_sock); //	Ҫ
		pj_assert(nullptr != m_local_sdp_inner);		//	ȻǱsdp
		pj_assert(nullptr != m_remote_sdp_inner);		//	ȻԶsdp

		pj_assert(0 != m_sockpair_outer.rtcp_sock); //	Ҫ
		pj_assert(nullptr != m_local_sdp_outer);		//	ȻǱsdp
		pj_assert(nullptr != m_remote_sdp_outer);		//	ȻԶsdp

		pj_assert(!m_mediaok); //	ɹٴһֻͨһ

		//	ڶⶼҪ
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
			//	ҪýϢڻû
			stop_media_player();
		}
		m_mediaok = _medok;
		return _medok;
	}

	//	ݲʹý岥, is_inner=trueڵý岥; is_inner=falseý岥
	bool sessmedia::create_media_player(bool is_inner) {
		if (m_mediaok) return true;
		//	Ҫ֤䱾ض˿ԼԶ˵ý˿
		pj_assert(nullptr != g_med_endpt);
		pj_assert(0 != m_sockpair_inner.rtcp_sock); //	Ҫ
		pj_assert(nullptr != m_local_sdp_inner);		//	ȻǱsdp
		pj_assert(nullptr != m_remote_sdp_inner);		//	ȻԶsdp
		pj_assert(!m_mediaok); //	ɹٴһֻͨһ

		//	ȸݷȷҪʹõĲ--Ĭ϶
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

		//	ֱʹЭ̵ķʽԻȡʵsdp--ֱӴӺлȡsdp֧֣ܲҪ˫˵sdpЭ
		pjmedia_sdp_neg* p_neg = nullptr;
		status = pjmedia_sdp_neg_create_w_remote_offer(g_pool, _plocalsdp, _premotesdp, &p_neg);
		pj_assert(PJ_SUCCESS == status);
		status = pjmedia_sdp_neg_set_prefer_remote_codec_order(p_neg, true);
		pj_assert(PJ_SUCCESS == status);
		//	Э..
		status = pjmedia_sdp_neg_negotiate(g_pool, p_neg, 0);
		pj_assert(PJ_SUCCESS == status);
		//	ٻȡЭ̺õsdp
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
				//	dtmf ֻڶ˵ļ⣬˵Թֻʾ
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

	//	ŵֹͣʱҪȡ˫˴ýͨͷԴͨص
	bool sessmedia::stop_media_player() {
		do {
			//	Ӧͷź:
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
				//	wg. 20251110, Ȼtransportattachģʵʱرյ޷ͨš
				//	طȲرtransport.
				/*status = pjmedia_transport_close(ar_transport[i]);
				pj_assert(PJ_SUCCESS == status);*/
			}
		} while (false);
		return true;
	}

	//	ŶԶΪͨȴȷ--b2buaעĻ
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
			0, //	ѭ.һֱȵȷϣԤĳʱ
			0,                    // buffer size
			&wavplayer);
		pj_assert(PJ_SUCCESS == status);
		
		//	resampleʲõģҪݴĶԶýָĲ
		status = pjmedia_resample_port_create(g_pool, wavplayer, m_streaminfo_inner.fmt.clock_rate,
			0, &resample);
		pj_assert(PJ_SUCCESS == status);

		if (!wavfile_outer.empty()) {
			status = pjmedia_wav_player_port_create(g_pool,
				(_wav_dir + wavfile_outer).c_str(),          // file name
				20,                   // ptime.
				0, //	ѭ.һֱȵȷϣԤĳʱ
				0,                    // buffer size
				&wavplayer_outer);
			pj_assert(PJ_SUCCESS == status);

			status = pjmedia_resample_port_create(g_pool, wavplayer_outer, m_streaminfo_outer.fmt.clock_rate,
				0, &resample_outer);
			pj_assert(PJ_SUCCESS == status);
		}

		int bufcnt = 16384;
		std::unique_ptr< pj_int16_t> samplebuf(new pj_int16_t[bufcnt]), samplebuf_outer(new pj_int16_t[bufcnt]);
		//	ȷ߹һһֹͣ
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

			//	ͬһ
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
			pj_thread_sleep(20);	//	ÿ֡ʱӦøwavļĲͨȲ㣬ڻ㲻
		}
		m_playing = false;
		//	ɺֹͣͨͨý
		stop_media_player();
	}

	///////////////////////////////////////////////////////////////
	//	߳
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
				break; //	ֹͣϢ
			}
			//	ִ
			ptr->_taskfunc();
			//	ִɺִɺ¼
			if (!ptr->_uasess->is_hung_up()) {
				ptr->_completedfun(ptr->_uasess);
			}
			
		}
	}
}	//	namespace ccsua
