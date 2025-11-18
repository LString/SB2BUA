//	mediaplayer.h
/*
* 实现媒体播放的相关操作, 通话建立前的一些自动语音播放，它要和通话绑定
* 这个实现中会根据通话的相关信息创建出媒体信息，媒体流，加载wav音频文件等
* 为简单实现，这个会话媒体只针对接入b2bua的话机进行播放，不给对端话机播放。因此这个
* 会话媒体只有一个方向的传输，uasess会自行将与b2bua话机关联的网络信息传递给sessmedia
* 会话媒体只会在通话过建立前参与，通话建立后不会再参与(后续如有任何问题直接主动挂机)。
* 会话媒体中需要负责加载出相应的自动播放语音文件，在合适的时机向话机播放语音，并且
* 在必要时做DTMF按键检测并给出响应到b2bua。
* 
* wg. 20251107. 媒体播放需要改进，前期定义的单向播放应该无法满足正常通话时的需求:
* 当普通外端呼入时，b2bua正在等待话机确认时，应该也需要向对端播放等待的语音,或者这个时候不回复200 INVITE，继续响铃也行。
* 当b2bua呼出时，普通对端已经发送200 INVITE，它认为通话已经建立，此时b2bua才知道对端是否是普通话机并且等待内网话机确认，
* 这个时候就一定需要给对端播放等待语音，避免对端通话网络异常。
* 
* sessmedia中定义了 local/remote sdp inner 与 local/remote sdp outer 四个方向的sdp,本质上只有两个,一个是内端话机的sdp,另一个是
* 外端话机的sdp,中途涉及到地址信息的更新。在呼叫请求和响应处理流程中设置上正确的sdp。更新流程参照以下说明:
* 内端呼出时: 
* INVITE请求中获取到的sdp作为 remote_sdp_inner, 然后创建出的uac端invite且被更新过地址的作为 local_sdp_outer
* 接收到200 INVITE时，uac 200 INVITE响应中的sdp直接作为 remote_sdp_outer, 转发给uas且被更新过地址的作为 local_sdp_inner
* 外端呼入时:
* INVITE请求中获取到的sdp作为remote_sdp_outer, 然后创建出的uac端invite且被更新成内网地址的作为 local_sdp_inner
* 接收到内网200 INVITE时，uac 200 INVITE响应中的sdp直接作为 remote_sdp_inner, 转发给uas且被更新成外网地址的作为 local_sdp_outer
*/

#ifndef _CCS_UA_MEDIA_PLAYER_H_
#define _CCS_UA_MEDIA_PLAYER_H_

#include "commons.h"


namespace ccsua {
	class uasess;
	//	这是一个会话媒体，不是媒体会话.
	class sessmedia : public std::enable_shared_from_this<sessmedia> {
	public:
		sessmedia();
		virtual ~sessmedia();
		//	设置网络参数，这个就是 sock pair, 
		//	自行使用 UAC 或者UAS的网络信息设置，这里面不做检测和验证
		void set_netpara_inner(const media_sock_pair_t &_sockpair) {
			memcpy(&m_sockpair_inner, &_sockpair, sizeof(media_sock_pair_t));
		}
		//	设置外部媒体网络参数,必要时需要向对端播放语音
		void set_netpara_outer(const media_sock_pair_t& _sockpair) {
			memcpy(&m_sockpair_outer, &_sockpair, sizeof(media_sock_pair_t));
		}
		//	播放中途挂机调用
		void hung_up() { m_ishunup = true; }

		//	设置本要sdp session，后续用来创建媒体会话使用--这两个分开设置是因为它们创建出来的时机不同
		//	local sdp 是指b2bua内网侧的sdp,与UAS/UAC要区分开
		void set_local_sdp_session_inner(const std::string & _localsdp);		
		//	设置对端的sdp session后续用来创建媒体会话使用
		//	remote sdp是指b2bua接入的话机侧的sdp,并不是指对端话机
		void set_remote_sdp_session_inner(const std::string & _rmtsdp);

		//	外端话机的sdp
		void set_local_sdp_session_outer(const std::string& _localsdp);
		//	设置对端的sdp session后续用来创建媒体会话使用
		void set_remote_sdp_session_outer(const std::string& _rmtsdp);

		//	创建会话媒体并完成与话机的端口绑定--需要先设置网络参数和sdp信息
		//	这个创建会将通话两端的都创建出来，根据需要可能会向两端都播放语音
		bool create_media_player();

		//	语音播放的停止，此时需要取消掉双端创建的媒体通话并释放相关资源，将通话交回到语音桥
		bool stop_media_player();

		//	播放媒体信息，先预设几种固定的播放
		//	播放对端为普通话机，并等待按键确认--向b2bua注册的话机播放
		void play_remote_is_normal();
		
	protected:
		//	播放媒体信息并且可能做等待确认--这个可能涉及到双向播放，如果wavfile_outer不为空，则需要双向播放
		void replay_wav_and_wait(const std::string &wavfile, const std::string &wavfile_outer = "");

		//	根据参数类型创建媒体播放, is_inner=true创建对内的媒体播放; is_inner=false创建对外的媒体播放
		bool create_media_player(bool is_inner);

	protected:

		pjmedia_transport* m_transport_inner, * m_transport_outer;
		pjmedia_stream* m_stream_inner, * m_stream_outer;
		pjmedia_port* m_media_port_inner, * m_media_port_outer;

		pjmedia_stream_info m_streaminfo_inner, m_streaminfo_outer;

		//	这两个SDP需要保存用来创建媒体会话--媒体会话同样需要有一个对内和对外
		std::string m_local_sdp_str_inner, m_remote_sdp_str_inner, m_local_sdp_str_outer, m_remote_sdp_str_outer;
		pjmedia_sdp_session* m_local_sdp_inner, * m_remote_sdp_inner, * m_local_sdp_outer, * m_remote_sdp_outer;

		//	媒体会话的网络参数--现在需要有两端:对内和对外
		media_sock_pair_t m_sockpair_inner, m_sockpair_outer;

		std::atomic<bool> m_mediaok;
		std::atomic<bool> m_playing;	//	是否正在播放语音，
		std::atomic<bool> m_ishunup;	//	是否已挂机
	}; //	class sessmedia

	//	wg. 20251110, 添加一个媒体播放线程，在播放线程中实现语音播放并且执行播放完成后的操作,避免主流程中调用阻塞式的播放
	//	导致无法处理协议，

	class mediathread {
	public:
		mediathread();
		virtual ~mediathread();

		//	媒体播放线程是程序启动的时候启动，退出的时候退出，其它的时候需要等待业务协议的触发
		void start();
		void stop();

		//	对外提供的接口: 业务处理中添加一个播放事件,需要完成函数和执行函数
		void add_task(std::shared_ptr<ccsua::uasess> _uasess, std::function<void(void)> _taskfunc,
			std::function<void(std::shared_ptr<ccsua::uasess>)> _completed);
		
	protected:
		//	需要先验证播放线程功能，暂定任务类型长这样，完成后再重新设计接口
		typedef struct _media_task {
			std::shared_ptr < ccsua::uasess> _uasess;
			std::function<void(void)> _taskfunc;
			std::function<void(std::shared_ptr<ccsua::uasess>)> _completedfun;
		}media_task, *pmedia_task;

		//	线程函数
		void run();
		
		std::mutex m_taskmutex;
		std::list< std::shared_ptr<media_task> > m_tasklist;
		simple_semaphore m_simple_semphore;

		std::thread m_workthread;
	}; //	class mediathread
	
} //	namespace ccsua

#endif //	_CCS_UA_MEDIA_PLAYER_H_
