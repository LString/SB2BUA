//	config.cpp
//	config配置信息的实现
#include "config.h"

namespace ccsua {
	config config::m_config;
	config::config() {
		m_wav_dir = "F:\\wg\\voip\\sb2bua20251023\\wav_files\\";
		m_certkey_dir = "F:\\wg\\voip\\sb2bua20251023\\certkey\\";

		m_certchain = "rootCA.crt";
		m_selfcert = "1005.crt";
		m_selfkey = "1005.key";
		m_user = "1005";
		m_userpwd = "password555";

		m_sip_addr = "60.40.0.205";
		m_outer_addr = "60.40.0.233";
		m_inner_addr = "192.168.99.233";
	}
	config::~config() {}
	config& config::get() {
		return m_config;
	}


	//	加载配置信息--需要指定配置文件路径，然后读取配置文件并加载
	bool config::load() {
		return true;
	}

	//	获取到配置的各项信息

	//	获取到wav文件存放路径
	const std::string config::wav_dir() const {
		return m_wav_dir;
	}
	//	获取到证书链路径--证书链路径的格式为: 根->签发者0->签发者1->...签发者N, 需要逐层验证。链中的最后一个用来验用户证书
	//	如果是直接用根签用户证书，证书链路径中就只有一个根证书
	const std::list<std::string> config::root_cert_file() const {
		std::string _rootcert = m_certkey_dir + m_certchain;
		std::list<std::string> _ret;
		_ret.push_back(_rootcert);
		return _ret;
	}
	//	获取到自身证书路径
	const std::string config::self_cert_file() const {
		return m_certkey_dir + m_selfcert;
	}
	//	获取到自身私钥路径
	const std::string config::self_priv_key() const {
		return m_certkey_dir + m_selfkey;
	}

	//	获取到向sip服务注册的密码--用户名应直接从证书中提取,或者至少要做验证,必须与用户证书中匹配
	const std::string config::sip_user_pwd() const {
		return m_userpwd;
	}
	const std::string config::sip_user() const {
		return m_user;
	}

	//	sip 服务地址
	const std::string config::sip_addr() const {
		return m_sip_addr;
	}
	//	外网地址: 与sip服务相连
	const std::string config::outer_addr() const {
		return m_outer_addr;
	}
	//	内网地址: 与话机相连
	const std::string config::inner_addr() const {
		return m_inner_addr;
	}

}	//	namespace ccsua
