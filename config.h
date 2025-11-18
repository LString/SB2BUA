//	config.h
//	b2bua相关的配置程序,需要配置内、外网地址，证书、私钥、端口、语音文件等

#ifndef _CCS_UA_CONFIGS_H_
#define _CCS_UA_CONFIGS_H_

#include "commons.h"

namespace ccsua {
	class config {
	private:
		config();
		virtual ~config();
		static config m_config;
	public:
		static config& get();
		//	加载配置信息
		bool load();

		//	获取到配置的各项信息

		//	获取到wav文件存放路径
		const std::string wav_dir() const;
		//	获取到证书链路径--证书链路径的格式为: 根->签发者0->签发者1->...签发者N, 需要逐层验证。链中的最后一个用来验用户证书
		//	如果是直接用根签用户证书，证书链路径中就只有一个根证书
		const std::list<std::string> root_cert_file() const;
		//	获取到自身证书路径
		const std::string self_cert_file() const;
		//	获取到自身私钥路径
		const std::string self_priv_key() const;

		//	获取到向sip服务注册的密码--用户名应直接从证书中提取,或者至少要做验证,必须与用户证书中匹配
		const std::string sip_user_pwd() const;
		const std::string sip_user() const;

		//	sip 服务地址
		const std::string sip_addr() const;
		//	外网地址: 与sip服务相连
		const std::string outer_addr() const;
		//	内网地址: 与话机相连
		const std::string inner_addr() const;
		
#ifdef _UNIT_TEST_
		//	测试状态下可修改证书用户key等信息
		void set_self_cert_file(const std::string& file) {
			m_selfcert = file;
		}
		void set_self_priv_key(const std::string& file) {
			m_selfkey = file;
		}
		void set_sip_user(const std::string& user) {
			m_user = user;
		}
		void set_sip_user_pwd(const std::string& pwd) {
			m_userpwd = pwd;
		}
#endif
	protected:
		std::string m_wav_dir, m_certkey_dir;
		std::string m_certchain, m_selfcert, m_selfkey;
		std::string m_user, m_userpwd;

		std::string m_sip_addr, m_outer_addr, m_inner_addr;
	};
}	//	namespace ccsua


#endif	//	_CCS_UA_CONFIGS_H_
